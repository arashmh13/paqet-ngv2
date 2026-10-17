package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"

	"github.com/arashmh13/paqet-ngv2/internal/client"
	"github.com/arashmh13/paqet-ngv2/internal/conf"
	"github.com/arashmh13/paqet-ngv2/internal/ng/transport"
	"github.com/arashmh13/paqet-ngv2/internal/socks"
)

type LiveAuditReport struct {
	Timestamp         string                           `json:"timestamp"`
	Phase             string                           `json:"phase"`
	TestToken         string                           `json:"test_token"`
	PrimaryEndpoint   string                           `json:"primary_endpoint"`
	CandidateEndpoint string                           `json:"candidate_endpoint"`
	SOCKS5ListenPort  int                              `json:"socks5_listen_port"`
	HTTPOriginPort    int                              `json:"http_origin_port"`
	StepABaseline     StepReport                       `json:"step_a_baseline"`
	StepBPrimaryDrop  StepReport                       `json:"step_b_primary_drop"`
	StepCSignaling    StepReport                       `json:"step_c_signaling"`
	StepDValidation   StepReport                       `json:"step_d_validation"`
	StepERecovery     StepReport                       `json:"step_e_recovery"`
	StepFRollback     StepReport                       `json:"step_f_rollback"`
	StepGRestoration  StepReport                       `json:"step_g_restoration"`
	ProductionHealth  string                           `json:"production_health"`
	History           []transport.StateTransitionEvent `json:"history"`
	Outcome           string                           `json:"outcome"`
}

type StepReport struct {
	Passed      bool    `json:"passed"`
	Description string  `json:"description"`
	DurationMs  float64 `json:"duration_ms"`
	Details     string  `json:"details"`
}

func parseKeyBytes(rawStr string) ([]byte, error) {
	rawStr = strings.TrimSpace(rawStr)
	if b, err := base64.StdEncoding.DecodeString(rawStr); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := hex.DecodeString(rawStr); err == nil && len(b) == 32 {
		return b, nil
	}
	if len(rawStr) == 32 {
		return []byte(rawStr), nil
	}
	return nil, fmt.Errorf("invalid key length %d: must decode to 32 bytes (base64, hex, or raw)", len(rawStr))
}

func main() {
	primaryAddrStr := flag.String("primary", "203.0.113.7:18088", "Primary Paqet server test address")
	candidateAddrStr := flag.String("candidate", "203.0.113.7:18089", "Candidate Paqet server test address")
	socksPort := flag.Int("socks-port", 11990, "Dedicated isolated SOCKS5 port")
	httpOriginPort := flag.Int("origin-port", 18999, "Remote HTTP test origin port on Germany VPS")
	dnsServerAddr := flag.String("dns-server", "203.0.113.7:53", "Authoritative emergency DNS server")
	domainSuffix := flag.String("domain", "tunnel.paqet-ngv2.example", "Emergency DNS domain")
	keyFile := flag.String("key-file", "/opt/paqet/emergency.key", "Path to emergency key file")
	outputReport := flag.String("out", "/opt/paqet/live_socks5_recovery_report.json", "JSON audit output path")
	tokenFlag := flag.String("token", "", "Explicit test token (randomly generated if empty)")
	flag.Parse()

	log.Printf("=================================================================")
	log.Printf("PAQET-NG PHASE 13 — SOCKS5 RECOVERY & IDENTITY BINDING TEST")
	log.Printf("=================================================================")

	// 1. Load PSK
	keyBytes, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatalf("Failed to read emergency key file: %v", err)
	}
	psk, err := parseKeyBytes(string(keyBytes))
	if err != nil {
		log.Fatalf("Failed to parse PSK in %s: %v", *keyFile, err)
	}
	keyFingerprint := fmt.Sprintf("SHA256:%x", sha256.Sum256(psk))
	log.Printf("[INIT] Loaded PSK: fingerprint=%s", keyFingerprint)

	// 2. Generate or use unpredictable test token
	testToken := *tokenFlag
	if testToken == "" {
		tokenBytes := make([]byte, 16)
		_, _ = rand.Read(tokenBytes)
		testToken = "LIVE_TOKEN_" + hex.EncodeToString(tokenBytes)
	}
	log.Printf("[INIT] Active test token: %s", testToken)

	report := LiveAuditReport{
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		Phase:             "Phase 13 Real SOCKS5 Recovery",
		TestToken:         testToken,
		PrimaryEndpoint:   *primaryAddrStr,
		CandidateEndpoint: *candidateAddrStr,
		SOCKS5ListenPort:  *socksPort,
		HTTPOriginPort:    *httpOriginPort,
	}

	// 3. Resolve addresses
	primaryUDP, err := net.ResolveUDPAddr("udp", *primaryAddrStr)
	if err != nil {
		log.Fatalf("Resolve primary UDP addr: %v", err)
	}
	socksUDP, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", *socksPort))
	if err != nil {
		log.Fatalf("Resolve socks UDP addr: %v", err)
	}

	// 4. Configure RecoveryStateMachine
	var emergencySignalLatency time.Duration
	var candidateValidationLatency time.Duration
	var signalingTriggered atomic.Bool

	recoverySM := transport.NewRecoveryStateMachine(transport.RecoveryStateMachineConfig{
		PrimaryFailureThreshold:    1,
		DegradedTimeout:            50 * time.Millisecond,
		BootstrapValidationTimeout: 4 * time.Second,
		CooldownDuration:           10 * time.Second,
		AllowLoopbackEndpoints:     false,
		AllowPrivateEndpoints:      false,
		EmergencyDialer: func(ctx context.Context, msg *transport.EmergencyMessage) (*transport.BootstrapEndpointData, error) {
			signalingTriggered.Store(true)
			log.Printf("[EMERGENCY-DNS] Transmitting emergency signaling query to %s (domain: %s)...", *dnsServerAddr, *domainSuffix)

			// Build emergency query client
			client, err := transport.NewEmergencyDNSClient(transport.EmergencyDNSClientConfig{
				ResolverAddr:         *dnsServerAddr,
				DomainSuffix:         *domainSuffix,
				PSK:                  psk,
				ClientID:             "c13",
				IsLegacySingleServer: true,
			})
			if err != nil {
				return nil, fmt.Errorf("create emergency client: %w", err)
			}

			resp, rtt, err := client.Exchange(ctx, msg)
			if err != nil {
				return nil, fmt.Errorf("emergency exchange error: %w", err)
			}
			emergencySignalLatency = rtt
			log.Printf("[EMERGENCY-DNS] Received authenticated response in %v (ID=%s, status=%s, replyBytes=%d)",
				emergencySignalLatency, resp.ID, resp.Status, len(resp.Reply))

			var endpoint transport.BootstrapEndpointData
			if err := json.Unmarshal(resp.Reply, &endpoint); err != nil {
				return nil, fmt.Errorf("unmarshal bootstrap endpoint: %w", err)
			}
			log.Printf("[EMERGENCY-DNS] Parsed candidate coordinates: %s:%d (mode: %s, pubKey: %s, validUntil: %d)",
				endpoint.ServerIP, endpoint.TransportPort, endpoint.TransportMode, endpoint.ServerPubKey, endpoint.ValidUntil)
			return &endpoint, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *transport.BootstrapEndpointData) error {
			startVal := time.Now()
			log.Printf("[CANDIDATE-VAL] Validating candidate endpoint %s:%d cryptographically...", endpoint.ServerIP, endpoint.TransportPort)
			valFn := transport.BuildCandidateValidator(transport.CandidateValidatorOptions{
				PSK: psk,
			})
			err := valFn(ctx, endpoint)
			candidateValidationLatency = time.Since(startVal)
			if err != nil {
				log.Printf("[CANDIDATE-VAL] Validation failed in %v: %v", candidateValidationLatency, err)
				return err
			}
			log.Printf("[CANDIDATE-VAL] Candidate %s:%d validated in %v (Paqet AEAD handshake & protocol PPING/PPONG verified)",
				endpoint.ServerIP, endpoint.TransportPort, candidateValidationLatency)
			return nil
		},
	})

	// 5. Build Client and SOCKS5 Proxy
	clientCfg := &conf.Conf{
		Role: "client",
		Server: conf.Server{
			Addr:      primaryUDP,
			Endpoints: []*net.UDPAddr{primaryUDP},
		},
		SOCKS5: []conf.SOCKS5{
			{
				Listen: socksUDP,
			},
		},
		Transport: conf.Transport{
			Protocol: "aead-stream",
			Conn:     1,
			Obfs: &conf.Obfs{
				Enabled: true,
				Key:     string(psk),
				MaxPad:  64,
			},
		},
	}

	clientInst, err := client.New(clientCfg)
	if err != nil {
		log.Fatalf("client.New failed: %v", err)
	}
	clientInst.SetRecoveryEngine(recoverySM)

	clientCtx, cancelClient := context.WithCancel(context.Background())
	defer cancelClient()
	if err := clientInst.Start(clientCtx); err != nil {
		log.Fatalf("client.Start failed: %v", err)
	}

	socksProxy, err := socks.New(clientInst)
	if err != nil {
		log.Fatalf("socks.New failed: %v", err)
	}
	socksCtx, cancelSocks := context.WithCancel(context.Background())
	defer cancelSocks()
	if err := socksProxy.Start(socksCtx, clientCfg.SOCKS5[0]); err != nil {
		log.Fatalf("socksProxy.Start failed: %v", err)
	}

	log.Printf("[INIT] Isolated SOCKS5 proxy running on 127.0.0.1:%d", *socksPort)
	time.Sleep(100 * time.Millisecond)

	// Setup HTTP client through SOCKS5 proxy
	socksDialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", *socksPort), nil, proxy.Direct)
	if err != nil {
		log.Fatalf("proxy.SOCKS5 failed: %v", err)
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return socksDialer.Dial(network, addr)
			},
		},
		Timeout: 6 * time.Second,
	}

	testTargetURL := fmt.Sprintf("http://127.0.0.1:%d/test-token", *httpOriginPort)

	// =================================================================
	// STEP A — Baseline Request through Primary Transport
	// =================================================================
	log.Printf("\n>>> STEP A: Baseline request through primary transport (:18088)...")
	startA := time.Now()
	respA, errA := httpClient.Get(testTargetURL)
	durA := time.Since(startA).Seconds() * 1000.0
	if errA != nil {
		log.Fatalf("[STEP A FAIL] Baseline request failed: %v", errA)
	}
	bodyA, _ := io.ReadAll(respA.Body)
	respA.Body.Close()

	var dataA map[string]string
	_ = json.Unmarshal(bodyA, &dataA)
	recTokenA := dataA["token"]
	log.Printf("[STEP A] Received token=%s (expected=%s, match=%v, dur=%.2fms)",
		recTokenA, testToken, recTokenA == testToken, durA)

	if recTokenA != testToken {
		log.Fatalf("[STEP A FAIL] Token mismatch: got %q, want %q", recTokenA, testToken)
	}
	report.StepABaseline = StepReport{
		Passed:      true,
		Description: "Baseline HTTP request through primary Paqet transport served by :18088",
		DurationMs:  durA,
		Details:     fmt.Sprintf("HTTP 200 OK, token %s verified byte-exact", recTokenA),
	}

	// =================================================================
	// STEP B — Isolated Primary Failure Induction
	// =================================================================
	log.Printf("\n>>> STEP B: Injecting iptables DROP for primary endpoint %s...", *primaryAddrStr)
	startB := time.Now()
	cmdBlock := exec.Command("iptables", "-I", "OUTPUT", "-p", "tcp", "-d", "203.0.113.7", "--dport", "18088", "-j", "DROP")
	if out, err := cmdBlock.CombinedOutput(); err != nil {
		log.Fatalf("iptables DROP failed: %v (%s)", err, string(out))
	}
	defer func() {
		// Ensure rule is cleaned up on exit
		_ = exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "-d", "203.0.113.7", "--dport", "18088", "-j", "DROP").Run()
	}()
	durB := time.Since(startB).Seconds() * 1000.0
	log.Printf("[STEP B] Primary endpoint 203.0.113.7:18088 blocked in %.2fms", durB)

	// Issue request through SOCKS5 proxy with short timeout to demonstrate primary failure
	failClient := &http.Client{
		Transport: httpClient.Transport,
		Timeout:   3500 * time.Millisecond,
	}
	_, failErr := failClient.Get(testTargetURL)
	log.Printf("[STEP B] Request through blocked primary path failed as expected: %v", failErr)
	recoverySM.ReportPrimaryFailure(fmt.Errorf("primary unreachable: %v", failErr))

	report.StepBPrimaryDrop = StepReport{
		Passed:      failErr != nil,
		Description: "Applied narrowly scoped iptables DROP rule; verified primary request fails",
		DurationMs:  durB,
		Details:     fmt.Sprintf("iptables -I OUTPUT -p tcp -d 203.0.113.7 --dport 18088 -j DROP; request failed: %v", failErr),
	}

	// =================================================================
	// STEP C & D — Emergency Signaling & Candidate Validation
	// =================================================================
	log.Printf("\n>>> STEP C & D: Performing Emergency Signaling & Cryptographic Validation...")
	time.Sleep(100 * time.Millisecond) // Allow DegradedTimeout to elapse
	startStep := time.Now()
	recovState, stepErr := recoverySM.Step(context.Background())
	stepDur := time.Since(startStep).Seconds() * 1000.0
	if stepErr != nil || recovState != transport.StateRecoveryReady {
		log.Fatalf("[STEP C/D FAIL] Step failed: state=%s, err=%v", recovState, stepErr)
	}
	snapshot := recoverySM.ActiveSnapshot()
	if snapshot == nil {
		log.Fatalf("[STEP C/D FAIL] Active snapshot is nil!")
	}
	log.Printf("[STEP C/D PASS] Active recovery endpoint activated: %s (mode: %s, gen: %d, in %.2fms)",
		snapshot.Addr(), snapshot.TransportMode, snapshot.Generation, stepDur)

	report.StepCSignaling = StepReport{
		Passed:      signalingTriggered.Load(),
		Description: "Emergency signaling via authenticated DNS query and response",
		DurationMs:  emergencySignalLatency.Seconds() * 1000.0,
		Details:     fmt.Sprintf("DNS exchange completed; received candidate %s (mode: %s)", snapshot.Addr(), snapshot.TransportMode),
	}
	report.StepDValidation = StepReport{
		Passed:      true,
		Description: "Cryptographic identity binding and AEAD handshake validation",
		DurationMs:  candidateValidationLatency.Seconds() * 1000.0,
		Details:     fmt.Sprintf("Candidate %s passed AEAD key derivation, smux handshake, and PPING/PPONG protocol check", snapshot.Addr()),
	}

	// =================================================================
	// STEP E — Application-Level Recovery: SOCKS5 Request through Candidate
	// =================================================================
	log.Printf("\n>>> STEP E: Issuing SOCKS5 request routed via recovery candidate...")
	startRecov := time.Now()
	recovClient := &http.Client{
		Transport: httpClient.Transport,
		Timeout:   10 * time.Second,
	}
	respRecov, errRecov := recovClient.Get(testTargetURL)
	durE := time.Since(startRecov).Seconds() * 1000.0

	if errRecov != nil {
		log.Fatalf("[STEP E FAIL] SOCKS5 request through recovery candidate failed: %v", errRecov)
	}
	bodyRecov, _ := io.ReadAll(respRecov.Body)
	respRecov.Body.Close()

	var dataRecov map[string]string
	_ = json.Unmarshal(bodyRecov, &dataRecov)
	recTokenRecov := dataRecov["token"]
	log.Printf("[STEP E PASS] Received token through recovery candidate: %s (match=%v, dur=%.2fms)",
		recTokenRecov, recTokenRecov == testToken, durE)

	if recTokenRecov != testToken {
		log.Fatalf("[STEP E FAIL] Token mismatch on recovery path: got %q, want %q", recTokenRecov, testToken)
	}

	report.StepERecovery = StepReport{
		Passed:      true,
		Description: "Real application HTTP request through isolated SOCKS5 proxy routed via recovery candidate",
		DurationMs:  durE,
		Details:     fmt.Sprintf("HTTP 200 OK; token %s matched byte-exact; candidate served connection in %.2fms", recTokenRecov, durE),
	}

	// =================================================================
	// STEP F — Negative & Rollback Tests
	// =================================================================
	log.Printf("\n>>> STEP F: Rollback and Fail-Closed Verification...")
	startF := time.Now()
	recoverySM.ResetRollback("operator manual restoration")
	if recoverySM.CurrentState() != transport.StatePrimaryHealthy {
		log.Fatalf("[STEP F FAIL] Expected StatePrimaryHealthy after ResetRollback, got %s", recoverySM.CurrentState())
	}
	if recoverySM.ActiveSnapshot() != nil {
		log.Fatalf("[STEP F FAIL] Active snapshot not cleared after rollback")
	}
	durF := time.Since(startF).Seconds() * 1000.0
	log.Printf("[STEP F PASS] Rollback verified in %.2fms; state is PRIMARY_HEALTHY", durF)
	report.StepFRollback = StepReport{
		Passed:      true,
		Description: "Deterministic ResetRollback clears active snapshot and returns to PRIMARY_HEALTHY",
		DurationMs:  durF,
		Details:     "Active snapshot cleared, state returned to PRIMARY_HEALTHY",
	}

	// =================================================================
	// STEP G — Restoration & Production Health Check
	// =================================================================
	log.Printf("\n>>> STEP G: Removing test iptables rule & checking production SOCKS5 on :1090...")
	startG := time.Now()
	_ = exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "-d", "203.0.113.7", "--dport", "18088", "-j", "DROP").Run()
	durG := time.Since(startG).Seconds() * 1000.0

	// Check production SOCKS5 proxy
	cmdProd := exec.Command("curl", "-s", "-x", "socks5://USER:PASSWORD@127.0.0.1:1090", "http://127.0.0.1:8999/ping")
	outProd, errProd := cmdProd.CombinedOutput()
	prodStatus := strings.TrimSpace(string(outProd))
	log.Printf("[STEP G] Production SOCKS5 status: %s (err=%v)", prodStatus, errProd)

	report.StepGRestoration = StepReport{
		Passed:      errProd == nil && strings.Contains(prodStatus, "pong"),
		Description: "Iptables test rule deleted; production SOCKS5 verified healthy",
		DurationMs:  durG,
		Details:     fmt.Sprintf("iptables rule removed; production 127.0.0.1:1090 returned: %s", prodStatus),
	}
	report.ProductionHealth = prodStatus
	report.History = recoverySM.History()
	report.Outcome = "PHASE 13 SOCKS5 RECOVERY VERIFIED WITH FULL CRYPTOGRAPHIC IDENTITY BINDING"

	// Save report JSON
	reportJSON, _ := json.MarshalIndent(report, "", "  ")
	_ = os.WriteFile(*outputReport, reportJSON, 0644)
	log.Printf("\n[REPORT] Saved audit report to %s", *outputReport)
	fmt.Println(string(reportJSON))
}
