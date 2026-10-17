package transport_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/arashmh13/paqet-ngv2/internal/client"
	"github.com/arashmh13/paqet-ngv2/internal/conf"
	"github.com/arashmh13/paqet-ngv2/internal/ng/transport"
	"github.com/arashmh13/paqet-ngv2/internal/server"
	"github.com/arashmh13/paqet-ngv2/internal/socks"
)

func randomToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "TOKEN_" + hex.EncodeToString(b)
}

func getFreePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("getFreePort failed: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestSOCKS5_LiveApplicationRecoveryFlow(t *testing.T) {
	// 1. Ports for isolated test environment
	primaryServerPort := getFreePort(t)
	candidateServerPort := getFreePort(t)
	socks5Port := getFreePort(t)
	httpOriginPort := getFreePort(t)

	testPSK := []byte("0123456789abcdef0123456789abcdef")
	pskDigest := sha256.Sum256(testPSK)
	pubKeyFingerprint := fmt.Sprintf("SHA256:%x", pskDigest)

	// 2. Start HTTP Test Origin on 127.0.0.1:httpOriginPort
	expectedToken := randomToken()
	httpOriginMux := http.NewServeMux()
	var originHitCount atomic.Int32
	httpOriginMux.HandleFunc("/test-token", func(w http.ResponseWriter, r *http.Request) {
		originHitCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "RECOVERY_VERIFIED",
			"token":  expectedToken,
		})
	})
	httpServer := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", httpOriginPort),
		Handler: httpOriginMux,
	}
	originLn, err := net.Listen("tcp", httpServer.Addr)
	if err != nil {
		t.Fatalf("Failed to listen for HTTP test origin: %v", err)
	}
	defer originLn.Close()
	go func() { _ = httpServer.Serve(originLn) }()
	defer httpServer.Close()

	// 3. Start Primary Paqet Server (AEAD-Stream)
	primaryUDPAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", primaryServerPort))
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}
	primaryServerCfg := &conf.Conf{
		Role: "server",
		Listen: conf.Server{
			Addr:      primaryUDPAddr,
			Endpoints: []*net.UDPAddr{primaryUDPAddr},
		},
		Transport: conf.Transport{
			Protocol: "aead-stream",
			Obfs: &conf.Obfs{
				Enabled: true,
				Key:     string(testPSK),
				MaxPad:  64,
			},
		},
	}
	primarySrv, err := server.New(primaryServerCfg)
	if err != nil {
		t.Fatalf("Failed to create primary server: %v", err)
	}
	primaryCtx, cancelPrimary := context.WithCancel(context.Background())
	defer cancelPrimary()
	if err := primarySrv.Start(primaryCtx); err != nil {
		t.Fatalf("Failed to start primary server: %v", err)
	}

	// 4. Start Candidate Paqet Server (AEAD-Stream)
	candidateUDPAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", candidateServerPort))
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}
	candidateServerCfg := &conf.Conf{
		Role: "server",
		Listen: conf.Server{
			Addr:      candidateUDPAddr,
			Endpoints: []*net.UDPAddr{candidateUDPAddr},
		},
		Transport: conf.Transport{
			Protocol: "aead-stream",
			Obfs: &conf.Obfs{
				Enabled: true,
				Key:     string(testPSK),
				MaxPad:  64,
			},
		},
	}
	candidateSrv, err := server.New(candidateServerCfg)
	if err != nil {
		t.Fatalf("Failed to create candidate server: %v", err)
	}
	candidateCtx, cancelCandidate := context.WithCancel(context.Background())
	defer cancelCandidate()
	if err := candidateSrv.Start(candidateCtx); err != nil {
		t.Fatalf("Failed to start candidate server: %v", err)
	}

	// 5. Build and configure RecoveryStateMachine
	var emergencySignalingTriggered atomic.Bool
	recoverySM := transport.NewRecoveryStateMachine(transport.RecoveryStateMachineConfig{
		PrimaryFailureThreshold:    1,
		DegradedTimeout:            10 * time.Millisecond,
		BootstrapValidationTimeout: 2 * time.Second,
		CooldownDuration:           1 * time.Second,
		AllowLoopbackEndpoints:     true,
		AllowPrivateEndpoints:      true,
		EmergencyDialer: func(ctx context.Context, msg *transport.EmergencyMessage) (*transport.BootstrapEndpointData, error) {
			emergencySignalingTriggered.Store(true)
			return &transport.BootstrapEndpointData{
				Version:       2,
				ServerIP:      "127.0.0.1",
				TransportPort: candidateServerPort,
				TransportMode: "aead-stream",
				IdentityType:  transport.IdentityTypePSKID,
				IdentityValue: pubKeyFingerprint,
				ServerPubKey:  pubKeyFingerprint,
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: transport.BuildCandidateValidator(transport.CandidateValidatorOptions{
			PSK: testPSK,
		}),
	})

	// 6. Build Client with SOCKS5 Proxy
	socksUDPAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", socks5Port))
	if err != nil {
		t.Fatalf("ResolveUDPAddr socks failed: %v", err)
	}
	clientCfg := &conf.Conf{
		Role: "client",
		Server: conf.Server{
			Addr:      primaryUDPAddr,
			Endpoints: []*net.UDPAddr{primaryUDPAddr},
		},
		SOCKS5: []conf.SOCKS5{
			{
				Listen: socksUDPAddr,
			},
		},
		Transport: conf.Transport{
			Protocol: "aead-stream",
			Conn:     1,
			Obfs: &conf.Obfs{
				Enabled: true,
				Key:     string(testPSK),
				MaxPad:  64,
			},
		},
	}
	clientInst, err := client.New(clientCfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	clientInst.SetRecoveryEngine(recoverySM)
	clientCtx, cancelClient := context.WithCancel(context.Background())
	defer cancelClient()
	if err := clientInst.Start(clientCtx); err != nil {
		t.Fatalf("Failed to start client: %v", err)
	}

	socksProxy, err := socks.New(clientInst)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 service: %v", err)
	}
	socksCtx, cancelSocks := context.WithCancel(context.Background())
	defer cancelSocks()
	if err := socksProxy.Start(socksCtx, clientCfg.SOCKS5[0]); err != nil {
		t.Fatalf("Failed to start SOCKS5 proxy: %v", err)
	}

	// Wait for services to be ready
	time.Sleep(100 * time.Millisecond)

	// Build HTTP client routed through the dedicated isolated SOCKS5 proxy
	socksDialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socks5Port), nil, proxy.Direct)
	if err != nil {
		t.Fatalf("proxy.SOCKS5 dialer creation failed: %v", err)
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return socksDialer.Dial(network, addr)
			},
		},
		Timeout: 5 * time.Second,
	}

	// -------------------------------------------------------------
	// STEP A — Baseline: Request through Primary Transport
	// -------------------------------------------------------------
	testURL := fmt.Sprintf("http://127.0.0.1:%d/test-token", httpOriginPort)
	resp, err := httpClient.Get(testURL)
	if err != nil {
		t.Fatalf("Step A Baseline: HTTP GET through SOCKS5 failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var baselineData map[string]string
	if err := json.Unmarshal(body, &baselineData); err != nil {
		t.Fatalf("Step A Baseline: Failed to parse JSON: %v", err)
	}
	if baselineData["token"] != expectedToken {
		t.Fatalf("Step A Baseline: Token mismatch: got %q, want %q", baselineData["token"], expectedToken)
	}
	if recoverySM.CurrentState() != transport.StatePrimaryHealthy {
		t.Fatalf("Step A Baseline: Expected StatePrimaryHealthy, got %s", recoverySM.CurrentState())
	}
	t.Logf("[STEP A PASS] Baseline request succeeded through primary transport; token verified: %s", expectedToken)

	// -------------------------------------------------------------
	// STEP B through E — Primary Failure Induction & Automatic SOCKS5 Recovery
	// -------------------------------------------------------------
	cancelPrimary()
	t.Logf("[STEP B] Primary transport server on port %d stopped", primaryServerPort)

	// Issue request through SOCKS5 proxy while primary is stopped.
	// The client detects primary failure, executes emergency signaling and candidate validation,
	// transitions to RECOVERY_READY, and routes the connection through candidateServerPort!
	recovResp, err := httpClient.Get(testURL)
	if err != nil {
		t.Fatalf("HTTP GET through SOCKS5 failed during recovery: %v", err)
	}
	recovBody, _ := io.ReadAll(recovResp.Body)
	recovResp.Body.Close()

	var recovData map[string]string
	if err := json.Unmarshal(recovBody, &recovData); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}
	if recovData["token"] != expectedToken {
		t.Fatalf("Token mismatch on recovery path: got %q, want %q", recovData["token"], expectedToken)
	}
	t.Logf("[STEP B-E PASS] Real SOCKS5 connection routed to recovery candidate! Token matched byte-exact: %s", recovData["token"])

	// Verify recovery state machine transitioned to RECOVERY_READY
	if recoverySM.CurrentState() != transport.StateRecoveryReady {
		t.Fatalf("Expected StateRecoveryReady, got %s", recoverySM.CurrentState())
	}
	snapshot := recoverySM.ActiveSnapshot()
	if snapshot == nil {
		t.Fatalf("Active snapshot is nil!")
	}
	if snapshot.TransportPort != candidateServerPort {
		t.Fatalf("Snapshot port mismatch: got %d, want %d", snapshot.TransportPort, candidateServerPort)
	}
	if snapshot.TransportMode != transport.ModeAEADStream {
		t.Fatalf("Snapshot mode mismatch: got %s, want %s", snapshot.TransportMode, transport.ModeAEADStream)
	}
	t.Logf("[STEP C/D PASS] Active snapshot verified for candidate %s (%s)", snapshot.Addr(), snapshot.TransportMode)

	// Verify transition history contains the complete lifecycle
	history := recoverySM.History()
	expectedStates := []transport.RecoveryState{
		transport.StatePrimaryHealthy,
		transport.StatePrimaryDegraded,
		transport.StateEmergencySignaling,
		transport.StateBootstrapReceived,
		transport.StateCandidateEndpointValidating,
		transport.StateRecoveryReady,
	}
	for _, exp := range expectedStates {
		found := false
		for _, ev := range history {
			if ev.ToState == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing expected state transition to %s in recovery history", exp)
		}
	}

	// -------------------------------------------------------------
	// STEP F — Negative Tests & Rollback
	// -------------------------------------------------------------
	recoverySM.ResetRollback("test rollback")
	if recoverySM.CurrentState() != transport.StatePrimaryHealthy {
		t.Fatalf("Step F: Expected StatePrimaryHealthy after ResetRollback, got %s", recoverySM.CurrentState())
	}
	if recoverySM.ActiveSnapshot() != nil {
		t.Fatalf("Step F: Active snapshot must be nil after rollback, got %v", recoverySM.ActiveSnapshot())
	}
	t.Logf("[STEP F PASS] Rollback restored state machine to StatePrimaryHealthy and cleared active snapshot")
}
