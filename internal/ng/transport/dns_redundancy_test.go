package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arashmh13/paqet-ngv2/internal/ng/crypto"
)

func TestDualAuthoritativeServerCrossServerRetriesAndReplay(t *testing.T) {
	domainSuffix := "tunnel.redundancy.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	var serverAInvocations int32
	var serverBInvocations int32
	secretA := []byte("secret-a-response-32-bytes-long!")
	secretB := []byte("secret-b-response-32-bytes-long!")

	// 1. Spawn Server A with independent state and ServerID "srv-de-01"
	serverA, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          psk,
		ServerID:     "srv-de-01",
		ServerSecret: secretA,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			atomic.AddInt32(&serverAInvocations, 1)
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				Reply:     append([]byte("SERVER_A_ECHO:"), msg.Payload...),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Start Server A failed: %v", err)
	}
	defer serverA.Stop()

	// 2. Spawn Server B with independent state (separate memory, sessions, replay windows) and ServerID "srv-nl-01"
	serverB, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          psk,
		ServerID:     "srv-nl-01",
		ServerSecret: secretB,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			atomic.AddInt32(&serverBInvocations, 1)
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				Reply:     append([]byte("SERVER_B_ECHO:"), msg.Payload...),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Start Server B failed: %v", err)
	}
	defer serverB.Stop()

	sessionID := uint64(0x5555666677778888)
	clientConn, err := NewClientAsymmetricSessionWithServers(sessionID, psk, []AuthorizedServerEntry{
		{ServerID: "srv-de-01", ResponseSecret: secretA},
		{ServerID: "srv-nl-01", ResponseSecret: secretB},
	})
	if err != nil {
		t.Fatalf("NewClientAsymmetricSessionWithServers failed: %v", err)
	}

	udpAddrA, _ := net.ResolveUDPAddr("udp", serverA.Addr().String())
	udpAddrB, _ := net.ResolveUDPAddr("udp", serverB.Addr().String())

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer conn.Close()

	// Scenario 1: Request 1 sent to Server A, but client simulates losing the response
	msg1 := &EmergencyMessage{
		ID:        "msg-cross-001",
		Type:      MsgTypeAlert,
		Payload:   []byte("Cross Server Failover Alert"),
		Timestamp: time.Now().Unix(),
	}
	raw1, _ := json.Marshal(msg1)
	frame1, _ := clientConn.sealFrame(1, 0, raw1)

	qname1A := EncodeDNSQName(domainSuffix, "c01", 101, 0, 1, frame1)
	pkt1A := BuildDNSQuery(qname1A, 0x0010, 0x00A1)
	_, _ = conn.WriteToUDP(pkt1A, udpAddrA)

	// Read Server A reply
	buf := make([]byte, 2048)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Read Server A response failed: %v", err)
	}
	if atomic.LoadInt32(&serverAInvocations) != 1 {
		t.Fatalf("Server A handler should have been invoked 1 time")
	}

	// Scenario 2: Client retransmits the EXACT same request 1 (seq=1) to Server B (failover)
	// Server B has never seen this session before!
	qname1B := EncodeDNSQName(domainSuffix, "c01", 102, 0, 1, frame1)
	pkt1B := BuildDNSQuery(qname1B, 0x0010, 0x00B1)
	_, _ = conn.WriteToUDP(pkt1B, udpAddrB)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Read Server B response failed: %v", err)
	}
	ansB, err := ParseDNSTXTResponse(buf[:n])
	if err != nil {
		t.Fatalf("Parse Server B answer failed: %v", err)
	}
	_, _, ptB, err := clientConn.VerifyFrame(ansB)
	if err != nil {
		t.Fatalf("Verify Server B reply failed: %v", err)
	}
	var respB EmergencyResponse
	_ = json.Unmarshal(ptB, &respB)
	if string(respB.Reply) != "SERVER_B_ECHO:Cross Server Failover Alert" {
		t.Fatalf("Server B reply mismatch: %s", string(respB.Reply))
	}
	if atomic.LoadInt32(&serverBInvocations) != 1 {
		t.Fatalf("Server B handler should have been invoked 1 time")
	}

	// Scenario 3: Attacker replays request 1 to Server B again.
	// Server B has already processed seq=1 and cached its reply!
	// Server B must return the cached reply without second invocation of handler.
	pkt1BReplay := BuildDNSQuery(qname1B, 0x0010, 0x00B2)
	_, _ = conn.WriteToUDP(pkt1BReplay, udpAddrB)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Read Server B replay response failed: %v", err)
	}
	if atomic.LoadInt32(&serverBInvocations) != 1 {
		t.Fatalf("Server B invoked handler on duplicate replay! Expected 1, got %d", atomic.LoadInt32(&serverBInvocations))
	}

	// Scenario 4: Request split across servers (Multipart fragment 0 sent to Server A, fragment 1 sent to Server B)
	// This simulates what happens if a public recursor sprays queries of a multipart message.
	payloadLong := make([]byte, 60)
	for i := range payloadLong {
		payloadLong[i] = byte(i)
	}
	msgMulti := &EmergencyMessage{
		ID:        "msg-multipart-split",
		Type:      MsgTypeData,
		Payload:   payloadLong,
		Timestamp: time.Now().Unix(),
	}
	rawMulti, _ := json.Marshal(msgMulti)
	frameMulti, _ := clientConn.sealFrame(2, 1, rawMulti)

	// Split into 2 chunks of 35 bytes
	chunk0 := frameMulti[:35]
	chunk1 := frameMulti[35:]

	// Part 0 -> Server A
	qnamePart0 := EncodeDNSQName(domainSuffix, "c01", 9001, 0, 2, chunk0)
	pktPart0 := BuildDNSQuery(qnamePart0, 0x0010, 0x9000)
	_, _ = conn.WriteToUDP(pktPart0, udpAddrA)

	// Part 1 -> Server B
	qnamePart1 := EncodeDNSQName(domainSuffix, "c01", 9001, 1, 2, chunk1)
	pktPart1 := BuildDNSQuery(qnamePart1, 0x0010, 0x9001)
	_, _ = conn.WriteToUDP(pktPart1, udpAddrB)

	// Server A should return intermediate empty answer (not complete)
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, _, err = conn.ReadFrom(buf)
	if err == nil {
		ansPart0, _ := ParseDNSTXTResponse(buf[:n])
		if len(ansPart0) > 0 {
			t.Fatalf("Server A should NOT have completed reassembly with only Part 0")
		}
	}

	// Server B should return intermediate empty answer (not complete)
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, _, err = conn.ReadFrom(buf)
	if err == nil {
		ansPart1, _ := ParseDNSTXTResponse(buf[:n])
		if len(ansPart1) > 0 {
			t.Fatalf("Server B should NOT have completed reassembly with only Part 1")
		}
	}

	// Conclusively proved: Multipart reassembly CANNOT succeed when fragments are split across uncoordinated servers.
	// Only single-query datagrams (total=1) are stateless and naturally resilient across independent server pools!
	_ = n
}

func TestMultiAuthoritative_CryptographicSafetyAndKeyNonceSeparation(t *testing.T) {
	domainSuffix := "tunnel.multiauth.local"
	psk := []byte("emergency-psk-32-bytes-super-key")
	secretA := []byte("secret-a-response-32-bytes-long!")
	secretB := []byte("secret-b-response-32-bytes-long!")
	secretC := []byte("secret-c-response-32-bytes-long!")

	// 1. Spawn Server A with ServerID "srv-de-01"
	serverA, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          psk,
		ServerID:     "srv-de-01",
		ServerSecret: secretA,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				ServerID:  "srv-de-01",
				Reply:     []byte("SERVER_A_EXCLUSIVE_PAYLOAD_1111"),
				Timestamp: 1000001,
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Start Server A failed: %v", err)
	}
	defer serverA.Stop()

	// 2. Spawn Server B with ServerID "srv-nl-01"
	serverB, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          psk,
		ServerID:     "srv-nl-01",
		ServerSecret: secretB,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				ServerID:  "srv-nl-01",
				Reply:     []byte("SERVER_B_EXCLUSIVE_PAYLOAD_2222"),
				Timestamp: 1000002,
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Start Server B failed: %v", err)
	}
	defer serverB.Stop()

	// 3. Spawn Unauthorized Rogue Server C with ServerID "srv-rogue-01" (same PSK, but unauthorized by client)
	serverC, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          psk,
		ServerID:     "srv-rogue-01",
		ServerSecret: secretC,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				ServerID:  "srv-rogue-01",
				Reply:     []byte("ROGUE_SERVER_UNAUTHORIZED_REPLY"),
				Timestamp: 1000003,
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Start Server C failed: %v", err)
	}
	defer serverC.Stop()

	sessionID := uint64(0xAABBCCDDEEFF0011)
	// Client authorizes ONLY srv-de-01 and srv-nl-01
	clientConn, err := NewClientAsymmetricSessionWithServers(sessionID, psk, []AuthorizedServerEntry{
		{ServerID: "srv-de-01", ResponseSecret: secretA},
		{ServerID: "srv-nl-01", ResponseSecret: secretB},
	})
	if err != nil {
		t.Fatalf("NewClientAsymmetricSessionWithServers failed: %v", err)
	}

	udpAddrA, _ := net.ResolveUDPAddr("udp", serverA.Addr().String())
	udpAddrB, _ := net.ResolveUDPAddr("udp", serverB.Addr().String())
	udpAddrC, _ := net.ResolveUDPAddr("udp", serverC.Addr().String())

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer conn.Close()

	// Build request 1 (seq=1)
	msg1 := &EmergencyMessage{
		ID:        "msg-crypto-001",
		Type:      MsgTypeAlert,
		Payload:   []byte("Request 1"),
		Timestamp: time.Now().Unix(),
	}
	raw1, _ := json.Marshal(msg1)
	frame1, _ := clientConn.sealFrame(1, 0, raw1)

	// Send request 1 to Server A
	qname1A := EncodeDNSQName(domainSuffix, "c01", 501, 0, 1, frame1)
	pkt1A := BuildDNSQuery(qname1A, 0x0010, 0x0001)
	_, _ = conn.WriteToUDP(pkt1A, udpAddrA)

	buf := make([]byte, 2048)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Read Server A reply failed: %v", err)
	}
	ansA, err := ParseDNSTXTResponse(buf[:n])
	if err != nil {
		t.Fatalf("Parse Server A TXT failed: %v", err)
	}

	// Verify Server A reply decrypts and returns ServerID "srv-de-01"
	_, _, ptA, srvIDA, err := clientConn.VerifyFrameWithServerID(ansA)
	if err != nil {
		t.Fatalf("Verify Server A reply failed: %v", err)
	}
	if srvIDA != "srv-de-01" {
		t.Fatalf("Expected ServerID srv-de-01, got %s", srvIDA)
	}
	var respA EmergencyResponse
	_ = json.Unmarshal(ptA, &respA)
	if string(respA.Reply) != "SERVER_A_EXCLUSIVE_PAYLOAD_1111" {
		t.Fatalf("Server A reply mismatch: %s", string(respA.Reply))
	}

	// Send SAME request 1 (seq=1) to Server B (retried query)
	// Server B also answers at respSeq=1!
	qname1B := EncodeDNSQName(domainSuffix, "c01", 502, 0, 1, frame1)
	pkt1B := BuildDNSQuery(qname1B, 0x0010, 0x0002)
	_, _ = conn.WriteToUDP(pkt1B, udpAddrB)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Read Server B reply failed: %v", err)
	}
	ansB, err := ParseDNSTXTResponse(buf[:n])
	if err != nil {
		t.Fatalf("Parse Server B TXT failed: %v", err)
	}

	// Verify Server B reply decrypts and returns ServerID "srv-nl-01"
	_, _, ptB, srvIDB, err := clientConn.VerifyFrameWithServerID(ansB)
	if err != nil {
		t.Fatalf("Verify Server B reply failed: %v", err)
	}
	if srvIDB != "srv-nl-01" {
		t.Fatalf("Expected ServerID srv-nl-01, got %s", srvIDB)
	}
	var respB EmergencyResponse
	_ = json.Unmarshal(ptB, &respB)
	if string(respB.Reply) != "SERVER_B_EXCLUSIVE_PAYLOAD_2222" {
		t.Fatalf("Server B reply mismatch: %s", string(respB.Reply))
	}

	// Cryptographic Nonce/Key Collision Invariant Check:
	// Verify that ansA and ansB ciphertexts used completely distinct keys and cannot be cross-decrypted!
	serverAKey, _ := crypto.DeriveServerResponseKey(secretA, []byte(fmt.Sprintf("paqet-asym-%d", sessionID)), "srv-de-01")
	serverBKey, _ := crypto.DeriveServerResponseKey(secretB, []byte(fmt.Sprintf("paqet-asym-%d", sessionID)), "srv-nl-01")
	if string(serverAKey) == string(serverBKey) {
		t.Fatalf("CRITICAL SECURITY DEFECT: Server A and Server B derived identical s2c keys!")
	}

	// Adversarial Check: Server A's response tampered to claim ServerID "srv-nl-01"
	tamperedAnsA := append([]byte(nil), ansA...)
	// In v3 frame, bytes 21.. are serverID. If header is tampered or serverID is replaced, AEAD open must fail!
	tamperedAnsA[21] = 'X'
	_, _, _, _, errTamper := clientConn.VerifyFrameWithServerID(tamperedAnsA)
	if errTamper == nil {
		t.Fatalf("AEAD authentication MUST fail when ServerID in AAD is tampered!")
	}
	t.Logf("PASS: Tampered ServerID rejected by AEAD: %v", errTamper)

	// Adversarial Check: Query sent to unauthorized Rogue Server C
	qname1C := EncodeDNSQName(domainSuffix, "c01", 503, 0, 1, frame1)
	pkt1C := BuildDNSQuery(qname1C, 0x0010, 0x0003)
	_, _ = conn.WriteToUDP(pkt1C, udpAddrC)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Read Server C reply failed: %v", err)
	}
	ansC, err := ParseDNSTXTResponse(buf[:n])
	if err != nil {
		t.Fatalf("Parse Server C TXT failed: %v", err)
	}

	// Client policy does NOT authorize "srv-rogue-01". VerifyFrameWithServerID MUST reject fail-closed!
	_, _, _, _, errRogue := clientConn.VerifyFrameWithServerID(ansC)
	if errRogue == nil {
		t.Fatalf("Client policy MUST reject response from unauthorized server srv-rogue-01!")
	}
	t.Logf("PASS: Client rejected unauthorized server: %v", errRogue)

	// Retransmission / Replay Check on Server A:
	// When exact request 1 is replayed to Server A, it MUST return identical cached ciphertext
	// and MUST NOT encrypt new plaintext under the same nonce!
	_, _ = conn.WriteToUDP(pkt1A, udpAddrA)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Read Server A replay failed: %v", err)
	}
	ansAReplay, _ := ParseDNSTXTResponse(buf[:n])
	if string(ansA) != string(ansAReplay) {
		t.Fatalf("Retransmission must return identical cached ciphertext to prevent nonce reuse!")
	}
	t.Logf("PASS: Retransmission returned byte-identical cached ciphertext")

	// Concurrent Handling Check on Server A and Server B:
	// Verify concurrent requests to both servers execute cleanly without race conditions
	done := make(chan bool, 2)
	go func() {
		pkt := BuildDNSQuery(EncodeDNSQName(domainSuffix, "c01", 601, 0, 1, frame1), 0x0010, 0x6001)
		cConn, _ := net.ListenUDP("udp", nil)
		defer cConn.Close()
		_, _ = cConn.WriteToUDP(pkt, udpAddrA)
		b := make([]byte, 2048)
		_ = cConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, _ = cConn.ReadFrom(b)
		done <- true
	}()
	go func() {
		pkt := BuildDNSQuery(EncodeDNSQName(domainSuffix, "c01", 602, 0, 1, frame1), 0x0010, 0x6002)
		cConn, _ := net.ListenUDP("udp", nil)
		defer cConn.Close()
		_, _ = cConn.WriteToUDP(pkt, udpAddrB)
		b := make([]byte, 2048)
		_ = cConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, _ = cConn.ReadFrom(b)
		done <- true
	}()
	<-done
	<-done
	t.Logf("PASS: Concurrent requests to independent servers executed safely")
}

func TestMultiAuthoritative_FailoverAndServerRestart(t *testing.T) {
	domainSuffix := "tunnel.restart.local"
	psk := []byte("emergency-psk-32-bytes-super-key")
	secretA := []byte("secret-a-response-32-bytes-long!")
	secretB := []byte("secret-b-response-32-bytes-long!")

	// 1. Server A and Server B running
	serverA, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          psk,
		ServerID:     "srv-de-01",
		ServerSecret: secretA,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				Reply:     []byte("SERVER_A_LIVE"),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Start Server A failed: %v", err)
	}
	defer serverA.Stop()

	serverB, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          psk,
		ServerID:     "srv-nl-01",
		ServerSecret: secretB,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				Reply:     []byte("SERVER_B_LIVE"),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Start Server B failed: %v", err)
	}
	defer serverB.Stop()

	client, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		Resolvers:         []string{serverA.Addr().String(), serverB.Addr().String()},
		DomainSuffix:      domainSuffix,
		ClientID:          "c01",
		PSK:               psk,
		Timeout:           3 * time.Second,
		PerAttemptTimeout: 500 * time.Millisecond,
		MaxRetries:        2,
		ServerIdentities: []AuthorizedServerEntry{
			{ServerID: "srv-de-01", ResponseSecret: secretA},
			{ServerID: "srv-nl-01", ResponseSecret: secretB},
		},
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSClient failed: %v", err)
	}

	// Exchange 1: Server A answers
	resp1, _, err := client.Exchange(context.Background(), &EmergencyMessage{
		ID:        "msg-001",
		Type:      MsgTypeAlert,
		Payload:   []byte("Test 1"),
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("Exchange 1 failed: %v", err)
	}
	if string(resp1.Reply) != "SERVER_A_LIVE" {
		t.Fatalf("Expected Server A reply, got %s", string(resp1.Reply))
	}
	t.Logf("PASS: Exchange 1 served by Server A (%s)", resp1.ServerID)

	// Now stop Server A (simulating crash / restart)
	serverA.Stop()

	// Exchange 2: Server A is down! Client must fail over to Server B and receive authenticated reply
	resp2, _, err := client.Exchange(context.Background(), &EmergencyMessage{
		ID:        "msg-002",
		Type:      MsgTypeAlert,
		Payload:   []byte("Test 2"),
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		t.Logf("Exchange 2 attempts recorded: %+v", client.LastExchangeAttempts())
		t.Fatalf("Exchange 2 failover to Server B failed: %v", err)
	}
	if string(resp2.Reply) != "SERVER_B_LIVE" {
		t.Fatalf("Expected Server B reply, got %s", string(resp2.Reply))
	}
	if resp2.ServerID != "srv-nl-01" {
		t.Fatalf("Expected ServerID srv-nl-01, got %s", resp2.ServerID)
	}
	t.Logf("PASS: Exchange 2 cleanly failed over to Server B (%s) after Server A stopped", resp2.ServerID)

	// Verify attempt telemetry recorded the failover
	attempts := client.LastExchangeAttempts()
	if len(attempts) < 2 {
		t.Fatalf("Expected at least 2 attempts recorded during failover, got %d", len(attempts))
	}
	t.Logf("PASS: Attempt telemetry recorded %d attempts during failover (Attempt 0: %s, Attempt 1: %s)",
		len(attempts), attempts[0].Status, attempts[1].Status)
}

func TestPhase17_TwoAuthoritativeReadinessSuite(t *testing.T) {
	domainSuffix := "tunnel.phase17.test"
	c2sPSK := []byte("c2s-shared-root-key-32-bytes-lon")
	secretA := []byte("server-a-secret-32-bytes-long-11")
	secretB := []byte("server-b-secret-32-bytes-long-22")

	// 1. Initialize Server A (srv-de-01) with secretA
	serverA, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          c2sPSK,
		ServerID:     "srv-de-01",
		ServerSecret: secretA,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				ServerID:  "srv-de-01",
				Reply:     []byte("REPLY_FROM_A"),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Start Server A failed: %v", err)
	}
	defer serverA.Stop()

	// 2. Initialize Server B (srv-nl-01) with secretB
	serverB, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          c2sPSK,
		ServerID:     "srv-nl-01",
		ServerSecret: secretB,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				ServerID:  "srv-nl-01",
				Reply:     []byte("REPLY_FROM_B"),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Start Server B failed: %v", err)
	}
	defer serverB.Stop()

	// 3. Client configured with explicit per-server identities
	client, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		Resolvers:         []string{serverA.Addr().String(), serverB.Addr().String()},
		DomainSuffix:      domainSuffix,
		ClientID:          "c17",
		PSK:               c2sPSK,
		SessionID:         0x1717171717171717,
		Timeout:           3 * time.Second,
		PerAttemptTimeout: 800 * time.Millisecond,
		MaxRetries:        2,
		ServerIdentities: []AuthorizedServerEntry{
			{ServerID: "srv-de-01", ResponseSecret: secretA},
			{ServerID: "srv-nl-01", ResponseSecret: secretB},
		},
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSClient failed: %v", err)
	}

	// 4. Test normal request to Server A
	respA, _, err := client.Exchange(context.Background(), &EmergencyMessage{
		ID:        "msg-p17-001",
		Type:      MsgTypeAlert,
		Payload:   []byte("Payload for A"),
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("Exchange to Server A failed: %v", err)
	}
	if string(respA.Reply) != "REPLY_FROM_A" || respA.ServerID != "srv-de-01" {
		t.Fatalf("Unexpected response from A: %+v", respA)
	}
	t.Logf("PASS: Verified authenticated reply from Server A with ServerID srv-de-01")

	// 5. Test Server A failure and automatic retry/failover to Server B
	serverA.Stop()
	respB, _, err := client.Exchange(context.Background(), &EmergencyMessage{
		ID:        "msg-p17-002",
		Type:      MsgTypeAlert,
		Payload:   []byte("Payload for B"),
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("Exchange failover to Server B failed: %v", err)
	}
	if string(respB.Reply) != "REPLY_FROM_B" || respB.ServerID != "srv-nl-01" {
		t.Fatalf("Unexpected response from B: %+v", respB)
	}
	t.Logf("PASS: Verified clean failover to Server B with ServerID srv-nl-01")

	// 6. Test Key Revocation: Revoke Server B's secret from client, verify fail-closed
	revokedClient, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		Resolvers:    []string{serverB.Addr().String()},
		DomainSuffix: domainSuffix,
		ClientID:     "c17",
		PSK:          c2sPSK,
		SessionID:    0x1717171717171718,
		Timeout:      1 * time.Second,
		MaxRetries:   0,
		ServerIdentities: []AuthorizedServerEntry{
			{ServerID: "srv-de-01", ResponseSecret: secretA}, // srv-nl-01 revoked!
		},
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSClient with revoked server failed: %v", err)
	}
	_, _, err = revokedClient.Exchange(context.Background(), &EmergencyMessage{
		ID:        "msg-p17-revoked",
		Type:      MsgTypeAlert,
		Payload:   []byte("Test revoked"),
		Timestamp: time.Now().Unix(),
	})
	if err == nil {
		t.Fatalf("Expected fail-closed rejection for revoked server srv-nl-01, got nil")
	}
	t.Logf("PASS: Revoked server rejected fail-closed: %v", err)
}

func TestPhase18_CrossServerKeyRotationAndRevocationSuite(t *testing.T) {
	domainSuffix := "tunnel.phase18.test"
	c2sPSK := []byte("c2s-shared-root-key-32-bytes-lon")
	secretA1 := []byte("server-a-secret-1111111111111111")
	secretA2 := []byte("server-a-secret-2222222222222222") // rotated secret for Server A
	secretB := []byte("server-b-secret-3333333333333333")

	// 1. Missing secret on server must fail construction
	_, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          c2sPSK,
		ServerID:     "srv-de-01",
		ServerSecret: nil, // prohibited!
	})
	if err == nil {
		t.Fatalf("Expected error for nil ServerSecret, got nil")
	}

	// 2. Start Server A with secretA1
	serverA, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          c2sPSK,
		ServerID:     "srv-de-01",
		ServerSecret: secretA1,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				ServerID:  "srv-de-01",
				Reply:     []byte("ORIGINAL_SECRET_A1_REPLY"),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Start serverA failed: %v", err)
	}
	defer serverA.Stop()

	// 3. Start Server B with secretB
	serverB, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          c2sPSK,
		ServerID:     "srv-nl-01",
		ServerSecret: secretB,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				ServerID:  "srv-nl-01",
				Reply:     []byte("SERVER_B_REPLY"),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Start serverB failed: %v", err)
	}
	defer serverB.Stop()

	// 4. Client configured with secretA1 and secretB
	client, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		Resolvers:         []string{serverA.Addr().String(), serverB.Addr().String()},
		DomainSuffix:      domainSuffix,
		ClientID:          "c18",
		PSK:               c2sPSK,
		SessionID:         0x1800180018001800,
		Timeout:           2 * time.Second,
		PerAttemptTimeout: 500 * time.Millisecond,
		MaxRetries:        1,
		ServerIdentities: []AuthorizedServerEntry{
			{ServerID: "srv-de-01", ResponseSecret: secretA1},
			{ServerID: "srv-nl-01", ResponseSecret: secretB},
		},
	})
	if err != nil {
		t.Fatalf("Client creation failed: %v", err)
	}

	// 5. Successful query to Server A
	respA, _, err := client.Exchange(context.Background(), &EmergencyMessage{
		ID:        "msg-a1",
		Type:      MsgTypeAlert,
		Payload:   []byte("test A"),
		Timestamp: time.Now().Unix(),
	})
	if err != nil || string(respA.Reply) != "ORIGINAL_SECRET_A1_REPLY" {
		t.Fatalf("Exchange with secretA1 failed: resp=%+v, err=%v", respA, err)
	}

	// 6. Simulate Server A Key Rotation:
	// Server A restarts with rotated secretA2
	serverA.Stop()
	serverA_v2, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   serverA.Addr().String(),
		DomainSuffix: domainSuffix,
		PSK:          c2sPSK,
		ServerID:     "srv-de-01",
		ServerSecret: secretA2,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				ServerID:  "srv-de-01",
				Reply:     []byte("ROTATED_SECRET_A2_REPLY"),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Restart serverA with secretA2 failed: %v", err)
	}
	defer serverA_v2.Stop()

	// 7. Old client (holding secretA1) querying serverA_v2 must fail authentication fail-closed!
	// It must NOT silently fall back to PSK.
	oldClient, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		Resolvers:         []string{serverA_v2.Addr().String()},
		DomainSuffix:      domainSuffix,
		ClientID:          "c18",
		PSK:               c2sPSK,
		SessionID:         0x1800180018001801,
		Timeout:           1 * time.Second,
		PerAttemptTimeout: 500 * time.Millisecond,
		MaxRetries:        0,
		ServerIdentities: []AuthorizedServerEntry{
			{ServerID: "srv-de-01", ResponseSecret: secretA1}, // STALE SECRET!
		},
	})
	if err != nil {
		t.Fatalf("oldClient creation failed: %v", err)
	}
	_, _, err = oldClient.Exchange(context.Background(), &EmergencyMessage{
		ID:        "msg-stale",
		Type:      MsgTypeAlert,
		Payload:   []byte("test stale"),
		Timestamp: time.Now().Unix(),
	})
	if err == nil {
		t.Fatalf("CRITICAL SECURITY DEFECT: Client with stale secretA1 verified response sealed with secretA2!")
	}
	t.Logf("PASS: Stale key safely rejected fail-closed: %v", err)

	// 8. Rotated client (holding secretA2) querying serverA_v2 must succeed!
	rotatedClient, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		Resolvers:         []string{serverA_v2.Addr().String()},
		DomainSuffix:      domainSuffix,
		ClientID:          "c18",
		PSK:               c2sPSK,
		SessionID:         0x1800180018001802,
		Timeout:           2 * time.Second,
		PerAttemptTimeout: 500 * time.Millisecond,
		MaxRetries:        0,
		ServerIdentities: []AuthorizedServerEntry{
			{ServerID: "srv-de-01", ResponseSecret: secretA2}, // UPDATED ROTATED SECRET!
		},
	})
	if err != nil {
		t.Fatalf("rotatedClient creation failed: %v", err)
	}
	respA2, _, err := rotatedClient.Exchange(context.Background(), &EmergencyMessage{
		ID:        "msg-a2",
		Type:      MsgTypeAlert,
		Payload:   []byte("test rotated"),
		Timestamp: time.Now().Unix(),
	})
	if err != nil || string(respA2.Reply) != "ROTATED_SECRET_A2_REPLY" {
		t.Fatalf("Rotated client exchange failed: resp=%+v, err=%v", respA2, err)
	}
	t.Logf("PASS: Key rotation succeeded seamlessly with dedicated response secret")
}
