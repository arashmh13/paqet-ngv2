package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arashmh13/paqet-ngv2/internal/ng/dns"
)

func TestEmergencyDNSRoundTripSmallAndFragmented(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	// 1. Start Emergency DNS Server on loopback port
	server, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:           "127.0.0.1:0",
		DomainSuffix:         domainSuffix,
		PSK:                  psk,
		IsLegacySingleServer: true,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				Reply:     append([]byte("SERVER_ECHO:"), msg.Payload...),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSServer failed: %v", err)
	}
	defer server.Stop()

	serverAddr := server.Addr().String()

	// 2. Initialize Emergency DNS Client
	client, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		ResolverAddr:         serverAddr,
		DomainSuffix:         domainSuffix,
		ClientID:             "c99",
		PSK:                  psk,
		SessionID:            0x123456789ABCDEF0,
		Timeout:              2 * time.Second,
		MaxRetries:           2,
		IsLegacySingleServer: true,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSClient failed: %v", err)
	}

	ctx := context.Background()

	// Case A: Small single-part payload (20 bytes)
	msgSmall := &EmergencyMessage{
		ID:        "test-small-001",
		Type:      "ping",
		Payload:   []byte("Short Emergency Text"),
		Timestamp: time.Now().Unix(),
	}

	respSmall, rttSmall, err := client.Exchange(ctx, msgSmall)
	if err != nil {
		t.Fatalf("Case A Exchange failed: %v", err)
	}
	if respSmall.ID != msgSmall.ID {
		t.Fatalf("Case A ID mismatch: got %s, want %s", respSmall.ID, msgSmall.ID)
	}
	if string(respSmall.Reply) != "SERVER_ECHO:Short Emergency Text" {
		t.Fatalf("Case A Reply mismatch: got %s", respSmall.Reply)
	}
	t.Logf("Case A (Small) succeeded in %v", rttSmall)

	// Case B: Large multipart payload requiring 4 fragments (120 bytes)
	randBytes := make([]byte, 120)
	_, _ = io.ReadFull(rand.Reader, randBytes)

	msgLarge := &EmergencyMessage{
		ID:        "test-large-002",
		Type:      "data",
		Payload:   randBytes,
		Timestamp: time.Now().Unix(),
	}

	respLarge, rttLarge, err := client.Exchange(ctx, msgLarge)
	if err != nil {
		t.Fatalf("Case B Multipart Exchange failed: %v", err)
	}
	if respLarge.ID != msgLarge.ID {
		t.Fatalf("Case B ID mismatch: got %s, want %s", respLarge.ID, msgLarge.ID)
	}
	expectedLargeReply := append([]byte("SERVER_ECHO:"), randBytes...)
	if !bytes.Equal(respLarge.Reply, expectedLargeReply) {
		t.Fatalf("Case B Multipart Reply bytes mismatch")
	}
	t.Logf("Case B (Large Multipart) succeeded in %v", rttLarge)
}

func TestEmergencyDNSServerSecurityAndRefused(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	server, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:           "127.0.0.1:0",
		DomainSuffix:         domainSuffix,
		PSK:                  psk,
		IsLegacySingleServer: true,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSServer failed: %v", err)
	}
	defer server.Stop()

	serverAddr := server.Addr().String()

	// 1. Query for domain outside domainSuffix (e.g. google.com) -> Must be REFUSED (RCODE 5)
	host, portStr, _ := net.SplitHostPort(serverAddr)
	port, _ := strconv.Atoi(portStr)
	resp, _, err := dns.SendQuery(context.Background(), host, port, "google.com", dns.TypeA, 0, 1*time.Second)
	if err == nil && len(resp) >= 4 {
		rcode := resp[3] & 0x0F
		if rcode != 5 {
			t.Errorf("Expected RCODE=5 REFUSED for query outside domainSuffix, got %d", rcode)
		}
	}

	// 2. Client with wrong PSK dialing server -> Must fail authentication
	badClient, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		ResolverAddr:         serverAddr,
		DomainSuffix:         domainSuffix,
		ClientID:             "c99",
		PSK:                  []byte("WRONG-KEY-32-BYTES-MUST-NOT-WORK"),
		SessionID:            0x99999999,
		Timeout:              1 * time.Second,
		MaxRetries:           0,
		IsLegacySingleServer: true,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSClient failed: %v", err)
	}

	msg := &EmergencyMessage{
		ID:        "test-bad-key",
		Type:      "ping",
		Payload:   []byte("Should be rejected"),
		Timestamp: time.Now().Unix(),
	}

	_, _, err = badClient.Exchange(context.Background(), msg)
	if err == nil {
		t.Errorf("Expected exchange with wrong PSK to fail, but succeeded")
	}
}

func TestUnauthenticatedSessionIDMemoryExhaustionProtection(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	server, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:           "127.0.0.1:0",
		DomainSuffix:         domainSuffix,
		PSK:                  psk,
		IsLegacySingleServer: true,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSServer failed: %v", err)
	}
	defer server.Stop()

	serverAddr := server.Addr().String()
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer conn.Close()

	srvUDP, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}

	// Send 50 queries with completely fabricated random session IDs and corrupted AEAD tags
	for i := 0; i < 50; i++ {
		fakeSessionID := uint64(0x2AAA000000000000) + uint64(i)
		fakeChunk := make([]byte, 35)
		// Embed fake session ID into chunk
		for b := 0; b < 8; b++ {
			fakeChunk[4+b] = byte(fakeSessionID >> (56 - b*8))
		}
		qname := EncodeDNSQName(domainSuffix, "c01", uint64(i+1), 0, 1, fakeChunk)
		pkt := BuildDNSQuery(qname, 0x0010 /* TXT */, uint16(i+1))
		_, _ = conn.WriteToUDP(pkt, srvUDP)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify that ZERO unauthenticated sessions were persisted in server memory!
	activeSessions := server.ActiveSessionsCount()
	if activeSessions != 0 {
		t.Fatalf("Memory exhaustion vulnerability detected! Expected 0 active sessions, got %d", activeSessions)
	}
}

func TestIdempotentDuplicateRetransmission(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	var handlerInvocations int32
	server, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:           "127.0.0.1:0",
		DomainSuffix:         domainSuffix,
		PSK:                  psk,
		IsLegacySingleServer: true,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			atomic.AddInt32(&handlerInvocations, 1)
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				Reply:     append([]byte("ACK_IDEMPOTENT:"), msg.Payload...),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSServer failed: %v", err)
	}
	defer server.Stop()

	client, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		ResolverAddr:         server.Addr().String(),
		DomainSuffix:         domainSuffix,
		ClientID:             "c01",
		PSK:                  psk,
		SessionID:            0xDEADBEEFCAFE0001,
		Timeout:              2 * time.Second,
		MaxRetries:           0,
		IsLegacySingleServer: true,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSClient failed: %v", err)
	}

	ctx := context.Background()
	msg := &EmergencyMessage{
		ID:        "test-retry-001",
		Type:      "alert",
		Payload:   []byte("Critical Payload"),
		Timestamp: time.Now().Unix(),
	}

	// 1. Initial transmission
	resp1, _, err := client.Exchange(ctx, msg)
	if err != nil {
		t.Fatalf("First exchange failed: %v", err)
	}
	if string(resp1.Reply) != "ACK_IDEMPOTENT:Critical Payload" {
		t.Fatalf("Unexpected response reply: %s", string(resp1.Reply))
	}
	if atomic.LoadInt32(&handlerInvocations) != 1 {
		t.Fatalf("Expected 1 handler invocation, got %d", atomic.LoadInt32(&handlerInvocations))
	}

	// 2. Transmit exact same frame (retransmission of duplicate sequence)
	// We craft the duplicate by dialing the server with the exact frame from the first sequence
	// Client session has advanced, so we create a duplicate client with same sequence to simulate network duplicate
	dupClient, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		ResolverAddr:         server.Addr().String(),
		DomainSuffix:         domainSuffix,
		ClientID:             "c01",
		PSK:                  psk,
		SessionID:            0xDEADBEEFCAFE0001,
		Timeout:              2 * time.Second,
		MaxRetries:           0,
		IsLegacySingleServer: true,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSClient failed: %v", err)
	}

	// Duplicate sends with the same initial sequence (1)
	resp2, _, err := dupClient.Exchange(ctx, msg)
	if err != nil {
		t.Fatalf("Retransmit exchange failed: %v", err)
	}
	if string(resp2.Reply) != "ACK_IDEMPOTENT:Critical Payload" {
		t.Fatalf("Retransmit response mismatch: %s", string(resp2.Reply))
	}

	// Crucial check: handler was NOT called a second time! Reply was served from idempotent replyCache!
	if atomic.LoadInt32(&handlerInvocations) != 1 {
		t.Fatalf("Idempotency violation! Handler was invoked %d times instead of 1", atomic.LoadInt32(&handlerInvocations))
	}
}

func TestTCPPort53QueryHandling(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	server, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:           "127.0.0.1:0",
		DomainSuffix:         domainSuffix,
		PSK:                  psk,
		IsLegacySingleServer: true,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSServer failed: %v", err)
	}
	defer server.Stop()

	serverAddr := server.Addr().String()

	// Dial TCP to the server
	tcpConn, err := net.DialTimeout("tcp", serverAddr, 1*time.Second)
	if err != nil {
		t.Fatalf("TCP dial failed: %v", err)
	}
	defer tcpConn.Close()

	// Build a diagnostic query over TCP
	queryPkt := BuildDNSQuery(domainSuffix, 0x0010 /* TXT */, 0x1234)

	// RFC 7766: 2-byte prefix length
	var lenBuf [2]byte
	lenBuf[0] = byte(len(queryPkt) >> 8)
	lenBuf[1] = byte(len(queryPkt))

	if _, err := tcpConn.Write(lenBuf[:]); err != nil {
		t.Fatalf("Write len prefix failed: %v", err)
	}
	if _, err := tcpConn.Write(queryPkt); err != nil {
		t.Fatalf("Write query failed: %v", err)
	}

	// Read response len
	var respLenBuf [2]byte
	if _, err := io.ReadFull(tcpConn, respLenBuf[:]); err != nil {
		t.Fatalf("Read resp len failed: %v", err)
	}
	respLen := int(respLenBuf[0])<<8 | int(respLenBuf[1])
	if respLen < 12 {
		t.Fatalf("Response len too small: %d", respLen)
	}

	respPkt := make([]byte, respLen)
	if _, err := io.ReadFull(tcpConn, respPkt); err != nil {
		t.Fatalf("Read resp pkt failed: %v", err)
	}

	// Verify DNS transaction ID matches
	if respPkt[0] != 0x12 || respPkt[1] != 0x34 {
		t.Fatalf("TxID mismatch in TCP response: got %02x%02x, want 1234", respPkt[0], respPkt[1])
	}
}

func TestKeyLengthValidationAndFailClosed(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"

	invalidKeys := [][]byte{
		nil,
		{},
		[]byte("short-key"),
		make([]byte, 31),
		make([]byte, 33),
		make([]byte, 64),
	}

	for _, k := range invalidKeys {
		_, errSrv := NewEmergencyDNSServer(EmergencyDNSServerConfig{
			ListenAddr:   "127.0.0.1:0",
			DomainSuffix: domainSuffix,
			PSK:          k,
		})
		if errSrv == nil {
			t.Fatalf("Expected NewEmergencyDNSServer to fail for key len %d, but succeeded", len(k))
		}

		_, errCli := NewEmergencyDNSClient(EmergencyDNSClientConfig{
			ResolverAddr: "127.0.0.1:53",
			DomainSuffix: domainSuffix,
			PSK:          k,
		})
		if errCli == nil {
			t.Fatalf("Expected NewEmergencyDNSClient to fail for key len %d, but succeeded", len(k))
		}
	}
}

func TestOversizedPayloadRejection(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	client, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		ResolverAddr:         "127.0.0.1:53",
		DomainSuffix:         domainSuffix,
		PSK:                  psk,
		IsLegacySingleServer: true,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSClient failed: %v", err)
	}

	// MaxEmergencyPayloadBytes is 512. Try 513 bytes.
	msg := &EmergencyMessage{
		ID:        "oversized-test",
		Type:      "alert",
		Payload:   make([]byte, 513),
		Timestamp: time.Now().Unix(),
	}

	_, _, err = client.Exchange(context.Background(), msg)
	if err == nil {
		t.Fatalf("Expected payload > 512 bytes to be rejected, but succeeded")
	}
}

func TestReplyCacheFingerprintMismatchRejection(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	var handlerInvocations int32
	server, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:           "127.0.0.1:0",
		DomainSuffix:         domainSuffix,
		PSK:                  psk,
		IsLegacySingleServer: true,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			atomic.AddInt32(&handlerInvocations, 1)
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				Reply:     append([]byte("REPLY_FOR:"), msg.Payload...),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSServer failed: %v", err)
	}
	defer server.Stop()

	sessionID := uint64(0x9876543210ABCDEF)
	clientConn, err := NewClientLegacyAsymmetricSession(sessionID, psk)
	if err != nil {
		t.Fatalf("NewClientLegacyAsymmetricSession failed: %v", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", server.Addr().String())
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer conn.Close()

	// 1. Send legitimate initial request (seq=1)
	msg1 := &EmergencyMessage{
		ID:        "msg-001",
		Type:      MsgTypeAlert,
		Payload:   []byte("Original Secret Request"),
		Timestamp: time.Now().Unix(),
	}
	rawMsg1, _ := json.Marshal(msg1)
	frame1, err := clientConn.sealFrame(1, 0, rawMsg1)
	if err != nil {
		t.Fatalf("sealFrame failed: %v", err)
	}

	qname1 := EncodeDNSQName(domainSuffix, "c01", 1001, 0, 1, frame1)
	pkt1 := BuildDNSQuery(qname1, 0x0010 /* TXT */, 0x1111)
	_, _ = conn.WriteToUDP(pkt1, udpAddr)

	buf := make([]byte, 2048)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Read reply 1 failed: %v", err)
	}
	ans1, err := ParseDNSTXTResponse(buf[:n])
	if err != nil {
		t.Fatalf("ParseDNSTXTResponse 1 failed: %v", err)
	}
	_, _, pt1, err := clientConn.openFrame(ans1)
	if err != nil {
		t.Fatalf("Decrypt reply 1 failed: %v", err)
	}
	var resp1 EmergencyResponse
	_ = json.Unmarshal(pt1, &resp1)
	if string(resp1.Reply) != "REPLY_FOR:Original Secret Request" {
		t.Fatalf("Unexpected response: %s", string(resp1.Reply))
	}
	if atomic.LoadInt32(&handlerInvocations) != 1 {
		t.Fatalf("Expected 1 handler invocation, got %d", atomic.LoadInt32(&handlerInvocations))
	}

	// 2. Attack attempt: send a frame with the same visible sessionID and same seq=1,
	// but with corrupted/modified ciphertext.
	tamperedFrame := append([]byte(nil), frame1...)
	tamperedFrame[len(tamperedFrame)-5] ^= 0xFF // Corrupt ciphertext / AEAD tag

	qnameTampered := EncodeDNSQName(domainSuffix, "c01", 1002, 0, 1, tamperedFrame)
	pktTampered := BuildDNSQuery(qnameTampered, 0x0010 /* TXT */, 0x2222)
	_, _ = conn.WriteToUDP(pktTampered, udpAddr)

	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, _, err = conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Expected response packet for tampered frame, got error: %v", err)
	}
	// Server must return REFUSED (RCODE 5)
	rcode := buf[3] & 0x0F
	if rcode != 5 {
		t.Fatalf("Security failure: expected REFUSED (5) for tampered frame, got RCODE %d", rcode)
	}
	// Verify cached reply was NOT leaked
	if bytes.Contains(buf[:n], []byte("Original Secret Request")) {
		t.Fatalf("Critical security leak: tampered frame retrieved cached reply!")
	}
	// Handler was NOT invoked
	if atomic.LoadInt32(&handlerInvocations) != 1 {
		t.Fatalf("Handler was invoked for tampered frame! Got %d invocations", atomic.LoadInt32(&handlerInvocations))
	}

	// 3. Send legitimate exact duplicate of request 1.
	pktDup := BuildDNSQuery(qname1, 0x0010 /* TXT */, 0x3333)
	_, _ = conn.WriteToUDP(pktDup, udpAddr)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Read duplicate reply failed: %v", err)
	}
	ansDup, err := ParseDNSTXTResponse(buf[:n])
	if err != nil {
		t.Fatalf("Parse duplicate answer failed: %v", err)
	}
	// VerifyFrame on duplicate should succeed
	_, _, ptDup, err := clientConn.VerifyFrame(ansDup)
	if err != nil {
		t.Fatalf("Verify duplicate reply failed: %v", err)
	}
	var respDup EmergencyResponse
	_ = json.Unmarshal(ptDup, &respDup)
	if string(respDup.Reply) != "REPLY_FOR:Original Secret Request" {
		t.Fatalf("Duplicate response mismatch: %s", string(respDup.Reply))
	}
	// Handler STILL executed only once!
	if atomic.LoadInt32(&handlerInvocations) != 1 {
		t.Fatalf("Duplicate frame triggered second handler invocation! Got %d", atomic.LoadInt32(&handlerInvocations))
	}
}

func TestReplyCacheEvictionBoundary(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	server, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:           "127.0.0.1:0",
		DomainSuffix:         domainSuffix,
		PSK:                  psk,
		IsLegacySingleServer: true,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSServer failed: %v", err)
	}
	defer server.Stop()

	client, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		ResolverAddr:         server.Addr().String(),
		DomainSuffix:         domainSuffix,
		PSK:                  psk,
		SessionID:            0x1122334455667788,
		Timeout:              2 * time.Second,
		MaxRetries:           0,
		IsLegacySingleServer: true,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSClient failed: %v", err)
	}

	// 1. Send first request (seq=1) and save its frame
	msg1 := &EmergencyMessage{
		ID:        "msg-seq-1",
		Type:      MsgTypePing,
		Payload:   []byte("First Message"),
		Timestamp: time.Now().Unix(),
	}
	rawMsg1, _ := json.Marshal(msg1)
	frame1, err := client.session.sealFrame(1, 0, rawMsg1)
	if err != nil {
		t.Fatalf("sealFrame failed: %v", err)
	}

	udpAddr, _ := net.ResolveUDPAddr("udp", server.Addr().String())
	conn, _ := net.ListenUDP("udp", nil)
	defer conn.Close()

	qname1 := EncodeDNSQName(domainSuffix, "c01", 100, 0, 1, frame1)
	pkt1 := BuildDNSQuery(qname1, 0x0010, 0x0101)
	_, _ = conn.WriteToUDP(pkt1, udpAddr)

	buf := make([]byte, 2048)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Read reply 1 failed: %v", err)
	}
	if buf[3]&0x0F != 0 {
		t.Fatalf("First query failed with RCODE %d", buf[3]&0x0F)
	}

	// 2. Send 35 distinct requests (seq 2 to 36) to overflow MaxCachedRepliesPerSession (32)
	for s := uint32(2); s <= 36; s++ {
		msg := &EmergencyMessage{
			ID:        fmt.Sprintf("msg-seq-%d", s),
			Type:      MsgTypePing,
			Payload:   []byte(fmt.Sprintf("Msg %d", s)),
			Timestamp: time.Now().Unix(),
		}
		raw, _ := json.Marshal(msg)
		frame, _ := client.session.sealFrame(s, 0, raw)
		qname := EncodeDNSQName(domainSuffix, "c01", uint64(100+s), 0, 1, frame)
		pkt := BuildDNSQuery(qname, 0x0010, uint16(0x0100+s))
		_, _ = conn.WriteToUDP(pkt, udpAddr)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, _ = conn.ReadFrom(buf)
	}

	// 3. Now re-send request with seq=1 (which was evicted from replyCache)
	// Because it was evicted, it must not be served from cache.
	// And because seq=1 was already recorded in anti-replay window, openFrame will reject it as duplicate!
	pktEvicted := BuildDNSQuery(qname1, 0x0010, 0x9999)
	_, _ = conn.WriteToUDP(pktEvicted, udpAddr)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Read evicted reply failed: %v", err)
	}
	rcode := buf[3] & 0x0F
	if rcode != 5 {
		t.Fatalf("Expected REFUSED (5) for replay of evicted sequence, got RCODE %d", rcode)
	}
	_ = n
}

func TestConcurrentFirstPacketsSameSession(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	var handlerInvocations int32
	server, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:           "127.0.0.1:0",
		DomainSuffix:         domainSuffix,
		PSK:                  psk,
		IsLegacySingleServer: true,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			atomic.AddInt32(&handlerInvocations, 1)
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				Reply:     append([]byte("CONCURRENCY_OK:"), msg.Payload...),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSServer failed: %v", err)
	}
	defer server.Stop()

	sessionID := uint64(0xFEDCBA9876543210)
	clientConn, err := NewClientLegacyAsymmetricSession(sessionID, psk)
	if err != nil {
		t.Fatalf("NewClientAsymmetricSession failed: %v", err)
	}

	// Prepare one authenticated first packet
	msg := &EmergencyMessage{
		ID:        "msg-concurrent-001",
		Type:      MsgTypeAlert,
		Payload:   []byte("First Packet Race"),
		Timestamp: time.Now().Unix(),
	}
	rawMsg, _ := json.Marshal(msg)
	frame, err := clientConn.sealFrame(1, 0, rawMsg)
	if err != nil {
		t.Fatalf("sealFrame failed: %v", err)
	}

	udpAddr, _ := net.ResolveUDPAddr("udp", server.Addr().String())

	// Launch 25 concurrent goroutines sending the exact same first frame simultaneously
	concurrency := 25
	var wg sync.WaitGroup
	var successCount int32

	startBarrier := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(txID int) {
			defer wg.Done()

			c, err := net.ListenUDP("udp", nil)
			if err != nil {
				return
			}
			defer c.Close()

			qname := EncodeDNSQName(domainSuffix, "c01", uint64(2000+txID), 0, 1, frame)
			pkt := BuildDNSQuery(qname, 0x0010, uint16(txID))

			<-startBarrier // Synchronize launch

			_, _ = c.WriteToUDP(pkt, udpAddr)
			buf := make([]byte, 2048)
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, _, err := c.ReadFrom(buf)
			if err == nil && n >= 12 && (buf[3]&0x0F) == 0 {
				ans, err := ParseDNSTXTResponse(buf[:n])
				if err == nil && len(ans) > 0 {
					atomic.AddInt32(&successCount, 1)
				}
			}
		}(i + 1)
	}

	close(startBarrier)
	wg.Wait()

	// Verify that exactly 1 handler invocation occurred!
	invocations := atomic.LoadInt32(&handlerInvocations)
	if invocations != 1 {
		t.Fatalf("Race condition detected! Expected strictly 1 handler invocation, got %d", invocations)
	}

	// Verify that all 25 concurrent callers received the response
	successes := atomic.LoadInt32(&successCount)
	if successes != int32(concurrency) {
		t.Fatalf("Expected all %d concurrent requests to succeed, got %d", concurrency, successes)
	}

	// Verify that exactly 1 session is tracked in the server map
	if server.ActiveSessionsCount() != 1 {
		t.Fatalf("Expected 1 active session, got %d", server.ActiveSessionsCount())
	}
}

func TestConcurrentDuplicatesWithHandlerDelay(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	var handlerInvocations int32
	server, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:           "127.0.0.1:0",
		DomainSuffix:         domainSuffix,
		PSK:                  psk,
		IsLegacySingleServer: true,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			atomic.AddInt32(&handlerInvocations, 1)
			// Simulate slow handler (50ms) to ensure concurrent duplicates arrive mid-processing
			time.Sleep(50 * time.Millisecond)
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				Reply:     append([]byte("SLOW_HANDLER_REPLY:"), msg.Payload...),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSServer failed: %v", err)
	}
	defer server.Stop()

	sessionID := uint64(0x3344556677889900)
	clientConn, err := NewClientLegacyAsymmetricSession(sessionID, psk)
	if err != nil {
		t.Fatalf("NewClientAsymmetricSession failed: %v", err)
	}

	msg := &EmergencyMessage{
		ID:        "msg-slow-001",
		Type:      MsgTypeAlert,
		Payload:   []byte("Slow In Flight"),
		Timestamp: time.Now().Unix(),
	}
	rawMsg, _ := json.Marshal(msg)
	frame, _ := clientConn.sealFrame(1, 0, rawMsg)

	udpAddr, _ := net.ResolveUDPAddr("udp", server.Addr().String())

	// Send 5 concurrent duplicates
	concurrency := 5
	var wg sync.WaitGroup
	var successCount int32

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(txID int) {
			defer wg.Done()
			c, err := net.ListenUDP("udp", nil)
			if err != nil {
				return
			}
			defer c.Close()

			qname := EncodeDNSQName(domainSuffix, "c01", uint64(3000+txID), 0, 1, frame)
			pkt := BuildDNSQuery(qname, 0x0010, uint16(txID))

			_, _ = c.WriteToUDP(pkt, udpAddr)
			buf := make([]byte, 2048)
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, _, err := c.ReadFrom(buf)
			if err == nil && n >= 12 && (buf[3]&0x0F) == 0 {
				atomic.AddInt32(&successCount, 1)
			}
		}(i + 1)
	}

	wg.Wait()

	if atomic.LoadInt32(&handlerInvocations) != 1 {
		t.Fatalf("Single-flight failed! Expected 1 handler invocation, got %d", atomic.LoadInt32(&handlerInvocations))
	}
	if atomic.LoadInt32(&successCount) != int32(concurrency) {
		t.Fatalf("Expected %d successful responses, got %d", concurrency, atomic.LoadInt32(&successCount))
	}
}

func TestUnauthenticatedPacketCannotJoinInFlightWaiters(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	handlerEntered := make(chan struct{})
	handlerRelease := make(chan struct{})
	var handlerInvocations int32

	server, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:           "127.0.0.1:0",
		DomainSuffix:         domainSuffix,
		PSK:                  psk,
		IsLegacySingleServer: true,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			atomic.AddInt32(&handlerInvocations, 1)
			close(handlerEntered)
			<-handlerRelease // Pause inside handler so sequence is actively in-flight
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				Reply:     []byte("SLOW_AUTHENTICATED_REPLY"),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSServer failed: %v", err)
	}
	defer server.Stop()

	sessionID := uint64(0x778899AABBCCDDEE)
	clientConn, err := NewClientLegacyAsymmetricSession(sessionID, psk)
	if err != nil {
		t.Fatalf("NewClientAsymmetricSession failed: %v", err)
	}

	udpAddr, _ := net.ResolveUDPAddr("udp", server.Addr().String())
	clientUDP, _ := net.ListenUDP("udp", nil)
	defer clientUDP.Close()

	// 1. Send legitimate initial request (seq=1)
	msg := &EmergencyMessage{
		ID:        "msg-inflight-001",
		Type:      MsgTypeAlert,
		Payload:   []byte("Legit In Flight Payload"),
		Timestamp: time.Now().Unix(),
	}
	rawMsg, _ := json.Marshal(msg)
	legitFrame, _ := clientConn.sealFrame(1, 0, rawMsg)

	qnameLegit := EncodeDNSQName(domainSuffix, "c01", 5001, 0, 1, legitFrame)
	pktLegit := BuildDNSQuery(qnameLegit, 0x0010, 0x1001)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = clientUDP.WriteToUDP(pktLegit, udpAddr)
	}()

	// Wait until handler is actively running and seq=1 is in-flight
	<-handlerEntered

	// 2. Attack: Send unauthenticated / tampered packet targeting seq=1 while it is in flight
	attackerUDP, _ := net.ListenUDP("udp", nil)
	defer attackerUDP.Close()

	tamperedFrame := append([]byte(nil), legitFrame...)
	tamperedFrame[len(tamperedFrame)-3] ^= 0xEE // Corrupt AEAD tag

	qnameTampered := EncodeDNSQName(domainSuffix, "c01", 5002, 0, 1, tamperedFrame)
	pktTampered := BuildDNSQuery(qnameTampered, 0x0010, 0x6666)

	t0 := time.Now()
	_, _ = attackerUDP.WriteToUDP(pktTampered, udpAddr)

	bufAttacker := make([]byte, 2048)
	_ = attackerUDP.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	nAttacker, _, err := attackerUDP.ReadFrom(bufAttacker)
	elapsedAttacker := time.Since(t0)

	if err != nil {
		t.Fatalf("Attacker read failed: %v", err)
	}
	// Attacker must be rejected with REFUSED (5) IMMEDIATELY! Must NOT wait for handlerRelease!
	if elapsedAttacker > 200*time.Millisecond {
		t.Fatalf("Security failure: unauthenticated packet was blocked waiting on in-flight channel (%v)!", elapsedAttacker)
	}
	if bufAttacker[3]&0x0F != 5 {
		t.Fatalf("Expected REFUSED (5) for unauthenticated frame targeting in-flight sequence, got RCODE %d", bufAttacker[3]&0x0F)
	}
	_ = nAttacker

	// 3. Release handler
	close(handlerRelease)
	wg.Wait()

	// Read legitimate client reply
	bufClient := make([]byte, 2048)
	_ = clientUDP.SetReadDeadline(time.Now().Add(2 * time.Second))
	nClient, _, err := clientUDP.ReadFrom(bufClient)
	if err != nil {
		t.Fatalf("Legitimate client read failed: %v", err)
	}
	if bufClient[3]&0x0F != 0 {
		t.Fatalf("Expected NOERROR for legitimate query, got %d", bufClient[3]&0x0F)
	}
	_ = nClient

	if atomic.LoadInt32(&handlerInvocations) != 1 {
		t.Fatalf("Expected 1 handler invocation, got %d", atomic.LoadInt32(&handlerInvocations))
	}
}
