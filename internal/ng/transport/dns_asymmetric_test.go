package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDNSAsymmetricFramingAndReassemblyDetails(t *testing.T) {
	domainSuffix := "tunnel.paqet.local"
	clientID := "c99"
	offset := uint64(1000)

	// Simulate a 100-byte payload split into 3 chunks
	payload := []byte("Emergency DNS payload for severe curfew testing. 100% authenticated chunk framing over UDP:53.")
	chunkSize := 35 // Fits comfortably in a 63-char base32 label

	var chunks [][]byte
	for i := 0; i < len(payload); i += chunkSize {
		end := i + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunks = append(chunks, payload[i:end])
	}

	totalParts := uint8(len(chunks))
	reassembler := NewDNSReassembler(5 * time.Second)

	// Encode and push out of order: Part 2, then Part 0, then Part 1
	order := []int{2, 0, 1}
	var complete []byte
	var ok bool

	for _, idx := range order {
		qname := EncodeDNSQName(domainSuffix, clientID, offset, uint8(idx), totalParts, chunks[idx])

		// Verify label lengths <= 63 (RFC 1035 limit)
		labels := bytes.Split([]byte(qname), []byte("."))
		for _, l := range labels {
			if len(l) > 63 {
				t.Fatalf("Label %q exceeds RFC 1035 limit (len %d > 63)", l, len(l))
			}
		}

		cID, off, p, tot, data, err := DecodeDNSQName(qname, domainSuffix)
		if err != nil {
			t.Fatalf("DecodeDNSQName failed for qname %s: %v", qname, err)
		}
		if cID != clientID || off != offset || p != uint8(idx) || tot != totalParts {
			t.Fatalf("Metadata mismatch: got (%s, %d, %d, %d), want (%s, %d, %d, %d)",
				cID, off, p, tot, clientID, offset, idx, totalParts)
		}

		res, finished := reassembler.PushFragment(cID, off, p, tot, data)
		if finished {
			complete = res
			ok = true
		}
	}

	if !ok {
		t.Fatalf("Reassembler failed to assemble all parts")
	}

	if !bytes.Equal(complete, payload) {
		t.Fatalf("Reassembled payload mismatch: got %q, want %q", complete, payload)
	}
}

func TestDNSOverheadAndThroughputBounds(t *testing.T) {
	// Calculate mathematical throughput and amplification
	rawChunkSize := 35 // bytes
	b32Len := (rawChunkSize*8 + 4) / 5
	domainSuffix := "t.paqet.ir"
	clientID := "c01"

	qname := fmt.Sprintf("p0.t1.o0.%s.%s.%s", string(make([]byte, b32Len)), clientID, domainSuffix)
	dnsQuerySize := 20 /* IPv4 */ + 8 /* UDP */ + 12 /* DNS Header */ + len(qname) + 2 + 4 /* Question */

	amplification := float64(dnsQuerySize) / float64(rawChunkSize)
	t.Logf("DNS Wire Query Size: %d bytes, Payload: %d bytes, Wire Amplification: %.2fx",
		dnsQuerySize, rawChunkSize, amplification)

	if amplification < 2.0 {
		t.Errorf("Expected wire amplification to exceed 2.0x, got %.2fx", amplification)
	}

	// At 20 queries/second (conservative resolver rate limit)
	conservativeThroughputBps := 20 * rawChunkSize * 8
	t.Logf("Conservative DNS Throughput @ 20 qps: %d bps (%.2f kbps)",
		conservativeThroughputBps, float64(conservativeThroughputBps)/1000.0)

	// At 100 queries/second (aggressive)
	aggressiveThroughputBps := 100 * rawChunkSize * 8
	t.Logf("Aggressive DNS Throughput @ 100 qps: %d bps (%.2f kbps)",
		aggressiveThroughputBps, float64(aggressiveThroughputBps)/1000.0)

	if conservativeThroughputBps > 100000 {
		t.Errorf("Conservative DNS throughput unexpectedly exceeded 100 kbps")
	}
}

func TestDNSQueryPackingAndTXTResponse(t *testing.T) {
	qname := "p0.t1.o1.mzxw6ytb.c01.tunnel.local"
	queryPkt := BuildDNSQuery(qname, 0x0010 /* TXT */, 0x1234)

	id, parsedQName, qtype, err := ParseDNSQuery(queryPkt)
	if err != nil {
		t.Fatalf("ParseDNSQuery failed: %v", err)
	}
	if id != 0x1234 {
		t.Errorf("ID mismatch: got 0x%x, want 0x1234", id)
	}
	if parsedQName != qname {
		t.Errorf("QNAME mismatch: got %q, want %q", parsedQName, qname)
	}
	if qtype != 0x0010 {
		t.Errorf("QTYPE mismatch: got 0x%x, want 0x0010", qtype)
	}

	// Test TXT response packing and extraction
	txtData := []byte("SECRET-RETURN-DATA-FROM-DNS-SERVER")
	respPkt, err := BuildDNSTXTResponse(queryPkt, txtData)
	if err != nil {
		t.Fatalf("BuildDNSTXTResponse failed: %v", err)
	}

	extracted, err := ParseDNSTXTResponse(respPkt)
	if err != nil {
		t.Fatalf("ParseDNSTXTResponse failed: %v", err)
	}
	if !bytes.Equal(extracted, txtData) {
		t.Fatalf("Extracted TXT mismatch: got %q, want %q", extracted, txtData)
	}
}

func TestRealSocketDNSAsymmetricCandidateAEndToEnd(t *testing.T) {
	sessionID := uint64(0x7766554433221100)
	psk := []byte("real-dns-socket-psk-32-bytes-ok!")
	domainSuffix := "tunnel.paqet.local"
	clientID := "c99"

	// 1. Authoritative DNS Server listening on a real UDP socket
	dnsServerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP for DNS server failed: %v", err)
	}
	defer dnsServerConn.Close()

	// 2. Client Downstream Receiver listening on a real UDP socket
	clientDownstreamConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP for client downstream failed: %v", err)
	}
	defer clientDownstreamConn.Close()

	// 3. Client Upstream Query Socket
	clientQueryConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP for client query failed: %v", err)
	}
	defer clientQueryConn.Close()

	clientSender := NewRealSocketDNSUpstreamSender(clientQueryConn, dnsServerConn.LocalAddr().(*net.UDPAddr), domainSuffix, clientID)
	clientReceiver := NewRealSocketDirectUDPReceiver(clientDownstreamConn)

	clientConn, err := NewClientAsymmetricConn(
		sessionID,
		psk,
		64, // Small MTU to force multipart DNS query fragmentation
		clientSender,
		clientReceiver,
		clientDownstreamConn.LocalAddr(),
		dnsServerConn.LocalAddr(),
	)
	if err != nil {
		t.Fatalf("NewClientAsymmetricConn failed: %v", err)
	}
	defer clientConn.Close()

	serverConn := &AsymmetricConn{
		sessionID: sessionID,
		role:      RoleServer,
		encKey:    clientConn.decKey,
		decKey:    clientConn.encKey,
	}

	reassembler := NewDNSReassembler(5 * time.Second)
	stopServer := make(chan struct{})

	// Server loop: receives DNS queries off the real wire, decodes QNAME, reassembles, and echoes via direct UDP
	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-stopServer:
				return
			default:
			}

			_ = dnsServerConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, _, err := dnsServerConn.ReadFrom(buf)
			if err != nil {
				continue
			}

			_, qname, _, err := ParseDNSQuery(buf[:n])
			if err != nil {
				continue
			}

			cID, off, part, total, data, err := DecodeDNSQName(qname, domainSuffix)
			if err != nil {
				continue
			}

			fullFrame, ok := reassembler.PushFragment(cID, off, part, total, data)
			if ok {
				// Reassembled full frame from real DNS queries!
				seq, _, payload, err := serverConn.openFrame(fullFrame)
				if err != nil {
					continue
				}

				// Echo back payload to clientDownstreamConn via direct UDP
				replyFrame, err := serverConn.sealFrame(seq, seq, payload)
				if err == nil {
					_, _ = dnsServerConn.WriteToUDP(replyFrame, clientDownstreamConn.LocalAddr().(*net.UDPAddr))
				}
			}
		}
	}()
	defer close(stopServer)

	// Send message over client connection (crosses real OS UDP sockets and DNS protocol)
	testMsg := []byte("REAL-SOCKET-DNS-UPSTREAM-DIRECT-UDP-DOWNSTREAM-SUCCESS")
	go func() {
		_, _ = clientConn.Write(testMsg)
	}()

	recvBuf := make([]byte, len(testMsg))
	_, err = io.ReadFull(clientConn, recvBuf)
	if err != nil {
		t.Fatalf("io.ReadFull failed: %v", err)
	}

	if !bytes.Equal(recvBuf, testMsg) {
		t.Fatalf("Received message mismatch: got %q, want %q", recvBuf, testMsg)
	}
}

func TestRealSocketDNSAsymmetricCandidateBEndToEnd(t *testing.T) {
	sessionID := uint64(0x11223344AABBCCDD)
	psk := []byte("real-dns-candidate-b-psk-32-byte")
	domainSuffix := "tunnel.paqet.local"
	clientID := "c77"

	// 1. Authoritative DNS Server socket
	dnsServerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP for DNS server failed: %v", err)
	}
	defer dnsServerConn.Close()

	// 2. Client query socket (serves both query TX and response RX in Candidate B)
	clientConnSocket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP for client failed: %v", err)
	}
	defer clientConnSocket.Close()

	clientSender := NewRealSocketDNSUpstreamSender(clientConnSocket, dnsServerConn.LocalAddr().(*net.UDPAddr), domainSuffix, clientID)

	// Channel for returning extracted frames from incoming DNS responses
	downFrameCh := make(chan []byte, 10)
	clientReceiver := NewMemoryPipeReceiver(downFrameCh)

	clientConn, err := NewClientAsymmetricConn(
		sessionID,
		psk,
		64,
		clientSender,
		clientReceiver,
		clientConnSocket.LocalAddr(),
		dnsServerConn.LocalAddr(),
	)
	if err != nil {
		t.Fatalf("NewClientAsymmetricConn failed: %v", err)
	}
	defer clientConn.Close()

	serverConn := &AsymmetricConn{
		sessionID: sessionID,
		role:      RoleServer,
		encKey:    clientConn.decKey,
		decKey:    clientConn.encKey,
	}

	reassembler := NewDNSReassembler(5 * time.Second)
	stopServer := make(chan struct{})

	// Server loop: receives query, reassembles frame, echoes inside DNS TXT response to client
	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-stopServer:
				return
			default:
			}

			_ = dnsServerConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, clientAddr, err := dnsServerConn.ReadFrom(buf)
			if err != nil {
				continue
			}

			reqPkt := buf[:n]
			_, qname, _, err := ParseDNSQuery(reqPkt)
			if err != nil {
				continue
			}

			cID, off, part, total, data, err := DecodeDNSQName(qname, domainSuffix)
			if err != nil {
				continue
			}

			fullFrame, ok := reassembler.PushFragment(cID, off, part, total, data)
			if ok {
				// Reassembled upstream frame!
				seq, _, payload, err := serverConn.openFrame(fullFrame)
				if err != nil {
					continue
				}

				// Craft reply frame
				replyFrame, err := serverConn.sealFrame(seq, seq, payload)
				if err != nil {
					continue
				}

				// Embed replyFrame inside DNS TXT answer record!
				respPkt, err := BuildDNSTXTResponse(reqPkt, replyFrame)
				if err == nil {
					_, _ = dnsServerConn.WriteTo(respPkt, clientAddr)
				}
			}
		}
	}()
	defer close(stopServer)

	// Client response listener: reads DNS responses on clientConnSocket and feeds TXT answers to downFrameCh
	stopClientRx := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-stopClientRx:
				return
			default:
			}

			_ = clientConnSocket.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, _, err := clientConnSocket.ReadFrom(buf)
			if err != nil {
				continue
			}

			txtAnswer, err := ParseDNSTXTResponse(buf[:n])
			if err == nil && len(txtAnswer) > 0 {
				downFrameCh <- txtAnswer
			}
		}
	}()
	defer close(stopClientRx)

	testMsg := []byte("CANDIDATE-B-BIDIRECTIONAL-DNS-TXT-RESPONSE-SUCCESS")
	go func() {
		_, _ = clientConn.Write(testMsg)
	}()

	recvBuf := make([]byte, len(testMsg))
	_, err = io.ReadFull(clientConn, recvBuf)
	if err != nil {
		t.Fatalf("io.ReadFull failed: %v", err)
	}

	if !bytes.Equal(recvBuf, testMsg) {
		t.Fatalf("Message mismatch: got %q, want %q", recvBuf, testMsg)
	}
}

func TestSelectBestResolverWithScoring(t *testing.T) {
	// Start mock authentic DNS server on port 5354
	mockSrv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP mock failed: %v", err)
	}
	defer mockSrv.Close()

	go func() {
		buf := make([]byte, 2048)
		for {
			n, clientAddr, err := mockSrv.ReadFrom(buf)
			if err != nil {
				return
			}
			req := buf[:n]
			if len(req) < 12 {
				continue
			}

			txID := req[:2]
			// Respond with NOERROR
			hdr := append([]byte(nil), txID...)
			hdr = append(hdr, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
			question := req[12:]
			ans := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93, 184, 216, 34}
			resp := append(hdr, append(question, ans...)...)
			_, _ = mockSrv.WriteTo(resp, clientAddr)
		}
	}()

	dialer := NewDNSAsymmetricDialer(DNSAsymmetricConfig{
		ResolverAddr: "192.0.2.1:53", // Unreachable initial resolver
		ResolverPool: []string{"192.0.2.1", mockSrv.LocalAddr().String()},
		DomainSuffix: "tunnel.paqet.local",
		ClientID:     "c01",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	best := dialer.SelectBestResolver(ctx)
	if !strings.HasPrefix(best, "127.0.0.1:") {
		t.Fatalf("Expected SelectBestResolver to pick working 127.0.0.1 resolver, got %s", best)
	}
}
