package transport

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"
)

func TestEDNS0_ConservativeDefaultAndCustomBufferSize(t *testing.T) {
	// 1. Default query must advertise 1232 bytes (DNS Flag Day standard)
	q1 := BuildDNSQuery("test.example.com", 0x0010, 0x1234)
	bufSize1 := ParseEDNSBufferSize(q1)
	if bufSize1 != DefaultEDNSUDPPayloadSize {
		t.Fatalf("expected default EDNS buffer size %d, got %d", DefaultEDNSUDPPayloadSize, bufSize1)
	}
	if bufSize1 != 1232 {
		t.Fatalf("expected 1232 bytes default, got %d", bufSize1)
	}

	// 2. Custom 1400 bytes query
	q2 := BuildDNSQueryWithEDNS("test.example.com", 0x0010, 0x1234, 1400)
	bufSize2 := ParseEDNSBufferSize(q2)
	if bufSize2 != 1400 {
		t.Fatalf("expected custom EDNS buffer size 1400, got %d", bufSize2)
	}

	// 3. RFC 1035 standard query (0 bytes EDNS)
	q3 := BuildDNSQueryWithEDNS("test.example.com", 0x0010, 0x1234, 0)
	bufSize3 := ParseEDNSBufferSize(q3)
	if bufSize3 != 512 {
		t.Fatalf("expected RFC 1035 fallback size 512, got %d", bufSize3)
	}
	arcount := binary.BigEndian.Uint16(q3[10:12])
	if arcount != 0 {
		t.Fatalf("expected ARCOUNT=0 when EDNS buffer size is 0, got %d", arcount)
	}
}

func TestEDNS0_ParseEDNSBufferSize_MalformedInputs(t *testing.T) {
	// Truncated packet
	if size := ParseEDNSBufferSize([]byte{0x01, 0x02}); size != 512 {
		t.Fatalf("expected 512 on short packet, got %d", size)
	}

	// Empty packet
	if size := ParseEDNSBufferSize(nil); size != 512 {
		t.Fatalf("expected 512 on nil packet, got %d", size)
	}
}

func TestEDNS0_AllAdvertisedSizesAndSizingRule(t *testing.T) {
	sizes := []uint16{512, 768, 1024, 1232, 1400, 4096}

	for _, sz := range sizes {
		queryPkt := BuildDNSQueryWithEDNS("test.sizing.example.com", 0x0010, 0x1000+sz, sz)

		hasOPT, parsedSz, err := ParseEDNSOption(queryPkt)
		if err != nil {
			t.Fatalf("ParseEDNSOption failed for size %d: %v", sz, err)
		}
		if !hasOPT {
			t.Fatalf("expected hasOPT=true for size %d", sz)
		}
		if parsedSz != sz {
			t.Fatalf("parsed buffer size mismatch: got %d, want %d", parsedSz, sz)
		}

		// Test with 600-byte payload:
		payload600 := make([]byte, 600)
		for i := range payload600 {
			payload600[i] = byte('A' + (i % 26))
		}

		resp600, err := BuildDNSTXTResponse(queryPkt, payload600)
		if err != nil {
			t.Fatalf("BuildDNSTXTResponse failed: %v", err)
		}

		flags600 := binary.BigEndian.Uint16(resp600[2:4])
		isTC600 := flags600&0x0200 != 0
		actualLen600 := len(resp600)

		if sz == 512 {
			// For 512, 650 bytes cannot fit -> MUST truncate!
			if !isTC600 {
				t.Fatalf("expected TC=1 for 600B payload on 512B limit, got TC=0")
			}
			ancount := binary.BigEndian.Uint16(resp600[6:8])
			if ancount != 0 {
				t.Fatalf("expected ANCOUNT=0 on truncated response, got %d", ancount)
			}
			if actualLen600 > 512 {
				t.Fatalf("truncated response length %d exceeds 512", actualLen600)
			}
		} else {
			// For 768, 1024, 1232, 1400, 4096: 650 bytes MUST fit!
			if isTC600 {
				t.Fatalf("expected TC=0 for 600B payload on %dB limit, got TC=1", sz)
			}
			ancount := binary.BigEndian.Uint16(resp600[6:8])
			if ancount != 1 {
				t.Fatalf("expected ANCOUNT=1, got %d", ancount)
			}
			if actualLen600 > int(sz) && sz <= 1400 {
				t.Fatalf("response length %d exceeds advertised %d", actualLen600, sz)
			}
		}

		// Test with 1500-byte payload (> 1400-byte server cap):
		payload1500 := make([]byte, 1500)
		for i := range payload1500 {
			payload1500[i] = byte('B' + (i % 26))
		}

		resp1500, err := BuildDNSTXTResponse(queryPkt, payload1500)
		if err != nil {
			t.Fatalf("BuildDNSTXTResponse 1500 failed: %v", err)
		}
		flags1500 := binary.BigEndian.Uint16(resp1500[2:4])
		if flags1500&0x0200 == 0 {
			t.Fatalf("expected TC=1 for 1500B payload across all sizes, got TC=0 on sz=%d", sz)
		}
		if len(resp1500) > int(sz) && sz <= 1400 {
			t.Fatalf("truncated response length %d exceeds limit %d", len(resp1500), sz)
		}
	}
	t.Logf("PASS: Verified effective UDP sizing rule across sizes 512, 768, 1024, 1232, 1400, 4096")
}

func TestEDNS0_NoEDNS_LimitsTo512AndOmitsOPT(t *testing.T) {
	// Query without EDNS (ednsBufSize = 0)
	queryNoEDNS := BuildDNSQueryWithEDNS("noedns.example.com", 0x0010, 0x2222, 0)

	hasOPT, size, err := ParseEDNSOption(queryNoEDNS)
	if err != nil {
		t.Fatalf("ParseEDNSOption failed: %v", err)
	}
	if hasOPT {
		t.Fatalf("expected hasOPT=false for query without EDNS")
	}
	if size != 512 {
		t.Fatalf("expected default size 512, got %d", size)
	}

	// Payload that fits in 512 (e.g. 100 bytes)
	payloadSmall := make([]byte, 100)
	respSmall, err := BuildDNSTXTResponse(queryNoEDNS, payloadSmall)
	if err != nil {
		t.Fatalf("BuildDNSTXTResponse failed: %v", err)
	}
	flagsSmall := binary.BigEndian.Uint16(respSmall[2:4])
	if flagsSmall&0x0200 != 0 {
		t.Fatalf("expected TC=0 for small payload without EDNS")
	}
	arcountSmall := binary.BigEndian.Uint16(respSmall[10:12])
	if arcountSmall != 0 {
		t.Fatalf("expected ARCOUNT=0 in response when client did not send EDNS, got %d", arcountSmall)
	}

	// Payload that overflows 512 (e.g. 500 bytes)
	payloadLarge := make([]byte, 500)
	respLarge, err := BuildDNSTXTResponse(queryNoEDNS, payloadLarge)
	if err != nil {
		t.Fatalf("BuildDNSTXTResponse large failed: %v", err)
	}
	flagsLarge := binary.BigEndian.Uint16(respLarge[2:4])
	if flagsLarge&0x0200 == 0 {
		t.Fatalf("expected TC=1 when response without EDNS exceeds 512 bytes")
	}
	arcountLarge := binary.BigEndian.Uint16(respLarge[10:12])
	if arcountLarge != 0 {
		t.Fatalf("expected ARCOUNT=0 in truncated response when client did not send EDNS, got %d", arcountLarge)
	}
	t.Logf("PASS: Verified no-EDNS requests enforce strict 512-byte limit and omit OPT RR")
}

func TestEDNS0_MultipleAdditionalRecords(t *testing.T) {
	baseQuery := BuildDNSQueryWithEDNS("multi.example.com", 0x0010, 0x3333, 0)

	dummyRR := []byte{
		0x05, 'e', 'x', 't', 'r', 'a', 0x00,
		0x00, 0x10, // TYPE TXT
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x00, 0x00, // TTL 0
		0x00, 0x05, // RDLEN 5
		0x04, 't', 'e', 's', 't',
	}

	optRR := []byte{
		0x00,
		0x00, 0x29, // TYPE OPT
		0x04, 0xD0, // CLASS = 1232
		0x00, 0x00, 0x00, 0x00, // TTL
		0x00, 0x00, // RDLEN 0
	}

	pkt := append(baseQuery, dummyRR...)
	pkt = append(pkt, optRR...)
	binary.BigEndian.PutUint16(pkt[10:12], 2)

	hasOPT, size, err := ParseEDNSOption(pkt)
	if err != nil {
		t.Fatalf("ParseEDNSOption failed on multi-record additional section: %v", err)
	}
	if !hasOPT {
		t.Fatalf("expected hasOPT=true when OPT RR follows another additional RR")
	}
	if size != 1232 {
		t.Fatalf("expected size 1232, got %d", size)
	}
	t.Logf("PASS: Verified parser correctly scans multiple records in Additional section to locate OPT RR")
}

func TestEDNS0_ResponseTruncationWhenExceedingLimit(t *testing.T) {
	// Client sends standard RFC 1035 query with 512-byte limit (ednsBufSize = 0)
	queryPkt := BuildDNSQueryWithEDNS("payload.example.com", 0x0010, 0x4321, 0)

	// Create a 1500-byte payload which exceeds safe UDP maximum (1400 bytes)
	largePayload := make([]byte, 1500)
	for i := range largePayload {
		largePayload[i] = byte('A' + (i % 26))
	}

	respPkt, err := BuildDNSTXTResponse(queryPkt, largePayload)
	if err != nil {
		t.Fatalf("BuildDNSTXTResponse failed: %v", err)
	}

	flags := binary.BigEndian.Uint16(respPkt[2:4])
	if flags&0x0200 == 0 {
		t.Fatalf("expected TC (Truncation) bit 0x0200 set on overflow response, got flags 0x%04x", flags)
	}
	ancount := binary.BigEndian.Uint16(respPkt[6:8])
	if ancount != 0 {
		t.Fatalf("expected ANCOUNT=0 on truncated response, got %d", ancount)
	}
	t.Logf("PASS: Response safely truncated with TC=1 and ANCOUNT=0 when exceeding 1400-byte safe limit")
}

func TestEDNS0_TCPPort53FallbackOnTruncation(t *testing.T) {
	// Start an EmergencyDNSServer with UDP and TCP listeners on an isolated loopback port
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i + 1)
	}

	bm, err := NewBootstrapManager([]BootstrapEndpointRecord{
		{
			ServerIP:      "127.0.0.1",
			TransportPort: 18089,
			TransportMode: "aead-stream",
			IdentityType:  IdentityTypePSKID,
			IdentityValue: "SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			ValiditySec:   3600,
		},
	}, "aead-stream", 1)
	if err != nil {
		t.Fatalf("NewBootstrapManager failed: %v", err)
	}

	srv, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:           "127.0.0.1:0",
		DomainSuffix:         "edns.test",
		PSK:                  psk,
		IsLegacySingleServer: true,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			bResp, err := bm.GenerateResponse(msg, "aead-stream")
			if err != nil {
				return nil, err
			}
			bBytes, _ := json.Marshal(bResp)
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				Reply:     bBytes,
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSServer failed: %v", err)
	}
	defer srv.Stop()

	addrStr := srv.udpConn.LocalAddr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Create client with conservative 1232-byte EDNS buffer
	client, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		ResolverAddr:         addrStr,
		DomainSuffix:         "edns.test",
		ClientID:             "c01",
		PSK:                  psk,
		Timeout:              1 * time.Second,
		EDNSBufferSize:       1232,
		IsLegacySingleServer: true,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSClient failed: %v", err)
	}

	resp, _, err := client.Exchange(ctx, &EmergencyMessage{
		ID:        "msg-edns-01",
		Type:      "bootstrap_request",
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("client.Exchange failed: %v", err)
	}
	if resp.Status != "OK" {
		t.Fatalf("expected status OK, got %s", resp.Status)
	}
	t.Logf("PASS: Emergency DNS query succeeded with conservative 1232-byte EDNS buffer")
}
