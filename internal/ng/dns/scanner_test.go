package dns

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBuildQueryPacketAndEDNS0(t *testing.T) {
	// 1. Standard query without EDNS0
	pktStandard := BuildQueryPacket("example.com", TypeA, 0x1234, 0)
	if len(pktStandard) < 12 {
		t.Fatalf("Standard query too short: %d", len(pktStandard))
	}
	if binary.BigEndian.Uint16(pktStandard[0:2]) != 0x1234 {
		t.Errorf("TxID mismatch: got 0x%x, want 0x1234", binary.BigEndian.Uint16(pktStandard[0:2]))
	}
	if binary.BigEndian.Uint16(pktStandard[4:6]) != 1 {
		t.Errorf("QDCOUNT mismatch: got %d, want 1", binary.BigEndian.Uint16(pktStandard[4:6]))
	}
	if binary.BigEndian.Uint16(pktStandard[10:12]) != 0 {
		t.Errorf("ARCOUNT must be 0 when EDNS0 disabled, got %d", binary.BigEndian.Uint16(pktStandard[10:12]))
	}

	// 2. Query with EDNS0 OPT RR (1232 bytes)
	pktEDNS := BuildQueryPacket("tunnel.example.com", TypeTXT, 0x5678, 1232)
	if binary.BigEndian.Uint16(pktEDNS[10:12]) != 1 {
		t.Fatalf("ARCOUNT must be 1 with EDNS0, got %d", binary.BigEndian.Uint16(pktEDNS[10:12]))
	}

	// Verify OPT RR structure at the end: Root name (0x00), Type OPT (41), Payload (1232)
	optOffset := len(pktEDNS) - 11
	if pktEDNS[optOffset] != 0x00 {
		t.Errorf("OPT RR name must be root 0x00, got 0x%x", pktEDNS[optOffset])
	}
	optType := binary.BigEndian.Uint16(pktEDNS[optOffset+1 : optOffset+3])
	if optType != TypeOPT {
		t.Errorf("OPT RR type mismatch: got %d, want %d", optType, TypeOPT)
	}
	optPayload := binary.BigEndian.Uint16(pktEDNS[optOffset+3 : optOffset+5])
	if optPayload != 1232 {
		t.Errorf("OPT RR payload mismatch: got %d, want 1232", optPayload)
	}
}

func startMockDNSServer(t *testing.T, hijackNXDOMAIN bool) (*net.UDPConn, string) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}

	go func() {
		buf := make([]byte, 2048)
		for {
			n, clientAddr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			req := buf[:n]
			if len(req) < 12 {
				continue
			}

			txID := binary.BigEndian.Uint16(req[0:2])
			// Find question name
			offset := 12
			var labels []string
			for offset < len(req) {
				lLen := int(req[offset])
				offset++
				if lLen == 0 {
					break
				}
				labels = append(labels, string(req[offset:offset+lLen]))
				offset += lLen
			}
			offset += 4 // QTYPE + QCLASS
			question := req[12:offset]
			qname := strings.Join(labels, ".")

			var resp []byte
			hdr := make([]byte, 12)
			binary.BigEndian.PutUint16(hdr[0:2], txID)

			if strings.HasSuffix(qname, ".invalid") {
				if hijackNXDOMAIN {
					// Simulate censorship / ISP NXDOMAIN hijacking: return NOERROR (0) + 1 answer with fake IP
					binary.BigEndian.PutUint16(hdr[2:4], 0x8180) // NOERROR
					binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT
					binary.BigEndian.PutUint16(hdr[6:8], 1)      // ANCOUNT = 1
					resp = append(resp, hdr...)
					resp = append(resp, question...)
					// A Record 10.10.34.34
					resp = append(resp, []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 10, 10, 34, 34}...)
				} else {
					// Authentic RFC 1035 NXDOMAIN (RCODE = 3)
					binary.BigEndian.PutUint16(hdr[2:4], 0x8183) // NXDOMAIN
					binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT
					resp = append(resp, hdr...)
					resp = append(resp, question...)
				}
			} else {
				// Standard NOERROR response with OPT RR if query had ARCOUNT > 0
				hasOPT := binary.BigEndian.Uint16(req[10:12]) > 0
				binary.BigEndian.PutUint16(hdr[2:4], 0x8180) // NOERROR
				binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT
				binary.BigEndian.PutUint16(hdr[6:8], 1)      // ANCOUNT
				if hasOPT {
					binary.BigEndian.PutUint16(hdr[10:12], 1) // ARCOUNT
				}
				resp = append(resp, hdr...)
				resp = append(resp, question...)

				// Dummy answer
				resp = append(resp, []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93, 184, 216, 34}...)
				if hasOPT {
					optRR := []byte{0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} // OPT 1232
					resp = append(resp, optRR...)
				}
			}

			_, _ = conn.WriteTo(resp, clientAddr)
		}
	}()

	host, portStr, _ := net.SplitHostPort(conn.LocalAddr().String())
	_ = portStr
	return conn, host
}

func TestScanResolverAuthenticAndHijacked(t *testing.T) {
	// 1. Authentic Resolver Test
	srvAuth, hostAuth := startMockDNSServer(t, false)
	defer srvAuth.Close()
	portAuth := srvAuth.LocalAddr().(*net.UDPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	capAuth := ScanResolver(ctx, hostAuth, portAuth, "example.com", 1*time.Second)
	if capAuth.Status != StatusWorking {
		t.Fatalf("Expected authentic resolver to be WORKING, got %s (err: %s)", capAuth.Status, capAuth.LastError)
	}
	if !capAuth.NXDOMAINPreserved {
		t.Errorf("Expected authentic resolver to preserve NXDOMAIN")
	}
	if !capAuth.EDNS0Support {
		t.Errorf("Expected EDNS0 support on authentic resolver")
	}
	if capAuth.Score < 5 {
		t.Errorf("Expected high score >= 5 for authentic resolver, got %d", capAuth.Score)
	}
	if capAuth.Profile != ProfileTunnelCompatible {
		t.Errorf("Expected ProfileTunnelCompatible, got %s", capAuth.Profile)
	}

	// 2. Hijacked Resolver Test (simulating Iranian ISP NXDOMAIN interception)
	srvHijack, hostHijack := startMockDNSServer(t, true)
	defer srvHijack.Close()
	portHijack := srvHijack.LocalAddr().(*net.UDPAddr).Port

	capHijack := ScanResolver(ctx, hostHijack, portHijack, "example.com", 1*time.Second)
	if capHijack.Status != StatusWorking {
		t.Fatalf("Expected hijacked resolver to be reachable, got %s", capHijack.Status)
	}
	if capHijack.NXDOMAINPreserved {
		t.Errorf("Expected hijacked resolver to FAIL NXDOMAIN check")
	}
	if capHijack.Profile != ProfileBlocked {
		t.Errorf("Expected hijacked resolver to be classified as ProfileBlocked, got %s", capHijack.Profile)
	}
}

func TestScanResolverPoolConcurrent(t *testing.T) {
	srv1, _ := startMockDNSServer(t, false)
	defer srv1.Close()
	p1 := srv1.LocalAddr().(*net.UDPAddr).Port

	srv2, _ := startMockDNSServer(t, true)
	defer srv2.Close()
	p2 := srv2.LocalAddr().(*net.UDPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Provide candidate pool (including an unreachable IP)
	candidates := []string{"127.0.0.1", "127.0.0.1", "192.0.2.1"}
	_ = p2

	results := ScanResolverPool(ctx, candidates, p1, "test.local", 500*time.Millisecond, 4)
	if len(results) != len(candidates) {
		t.Fatalf("Expected %d results, got %d", len(candidates), len(results))
	}

	// Verify sorting: highest score first
	for i := 0; i < len(results)-1; i++ {
		if results[i].Score < results[i+1].Score {
			t.Errorf("Results not sorted by score: %d < %d", results[i].Score, results[i+1].Score)
		}
	}
}
