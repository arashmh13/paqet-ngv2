package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"
)

func TestSNIDecoyClientHelloStructure(t *testing.T) {
	decoySNI := "hcaptcha.com"
	rawHello := BuildDecoyClientHello(decoySNI, "chrome")

	// 1. Must be at least TLS record header (5 bytes) + handshake header (4 bytes)
	if len(rawHello) < 9 {
		t.Fatalf("ClientHello too short: %d bytes", len(rawHello))
	}

	// 2. Record header: 0x16 (Handshake), 0x03, 0x01
	if rawHello[0] != 0x16 {
		t.Errorf("Expected ContentType 0x16, got 0x%02x", rawHello[0])
	}
	if rawHello[1] != 0x03 || rawHello[2] != 0x01 {
		t.Errorf("Expected version 0x0301, got 0x%02x%02x", rawHello[1], rawHello[2])
	}

	recordLen := binary.BigEndian.Uint16(rawHello[3:5])
	if int(recordLen) != len(rawHello)-5 {
		t.Errorf("Record length mismatch: hdr=%d, actual=%d", recordLen, len(rawHello)-5)
	}

	// 3. Handshake type: 0x01 (ClientHello)
	if rawHello[5] != 0x01 {
		t.Errorf("Expected handshake type 0x01, got 0x%02x", rawHello[5])
	}

	// 4. Must contain the SNI string in payload
	if !bytes.Contains(rawHello, []byte(decoySNI)) {
		t.Errorf("Decoy SNI %q not found in ClientHello payload", decoySNI)
	}
}

func TestSNIAssistedEndToEnd(t *testing.T) {
	psk := []byte("test-shared-secret-key-32bytes!!")
	decoySNI := "bank.ir"

	// 1. Start listener
	l, err := NewAEADStreamListener("127.0.0.1:0", psk)
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer l.Close()

	// 2. Start server accept loop
	errCh := make(chan error, 1)
	go func() {
		sess, err := l.Accept(context.Background())
		if err != nil {
			errCh <- err
			return
		}
		defer sess.Close()

		strm, err := sess.AcceptStream()
		if err != nil {
			errCh <- err
			return
		}
		defer strm.Close()

		buf := make([]byte, 1024)
		n, err := strm.Read(buf)
		if err != nil {
			errCh <- err
			return
		}

		// Echo back
		_, err = strm.Write(buf[:n])
		errCh <- err
	}()

	// 3. Dial using SNIAssistedDialer
	dialer := NewSNIAssistedDialer(SNIAssistedConfig{
		PSK:          psk,
		DecoySNI:     decoySNI,
		InjectMethod: "fragment",
		MaxPad:       32,
	})

	sess, err := dialer.Dial(context.Background(), l.Addr().String())
	if err != nil {
		t.Fatalf("SNIAssistedDialer failed: %v", err)
	}
	defer sess.Close()

	strm, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}
	defer strm.Close()

	payload := []byte("Hello via SNI-Assisted Decoy Transport!")
	if _, err := strm.Write(payload); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(strm, reply); err != nil {
		t.Fatalf("Read reply failed: %v", err)
	}

	if !bytes.Equal(payload, reply) {
		t.Errorf("Payload mismatch: got %q, want %q", reply, payload)
	}

	if err := <-errCh; err != nil && err != io.EOF {
		t.Errorf("Server error: %v", err)
	}

	metrics := dialer.Metrics()
	if metrics.TotalSuccesses != 1 {
		t.Errorf("Expected 1 success metric, got %d", metrics.TotalSuccesses)
	}
}

func TestDNSQNameFramingAndReassembly(t *testing.T) {
	domainSuffix := "tunnel.example.com"
	clientID := "c99"
	offset := uint64(1005)

	payload := []byte("Censorship resistance via asymmetric DNS query transport")

	// Split payload into 2 fragments
	mid := len(payload) / 2
	chunk0 := payload[:mid]
	chunk1 := payload[mid:]

	qname0 := EncodeDNSQName(domainSuffix, clientID, offset, 0, 2, chunk0)
	qname1 := EncodeDNSQName(domainSuffix, clientID, offset, 1, 2, chunk1)

	// Decode both
	cID0, off0, p0, t0, data0, err0 := DecodeDNSQName(qname0, domainSuffix)
	if err0 != nil {
		t.Fatalf("Decode fragment 0 failed: %v", err0)
	}
	if cID0 != clientID || off0 != offset || p0 != 0 || t0 != 2 || !bytes.Equal(data0, chunk0) {
		t.Errorf("Decoded fragment 0 mismatch: %s, %d, %d, %d", cID0, off0, p0, t0)
	}

	cID1, off1, p1, t1, data1, err1 := DecodeDNSQName(qname1, domainSuffix)
	if err1 != nil {
		t.Fatalf("Decode fragment 1 failed: %v", err1)
	}
	if cID1 != clientID || off1 != offset || p1 != 1 || t1 != 2 || !bytes.Equal(data1, chunk1) {
		t.Errorf("Decoded fragment 1 mismatch")
	}

	// Test Reassembler out-of-order arrival (fragment 1 before fragment 0)
	reassembler := NewDNSReassembler(2 * time.Second)

	fullData, complete := reassembler.PushFragment(clientID, offset, 1, 2, chunk1)
	if complete || fullData != nil {
		t.Errorf("Expected incomplete on first fragment")
	}

	fullData, complete = reassembler.PushFragment(clientID, offset, 0, 2, chunk0)
	if !complete {
		t.Fatalf("Expected complete on second fragment")
	}

	if !bytes.Equal(fullData, payload) {
		t.Errorf("Reassembled payload mismatch: got %q, want %q", fullData, payload)
	}
}

func TestAsymmetricSpoofQualificationGating(t *testing.T) {
	cfg := AsymmetricSpoofConfig{
		TargetAddr:      "127.0.0.1:29999",
		SpoofIP:         "198.51.100.1",
		AllowUnverified: false, // Strict qualification required
	}

	dialer := NewAsymmetricSpoofDialer(cfg)
	caps := dialer.Capabilities()
	if caps.PrerequisitesMet {
		t.Errorf("Expected PrerequisitesMet=false initially")
	}

	// Dialing must fail with ErrBCP38Enforced
	_, err := dialer.Dial(context.Background(), "127.0.0.1:29999")
	if !errors.Is(err, ErrBCP38Enforced) {
		t.Errorf("Expected ErrBCP38Enforced, got %v", err)
	}
}

// mockFailingStrategy is a test strategy that always fails dial
type mockFailingStrategy struct {
	mode TransportMode
}

func (m *mockFailingStrategy) Dial(ctx context.Context, addr string) (Session, error) {
	return nil, errors.New("connection reset by peer")
}
func (m *mockFailingStrategy) Mode() TransportMode { return m.mode }
func (m *mockFailingStrategy) Capabilities() TransportCapabilities {
	return TransportCapabilities{
		Mode:             m.mode,
		PrerequisitesMet: true,
	}
}
func (m *mockFailingStrategy) CheckHealth(ctx context.Context, addr string) (time.Duration, error) {
	return 0, errors.New("health check timeout")
}
func (m *mockFailingStrategy) Metrics() HealthMetrics {
	return HealthMetrics{
		Mode:         m.mode,
		Available:    false,
		CircuitState: "open",
	}
}

func TestStrategySelectorResilienceAndFallback(t *testing.T) {
	psk := []byte("test-shared-secret-key-32bytes!!")

	// Listener for AEAD stream
	l, err := NewAEADStreamListener("127.0.0.1:0", psk)
	if err != nil {
		t.Fatalf("NewAEADStreamListener: %v", err)
	}
	defer l.Close()

	go func() {
		for {
			sess, err := l.Accept(context.Background())
			if err != nil {
				return
			}
			go func(s Session) {
				defer s.Close()
				strm, err := s.AcceptStream()
				if err != nil {
					return
				}
				defer strm.Close()
				io.Copy(strm, strm)
			}(sess)
		}
	}()

	failingStrat := &mockFailingStrategy{mode: ModeRawKCP}
	workingStrat := NewAEADStreamDialer(psk, 32)

	// Selector preferred failing mode first, with workingStrat as fallback
	selector := NewStrategySelector(SelectorConfig{
		Candidates:          []Strategy{failingStrat, workingStrat},
		PreferredMode:       ModeRawKCP,
		CircuitFailureLimit: 2,
		CircuitCooldown:     10 * time.Second,
	})

	// Dialing should attempt failingStrat, fail, and smoothly fall back to workingStrat
	sess, err := selector.Dial(context.Background(), l.Addr().String())
	if err != nil {
		t.Fatalf("Selector dial failed to fall back: %v", err)
	}
	defer sess.Close()

	if selector.Mode() != ModeAEADStream {
		t.Errorf("Expected active mode to switch to %s, got %s", ModeAEADStream, selector.Mode())
	}

	report := selector.StatusReport()
	if report["active_mode"] != string(ModeAEADStream) {
		t.Errorf("Expected active mode in report to be aead-stream, got %v", report["active_mode"])
	}
}

func TestStrategySelectorCircuitBreakerAndCooldown(t *testing.T) {
	fail1 := &mockFailingStrategy{mode: ModeRawKCP}
	fail2 := &mockFailingStrategy{mode: ModeAEADStream}

	selector := NewStrategySelector(SelectorConfig{
		Candidates:          []Strategy{fail1, fail2},
		PreferredMode:       ModeRawKCP,
		CircuitFailureLimit: 1,
		CircuitCooldown:     200 * time.Millisecond,
	})

	// 1. First dial should attempt both and fail with ErrNoEligibleStrategy
	_, err := selector.Dial(context.Background(), "127.0.0.1:9999")
	if !errors.Is(err, ErrNoEligibleStrategy) {
		t.Fatalf("Expected ErrNoEligibleStrategy, got %v", err)
	}

	// 2. Immediate second dial should reject both without dial attempts (both in cooldown)
	_, err2 := selector.Dial(context.Background(), "127.0.0.1:9999")
	if !errors.Is(err2, ErrNoEligibleStrategy) {
		t.Fatalf("Expected ErrNoEligibleStrategy during cooldown, got %v", err2)
	}

	report := selector.StatusReport()
	candidates, ok := report["candidates"].([]map[string]interface{})
	if !ok || len(candidates) != 2 {
		t.Fatalf("Expected 2 candidates in status report, got %v", report["candidates"])
	}

	// 3. Wait for cooldown to expire
	time.Sleep(250 * time.Millisecond)

	// After cooldown, isEligible should become true again
	if !selector.isEligible(fail1) {
		t.Errorf("Expected fail1 to become eligible after cooldown")
	}
}
