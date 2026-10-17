package transport

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func TestTLSDialerAndListenerStrategy(t *testing.T) {
	cert, err := GenerateSelfSignedCertificate("cloudflare.com")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertificate failed: %v", err)
	}

	listener, err := NewTLSListener("127.0.0.1:0", cert, []string{"h2", "http/1.1"})
	if err != nil {
		t.Fatalf("NewTLSListener failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	stopCh := make(chan struct{})
	defer close(stopCh)

	go func() {
		for {
			select {
			case <-stopCh:
				return
			default:
			}
			sess, err := listener.Accept(context.Background())
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
				buf := make([]byte, 1024)
				n, _ := strm.Read(buf)
				if n > 0 {
					_, _ = strm.Write(buf[:n])
				}
			}(sess)
		}
	}()

	dialer := NewTLSDialer(TLSOptions{
		ServerName:         "cloudflare.com",
		InsecureSkipVerify: true,
	})

	caps := dialer.Capabilities()
	if caps.Mode != ModeTLSStream || !caps.PrerequisitesMet {
		t.Errorf("Unexpected capabilities: %+v", caps)
	}

	// Health check
	rtt, err := dialer.CheckHealth(context.Background(), addr)
	if err != nil {
		t.Fatalf("CheckHealth failed: %v", err)
	}
	if rtt <= 0 {
		t.Errorf("Expected positive RTT, got %v", rtt)
	}

	sess, err := dialer.Dial(context.Background(), addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer sess.Close()

	strm, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}
	defer strm.Close()

	payload := []byte("Testing Strategy TLSDialer")
	if _, err := strm.Write(payload); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(strm, buf); err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}

	if !bytes.Equal(buf, payload) {
		t.Errorf("Payload mismatch: got %q, want %q", buf, payload)
	}

	metrics := dialer.Metrics()
	if metrics.TotalSuccesses == 0 {
		t.Errorf("Expected successes > 0, got %d", metrics.TotalSuccesses)
	}
}
