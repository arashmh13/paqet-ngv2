package transport

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestAEADStreamEndToEnd(t *testing.T) {
	psk := []byte("master-psk-test-key-1234567890123")

	listener, err := NewAEADStreamListener("127.0.0.1:0", psk)
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	// Server worker goroutine
	serverErrCh := make(chan error, 1)
	go func() {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			serverErrCh <- err
			return
		}
		defer sess.Close()

		strm, err := sess.AcceptStream()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer strm.Close()

		// Echo server
		buf := make([]byte, 1024)
		n, err := strm.Read(buf)
		if err != nil && err != io.EOF {
			serverErrCh <- err
			return
		}
		_, err = strm.Write(buf[:n])
		serverErrCh <- err
	}()

	// Client dialer
	dialer := NewAEADStreamDialer(psk, 64)
	sess, err := dialer.Dial(context.Background(), addr)
	if err != nil {
		t.Fatalf("client dial failed: %v", err)
	}
	defer sess.Close()

	strm, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}
	defer strm.Close()

	testMsg := []byte("Testing Paqet-NG AEAD stream high throughput!")
	if _, err := strm.Write(testMsg); err != nil {
		t.Fatalf("failed to write test data: %v", err)
	}

	reply := make([]byte, 1024)
	n, err := strm.Read(reply)
	if err != nil {
		t.Fatalf("failed to read reply: %v", err)
	}

	if !bytes.Equal(reply[:n], testMsg) {
		t.Fatalf("echo mismatch: got %s, want %s", string(reply[:n]), string(testMsg))
	}

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server encountered error: %v", err)
	}
}

func TestAEADStreamActiveProbingRejection(t *testing.T) {
	psk := []byte("master-psk-test-key-1234567890123")

	listener, err := NewAEADStreamListener("127.0.0.1:0", psk)
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	// Launch server accept loop in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			sess, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			sess.Close()
		}
	}()

	// Prober 1: Random data / HTTP GET scanner
	t.Run("HTTP Probe Must Be Rejected Immediately", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		defer conn.Close()

		t0 := time.Now()
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))

		buf := make([]byte, 128)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Read(buf)

		duration := time.Since(t0)
		// Server must close connection promptly with EOF/Reset, NOT hang as a tarpit
		if err == nil {
			t.Fatal("expected connection closure on HTTP probe, but received data")
		}
		if duration > 1500*time.Millisecond {
			t.Fatalf("server took too long to reject probe (%v), behaving like tarpit", duration)
		}
	})

	// Prober 2: Client with wrong pre-shared key
	t.Run("Wrong PSK Must Be Rejected", func(t *testing.T) {
		wrongDialer := NewAEADStreamDialer([]byte("wrong-password-keys-12345678901"), 0)
		dctx, dcancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer dcancel()

		sess, err := wrongDialer.Dial(dctx, addr)
		if err != nil {
			return // Expected failure
		}
		// If dial succeeded (because TCP connected and wrote init frame before server RST), stream open or read must fail immediately
		strm, err := sess.OpenStream()
		if err == nil {
			_, _ = strm.Write([]byte("hello"))
			buf := make([]byte, 10)
			strm.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			_, err = strm.Read(buf)
		}
		if err == nil {
			t.Fatal("session with wrong PSK should have failed")
		}
	})
}
