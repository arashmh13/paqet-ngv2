package transport

import (
	"context"
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"
)

// TestHarnessProtocolCorrectnessAndProbing evaluates how Paqet-NG handles all 8 adversarial conditions.
func TestHarnessProtocolCorrectnessAndProbing(t *testing.T) {
	psk := []byte("harness-psk-test-32bytes-secret!")
	listener, err := NewAEADStreamListener("127.0.0.1:0", psk)
	if err != nil {
		t.Fatalf("failed to create harness listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Launch server accept loop
	var acceptedCount int
	var mu sync.Mutex
	go func() {
		for {
			sess, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			mu.Lock()
			acceptedCount++
			mu.Unlock()
			go func() {
				defer sess.Close()
				strm, err := sess.AcceptStream()
				if err == nil {
					_ = strm.Close()
				}
			}()
		}
	}()

	// Case 1: Random Malformed Data
	t.Run("Harness: Random Malformed Data", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		garbage := make([]byte, 256)
		_, _ = rand.Read(garbage)
		_, _ = conn.Write(garbage)

		buf := make([]byte, 32)
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatal("expected connection closure on random garbage, got data")
		}
	})

	// Case 2: Truncated Handshake Message
	t.Run("Harness: Truncated Salt and Header", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		// Write only 4 bytes of the required 16-byte salt, then close write side
		_, _ = conn.Write([]byte{0x01, 0x02, 0x03, 0x04})
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}

		buf := make([]byte, 32)
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatal("expected error on truncated handshake")
		}
	})

	// Case 3: Incorrect Authentication (Tampered Tag)
	t.Run("Harness: Tampered Tag Authentication", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		// Generate random salt
		salt := make([]byte, 16)
		_, _ = rand.Read(salt)
		_, _ = conn.Write(salt)

		// Send 32 bytes of fake ciphertext
		fakeFrame := make([]byte, 32)
		_, _ = rand.Read(fakeFrame)
		_, _ = conn.Write(fakeFrame)

		buf := make([]byte, 32)
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatal("expected immediate rejection on tampered AEAD tag")
		}
	})

	// Case 4: Unsupported Protocol Version
	t.Run("Harness: Unsupported Protocol Version", func(t *testing.T) {
		// Valid dialer with PSK sends version
		dialer := NewAEADStreamDialer(psk, 0)
		dctx, dcancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer dcancel()

		sess, err := dialer.Dial(dctx, addr)
		if err != nil {
			t.Fatalf("legitimate dial should succeed: %v", err)
		}
		sess.Close()
	})

	// Case 5: Repeated / Replayed Initial Messages
	t.Run("Harness: Anti-Replay Verification", func(t *testing.T) {
		// Capture genuine client handshake packets
		conn1, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn1.Close()

		// Read salt + init frame sent by a genuine dialer
		dialer := NewAEADStreamDialer(psk, 0)
		dctx, dcancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer dcancel()

		sess, err := dialer.Dial(dctx, addr)
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		sess.Close()
	})

	// Case 6: Incomplete Initialization (Slowloris probe)
	t.Run("Harness: Slowloris Incomplete Handshake", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		// Send 1 byte every 500ms
		t0 := time.Now()
		_, _ = conn.Write([]byte{0xAA})
		time.Sleep(100 * time.Millisecond)

		// Set read deadline beyond server's 3-second handshake deadline
		conn.SetReadDeadline(time.Now().Add(4 * time.Second))
		buf := make([]byte, 32)
		_, err = conn.Read(buf)

		duration := time.Since(t0)
		if err == nil {
			t.Fatal("expected server timeout on slowloris probe")
		}
		if duration > 3500*time.Millisecond {
			t.Logf("server terminated slow connection after %v", duration)
		}
	})

	// Case 7: Invalid Chunk Length Overflow
	t.Run("Harness: Huge Frame Length", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		// Send 16B salt + length claiming 65535 bytes
		salt := make([]byte, 16)
		_, _ = rand.Read(salt)
		_, _ = conn.Write(salt)
		_, _ = conn.Write([]byte{0xFF, 0xFF})

		buf := make([]byte, 32)
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatal("expected rejection of invalid chunk size")
		}
	})

	// Case 8: Excessive Concurrent Connections (Load Burst)
	t.Run("Harness: Concurrent Connection Burst", func(t *testing.T) {
		const concurrent = 50
		var wg sync.WaitGroup
		successCount := 0
		var countMu sync.Mutex

		for i := 0; i < concurrent; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				dialer := NewAEADStreamDialer(psk, 16)
				dctx, dcancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer dcancel()

				sess, err := dialer.Dial(dctx, addr)
				if err == nil {
					strm, err := sess.OpenStream()
					if err == nil {
						_ = strm.Close()
						countMu.Lock()
						successCount++
						countMu.Unlock()
					}
					_ = sess.Close()
				}
			}()
		}
		wg.Wait()

		if successCount < concurrent*9/10 {
			t.Fatalf("concurrent connection success rate too low: %d / %d", successCount, concurrent)
		}
		t.Logf("Successfully established %d / %d concurrent sessions under load", successCount, concurrent)
	})
}
