package stream

import (
	"bytes"
	"io"
	"testing"

	"github.com/arashmh13/paqet-ngv2/internal/conf"
)

func TestStreamTransportEndToEnd(t *testing.T) {
	obfsCfg := &conf.Obfs{
		Key:    "test-secret-key-32bytes-stream!!",
		MaxPad: 32,
	}

	listener, err := Listen("127.0.0.1:0", obfsCfg)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			strm, err := conn.AcceptStrm()
			if err != nil {
				return
			}
			go func() {
				defer strm.Close()
				buf := make([]byte, 1024)
				n, err := strm.Read(buf)
				if err != nil && err != io.EOF {
					return
				}
				if n > 0 {
					_, _ = strm.Write(buf[:n])
				}
			}()
		}
	}()

	clientConn, err := Dial(addr, obfsCfg)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientConn.Close()

	// Test ping
	if err := clientConn.Ping(false); err != nil {
		t.Fatalf("ping failed: %v", err)
	}

	strm, err := clientConn.OpenStrm()
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}
	defer strm.Close()

	msg := []byte("Hello Stream Transport!")
	if _, err := strm.Write(msg); err != nil {
		t.Fatalf("failed to write data: %v", err)
	}

	reply := make([]byte, 1024)
	n, err := strm.Read(reply)
	if err != nil {
		t.Fatalf("failed to read reply: %v", err)
	}

	if !bytes.Equal(reply[:n], msg) {
		t.Fatalf("reply mismatch: got %s, want %s", string(reply[:n]), string(msg))
	}
}

func TestSNIAssistedTransportEndToEnd(t *testing.T) {
	obfsCfg := &conf.Obfs{
		Key:    "test-secret-key-32bytes-stream!!",
		MaxPad: 32,
	}
	sniCfg := &conf.SNI{
		Decoy:  "bank.ir",
		Preset: "chrome",
		Method: "fragment",
	}

	listener, err := Listen("127.0.0.1:0", obfsCfg)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		strm, err := conn.AcceptStrm()
		if err != nil {
			return
		}
		defer strm.Close()

		buf := make([]byte, 1024)
		n, err := strm.Read(buf)
		if err != nil && err != io.EOF {
			return
		}
		if n > 0 {
			_, _ = strm.Write(buf[:n])
		}
	}()

	clientConn, err := DialSNIAssisted(addr, obfsCfg, sniCfg)
	if err != nil {
		t.Fatalf("failed to dial sni-assisted: %v", err)
	}
	defer clientConn.Close()

	strm, err := clientConn.OpenStrm()
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}
	defer strm.Close()

	msg := []byte("Hello SNI-Assisted Decoy Transport!")
	if _, err := strm.Write(msg); err != nil {
		t.Fatalf("failed to write data: %v", err)
	}

	reply := make([]byte, 1024)
	n, err := strm.Read(reply)
	if err != nil {
		t.Fatalf("failed to read reply: %v", err)
	}

	if !bytes.Equal(reply[:n], msg) {
		t.Fatalf("reply mismatch: got %s, want %s", string(reply[:n]), string(msg))
	}
}
