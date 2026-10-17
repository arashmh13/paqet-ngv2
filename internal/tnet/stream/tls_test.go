package stream

import (
	"bytes"
	"crypto/tls"
	"io"
	"os"
	"testing"

	"github.com/arashmh13/paqet-ngv2/internal/conf"
	"github.com/arashmh13/paqet-ngv2/internal/ng/transport"
)

func TestGenuineTLSOuterTransportEndToEnd(t *testing.T) {
	tlsCfg := &conf.TLS{
		Enabled:            true,
		ServerName:         "cloudflare.com",
		InsecureSkipVerify: true,
		MinVersion:         "1.3",
		ALPN:               []string{"h2", "http/1.1"},
	}

	listener, err := ListenTLS("127.0.0.1:0", nil, tlsCfg)
	if err != nil {
		t.Fatalf("ListenTLS failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		strm, err := conn.AcceptStrm()
		if err != nil {
			errCh <- err
			return
		}
		defer strm.Close()

		buf := make([]byte, 1024)
		n, err := strm.Read(buf)
		if err != nil && err != io.EOF {
			errCh <- err
			return
		}
		_, err = strm.Write(buf[:n])
		errCh <- err
	}()

	clientConn, err := DialTLS(addr, nil, tlsCfg)
	if err != nil {
		t.Fatalf("DialTLS failed: %v", err)
	}
	defer clientConn.Close()

	// Verify that the underlying connection is an authentic *tls.Conn
	tlsStreamConn, ok := clientConn.(*Conn)
	if !ok {
		t.Fatalf("clientConn is not *Conn")
	}
	realTLSConn, ok := tlsStreamConn.underlying.(*tls.Conn)
	if !ok {
		t.Fatalf("underlying is not *tls.Conn")
	}

	state := realTLSConn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		t.Errorf("Expected TLS 1.3 (0x%04x), got 0x%04x", tls.VersionTLS13, state.Version)
	}
	if !state.HandshakeComplete {
		t.Errorf("Expected HandshakeComplete=true")
	}
	if state.ServerName != "cloudflare.com" {
		t.Errorf("Expected ServerName 'cloudflare.com', got %q", state.ServerName)
	}

	// Test stream data exchange over genuine TLS
	strm, err := clientConn.OpenStrm()
	if err != nil {
		t.Fatalf("OpenStrm failed: %v", err)
	}
	defer strm.Close()

	msg := []byte("Testing Authentic TLS 1.3 Outer Transport in Paqet-NG")
	if _, err := strm.Write(msg); err != nil {
		t.Fatalf("strm.Write failed: %v", err)
	}

	reply := make([]byte, 1024)
	n, err := strm.Read(reply)
	if err != nil {
		t.Fatalf("strm.Read failed: %v", err)
	}

	if !bytes.Equal(reply[:n], msg) {
		t.Fatalf("reply mismatch: got %q, want %q", reply[:n], msg)
	}

	if err := <-errCh; err != nil && err != io.EOF {
		t.Fatalf("Server error: %v", err)
	}
}

func TestTLSRejectsUntrustedOrMismatchedCert(t *testing.T) {
	// 1. Generate custom CA and Server Cert for "paqet.local"
	caPEM, certPEM, keyPEM, err := transport.GenerateCAAndSignedCert("paqet.local")
	if err != nil {
		t.Fatalf("GenerateCAAndSignedCert failed: %v", err)
	}

	tmpDir := t.TempDir()
	caFile := tmpDir + "/ca.crt"
	certFile := tmpDir + "/server.crt"
	keyFile := tmpDir + "/server.key"

	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatalf("write caFile: %v", err)
	}
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("write certFile: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("write keyFile: %v", err)
	}

	serverTLSCfg := &conf.TLS{
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	listener, err := ListenTLS("127.0.0.1:0", nil, serverTLSCfg)
	if err != nil {
		t.Fatalf("ListenTLS failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	// Server accept loop
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	// Scenario A: Client with InsecureSkipVerify=false and NO CA file -> MUST FAIL (untrusted)
	untrustedClientCfg := &conf.TLS{
		ServerName:         "paqet.local",
		InsecureSkipVerify: false,
	}
	_, err = DialTLS(addr, nil, untrustedClientCfg)
	if err == nil {
		t.Errorf("Expected DialTLS to fail on untrusted certificate when InsecureSkipVerify=false")
	}

	// Scenario B: Client with CAFile but wrong ServerName -> MUST FAIL (hostname mismatch)
	mismatchedClientCfg := &conf.TLS{
		ServerName:         "wronghost.com",
		InsecureSkipVerify: false,
		CAFile:             caFile,
	}
	_, err = DialTLS(addr, nil, mismatchedClientCfg)
	if err == nil {
		t.Errorf("Expected DialTLS to fail on mismatched hostname")
	}

	// Scenario C: Client with CAFile and matching ServerName -> MUST SUCCEED (verified)
	validClientCfg := &conf.TLS{
		ServerName:         "paqet.local",
		InsecureSkipVerify: false,
		CAFile:             caFile,
	}
	validConn, err := DialTLS(addr, nil, validClientCfg)
	if err != nil {
		t.Fatalf("Expected DialTLS to succeed with matching CA and ServerName: %v", err)
	}
	validConn.Close()
}
