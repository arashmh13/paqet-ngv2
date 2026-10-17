package stream

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/xtaci/smux"

	"github.com/arashmh13/paqet-ngv2/internal/conf"
	"github.com/arashmh13/paqet-ngv2/internal/ng/transport"
	"github.com/arashmh13/paqet-ngv2/internal/tnet"
)

// DialTLS establishes an authentic TLS 1.3 outer connection and wraps it into tnet.Conn.
func DialTLS(addr string, obfsCfg *conf.Obfs, tlsCfg *conf.TLS) (tnet.Conn, error) {
	netDialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := netDialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tls stream: dial %s failed: %w", addr, err)
	}
	if tcp, ok := rawConn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	serverName := ""
	insecureSkipVerify := true
	alpn := []string{"h2", "http/1.1"}
	var rootCAs *x509.CertPool

	if tlsCfg != nil {
		serverName = tlsCfg.ServerName
		insecureSkipVerify = tlsCfg.InsecureSkipVerify
		if len(tlsCfg.ALPN) > 0 {
			alpn = tlsCfg.ALPN
		}
		if tlsCfg.CAFile != "" {
			caData, err := os.ReadFile(tlsCfg.CAFile)
			if err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("tls stream: read ca file %s: %w", tlsCfg.CAFile, err)
			}
			rootCAs = x509.NewCertPool()
			if !rootCAs.AppendCertsFromPEM(caData) {
				rawConn.Close()
				return nil, fmt.Errorf("tls stream: failed to parse ca pem in %s", tlsCfg.CAFile)
			}
		}
	}
	if serverName == "" {
		host, _, _ := net.SplitHostPort(addr)
		serverName = host
	}

	config := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: insecureSkipVerify,
		RootCAs:            rootCAs,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         alpn,
	}

	tlsConn := tls.Client(rawConn, config)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("tls stream: client handshake failed: %w", err)
	}

	smuxCfg := smux.DefaultConfig()
	smuxCfg.Version = 2
	smuxCfg.MaxReceiveBuffer = 16 * 1024 * 1024
	smuxCfg.MaxStreamBuffer = 2 * 1024 * 1024

	sess, err := smux.Client(tlsConn, smuxCfg)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("tls stream: smux client init: %w", err)
	}

	return &Conn{
		underlying: tlsConn,
		session:    sess,
		rawConn:    rawConn,
	}, nil
}

// DialTLSPinned establishes an authentic TLS 1.3 outer connection and validates that the remote peer
// presents a leaf certificate (or public key) matching expectedPin.
func DialTLSPinned(addr string, obfsCfg *conf.Obfs, tlsCfg *conf.TLS, expectedPin string, isPubKeyPin bool) (tnet.Conn, error) {
	conn, err := DialTLS(addr, obfsCfg, tlsCfg)
	if err != nil {
		return nil, err
	}

	streamConn, ok := conn.(*Conn)
	if !ok || streamConn.underlying == nil {
		_ = conn.Close()
		return nil, errors.New("tls stream: invalid underlying connection type")
	}

	tlsConn, ok := streamConn.underlying.(*tls.Conn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("tls stream: underlying connection is not *tls.Conn")
	}

	cs := tlsConn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		_ = conn.Close()
		return nil, errors.New("tls stream: peer presented no certificates")
	}
	leaf := cs.PeerCertificates[0]

	expectedDigest, err := transport.ParseSHA256Fingerprint(expectedPin)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tls stream: invalid expected pin %q: %w", expectedPin, err)
	}

	var actualDigest [32]byte
	if isPubKeyPin {
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("tls stream: marshal leaf public key: %w", err)
		}
		actualDigest = sha256.Sum256(pubKeyBytes)
	} else {
		actualDigest = sha256.Sum256(leaf.Raw)
	}

	if actualDigest != expectedDigest {
		_ = conn.Close()
		return nil, fmt.Errorf("tls stream: peer certificate pin mismatch: got SHA256:%x, want %s (fail-closed)",
			actualDigest, expectedPin)
	}

	return conn, nil
}

// TLSListener wraps net.Listener to accept genuine TLS connections into tnet.Conn.
type TLSListener struct {
	listener  net.Listener
	tlsConfig *tls.Config
}

// ListenTLS starts a genuine TLS server listener.
func ListenTLS(addr string, obfsCfg *conf.Obfs, tlsCfg *conf.TLS) (tnet.Listener, error) {
	var cert tls.Certificate
	var err error

	if tlsCfg != nil && tlsCfg.CertFile != "" && tlsCfg.KeyFile != "" {
		cert, err = tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls stream: failed to load keypair: %w", err)
		}
	} else {
		certName := "paqet.local"
		if tlsCfg != nil && tlsCfg.ServerName != "" {
			certName = tlsCfg.ServerName
		}
		cert, err = transport.GenerateSelfSignedCertificate(certName)
		if err != nil {
			return nil, fmt.Errorf("tls stream: generate cert failed: %w", err)
		}
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tls stream: failed to listen on %s: %w", addr, err)
	}

	alpn := []string{"h2", "http/1.1"}
	if tlsCfg != nil && len(tlsCfg.ALPN) > 0 {
		alpn = tlsCfg.ALPN
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   alpn,
	}

	return &TLSListener{
		listener:  l,
		tlsConfig: config,
	}, nil
}

func (l *TLSListener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *TLSListener) Close() error {
	return l.listener.Close()
}

func (l *TLSListener) SetClientTCPF(addr net.Addr, f []conf.TCPF)       {}
func (l *TLSListener) DeleteClientTCPF(addr net.Addr)                   {}
func (l *TLSListener) UpdateConfig(network conf.Network, kcp *conf.KCP) {}

func (l *TLSListener) Accept() (tnet.Conn, error) {
	for {
		rawConn, err := l.listener.Accept()
		if err != nil {
			return nil, err
		}
		if tcp, ok := rawConn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
		}

		rawConn.SetDeadline(time.Now().Add(5 * time.Second))
		tlsConn := tls.Server(rawConn, l.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			rawConn.Close()
			continue
		}
		rawConn.SetDeadline(time.Time{})

		smuxCfg := smux.DefaultConfig()
		smuxCfg.Version = 2
		smuxCfg.MaxReceiveBuffer = 16 * 1024 * 1024
		smuxCfg.MaxStreamBuffer = 2 * 1024 * 1024

		sess, err := smux.Server(tlsConn, smuxCfg)
		if err != nil {
			tlsConn.Close()
			continue
		}

		return &Conn{
			underlying: tlsConn,
			session:    sess,
			rawConn:    rawConn,
		}, nil
	}
}
