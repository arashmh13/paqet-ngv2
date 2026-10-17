package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

// GenerateSelfSignedCertificate creates a valid ECDSA P-256 certificate for server TLS.
func GenerateSelfSignedCertificate(commonName string) (tls.Certificate, error) {
	if commonName == "" {
		commonName = "paqet.local"
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate ecdsa key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Paqet-NG Secure Network"},
			CommonName:   commonName,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", commonName},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("203.0.113.7")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal ec key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// GenerateCAAndSignedCert creates an in-memory CA and a child certificate signed by that CA.
func GenerateCAAndSignedCert(commonName string) (caPEM, certPEM, keyPEM []byte, err error) {
	if commonName == "" {
		commonName = "paqet.local"
	}

	// 1. Root CA
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTemplate := x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			Organization: []string{"Paqet-NG Test CA"},
			CommonName:   "Paqet Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		return nil, nil, nil, err
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// 2. Server Cert
	serverPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	sSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	serverTemplate := x509.Certificate{
		SerialNumber: sSerial,
		Subject: pkix.Name{
			Organization: []string{"Paqet-NG Secure Endpoint"},
			CommonName:   commonName,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", commonName},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, &serverPriv.PublicKey, caPriv)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})

	b, _ := x509.MarshalECPrivateKey(serverPriv)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})

	return caPEM, certPEM, keyPEM, nil
}

// TLSOptions configures the genuine TLS outer transport.
type TLSOptions struct {
	ServerName         string
	InsecureSkipVerify bool
	CertFile           string
	KeyFile            string
	CAFile             string
	MinVersion         uint16
	ALPN               []string
}

// TLSDialer establishes authentic TLS outer transport sessions.
type TLSDialer struct {
	opts      TLSOptions
	metrics   HealthMetrics
	metricsMu sync.RWMutex
}

func NewTLSDialer(opts TLSOptions) *TLSDialer {
	if opts.MinVersion == 0 {
		opts.MinVersion = tls.VersionTLS13
	}
	if len(opts.ALPN) == 0 {
		opts.ALPN = []string{"h2", "http/1.1"}
	}
	return &TLSDialer{
		opts: opts,
		metrics: HealthMetrics{
			Mode:         ModeTLSStream,
			Available:    true,
			CircuitState: "closed",
		},
	}
}

func (d *TLSDialer) Mode() TransportMode {
	return ModeTLSStream
}

func (d *TLSDialer) Capabilities() TransportCapabilities {
	return TransportCapabilities{
		Mode:               ModeTLSStream,
		RequiresRoot:       false,
		SupportsNAT:        true,
		MaxThroughputMbps:  75.0,
		ExpectedLatencyMs:  90,
		IsAsymmetric:       false,
		PrerequisitesMet:   true,
		PrerequisiteNotice: "Genuine RFC 8446 TLS 1.3 outer transport",
	}
}

func (d *TLSDialer) Dial(ctx context.Context, addr string) (Session, error) {
	start := time.Now()
	sess, err := d.dialInternal(ctx, addr)
	d.recordMetric(err == nil, time.Since(start), err)
	return sess, err
}

func (d *TLSDialer) dialInternal(ctx context.Context, addr string) (Session, error) {
	netDialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := netDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tls dial tcp: %w", err)
	}
	if tcp, ok := rawConn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	serverName := d.opts.ServerName
	if serverName == "" {
		host, _, _ := net.SplitHostPort(addr)
		serverName = host
	}

	var rootCAs *x509.CertPool
	if d.opts.CAFile != "" {
		caData, err := os.ReadFile(d.opts.CAFile)
		if err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("tls ca file read %s: %w", d.opts.CAFile, err)
		}
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(caData) {
			rawConn.Close()
			return nil, fmt.Errorf("tls ca file parse failed: %s", d.opts.CAFile)
		}
	}

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: d.opts.InsecureSkipVerify,
		RootCAs:            rootCAs,
		MinVersion:         d.opts.MinVersion,
		NextProtos:         d.opts.ALPN,
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("tls client handshake: %w", err)
	}

	smuxCfg := smux.DefaultConfig()
	smuxCfg.Version = 2
	smuxCfg.MaxReceiveBuffer = 16 * 1024 * 1024
	smuxCfg.MaxStreamBuffer = 2 * 1024 * 1024

	sess, err := smux.Client(tlsConn, smuxCfg)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("tls smux client: %w", err)
	}

	return &smuxSessionWrapper{sess: sess, underlying: tlsConn, remote: rawConn.RemoteAddr()}, nil
}

func (d *TLSDialer) CheckHealth(ctx context.Context, addr string) (time.Duration, error) {
	start := time.Now()
	netDialer := &net.Dialer{Timeout: 5 * time.Second}
	rawConn, err := netDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		d.recordMetric(false, time.Since(start), err)
		return 0, err
	}
	defer rawConn.Close()

	serverName := d.opts.ServerName
	if serverName == "" {
		host, _, _ := net.SplitHostPort(addr)
		serverName = host
	}

	var rootCAs *x509.CertPool
	if d.opts.CAFile != "" {
		if caData, err := os.ReadFile(d.opts.CAFile); err == nil {
			rootCAs = x509.NewCertPool()
			rootCAs.AppendCertsFromPEM(caData)
		}
	}

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: d.opts.InsecureSkipVerify,
		RootCAs:            rootCAs,
		MinVersion:         d.opts.MinVersion,
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		d.recordMetric(false, time.Since(start), err)
		return 0, err
	}
	_ = tlsConn.Close()

	rtt := time.Since(start)
	d.recordMetric(true, rtt, nil)
	return rtt, nil
}

func (d *TLSDialer) recordMetric(success bool, rtt time.Duration, err error) {
	d.metricsMu.Lock()
	defer d.metricsMu.Unlock()

	d.metrics.TotalAttempts++
	d.metrics.LastAttemptTime = time.Now()

	if success {
		d.metrics.TotalSuccesses++
		d.metrics.FailureStreak = 0
		d.metrics.CircuitState = "closed"
		d.metrics.Available = true
		d.metrics.LastSuccessTime = time.Now()
		if d.metrics.LatencyEMA == 0 {
			d.metrics.LatencyEMA = rtt
		} else {
			d.metrics.LatencyEMA = time.Duration(0.8*float64(d.metrics.LatencyEMA) + 0.2*float64(rtt))
		}
	} else {
		d.metrics.FailureStreak++
		if err != nil {
			d.metrics.LastErrorReason = err.Error()
		}
		if d.metrics.FailureStreak >= 3 {
			d.metrics.CircuitState = "open"
			d.metrics.Available = false
		}
	}

	if d.metrics.TotalAttempts > 0 {
		d.metrics.SuccessRate = float64(d.metrics.TotalSuccesses) / float64(d.metrics.TotalAttempts)
	}
}

func (d *TLSDialer) Metrics() HealthMetrics {
	d.metricsMu.RLock()
	defer d.metricsMu.RUnlock()
	return d.metrics
}

// TLSListener accepts inbound genuine TLS connections and wraps them in smux.
type TLSListener struct {
	listener  net.Listener
	tlsConfig *tls.Config
}

func NewTLSListener(addr string, cert tls.Certificate, alpn []string) (*TLSListener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tls listen on %s: %w", addr, err)
	}

	if len(alpn) == 0 {
		alpn = []string{"h2", "http/1.1"}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   alpn,
	}

	return &TLSListener{
		listener:  l,
		tlsConfig: tlsConfig,
	}, nil
}

func (l *TLSListener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *TLSListener) Close() error {
	return l.listener.Close()
}

func (l *TLSListener) Accept(ctx context.Context) (Session, error) {
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
		if err := tlsConn.HandshakeContext(ctx); err != nil {
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

		return &smuxSessionWrapper{sess: sess, underlying: tlsConn, remote: rawConn.RemoteAddr()}, nil
	}
}
