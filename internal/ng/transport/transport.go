package transport

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/xtaci/smux"
)

// TransportMode defines the selectable transport strategy.
type TransportMode string

const (
	ModeRawKCP          TransportMode = "raw-kcp"
	ModeAEADStream      TransportMode = "aead-stream"
	ModeSNIAssisted     TransportMode = "sni-assisted"
	ModeTLSStream       TransportMode = "tls-stream"
	ModeAsymmetricSpoof TransportMode = "asymmetric-spoof"
	ModeDNSAsymmetric   TransportMode = "dns-asymmetric"
	ModeAuto            TransportMode = "auto"
)

// TransportCapabilities describes the operational requirements of a transport.
type TransportCapabilities struct {
	Mode               TransportMode `json:"mode"`
	RequiresRoot       bool          `json:"requires_root"`
	SupportsNAT        bool          `json:"supports_nat"`
	MaxThroughputMbps  float64       `json:"max_throughput_mbps"`
	ExpectedLatencyMs  int           `json:"expected_latency_ms"`
	IsAsymmetric       bool          `json:"is_asymmetric"`
	PrerequisitesMet   bool          `json:"prerequisites_met"`
	PrerequisiteNotice string        `json:"prerequisite_notice,omitempty"`
}

// HealthMetrics reports live telemetry for a transport strategy.
type HealthMetrics struct {
	Mode            TransportMode `json:"mode"`
	Available       bool          `json:"available"`
	LatencyEMA      time.Duration `json:"latency_ema"`
	SuccessRate     float64       `json:"success_rate"`
	TotalAttempts   uint64        `json:"total_attempts"`
	TotalSuccesses  uint64        `json:"total_successes"`
	FailureStreak   int           `json:"failure_streak"`
	CircuitState    string        `json:"circuit_state"` // "closed", "open", "half-open"
	LastAttemptTime time.Time     `json:"last_attempt_time"`
	LastSuccessTime time.Time     `json:"last_success_time"`
	LastErrorReason string        `json:"last_error_reason,omitempty"`
}

// Session represents an authenticated multiplexed transport session.
type Session interface {
	io.Closer
	OpenStream() (net.Conn, error)
	AcceptStream() (net.Conn, error)
	IsClosed() bool
	RemoteAddr() net.Addr
}

// smuxSessionWrapper wraps an *smux.Session into Session.
type smuxSessionWrapper struct {
	sess       *smux.Session
	underlying io.Closer
	remote     net.Addr
}

func (s *smuxSessionWrapper) OpenStream() (net.Conn, error) {
	strm, err := s.sess.OpenStream()
	if err != nil {
		return nil, err
	}
	return &streamConn{Stream: strm, remote: s.remote}, nil
}

func (s *smuxSessionWrapper) AcceptStream() (net.Conn, error) {
	strm, err := s.sess.AcceptStream()
	if err != nil {
		return nil, err
	}
	return &streamConn{Stream: strm, remote: s.remote}, nil
}

func (s *smuxSessionWrapper) Close() error {
	var err1, err2 error
	if s.sess != nil {
		err1 = s.sess.Close()
	}
	if s.underlying != nil {
		err2 = s.underlying.Close()
	}
	if err1 != nil {
		return err1
	}
	return err2
}

func (s *smuxSessionWrapper) IsClosed() bool {
	return s.sess.IsClosed()
}

func (s *smuxSessionWrapper) RemoteAddr() net.Addr {
	return s.remote
}

// streamConn adapts an smux.Stream to a full net.Conn.
type streamConn struct {
	*smux.Stream
	remote net.Addr
}

func (c *streamConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *streamConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// Dialer defines the interface to establish an outgoing transport connection.
type Dialer interface {
	Dial(ctx context.Context, addr string) (Session, error)
}

// Listener defines the interface to accept inbound transport connections.
type Listener interface {
	io.Closer
	Accept(ctx context.Context) (Session, error)
	Addr() net.Addr
}

// Strategy defines an independently testable, instrumented transport strategy.
type Strategy interface {
	Dialer
	Mode() TransportMode
	Capabilities() TransportCapabilities
	CheckHealth(ctx context.Context, addr string) (time.Duration, error)
	Metrics() HealthMetrics
}
