package transport

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"github.com/arashmh13/paqet-ngv2/internal/ng/crypto"
	"github.com/arashmh13/paqet-ngv2/internal/ng/replay"
)

const (
	SaltSize       = 16
	MaxChunkSize   = 16384
	ChunkHeaderLen = 2 // 2-byte uint16 length
)

var (
	ErrHandshakeFailed = errors.New("aead-stream: handshake authentication failed")
	ErrChunkTooLarge   = errors.New("aead-stream: chunk exceeds maximum allowed size")
)

// secureConn wraps a net.Conn with directional AEAD encryption.
type secureConn struct {
	net.Conn
	enc      cipher.AEAD
	dec      cipher.AEAD
	encNonce uint64
	decNonce uint64
	readBuf  []byte
	writeMu  sync.Mutex
	readMu   sync.Mutex
}

func newSecureConn(raw net.Conn, encKey, decKey []byte) (*secureConn, error) {
	enc, err := crypto.NewAEAD(encKey)
	if err != nil {
		return nil, err
	}
	dec, err := crypto.NewAEAD(decKey)
	if err != nil {
		return nil, err
	}
	return &secureConn{
		Conn: raw,
		enc:  enc,
		dec:  dec,
	}, nil
}

func (s *secureConn) makeNonce(counter uint64) [crypto.NonceSize]byte {
	var n [crypto.NonceSize]byte
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

func (s *secureConn) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	totalSent := 0
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > MaxChunkSize {
			chunkSize = MaxChunkSize
		}
		chunk := p[:chunkSize]
		p = p[chunkSize:]

		nonce := s.makeNonce(s.encNonce)
		s.encNonce++

		frame := make([]byte, ChunkHeaderLen, ChunkHeaderLen+chunkSize+crypto.TagSize)
		ciphertext := s.enc.Seal(frame, nonce[:], chunk, nil)
		frameLen := uint16(len(ciphertext) - ChunkHeaderLen)
		binary.BigEndian.PutUint16(ciphertext[:ChunkHeaderLen], frameLen)

		if _, err := s.Conn.Write(ciphertext); err != nil {
			return totalSent, err
		}
		totalSent += chunkSize
	}
	return totalSent, nil
}

func (s *secureConn) Read(b []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	if len(s.readBuf) > 0 {
		n := copy(b, s.readBuf)
		s.readBuf = s.readBuf[n:]
		return n, nil
	}

	var hdr [ChunkHeaderLen]byte
	if _, err := io.ReadFull(s.Conn, hdr[:]); err != nil {
		return 0, err
	}

	frameLen := int(binary.BigEndian.Uint16(hdr[:]))
	if frameLen > MaxChunkSize+crypto.TagSize+512 {
		return 0, ErrChunkTooLarge
	}

	ciphertext := make([]byte, frameLen)
	if _, err := io.ReadFull(s.Conn, ciphertext); err != nil {
		return 0, err
	}

	nonce := s.makeNonce(s.decNonce)
	s.decNonce++

	plaintext, err := s.dec.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("aead-stream: %w", crypto.ErrDecrypt)
	}

	n := copy(b, plaintext)
	if n < len(plaintext) {
		s.readBuf = append(s.readBuf[:0], plaintext[n:]...)
	}
	return n, nil
}

// AEADStreamDialer establishes secure client sessions.
type AEADStreamDialer struct {
	psk       []byte
	maxPad    int
	metrics   HealthMetrics
	metricsMu sync.RWMutex
}

func NewAEADStreamDialer(psk []byte, maxPad int) *AEADStreamDialer {
	return &AEADStreamDialer{
		psk:    psk,
		maxPad: maxPad,
		metrics: HealthMetrics{
			Mode:         ModeAEADStream,
			Available:    true,
			CircuitState: "closed",
		},
	}
}

func (d *AEADStreamDialer) Mode() TransportMode {
	return ModeAEADStream
}

func (d *AEADStreamDialer) Capabilities() TransportCapabilities {
	return TransportCapabilities{
		Mode:               ModeAEADStream,
		RequiresRoot:       false,
		SupportsNAT:        true,
		MaxThroughputMbps:  75.0,
		ExpectedLatencyMs:  105,
		IsAsymmetric:       false,
		PrerequisitesMet:   true,
		PrerequisiteNotice: "High-throughput userspace TCP stream",
	}
}

func (d *AEADStreamDialer) CheckHealth(ctx context.Context, addr string) (time.Duration, error) {
	start := time.Now()
	var netDialer net.Dialer
	conn, err := netDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		d.recordMetric(false, time.Since(start), err)
		return 0, err
	}
	_ = conn.Close()
	rtt := time.Since(start)
	d.recordMetric(true, rtt, nil)
	return rtt, nil
}

func (d *AEADStreamDialer) recordMetric(success bool, rtt time.Duration, err error) {
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

func (d *AEADStreamDialer) Metrics() HealthMetrics {
	d.metricsMu.RLock()
	defer d.metricsMu.RUnlock()
	return d.metrics
}

func (d *AEADStreamDialer) Dial(ctx context.Context, addr string) (Session, error) {
	start := time.Now()
	sess, err := d.dialInternal(ctx, addr)
	d.recordMetric(err == nil, time.Since(start), err)
	return sess, err
}

func (d *AEADStreamDialer) dialInternal(ctx context.Context, addr string) (Session, error) {
	var netDialer net.Dialer
	rawConn, err := netDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("aead-stream dial: %w", err)
	}

	// 1. Send random salt
	var salt [SaltSize]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		rawConn.Close()
		return nil, err
	}
	if _, err := rawConn.Write(salt[:]); err != nil {
		rawConn.Close()
		return nil, err
	}

	// 2. Derive directional keys
	c2sKey, s2cKey, err := crypto.DeriveKeys(d.psk, salt[:])
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	secConn, err := newSecureConn(rawConn, c2sKey, s2cKey)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	// 3. Send initial authenticated handshake frame with timestamp and random padding
	padLen := 0
	if d.maxPad > 0 {
		var pb [1]byte
		_, _ = rand.Read(pb[:])
		padLen = int(pb[0]) % d.maxPad
	}

	initFrame := make([]byte, 4+2+padLen)
	binary.BigEndian.PutUint32(initFrame[:4], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint16(initFrame[4:6], uint16(padLen))
	if padLen > 0 {
		_, _ = rand.Read(initFrame[6:])
	}

	if _, err := secConn.Write(initFrame); err != nil {
		secConn.Close()
		return nil, fmt.Errorf("aead-stream: failed to send handshake: %w", err)
	}

	// 4. Initialize smux multiplexer
	smuxCfg := smux.DefaultConfig()
	smuxCfg.Version = 2
	smuxCfg.MaxReceiveBuffer = 16 * 1024 * 1024
	smuxCfg.MaxStreamBuffer = 2 * 1024 * 1024
	sess, err := smux.Client(secConn, smuxCfg)
	if err != nil {
		secConn.Close()
		return nil, fmt.Errorf("aead-stream: smux client init: %w", err)
	}

	return &smuxSessionWrapper{sess: sess, underlying: secConn, remote: rawConn.RemoteAddr()}, nil
}

// AEADStreamListener accepts and authenticates inbound sessions.
type AEADStreamListener struct {
	listener net.Listener
	psk      []byte
	filter   *replay.Filter
}

func NewAEADStreamListener(addr string, psk []byte) (*AEADStreamListener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &AEADStreamListener{
		listener: l,
		psk:      psk,
		filter:   replay.NewFilter(30 * time.Second),
	}, nil
}

func (l *AEADStreamListener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *AEADStreamListener) Close() error {
	return l.listener.Close()
}

func (l *AEADStreamListener) Accept(ctx context.Context) (Session, error) {
	for {
		rawConn, err := l.listener.Accept()
		if err != nil {
			return nil, err
		}

		// Perform handshake with strict timeout (3 seconds)
		rawConn.SetDeadline(time.Now().Add(3 * time.Second))

		var lead [3]byte
		if _, err := io.ReadFull(rawConn, lead[:]); err != nil {
			rawConn.Close()
			continue
		}

		var salt [SaltSize]byte
		if lead[0] == 0x16 && lead[1] == 0x03 {
			// Decoy TLS ClientHello preamble detected: consume record
			var lenBytes [2]byte
			if _, err := io.ReadFull(rawConn, lenBytes[:]); err != nil {
				rawConn.Close()
				continue
			}
			recLen := int(binary.BigEndian.Uint16(lenBytes[:]))
			if recLen > 4096 {
				rawConn.Close()
				continue
			}
			decoyBuf := make([]byte, recLen)
			if _, err := io.ReadFull(rawConn, decoyBuf); err != nil {
				rawConn.Close()
				continue
			}
			// Read the real AEAD salt
			if _, err := io.ReadFull(rawConn, salt[:]); err != nil {
				rawConn.Close()
				continue
			}
		} else {
			// Standard AEAD stream: lead contains first 3 bytes of salt
			copy(salt[:3], lead[:])
			if _, err := io.ReadFull(rawConn, salt[3:]); err != nil {
				rawConn.Close()
				continue
			}
		}

		c2sKey, s2cKey, err := crypto.DeriveKeys(l.psk, salt[:])
		if err != nil {
			rawConn.Close()
			continue
		}

		// Server writes using s2cKey and reads using c2sKey
		secConn, err := newSecureConn(rawConn, s2cKey, c2sKey)
		if err != nil {
			rawConn.Close()
			continue
		}

		// Read and validate initial handshake frame
		initFrame := make([]byte, 512)
		n, err := secConn.Read(initFrame)
		if err != nil || n < 6 {
			// Prober or invalid authentication: terminate immediately
			rawConn.Close()
			continue
		}

		packetUnix := binary.BigEndian.Uint32(initFrame[:4])
		if err := l.filter.CheckTimestamp(packetUnix, time.Now()); err != nil {
			// Stale timestamp or replay: terminate immediately
			rawConn.Close()
			continue
		}

		rawConn.SetDeadline(time.Time{}) // Clear handshake deadline
		if tcp, ok := rawConn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
		}

		smuxCfg := smux.DefaultConfig()
		smuxCfg.Version = 2
		smuxCfg.MaxReceiveBuffer = 16 * 1024 * 1024
		smuxCfg.MaxStreamBuffer = 2 * 1024 * 1024
		sess, err := smux.Server(secConn, smuxCfg)
		if err != nil {
			secConn.Close()
			continue
		}

		return &smuxSessionWrapper{sess: sess, underlying: secConn, remote: rawConn.RemoteAddr()}, nil
	}
}
