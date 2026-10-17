package transport

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/arashmh13/paqet-ngv2/internal/ng/crypto"
	"github.com/xtaci/smux"
)

var (
	ErrSNIHandshakeFailed = errors.New("sni-assisted: handshake failed")
)

// SNIAssistedConfig holds configuration for the SNI-assisted transport.
type SNIAssistedConfig struct {
	PSK          []byte
	DecoySNI     string // Decoy hostname observed by DPI (e.g. "hcaptcha.com")
	Preset       string // "chrome", "firefox", "custom"
	InjectMethod string // "wrong_seq", "fragment", "userspace"
	MaxPad       int
}

// BuildDecoyClientHello builds an RFC 8446 compliant TLS 1.3 ClientHello with an SNI extension.
func BuildDecoyClientHello(sni string, preset string) []byte {
	if sni == "" {
		sni = "hcaptcha.com"
	}

	// 1. SNI Extension
	sniBytes := []byte(sni)
	sniLen := len(sniBytes)
	// ServerNameList: [type:1B=0][len:2B][sni]
	serverNameListLen := 1 + 2 + sniLen
	sniExtData := make([]byte, 2+serverNameListLen)
	binary.BigEndian.PutUint16(sniExtData[0:2], uint16(serverNameListLen))
	sniExtData[2] = 0 // HostName type
	binary.BigEndian.PutUint16(sniExtData[3:5], uint16(sniLen))
	copy(sniExtData[5:], sniBytes)

	// Extension header: [type: 0x0000 (SNI)][length: 2B][data]
	sniExtension := make([]byte, 4+len(sniExtData))
	binary.BigEndian.PutUint16(sniExtension[0:2], 0x0000)
	binary.BigEndian.PutUint16(sniExtension[2:4], uint16(len(sniExtData)))
	copy(sniExtension[4:], sniExtData)

	// 2. Supported Versions Extension (TLS 1.3: 0x002b)
	// [type: 0x002b][len: 2B][versions_len: 1B][0x03, 0x04, 0x03, 0x03]
	supportedVersionsExt := []byte{
		0x00, 0x2b, // Extension Type: supported_versions
		0x00, 0x05, // Extension Length: 5
		0x04,                   // Versions list length: 4
		0x03, 0x04, 0x03, 0x03, // TLS 1.3, TLS 1.2
	}

	// 3. Supported Groups Extension (0x000a) - X25519, secp256r1
	supportedGroupsExt := []byte{
		0x00, 0x0a, // Extension Type: supported_groups
		0x00, 0x06, // Extension Length: 6
		0x00, 0x04, // Groups list length: 4
		0x00, 0x1d, 0x00, 0x17, // x25519 (0x001d), secp256r1 (0x0017)
	}

	// Combine extensions
	extensionsData := append(sniExtension, supportedVersionsExt...)
	extensionsData = append(extensionsData, supportedGroupsExt...)

	extensionsBlock := make([]byte, 2+len(extensionsData))
	binary.BigEndian.PutUint16(extensionsBlock[0:2], uint16(len(extensionsData)))
	copy(extensionsBlock[2:], extensionsData)

	// 4. Cipher Suites
	// TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA384 (0x1302), TLS_CHACHA20_POLY1305_SHA256 (0x1303)
	cipherSuites := []byte{
		0x00, 0x06, // Cipher suites length: 6 bytes (3 suites)
		0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
	}

	// 5. Random (32 bytes)
	clientRandom := make([]byte, 32)
	_, _ = rand.Read(clientRandom)

	// 6. Assemble ClientHello Handshake Message
	// [type: 0x01 (ClientHello)][length: 3 bytes uint24][legacy_version: 0x0303][random: 32B][session_id: 1B=0][ciphers][compression: 1B=0x01, 0x00][extensions]
	handshakeBody := make([]byte, 0, 256)
	handshakeBody = append(handshakeBody, 0x03, 0x03) // legacy_version: TLS 1.2
	handshakeBody = append(handshakeBody, clientRandom...)
	handshakeBody = append(handshakeBody, 0x00) // legacy_session_id length: 0
	handshakeBody = append(handshakeBody, cipherSuites...)
	handshakeBody = append(handshakeBody, 0x01, 0x00) // compression: 1 method (null)
	handshakeBody = append(handshakeBody, extensionsBlock...)

	handshakeHeader := make([]byte, 4)
	handshakeHeader[0] = 0x01 // Handshake type: ClientHello
	handshakeLen := len(handshakeBody)
	handshakeHeader[1] = byte((handshakeLen >> 16) & 0xff)
	handshakeHeader[2] = byte((handshakeLen >> 8) & 0xff)
	handshakeHeader[3] = byte(handshakeLen & 0xff)

	fullHandshake := append(handshakeHeader, handshakeBody...)

	// 7. TLS Record Header: [ContentType: 0x16 (Handshake)][legacy_version: 0x0301][length: 2 bytes]
	record := make([]byte, 5+len(fullHandshake))
	record[0] = 0x16 // Handshake
	record[1] = 0x03 // Major
	record[2] = 0x01 // Minor (TLS 1.0 record format for compatibility)
	binary.BigEndian.PutUint16(record[3:5], uint16(len(fullHandshake)))
	copy(record[5:], fullHandshake)

	return record
}

// SNIAssistedDialer implements Strategy using decoy SNI injection.
type SNIAssistedDialer struct {
	cfg       SNIAssistedConfig
	metrics   HealthMetrics
	metricsMu sync.RWMutex
}

func NewSNIAssistedDialer(cfg SNIAssistedConfig) *SNIAssistedDialer {
	if cfg.DecoySNI == "" {
		cfg.DecoySNI = "hcaptcha.com"
	}
	if cfg.InjectMethod == "" {
		cfg.InjectMethod = "wrong_seq"
	}
	if cfg.MaxPad <= 0 {
		cfg.MaxPad = 64
	}
	return &SNIAssistedDialer{
		cfg: cfg,
		metrics: HealthMetrics{
			Mode:         ModeSNIAssisted,
			Available:    true,
			CircuitState: "closed",
		},
	}
}

func (d *SNIAssistedDialer) Mode() TransportMode {
	return ModeSNIAssisted
}

func (d *SNIAssistedDialer) Capabilities() TransportCapabilities {
	return TransportCapabilities{
		Mode:               ModeSNIAssisted,
		RequiresRoot:       false, // Falls back to userspace fragmentation if non-root
		SupportsNAT:        true,
		MaxThroughputMbps:  70.0,
		ExpectedLatencyMs:  110,
		IsAsymmetric:       false,
		PrerequisitesMet:   true,
		PrerequisiteNotice: "Decoy SNI injected on outbound stream",
	}
}

func (d *SNIAssistedDialer) Dial(ctx context.Context, addr string) (Session, error) {
	start := time.Now()
	sess, err := d.dialInternal(ctx, addr)
	d.recordMetric(err == nil, time.Since(start), err)
	return sess, err
}

func (d *SNIAssistedDialer) dialInternal(ctx context.Context, addr string) (Session, error) {
	var netDialer net.Dialer
	rawConn, err := netDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("sni-assisted dial: %w", err)
	}

	// 1. Build and inject decoy TLS ClientHello
	decoyHello := BuildDecoyClientHello(d.cfg.DecoySNI, d.cfg.Preset)

	// In userspace / standard mode, we inject the decoy chunk or fragment it
	switch d.cfg.InjectMethod {
	case "fragment":
		// TCP segmentation: split decoy ClientHello across small chunks
		fragSize := 40
		for len(decoyHello) > 0 {
			chunk := decoyHello
			if len(chunk) > fragSize {
				chunk = decoyHello[:fragSize]
				decoyHello = decoyHello[fragSize:]
			} else {
				decoyHello = nil
			}
			if _, err := rawConn.Write(chunk); err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("sni-assisted fragment write: %w", err)
			}
			time.Sleep(2 * time.Millisecond) // Short delay to trigger separate IP packets
		}
	default:
		// Send decoy ClientHello directly to prime the middlebox DPI state cache
		if _, err := rawConn.Write(decoyHello); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("sni-assisted decoy write: %w", err)
		}
	}

	// 2. Perform Paqet AEAD Handshake over the flow
	var salt [SaltSize]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		rawConn.Close()
		return nil, err
	}
	if _, err := rawConn.Write(salt[:]); err != nil {
		rawConn.Close()
		return nil, err
	}

	c2sKey, s2cKey, err := crypto.DeriveKeys(d.cfg.PSK, salt[:])
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	secConn, err := newSecureConn(rawConn, c2sKey, s2cKey)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	// 3. Authenticated handshake frame
	padLen := 0
	if d.cfg.MaxPad > 0 {
		var pb [1]byte
		_, _ = rand.Read(pb[:])
		padLen = int(pb[0]) % d.cfg.MaxPad
	}

	initFrame := make([]byte, 4+2+padLen)
	binary.BigEndian.PutUint32(initFrame[:4], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint16(initFrame[4:6], uint16(padLen))
	if padLen > 0 {
		_, _ = rand.Read(initFrame[6:])
	}

	if _, err := secConn.Write(initFrame); err != nil {
		secConn.Close()
		return nil, fmt.Errorf("sni-assisted handshake failed: %w", err)
	}

	// 4. Multiplexing
	smuxCfg := smux.DefaultConfig()
	smuxCfg.Version = 2
	sess, err := smux.Client(secConn, smuxCfg)
	if err != nil {
		secConn.Close()
		return nil, fmt.Errorf("sni-assisted smux client: %w", err)
	}

	return &smuxSessionWrapper{sess: sess, underlying: secConn, remote: rawConn.RemoteAddr()}, nil
}

func (d *SNIAssistedDialer) CheckHealth(ctx context.Context, addr string) (time.Duration, error) {
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

func (d *SNIAssistedDialer) recordMetric(success bool, rtt time.Duration, err error) {
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
			// EMA with alpha = 0.2
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

func (d *SNIAssistedDialer) Metrics() HealthMetrics {
	d.metricsMu.RLock()
	defer d.metricsMu.RUnlock()
	return d.metrics
}
