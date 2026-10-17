package transport

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arashmh13/paqet-ngv2/internal/ng/crypto"
)

const (
	// MaxActiveServerSessions caps live sessions to prevent heap exhaustion.
	MaxActiveServerSessions = 1024

	// ServerSessionIdleTimeout is the duration of silence before an inactive session is purged.
	ServerSessionIdleTimeout = 10 * time.Minute

	// MaxCachedRepliesPerSession bounds memory for idempotent reply recovery.
	MaxCachedRepliesPerSession = 32

	// MaxReplyCacheBytesPerSession bounds total bytes stored in replyCache per session (32 KB).
	MaxReplyCacheBytesPerSession = 32 * 1024

	// MaxEmergencyPayloadBytes limits application payload to prevent amplification and abuse.
	MaxEmergencyPayloadBytes = 512
)

// Allowed emergency message types
const (
	MsgTypePing              = "ping"
	MsgTypeAlert             = "alert"
	MsgTypeBootstrapRequest  = "bootstrap_request"
	MsgTypeBootstrapResponse = "bootstrap_response"
	MsgTypeStatus            = "status"
	MsgTypeData              = "data"
)

// MessageSafetyClass classifies the replay/duplicate-processing semantics of an
// authenticated emergency control message (Phase 20 P0-3). An in-memory reply
// cache is a RETRANSMISSION OPTIMIZATION, never durable replay protection: every
// supported type must therefore be safe to process twice even after the cache
// (and all session state) is lost to a restart.
type MessageSafetyClass int

const (
	// ClassReadOnly: answering twice produces identical semantics and no state change.
	ClassReadOnly MessageSafetyClass = iota
	// ClassIdempotent: answering twice produces the same effective state (safe duplicates).
	ClassIdempotent
	// ClassStateChanging: duplicates can create side effects — requires durable
	// deduplication before execution; rejected/unsupported unless a specific policy exists.
	ClassStateChanging
	// ClassUnsupported: not accepted from the network in this protocol revision.
	ClassUnsupported
)

// MessageTypeSafety returns the explicit replay/duplicate-processing policy for a
// message type. Unknown types are ClassUnsupported and are rejected fail-closed by
// Validate() before any handler runs; DNS payloads are never interpreted as shell
// commands by the transport layer.
//
//	ping                → read-only (echo/liveness probe)
//	status              → read-only (state report; no mutation)
//	bootstrap_request   → idempotent (re-generates a fresh validity window; same semantics)
//	bootstrap_response  → idempotent client-side apply (last-writer-wins endpoint set)
//	alert               → idempotent (duplicates re-notify; no durable state mutation)
//	data                → state-changing: UNSUPPORTED for exactly-once without a durable
//	                      dedup layer; transport marks it ClassStateChanging and callers
//	                      MUST NOT enable non-idempotent data operations unless they add
//	                      persistent (sessionID, message ID) dedup with bounded storage.
func MessageTypeSafety(msgType string) MessageSafetyClass {
	switch msgType {
	case MsgTypePing, MsgTypeStatus:
		return ClassReadOnly
	case MsgTypeBootstrapRequest, MsgTypeBootstrapResponse, MsgTypeAlert:
		return ClassIdempotent
	case MsgTypeData:
		return ClassStateChanging
	default:
		return ClassUnsupported
	}
}

// EndpointIdentityType defines the explicit cryptographic identity verification scheme.
type EndpointIdentityType string

const (
	// IdentityTypePSKID identifies AEAD or Raw-KCP endpoints via the SHA-256 fingerprint of the shared symmetric key.
	IdentityTypePSKID EndpointIdentityType = "psk-id"
	// IdentityTypeCertPin identifies TLS endpoints via the SHA-256 fingerprint of the server's leaf X.509 certificate.
	IdentityTypeCertPin EndpointIdentityType = "cert-pin"
	// IdentityTypePubKeyPin identifies TLS or asymmetric endpoints via the SHA-256 fingerprint of the server's public key.
	IdentityTypePubKeyPin EndpointIdentityType = "pubkey-pin"
)

// BootstrapEndpointData specifies authenticated transport coordinates for endpoint failover.
type BootstrapEndpointData struct {
	Version               int                  `json:"version"` // Schema version (2 for Phase 14)
	ServerIP              string               `json:"server_ip"`
	TransportPort         int                  `json:"transport_port"`
	TransportMode         string               `json:"transport_mode"`                    // "raw-kcp", "aead-stream", "tls-outer"
	IdentityType          EndpointIdentityType `json:"identity_type"`                     // "psk-id", "cert-pin", "pubkey-pin"
	IdentityValue         string               `json:"identity_value"`                    // Canonical format: "SHA256:<64 hex characters>"
	AuthoritativeServerID string               `json:"authoritative_server_id,omitempty"` // Authoritative server that produced this bootstrap
	ServerPubKey          string               `json:"server_pub_key,omitempty"`          // Backward-compatible alias for v1
	ValidUntil            int64                `json:"valid_until"`
	RecoveryGen           uint64               `json:"recovery_gen,omitempty"` // Authenticated recovery generation token
	RequestID             string               `json:"request_id,omitempty"`   // Bound message ID
}

// GetIdentityValue returns the canonical identity fingerprint, prioritizing IdentityValue over legacy ServerPubKey.
func (b *BootstrapEndpointData) GetIdentityValue() string {
	if b == nil {
		return ""
	}
	if b.IdentityValue != "" {
		return b.IdentityValue
	}
	return b.ServerPubKey
}

// GetIdentityType returns the explicit identity scheme, inferring safely for legacy records.
func (b *BootstrapEndpointData) GetIdentityType() EndpointIdentityType {
	if b == nil {
		return ""
	}
	if b.IdentityType != "" {
		return b.IdentityType
	}
	switch b.TransportMode {
	case "tls-outer", "tls", "tls-stream":
		return IdentityTypeCertPin
	case "aead-stream", "stream", "raw-kcp":
		return IdentityTypePSKID
	default:
		return ""
	}
}

// ParseSHA256Fingerprint parses and validates a canonical SHA-256 fingerprint string.
// Canonical format: "SHA256:<64 hex characters>" (case-insensitive hex).
func ParseSHA256Fingerprint(raw string) ([32]byte, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToUpper(raw), "SHA256:") {
		return [32]byte{}, fmt.Errorf("malformed fingerprint: missing 'SHA256:' prefix in %q", raw)
	}
	hexPart := raw[7:]
	if len(hexPart) != 64 {
		return [32]byte{}, fmt.Errorf("malformed fingerprint: expected 64 hex characters, got %d in %q", len(hexPart), raw)
	}
	b, err := hex.DecodeString(hexPart)
	if err != nil {
		return [32]byte{}, fmt.Errorf("malformed fingerprint hex decoding: %w", err)
	}
	var digest [32]byte
	copy(digest[:], b)
	return digest, nil
}

// Mode returns the strongly-typed TransportMode corresponding to b.TransportMode.
func (b *BootstrapEndpointData) Mode() TransportMode {
	if b == nil {
		return ModeAuto
	}
	switch b.TransportMode {
	case "raw-kcp":
		return ModeRawKCP
	case "aead-stream", "stream":
		return ModeAEADStream
	case "tls-outer", "tls", "tls-stream":
		return ModeTLSStream
	default:
		return TransportMode(b.TransportMode)
	}
}

// Validate validates that BootstrapEndpointData meets all cryptographic, network, and validity constraints.
func (b *BootstrapEndpointData) Validate(now time.Time, maxValidityWindow time.Duration, allowPrivate, allowLoopback bool) error {
	if b == nil {
		return errors.New("nil bootstrap endpoint data")
	}

	// 1. Version validation
	if b.Version < 0 || b.Version > 2 {
		return fmt.Errorf("bootstrap: unsupported schema version %d", b.Version)
	}

	// 2. IP address and address class validation
	if b.ServerIP == "" {
		return errors.New("bootstrap: missing server IP")
	}
	ip := net.ParseIP(b.ServerIP)
	if ip == nil {
		return fmt.Errorf("bootstrap: invalid server IP format: %q", b.ServerIP)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("bootstrap: disallowed unspecified IP: %s", b.ServerIP)
	}
	if ip.IsMulticast() {
		return fmt.Errorf("bootstrap: disallowed multicast IP: %s", b.ServerIP)
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("bootstrap: disallowed link-local IP: %s", b.ServerIP)
	}
	if ip.IsLoopback() && !allowLoopback {
		return fmt.Errorf("bootstrap: loopback IP rejected by production security policy: %s", b.ServerIP)
	}
	if ip.IsPrivate() && !allowPrivate {
		return fmt.Errorf("bootstrap: private IP rejected by production security policy: %s", b.ServerIP)
	}

	// 3. Port validation
	if b.TransportPort <= 0 || b.TransportPort > 65535 {
		return fmt.Errorf("bootstrap: invalid port: %d (must be 1-65535)", b.TransportPort)
	}

	// 4. Transport mode validation (strict whitelist)
	switch b.TransportMode {
	case "raw-kcp", "aead-stream", "tls-outer", "tls-stream":
		// Whitelisted supported modes
	default:
		return fmt.Errorf("bootstrap: unsupported transport mode: %q (fail-closed rejection)", b.TransportMode)
	}

	// 5. Timestamp & Validity Window (strictly nonzero and within bounds)
	// P0 REQUIREMENT: ValidUntil == now.Unix() MUST be treated as expired!
	if b.ValidUntil <= 0 {
		return errors.New("bootstrap: missing or zero expiry timestamp (nonzero ValidUntil required for fail-closed recovery)")
	}
	nowUnix := now.Unix()
	if b.ValidUntil <= nowUnix {
		return fmt.Errorf("bootstrap: endpoint coordinates expired at %d (current time %d, ValidUntil <= now is expired)", b.ValidUntil, nowUnix)
	}
	if maxValidityWindow > 0 {
		maxFutureUnix := now.Add(maxValidityWindow).Unix()
		if b.ValidUntil > maxFutureUnix {
			return fmt.Errorf("bootstrap: expiry timestamp %d exceeds maximum validity window %v (max allowed: %d)",
				b.ValidUntil, maxValidityWindow, maxFutureUnix)
		}
	}

	// 6. Cryptographic Identity Binding
	idVal := b.GetIdentityValue()
	if idVal == "" {
		return fmt.Errorf("bootstrap: missing server identity value for mode %s", b.TransportMode)
	}
	if _, err := ParseSHA256Fingerprint(idVal); err != nil {
		return fmt.Errorf("bootstrap: invalid cryptographic identity fingerprint %q: %w", idVal, err)
	}

	// 7. Identity Type vs Transport Mode consistency (P0 Requirement: separate rules per mode)
	idType := b.GetIdentityType()
	switch b.Mode() {
	case ModeTLSStream:
		if idType != IdentityTypeCertPin && idType != IdentityTypePubKeyPin {
			return fmt.Errorf("bootstrap: invalid identity type %q for TLS mode (must be %s or %s)",
				idType, IdentityTypeCertPin, IdentityTypePubKeyPin)
		}
	case ModeAEADStream:
		if idType != IdentityTypePSKID {
			return fmt.Errorf("bootstrap: invalid identity type %q for AEAD mode (must be %s)",
				idType, IdentityTypePSKID)
		}
	case ModeRawKCP:
		if idType != IdentityTypePSKID {
			return fmt.Errorf("bootstrap: invalid identity type %q for Raw-KCP mode (must be %s)",
				idType, IdentityTypePSKID)
		}
	default:
		return fmt.Errorf("bootstrap: unsupported transport mode: %q", b.TransportMode)
	}

	return nil
}

// BootstrapEndpointRecord specifies a pre-configured recovery endpoint candidate.
type BootstrapEndpointRecord struct {
	ServerIP              string               `json:"server_ip" yaml:"server_ip"`
	TransportPort         int                  `json:"transport_port" yaml:"transport_port"`
	TransportMode         string               `json:"transport_mode" yaml:"transport_mode"`
	IdentityType          EndpointIdentityType `json:"identity_type" yaml:"identity_type"`
	IdentityValue         string               `json:"identity_value" yaml:"identity_value"`                                       // Canonical "SHA256:<64 hex>"
	AuthoritativeServerID string               `json:"authoritative_server_id,omitempty" yaml:"authoritative_server_id,omitempty"` // Bound authoritative server ID
	Provenance            string               `json:"provenance,omitempty" yaml:"provenance,omitempty"`                           // Provenance metadata (e.g. "key_file:bundle.key", "pin:SHA256:...")
	ValiditySec           int64                `json:"validity_sec" yaml:"validity_sec"`                                           // Expiry seconds relative to generation time
}

// BootstrapManager manages mode-aware, validated recovery candidate records and produces authenticated bootstrap payloads.
type BootstrapManager struct {
	mu                    sync.RWMutex
	records               map[string]BootstrapEndpointRecord // Keyed by transport mode
	defaultMode           string
	authoritativeServerID string
	recoveryGen           uint64
}

// NewBootstrapManager creates a validated, mode-aware bootstrap manager.
func NewBootstrapManager(records []BootstrapEndpointRecord, defaultMode string, initialGen uint64) (*BootstrapManager, error) {
	bm := &BootstrapManager{
		records:     make(map[string]BootstrapEndpointRecord),
		defaultMode: defaultMode,
		recoveryGen: initialGen,
	}
	for _, rec := range records {
		if err := bm.AddRecord(rec); err != nil {
			return nil, err
		}
	}
	return bm, nil
}

// AddRecord validates and registers a candidate endpoint record.
func (bm *BootstrapManager) AddRecord(rec BootstrapEndpointRecord) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	// 1. IP validation & Disallowed IP address classes
	if rec.ServerIP == "" {
		return errors.New("bootstrap record: missing server IP")
	}
	ip := net.ParseIP(rec.ServerIP)
	if ip == nil {
		return fmt.Errorf("bootstrap record: invalid server IP: %q", rec.ServerIP)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("bootstrap record: disallowed unspecified IP: %s", rec.ServerIP)
	}
	if ip.IsMulticast() {
		return fmt.Errorf("bootstrap record: disallowed multicast IP: %s", rec.ServerIP)
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("bootstrap record: disallowed link-local IP: %s", rec.ServerIP)
	}

	// 2. Port validation
	if rec.TransportPort <= 0 || rec.TransportPort > 65535 {
		return fmt.Errorf("bootstrap record: invalid port %d (must be 1-65535)", rec.TransportPort)
	}

	// 3. Transport mode validation (strict whitelist)
	switch rec.TransportMode {
	case "raw-kcp", "aead-stream", "tls-outer", "tls-stream":
	default:
		return fmt.Errorf("bootstrap record: unsupported transport mode %q (fail-closed rejection)", rec.TransportMode)
	}

	// 4. Identity validation
	if rec.IdentityValue == "" {
		return fmt.Errorf("bootstrap record: missing identity value for mode %s", rec.TransportMode)
	}
	if _, err := ParseSHA256Fingerprint(rec.IdentityValue); err != nil {
		return fmt.Errorf("bootstrap record: invalid identity fingerprint %q: %w", rec.IdentityValue, err)
	}
	switch rec.TransportMode {
	case "tls-outer", "tls-stream":
		if rec.IdentityType != IdentityTypeCertPin && rec.IdentityType != IdentityTypePubKeyPin {
			return fmt.Errorf("bootstrap record: invalid identity type %q for TLS mode (must be cert-pin or pubkey-pin)", rec.IdentityType)
		}
	case "aead-stream", "raw-kcp":
		if rec.IdentityType != IdentityTypePSKID {
			return fmt.Errorf("bootstrap record: invalid identity type %q for %s mode (must be psk-id)", rec.IdentityType, rec.TransportMode)
		}
	}

	// 5. Validity window validation (positive, max 24h)
	if rec.ValiditySec <= 0 {
		return fmt.Errorf("bootstrap record: invalid non-positive validity duration %d (must be > 0)", rec.ValiditySec)
	}
	if rec.ValiditySec > 86400 {
		return fmt.Errorf("bootstrap record: validity duration %d exceeds maximum allowable 24h window", rec.ValiditySec)
	}

	// 6. Conflicting duplicate check
	if existing, exists := bm.records[rec.TransportMode]; exists {
		if existing.ServerIP != rec.ServerIP || existing.TransportPort != rec.TransportPort ||
			existing.IdentityValue != rec.IdentityValue || existing.IdentityType != rec.IdentityType {
			return fmt.Errorf("bootstrap record: duplicate conflicting record for transport mode %q", rec.TransportMode)
		}
	}

	bm.records[rec.TransportMode] = rec
	return nil
}

// RecordCount returns the count of registered candidate endpoints.
func (bm *BootstrapManager) RecordCount() int {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return len(bm.records)
}

// GetRecord retrieves a registered candidate endpoint record for a given mode.
func (bm *BootstrapManager) GetRecord(mode string) (BootstrapEndpointRecord, bool) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	rec, ok := bm.records[mode]
	return rec, ok
}

// SetAuthoritativeServerID sets the authoritative server identity associated with generated bootstrap records.
func (bm *BootstrapManager) SetAuthoritativeServerID(id string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.authoritativeServerID = id
}

// SetRecoveryGen updates the active recovery revision generation.
func (bm *BootstrapManager) SetRecoveryGen(gen uint64) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.recoveryGen = gen
}

// GenerateResponse generates an authenticated, versioned bootstrap response for the requested mode.
func (bm *BootstrapManager) GenerateResponse(req *EmergencyMessage, requestedMode string) (*BootstrapEndpointData, error) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	if len(bm.records) == 0 {
		return nil, errors.New("recovery: no recovery endpoints configured; recovery plane disabled (fail-closed safe state)")
	}

	mode := requestedMode
	if mode == "" || mode == "REQUEST_BOOTSTRAP_ENDPOINT" {
		mode = bm.defaultMode
	}
	if mode == "" {
		mode = "aead-stream"
	}

	rec, ok := bm.records[mode]
	if !ok {
		return nil, fmt.Errorf("no recovery candidate configured for transport mode %q", mode)
	}

	authID := rec.AuthoritativeServerID
	if authID == "" {
		authID = bm.authoritativeServerID
	}

	now := time.Now()
	data := &BootstrapEndpointData{
		Version:               2,
		ServerIP:              rec.ServerIP,
		TransportPort:         rec.TransportPort,
		TransportMode:         rec.TransportMode,
		IdentityType:          rec.IdentityType,
		IdentityValue:         rec.IdentityValue,
		AuthoritativeServerID: authID,
		ServerPubKey:          "", // omit to keep JSON compact for single-datagram DNS recursion
		ValidUntil:            now.Unix() + rec.ValiditySec,
		RecoveryGen:           bm.recoveryGen,
		RequestID:             req.ID,
	}
	return data, nil
}

// EmergencyMessage represents an authenticated application datagram exchanged over DNS.
type EmergencyMessage struct {
	ID        string `json:"id"`
	Type      string `json:"type"`      // "ping", "bootstrap_request", "bootstrap_response", "alert", "status", "data"
	Payload   []byte `json:"payload"`   // Application payload bytes (capped at MaxEmergencyPayloadBytes)
	Timestamp int64  `json:"timestamp"` // Unix timestamp
}

// Validate validates that the EmergencyMessage conforms to the strict control schema.
func (m *EmergencyMessage) Validate() error {
	if m == nil {
		return errors.New("nil emergency message")
	}
	if m.ID == "" {
		return errors.New("message ID required")
	}
	switch m.Type {
	case MsgTypePing, MsgTypeAlert, MsgTypeBootstrapRequest, MsgTypeBootstrapResponse, MsgTypeStatus, MsgTypeData:
		// Valid type
	default:
		return fmt.Errorf("unsupported message type: %q (strict schema rejection)", m.Type)
	}
	if len(m.Payload) > MaxEmergencyPayloadBytes {
		return fmt.Errorf("payload size %d exceeds max %d", len(m.Payload), MaxEmergencyPayloadBytes)
	}
	return nil
}

// EmergencyResponse represents an authenticated server response returned inside a DNS TXT record.
type EmergencyResponse struct {
	ID        string `json:"id"`                  // Echoes Request ID
	Status    string `json:"status"`              // e.g. "OK", "ERROR"
	ServerID  string `json:"server_id,omitempty"` // Cryptographic Server ID of the answering server
	Reply     []byte `json:"reply"`               // Dynamic response payload
	Timestamp int64  `json:"timestamp"`           // Server Unix timestamp
}

// EmergencyDNSServerConfig configures the authoritative DNS emergency service.
type EmergencyDNSServerConfig struct {
	ListenAddr           string
	DomainSuffix         string
	PSK                  []byte
	ServerID             string // Unique cryptographic identity of this authoritative server instance (e.g. "ns-de-01")
	ServerSecret         []byte // Dedicated 32-byte response secret (mandatory in multi-server mode)
	IsLegacySingleServer bool   // If true, enables legacy single-server mode using PSK only
	ProtocolV4           bool   // If true, sessions speak v4 ("PAQD") framing with per-session random seed keying
	Handler              func(msg *EmergencyMessage) (*EmergencyResponse, error)
}

type cachedReplyEntry struct {
	reqSeq             uint32
	requestFingerprint [32]byte // SHA-256 digest of complete authenticated request frame
	requestID          string
	respSeq            uint32
	replyFrame         []byte
	createdAt          time.Time
}

const (
	// MaxConcurrentDNSHandlers caps simultaneously running UDP worker goroutines
	MaxConcurrentDNSHandlers = 128
	// MaxConcurrentTCPConns caps simultaneously accepted TCP connections
	MaxConcurrentTCPConns = 32
	// MaxInFlightWaitersPerSequence limits duplicate callers waiting on the same in-flight sequence
	MaxInFlightWaitersPerSequence = 16
)

type inFlightEntry struct {
	reqSeq             uint32
	requestFingerprint [32]byte
	requestID          string
	doneCh             chan struct{}
	waitersCount       int32
}

type serverSessionEntry struct {
	mu         sync.Mutex // Serializes session replay state and reply cache
	conn       *AsymmetricConn
	lastActive time.Time
	activeOps  int32                     // Ref count of active goroutines; prevents idle eviction during in-flight processing
	inFlight   map[uint32]*inFlightEntry // Sequence -> in-flight request tracking
	replyCache map[uint32]*cachedReplyEntry
	seqOrder   []uint32 // FIFO order for eviction
	cacheBytes int      // Current total bytes in replyCache
}

func (e *serverSessionEntry) addReplyCacheLocked(seq uint32, digest [32]byte, reqID string, respSeq uint32, replyFrame []byte) {
	entryLen := len(replyFrame)
	for len(e.replyCache) >= MaxCachedRepliesPerSession || (e.cacheBytes+entryLen > MaxReplyCacheBytesPerSession && len(e.seqOrder) > 0) {
		oldestSeq := e.seqOrder[0]
		e.seqOrder = e.seqOrder[1:]
		if old, ok := e.replyCache[oldestSeq]; ok {
			e.cacheBytes -= len(old.replyFrame)
			delete(e.replyCache, oldestSeq)
		}
	}
	e.replyCache[seq] = &cachedReplyEntry{
		reqSeq:             seq,
		requestFingerprint: digest,
		requestID:          reqID,
		respSeq:            respSeq,
		replyFrame:         append([]byte(nil), replyFrame...),
		createdAt:          time.Now(),
	}
	e.seqOrder = append(e.seqOrder, seq)
	e.cacheBytes += entryLen
}

// EmergencyDNSServer hosts the authoritative DNS endpoint, receiving recursive DNS queries,
// reassembling multipart frames, decrypting authenticated requests, and returning dynamic responses in TXT records.
type EmergencyDNSServer struct {
	cfg         EmergencyDNSServerConfig
	udpConn     *net.UDPConn
	tcpListener net.Listener
	reassembler *DNSReassembler
	sessions    map[uint64]*serverSessionEntry
	udpSem      chan struct{} // Bounded semaphore for simultaneous UDP packet handlers
	tcpSem      chan struct{} // Bounded semaphore for simultaneous TCP connections
	mu          sync.Mutex
	stopOnce    sync.Once
	stopChan    chan struct{}
	wg          sync.WaitGroup
}

// NewEmergencyDNSServer creates a new authoritative emergency DNS daemon listening on UDP and TCP port 53.
func NewEmergencyDNSServer(cfg EmergencyDNSServerConfig) (*EmergencyDNSServer, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":53"
	}
	if cfg.DomainSuffix == "" {
		return nil, errors.New("emergency dns: domain suffix required")
	}
	if len(cfg.PSK) != 32 {
		return nil, errors.New("emergency dns: PSK must be exactly 32 bytes")
	}
	if cfg.IsLegacySingleServer && cfg.ProtocolV4 {
		return nil, errors.New("emergency dns: v4 protocol cannot be combined with legacy single-server mode (fail-closed)")
	}

	if !cfg.IsLegacySingleServer {
		if cfg.ServerID == "" {
			return nil, errors.New("emergency dns: server ID must be explicitly configured (no implicit default)")
		}
		if cfg.ServerID == "default" || cfg.ServerID == "legacy" {
			return nil, fmt.Errorf("emergency dns: production server cannot use default/legacy server ID %q", cfg.ServerID)
		}
		if err := ValidateServerID(cfg.ServerID); err != nil {
			return nil, fmt.Errorf("emergency dns: invalid server ID %q: %w", cfg.ServerID, err)
		}
		if len(cfg.ServerSecret) == 0 {
			return nil, ErrMissingResponseSecret
		}
		if len(cfg.ServerSecret) != 32 {
			return nil, ErrInvalidResponseSecret
		}
	} else {
		if cfg.ServerID == "" {
			cfg.ServerID = "legacy"
		}
	}

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve listen udp addr: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s: %w", cfg.ListenAddr, err)
	}

	actualPort := udpConn.LocalAddr().(*net.UDPAddr).Port
	tcpAddr := &net.TCPAddr{
		IP:   udpAddr.IP,
		Port: actualPort,
	}

	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("listen tcp %s: %w", tcpAddr, err)
	}

	srv := &EmergencyDNSServer{
		cfg:         cfg,
		udpConn:     udpConn,
		tcpListener: tcpListener,
		reassembler: NewDNSReassembler(30 * time.Second),
		sessions:    make(map[uint64]*serverSessionEntry),
		udpSem:      make(chan struct{}, MaxConcurrentDNSHandlers),
		tcpSem:      make(chan struct{}, MaxConcurrentTCPConns),
		stopChan:    make(chan struct{}),
	}

	srv.wg.Add(3)
	go srv.serveUDP()
	go srv.serveTCP()
	go srv.cleanerLoop()
	return srv, nil
}

// Addr returns the local listening address.
func (s *EmergencyDNSServer) Addr() net.Addr {
	return s.udpConn.LocalAddr()
}

// ActiveSessionsCount returns the number of authenticated live sessions currently tracked in memory.
func (s *EmergencyDNSServer) ActiveSessionsCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// Stop shuts down the authoritative DNS server cleanly.
func (s *EmergencyDNSServer) Stop() error {
	var errUDP, errTCP error
	s.stopOnce.Do(func() {
		close(s.stopChan)
		errUDP = s.udpConn.Close()
		errTCP = s.tcpListener.Close()
		s.wg.Wait()
	})
	if errUDP != nil {
		return errUDP
	}
	return errTCP
}

func (s *EmergencyDNSServer) cleanerLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.mu.Lock()
			s.evictIdleSessionsLocked(time.Now())
			s.mu.Unlock()
		}
	}
}

func (s *EmergencyDNSServer) evictIdleSessionsLocked(now time.Time) {
	for id, entry := range s.sessions {
		if atomic.LoadInt32(&entry.activeOps) == 0 && now.Sub(entry.lastActive) > ServerSessionIdleTimeout {
			delete(s.sessions, id)
		}
	}
}

func (s *EmergencyDNSServer) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 4096)
	normalizedSuffix := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s.cfg.DomainSuffix), "."))

	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		_ = s.udpConn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, remoteAddr, err := s.udpConn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}

		select {
		case s.udpSem <- struct{}{}:
			reqPacket := append([]byte(nil), buf[:n]...)
			go func(pkt []byte, addr net.Addr) {
				defer func() { <-s.udpSem }()
				resp := s.processQuery(pkt, normalizedSuffix)
				if resp != nil {
					_, _ = s.udpConn.WriteTo(resp, addr)
				}
			}(reqPacket, remoteAddr)
		default:
			// Bounded worker pool load shedding: drop packet under flood
			continue
		}
	}
}

func (s *EmergencyDNSServer) serveTCP() {
	defer s.wg.Done()
	normalizedSuffix := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s.cfg.DomainSuffix), "."))

	for {
		conn, err := s.tcpListener.Accept()
		if err != nil {
			select {
			case <-s.stopChan:
				return
			default:
				continue
			}
		}

		select {
		case s.tcpSem <- struct{}{}:
			go func(c net.Conn) {
				defer func() {
					_ = c.Close()
					<-s.tcpSem
				}()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))

				// RFC 7766 TCP DNS: 2-byte prefix length
				var lenBuf [2]byte
				if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
					return
				}
				msgLen := binary.BigEndian.Uint16(lenBuf[:])
				if msgLen < 12 || msgLen > 4096 {
					return
				}

				reqBuf := make([]byte, msgLen)
				if _, err := io.ReadFull(c, reqBuf); err != nil {
					return
				}

				resp := s.processQuery(reqBuf, normalizedSuffix)
				if resp != nil && len(resp) <= 65535 {
					var outLen [2]byte
					binary.BigEndian.PutUint16(outLen[:], uint16(len(resp)))
					_, _ = c.Write(outLen[:])
					_, _ = c.Write(resp)
				}
			}(conn)
		default:
			_ = conn.Close()
			continue
		}
	}
}

func (s *EmergencyDNSServer) processQuery(reqPacket []byte, normalizedSuffix string) []byte {
	if len(reqPacket) < 12 {
		return nil
	}

	id, qname, qtype, err := ParseDNSQuery(reqPacket)
	if err != nil {
		return BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
	}
	_ = id

	qnameLower := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), "."))

	// Security Rule: Reject domains outside our authoritative child zone with REFUSED (RCODE 5)
	// Prevents the server from operating as an open resolver or DNS amplifier.
	if !strings.HasSuffix(qnameLower, "."+normalizedSuffix) && qnameLower != normalizedSuffix {
		return BuildDNSErrorResponse(reqPacket, 5 /* REFUSED */)
	}

	// Handle non-TXT queries (e.g. A, AAAA, SOA) with NOERROR and empty answers
	if qtype != 0x0010 /* TXT */ {
		resp, _ := BuildDNSTXTResponse(reqPacket, nil)
		return resp
	}

	clientID, offset, part, total, chunk, err := DecodeDNSQName(qnameLower, normalizedSuffix)
	if err != nil {
		// Non-encoded query under child zone (e.g. diagnostic ping)
		resp, _ := BuildDNSTXTResponse(reqPacket, []byte("PAQET_EMERGENCY_DNS_ZONE_ACTIVE"))
		return resp
	}

	fullFrame, isComplete := s.reassembler.PushFragment(clientID, offset, part, total, chunk)
	if !isComplete {
		// Intermediate fragment received: return empty response so recursor does not stall
		resp, _ := BuildDNSTXTResponse(reqPacket, nil)
		return resp
	}

	// Reassembled frame must have valid header
	if len(fullFrame) < AsymmetricHeaderLen {
		return BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
	}

	magic := binary.BigEndian.Uint32(fullFrame[0:4])
	reqSeq := binary.BigEndian.Uint32(fullFrame[12:16])
	reqDigest := sha256.Sum256(fullFrame)

	var sessionID uint64
	switch magic {
	case AsymmetricMagicV4:
		// v4 header: Magic(4)+SessionID(8)+Seq(4)+Ack(4)+SeedLen(1)+Seed(16)...
		if len(fullFrame) < AsymmetricHeaderV4MinLen+crypto.SessionSeedSize {
			return BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
		}
		seedLen := int(fullFrame[20])
		if seedLen != crypto.SessionSeedSize {
			return BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
		}
		sessionID = binary.BigEndian.Uint64(fullFrame[4:12])
	case AsymmetricMagicV3, AsymmetricMagic:
		sessionID = binary.BigEndian.Uint64(fullFrame[4:12])
	default:
		return BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
	}

	// Step 1: Check if session already exists
	s.mu.Lock()
	entry, exists := s.sessions[sessionID]
	if exists {
		atomic.AddInt32(&entry.activeOps, 1)
	}
	s.mu.Unlock()

	if exists {
		defer atomic.AddInt32(&entry.activeOps, -1)
		return s.processExistingSessionQuery(reqPacket, entry, fullFrame, reqSeq, reqDigest)
	}

	// v4 frames are only processable by v4-configured servers (explicit reject otherwise)
	if magic == AsymmetricMagicV4 && !s.cfg.ProtocolV4 {
		return s.processNewSessionQuery(reqPacket, sessionID, fullFrame, reqSeq, reqDigest) // path itself fails closed on v4
	}

	return s.processNewSessionQuery(reqPacket, sessionID, fullFrame, reqSeq, reqDigest)
}

func (s *EmergencyDNSServer) processExistingSessionQuery(
	reqPacket []byte,
	entry *serverSessionEntry,
	fullFrame []byte,
	reqSeq uint32,
	reqDigest [32]byte,
) []byte {
	entry.mu.Lock()

	// P0 SECURITY REQUIREMENT: Authenticate frame and validate session/seq BEFORE touching in-flight or reply cache!
	seq, _, plaintext, err := entry.conn.VerifyFrame(fullFrame)
	if err != nil {
		// Unauthenticated attacker or corrupt frame! Reject immediately without waiting or leaking!
		entry.mu.Unlock()
		return BuildDNSErrorResponse(reqPacket, 5 /* REFUSED */)
	}

	// 1. Check if this exact sequence is currently in-flight
	if inflight, inFlight := entry.inFlight[reqSeq]; inFlight {
		// Unauthenticated packets already rejected above!
		// Verify fingerprint matches the active in-flight request:
		if reqDigest != inflight.requestFingerprint {
			// Sequence reused with different ciphertext or payload! Reject!
			entry.mu.Unlock()
			return BuildDNSErrorResponse(reqPacket, 5 /* REFUSED */)
		}

		// Exact authenticated duplicate of active in-flight request!
		// Bound simultaneous duplicate waiters
		if atomic.LoadInt32(&inflight.waitersCount) >= MaxInFlightWaitersPerSequence {
			entry.mu.Unlock()
			return BuildDNSErrorResponse(reqPacket, 5 /* REFUSED */)
		}

		atomic.AddInt32(&inflight.waitersCount, 1)
		doneCh := inflight.doneCh
		entry.mu.Unlock()

		select {
		case <-doneCh:
		case <-time.After(3 * time.Second):
			atomic.AddInt32(&inflight.waitersCount, -1)
			return BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
		}
		atomic.AddInt32(&inflight.waitersCount, -1)

		// Handler has finished! Retrieve sealed response from replyCache
		entry.mu.Lock()
		if cached, ok := entry.replyCache[reqSeq]; ok {
			cachedReply := append([]byte(nil), cached.replyFrame...)
			entry.lastActive = time.Now()
			entry.mu.Unlock()
			resp, err := BuildDNSTXTResponse(reqPacket, cachedReply)
			if err == nil {
				return resp
			}
			return nil
		}
		entry.mu.Unlock()
		return BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
	}

	// 2. Check replyCache
	if cached, ok := entry.replyCache[reqSeq]; ok {
		if reqDigest != cached.requestFingerprint {
			// Attacker or client reused seq with different ciphertext/content!
			// REJECT without invoking handler or leaking cached reply!
			entry.mu.Unlock()
			return BuildDNSErrorResponse(reqPacket, 5 /* REFUSED */)
		}

		// Exact authenticated duplicate! Return cached reply
		cachedReply := append([]byte(nil), cached.replyFrame...)
		entry.lastActive = time.Now()
		entry.mu.Unlock()

		resp, err := BuildDNSTXTResponse(reqPacket, cachedReply)
		if err == nil {
			return resp
		}
		return nil
	}

	// 3. New sequence for existing session: advance anti-replay window
	if entry.conn.replay != nil {
		if err := entry.conn.replay.Validate(uint64(seq)); err != nil {
			// Replay violation (e.g. sequence already seen and evicted from cache)
			entry.mu.Unlock()
			return BuildDNSErrorResponse(reqPacket, 5 /* REFUSED */)
		}
	}

	// Register in-flight operation
	doneCh := make(chan struct{})
	if entry.inFlight == nil {
		entry.inFlight = make(map[uint32]*inFlightEntry)
	}
	inflight := &inFlightEntry{
		reqSeq:             reqSeq,
		requestFingerprint: reqDigest,
		doneCh:             doneCh,
	}
	entry.inFlight[reqSeq] = inflight
	entry.lastActive = time.Now()
	entry.mu.Unlock()

	defer func() {
		entry.mu.Lock()
		delete(entry.inFlight, reqSeq)
		close(doneCh)
		entry.mu.Unlock()
	}()

	// 4. Schema validation outside lock
	var reqMsg EmergencyMessage
	if err := json.Unmarshal(plaintext, &reqMsg); err != nil {
		return BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
	}
	if err := reqMsg.Validate(); err != nil {
		return BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
	}

	// 5. Invoke handler outside lock
	var respMsg *EmergencyResponse
	if s.cfg.Handler != nil {
		respMsg, err = s.cfg.Handler(&reqMsg)
		if err != nil {
			respMsg = &EmergencyResponse{
				ID:        reqMsg.ID,
				Status:    "ERROR",
				ServerID:  s.cfg.ServerID,
				Reply:     []byte(err.Error()),
				Timestamp: time.Now().Unix(),
			}
		} else if respMsg != nil && respMsg.ServerID == "" {
			respMsg.ServerID = s.cfg.ServerID
		}
	} else {
		respMsg = &EmergencyResponse{
			ID:        reqMsg.ID,
			Status:    "OK",
			ServerID:  s.cfg.ServerID,
			Reply:     append([]byte("ACK_ECHO:"), reqMsg.Payload...),
			Timestamp: time.Now().Unix(),
		}
	}

	respPlaintext, _ := json.Marshal(respMsg)

	// 6. Seal response and cache it under session lock
	entry.mu.Lock()
	respSeq, err := entry.conn.NextSendSeq()
	if err != nil {
		entry.mu.Unlock()
		return BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
	}
	respFrame, err := entry.conn.sealFrame(respSeq, seq, respPlaintext)
	if err != nil {
		entry.mu.Unlock()
		return BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
	}

	entry.addReplyCacheLocked(reqSeq, reqDigest, reqMsg.ID, respSeq, respFrame)
	entry.lastActive = time.Now()
	entry.mu.Unlock()

	dnsRespPacket, err := BuildDNSTXTResponse(reqPacket, respFrame)
	if err != nil {
		return BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
	}
	return dnsRespPacket
}

func (s *EmergencyDNSServer) processNewSessionQuery(
	reqPacket []byte,
	sessionID uint64,
	fullFrame []byte,
	reqSeq uint32,
	reqDigest [32]byte,
) []byte {
	// 1. Ephemeral unpersisted session for candidate validation.
	//    The wire magic decides the keying mode; unsupported versions fail closed here.
	//    NOTE: legacy single-server clients seal v3-magic frames carrying PSK-only
	//    key schedules (Phase 18 contract), so legacy services accept that magic
	//    and reject only v4 (which requires dedicated per-session seed keying).
	magic := binary.BigEndian.Uint32(fullFrame[0:4])
	var candidateConn *AsymmetricConn
	var err error
	switch {
	case magic == AsymmetricMagicV4:
		if !s.cfg.ProtocolV4 {
			// v4 frame against a v3/legacy-configured service: explicit fail-closed reject (no silent keying fallback)
			return BuildDNSErrorResponse(reqPacket, 5 /* REFUSED */)
		}
		if len(fullFrame) < AsymmetricHeaderV4MinLen+crypto.SessionSeedSize {
			return BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
		}
		seed := append([]byte(nil), fullFrame[21:21+crypto.SessionSeedSize]...)
		candidateConn, err = NewServerAsymmetricSessionWithIDV4(sessionID, s.cfg.PSK, s.cfg.ServerSecret, seed, s.cfg.ServerID)
	case s.cfg.IsLegacySingleServer:
		// v3-magic frames sealed with the PSK-only legacy schedule (allow-magic, verify by AEAD tag)
		candidateConn, err = NewServerLegacyAsymmetricSession(sessionID, s.cfg.PSK)
	default:
		// v3 multi-authoritative path with mandatory dedicated response secret
		candidateConn, err = NewServerAsymmetricSessionWithID(sessionID, s.cfg.PSK, s.cfg.ServerSecret, s.cfg.ServerID)
	}
	if err != nil {
		return BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
	}

	// 2. Cryptographic authentication: openFrame validates AEAD tag, AAD headers, and anti-replay
	seq, _, plaintext, err := candidateConn.openFrame(fullFrame)
	if err != nil {
		// Authentication failed or bad magic. Drop immediately with REFUSED. Zero state persisted!
		return BuildDNSErrorResponse(reqPacket, 5 /* REFUSED */)
	}

	// 3. Validate JSON schema before committing to persistent session state
	var reqMsg EmergencyMessage
	if err := json.Unmarshal(plaintext, &reqMsg); err != nil {
		return BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
	}
	if err := reqMsg.Validate(); err != nil {
		return BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
	}

	// 4. Atomically commit or detect existing session
	doneCh := make(chan struct{})
	var entry *serverSessionEntry

	s.mu.Lock()
	existingEntry, alreadyCreated := s.sessions[sessionID]
	if alreadyCreated {
		// Another concurrent goroutine already committed this session while we were authenticating!
		entry = existingEntry
		atomic.AddInt32(&entry.activeOps, 1)
		s.mu.Unlock()

		// Discard candidateConn and route request through existing established session!
		defer atomic.AddInt32(&entry.activeOps, -1)
		return s.processExistingSessionQuery(reqPacket, entry, fullFrame, reqSeq, reqDigest)
	}

	// Session is genuinely new. Enforce session table bounds.
	now := time.Now()
	if len(s.sessions) >= MaxActiveServerSessions {
		s.evictIdleSessionsLocked(now)
	}
	if len(s.sessions) >= MaxActiveServerSessions {
		// Evict oldest session that has activeOps == 0
		var oldestID uint64
		var oldestTime time.Time
		found := false
		for id, e := range s.sessions {
			if atomic.LoadInt32(&e.activeOps) == 0 {
				if oldestTime.IsZero() || e.lastActive.Before(oldestTime) {
					oldestID = id
					oldestTime = e.lastActive
					found = true
				}
			}
		}
		if found {
			delete(s.sessions, oldestID)
		} else {
			// All 1024 sessions have active operations! Reject to prevent OOM
			s.mu.Unlock()
			return BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
		}
	}

	inflight := &inFlightEntry{
		reqSeq:             reqSeq,
		requestFingerprint: reqDigest,
		doneCh:             doneCh,
	}

	entry = &serverSessionEntry{
		conn:       candidateConn,
		lastActive: now,
		activeOps:  1,
		inFlight:   map[uint32]*inFlightEntry{reqSeq: inflight},
		replyCache: make(map[uint32]*cachedReplyEntry),
	}
	s.sessions[sessionID] = entry
	s.mu.Unlock()

	defer func() {
		entry.mu.Lock()
		delete(entry.inFlight, reqSeq)
		close(doneCh)
		entry.mu.Unlock()
		atomic.AddInt32(&entry.activeOps, -1)
	}()

	// 5. Invoke handler outside lock
	var respMsg *EmergencyResponse
	if s.cfg.Handler != nil {
		respMsg, err = s.cfg.Handler(&reqMsg)
		if err != nil {
			respMsg = &EmergencyResponse{
				ID:        reqMsg.ID,
				Status:    "ERROR",
				ServerID:  s.cfg.ServerID,
				Reply:     []byte(err.Error()),
				Timestamp: time.Now().Unix(),
			}
		} else if respMsg != nil && respMsg.ServerID == "" {
			respMsg.ServerID = s.cfg.ServerID
		}
	} else {
		respMsg = &EmergencyResponse{
			ID:        reqMsg.ID,
			Status:    "OK",
			ServerID:  s.cfg.ServerID,
			Reply:     append([]byte("ACK_ECHO:"), reqMsg.Payload...),
			Timestamp: time.Now().Unix(),
		}
	}

	respPlaintext, _ := json.Marshal(respMsg)

	// 6. Seal response and cache it
	entry.mu.Lock()
	respSeq, err := entry.conn.NextSendSeq()
	if err != nil {
		entry.mu.Unlock()
		return BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
	}
	respFrame, err := entry.conn.sealFrame(respSeq, seq, respPlaintext)
	if err != nil {
		entry.mu.Unlock()
		return BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
	}

	entry.addReplyCacheLocked(reqSeq, reqDigest, reqMsg.ID, respSeq, respFrame)
	entry.lastActive = time.Now()
	entry.mu.Unlock()

	dnsRespPacket, err := BuildDNSTXTResponse(reqPacket, respFrame)
	if err != nil {
		return BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
	}
	return dnsRespPacket
}

// Distinct terminal attempt statuses for DNS diagnostic records
const (
	DNSAttemptStatusSuccess           = "SUCCESS"
	DNSAttemptStatusTimeout           = "TIMEOUT"
	DNSAttemptStatusTruncatedTCP      = "TRUNCATED_FALLBACK_TCP"
	DNSAttemptStatusProtocolFail      = "PROTOCOL_FAIL"
	DNSAttemptStatusParseFail         = "PARSE_FAIL"
	DNSAttemptStatusAuthFail          = "AUTH_FAIL"
	DNSAttemptStatusAppValidationFail = "APP_VALIDATION_FAIL"
	DNSAttemptStatusCanceled          = "CANCELED"
)

// DNSQueryAttemptRecord tracks detailed metrics and outcomes for each query attempt.
type DNSQueryAttemptRecord struct {
	AttemptIndex      int     `json:"attempt_index"`
	ResolverAddr      string  `json:"resolver_addr"`
	Protocol          string  `json:"protocol"` // "udp" or "tcp"
	TxID              uint16  `json:"tx_id"`
	SentAtMonotonicMs float64 `json:"sent_at_monotonic_ms"`
	RcvdAtMonotonicMs float64 `json:"rcvd_at_monotonic_ms"`
	DurationMs        float64 `json:"duration_ms"`
	RCode             int     `json:"rcode"`
	Truncated         bool    `json:"truncated"`
	Authenticated     bool    `json:"authenticated"`
	ServerID          string  `json:"server_id"`
	Status            string  `json:"status"` // One of DNSAttemptStatus*
	Error             string  `json:"error,omitempty"`
}

// Validate ensures attempt record has consistent status, error, and monotonic timing.
func (r *DNSQueryAttemptRecord) Validate() error {
	if r.Status == DNSAttemptStatusSuccess {
		if r.Error != "" {
			return fmt.Errorf("contradictory status: SUCCESS attempt has non-empty error %q", r.Error)
		}
		if !r.Authenticated {
			return fmt.Errorf("contradictory status: SUCCESS attempt must be authenticated")
		}
		if r.ServerID == "" {
			return fmt.Errorf("contradictory status: SUCCESS attempt must have authenticated server_id")
		}
	}
	if r.SentAtMonotonicMs < 0 || r.RcvdAtMonotonicMs < 0 || r.DurationMs < 0 {
		return fmt.Errorf("invalid negative timing values in attempt record")
	}
	if r.RcvdAtMonotonicMs > 0 && r.RcvdAtMonotonicMs < r.SentAtMonotonicMs {
		return fmt.Errorf("non-monotonic attempt timing: rcvd (%f) < sent (%f)", r.RcvdAtMonotonicMs, r.SentAtMonotonicMs)
	}
	return nil
}

// DNSInterAttemptGap tracks timing and reason for pauses between consecutive resolver query attempts.
type DNSInterAttemptGap struct {
	FromAttemptIndex int     `json:"from_attempt_index"`
	ToAttemptIndex   int     `json:"to_attempt_index"`
	StartMonotonicMs float64 `json:"start_monotonic_ms"`
	EndMonotonicMs   float64 `json:"end_monotonic_ms"`
	DurationMs       float64 `json:"duration_ms"`
	Reason           string  `json:"reason"`
}

// DNSExchangeTimeline tracks the complete end-to-end breakdown of a logical DNS query exchange.
type DNSExchangeTimeline struct {
	StartMonotonicMs float64                 `json:"start_monotonic_ms"`
	EndMonotonicMs   float64                 `json:"end_monotonic_ms"`
	TotalDurationMs  float64                 `json:"total_duration_ms"`
	Attempts         []DNSQueryAttemptRecord `json:"attempts"`
	Gaps             []DNSInterAttemptGap    `json:"inter_attempt_gaps"`
	UnaccountedMs    float64                 `json:"unaccounted_ms"`
}

// Reconcile verifies that total logical exchange duration matches component attempts and gaps within tolerance.
func (t *DNSExchangeTimeline) Reconcile(toleranceMs float64) error {
	if t.TotalDurationMs < 0 || t.StartMonotonicMs < 0 || t.EndMonotonicMs < 0 {
		return fmt.Errorf("timeline has negative timing values")
	}
	if t.EndMonotonicMs < t.StartMonotonicMs {
		return fmt.Errorf("timeline end (%f) < start (%f)", t.EndMonotonicMs, t.StartMonotonicMs)
	}

	var sumAttempts float64
	for i, att := range t.Attempts {
		if err := att.Validate(); err != nil {
			return fmt.Errorf("attempt %d validation failed: %w", i, err)
		}
		sumAttempts += att.DurationMs
	}

	var sumGaps float64
	for i, gap := range t.Gaps {
		if gap.DurationMs < 0 {
			return fmt.Errorf("gap %d has negative duration %f", i, gap.DurationMs)
		}
		if gap.EndMonotonicMs < gap.StartMonotonicMs {
			return fmt.Errorf("gap %d end (%f) < start (%f)", i, gap.EndMonotonicMs, gap.StartMonotonicMs)
		}
		sumGaps += gap.DurationMs
	}

	totalComponents := sumAttempts + sumGaps
	unaccounted := t.TotalDurationMs - totalComponents
	t.UnaccountedMs = unaccounted

	if toleranceMs <= 0 {
		toleranceMs = 2.0
	}
	if unaccounted < -toleranceMs || unaccounted > toleranceMs {
		return fmt.Errorf("timeline reconciliation failed: total (%f ms) != components (attempts: %f + gaps: %f = %f ms), unaccounted=%f ms exceeds tolerance %f ms",
			t.TotalDurationMs, sumAttempts, sumGaps, totalComponents, unaccounted, toleranceMs)
	}
	return nil
}

// EmergencyDNSClientConfig configures the emergency DNS client.
type EmergencyDNSClientConfig struct {
	ResolverAddr         string   // e.g. "8.8.8.8:53"
	Resolvers            []string // Candidate resolvers for sequential failover (e.g. ["8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"])
	DomainSuffix         string   // e.g. "tunnel.paqet-ngv2.example"
	ClientID             string
	PSK                  []byte
	SessionID            uint64        // 0 -> full-entropy random generation at construction
	Timeout              time.Duration // Total timeout across all attempts
	PerAttemptTimeout    time.Duration // Timeout for an individual attempt (default 1500ms)
	MaxRetries           int
	EDNSBufferSize       uint16                  // Advertised UDP buffer size in OPT RR (default 1232)
	ServerIdentities     []AuthorizedServerEntry // Explicit per-server response secrets (mandatory in multi-server mode)
	IsLegacySingleServer bool                    // If true, enables legacy single-server mode using PSK only
	AllowLegacyV2        bool                    // Reject legacy v2 frames if false
	ProtocolV4           bool                    // v4 ("PAQD") framing with per-session random seed keying (session-ID collision safety)
}

// EmergencyDNSClient sends authenticated application messages over public recursive DNS and verifies responses.
type EmergencyDNSClient struct {
	cfg      EmergencyDNSClientConfig
	session  *AsymmetricConn
	mu       sync.Mutex
	attempts []DNSQueryAttemptRecord
	timeline DNSExchangeTimeline
}

// LastExchangeAttempts returns a copy of the query attempts recorded during the last Exchange call.
func (c *EmergencyDNSClient) LastExchangeAttempts() []DNSQueryAttemptRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	res := make([]DNSQueryAttemptRecord, len(c.attempts))
	copy(res, c.attempts)
	return res
}

// LastExchangeTimeline returns the detailed timeline breakdown of the last Exchange call.
func (c *EmergencyDNSClient) LastExchangeTimeline() DNSExchangeTimeline {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.timeline
}

func (c *EmergencyDNSClient) recordTimeline(start, end time.Time, totalDur time.Duration, attempts []DNSQueryAttemptRecord, gaps []DNSInterAttemptGap) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts = append([]DNSQueryAttemptRecord(nil), attempts...)
	totalDurMs := float64(totalDur.Microseconds()) / 1000.0
	tl := DNSExchangeTimeline{
		StartMonotonicMs: 0.0,
		EndMonotonicMs:   float64(end.Sub(start).Microseconds()) / 1000.0,
		TotalDurationMs:  totalDurMs,
		Attempts:         append([]DNSQueryAttemptRecord(nil), attempts...),
		Gaps:             append([]DNSInterAttemptGap(nil), gaps...),
	}
	_ = tl.Reconcile(2.0)
	c.timeline = tl
}

// NewEmergencyDNSClient initializes an emergency client for a given session.
func NewEmergencyDNSClient(cfg EmergencyDNSClientConfig) (*EmergencyDNSClient, error) {
	if cfg.ResolverAddr == "" && len(cfg.Resolvers) == 0 {
		cfg.ResolverAddr = "8.8.8.8:53"
	}
	if cfg.DomainSuffix == "" {
		return nil, errors.New("emergency client: domain suffix required")
	}
	if len(cfg.PSK) != 32 {
		return nil, errors.New("emergency client: PSK must be exactly 32 bytes")
	}
	if cfg.ClientID == "" {
		cfg.ClientID = "c01"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 6000 * time.Millisecond
	}
	if cfg.PerAttemptTimeout <= 0 {
		cfg.PerAttemptTimeout = 1500 * time.Millisecond
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 2
	}
	if cfg.SessionID == 0 {
		if full, rerr := crypto.GenerateFullRandomUint64(); rerr == nil && full != 0 {
			cfg.SessionID = full
		} else {
			cfg.SessionID = cryptoRandUint64()
		}
	}
	if cfg.EDNSBufferSize == 0 {
		cfg.EDNSBufferSize = DefaultEDNSUDPPayloadSize
	}
	if cfg.IsLegacySingleServer && cfg.ProtocolV4 {
		return nil, errors.New("emergency client: v4 protocol cannot be combined with legacy single-server mode (fail-closed)")
	}

	var sess *AsymmetricConn
	var err error
	switch {
	case cfg.IsLegacySingleServer:
		sess, err = NewClientLegacyAsymmetricSession(cfg.SessionID, cfg.PSK)
		if err != nil {
			return nil, err
		}
	case cfg.ProtocolV4:
		set, serr := NewAuthorizedServerSet("inline", cfg.ServerIdentities)
		if serr != nil {
			return nil, serr
		}
		sess, err = NewClientAsymmetricSessionV4(cfg.SessionID, cfg.PSK, set, nil)
		if err != nil {
			return nil, err
		}
	default:
		if len(cfg.ServerIdentities) == 0 {
			return nil, ErrEmptyServerAllowlist
		}
		sess, err = NewClientAsymmetricSessionWithServers(cfg.SessionID, cfg.PSK, cfg.ServerIdentities)
		if err != nil {
			return nil, err
		}
	}
	if cfg.AllowLegacyV2 {
		sess.SetAllowLegacyV2ForTest(true)
	}

	return &EmergencyDNSClient{
		cfg:     cfg,
		session: sess,
	}, nil
}

// SessionID returns the session identifier in use by this client.
func (c *EmergencyDNSClient) SessionID() uint64 {
	return c.cfg.SessionID
}

// AuthorizedServerIDs returns a deterministic, safe (non-secret) copy of the
// authorized server identities. Server IDs are observational metadata only;
// response secrets are never exposed through this accessor.
func (c *EmergencyDNSClient) AuthorizedServerIDs() []string {
	ids := make([]string, 0, len(c.session.authorizedServers))
	for id := range c.session.authorizedServers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ProtocolVersionName reports the active wire protocol generation.
func (c *EmergencyDNSClient) ProtocolVersionName() string {
	if c.session.protoV4 {
		return "v4-PAQD"
	}
	if c.session.isLegacySingleServer {
		return "v2-legacy"
	}
	return "v3-PAQC"
}

// Exchange transmits an EmergencyMessage through the recursive DNS resolver and waits for an authenticated response.
func (c *EmergencyDNSClient) Exchange(ctx context.Context, msg *EmergencyMessage) (*EmergencyResponse, time.Duration, error) {
	if msg == nil {
		return nil, 0, errors.New("emergency client: nil message")
	}
	if msg.Timestamp == 0 {
		msg.Timestamp = time.Now().Unix()
	}
	if err := msg.Validate(); err != nil {
		return nil, 0, fmt.Errorf("emergency client invalid message: %w", err)
	}

	reqBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal message: %w", err)
	}

	seq, err := c.session.NextSendSeq()
	if err != nil {
		return nil, 0, fmt.Errorf("emergency client sequence exhausted: %w", err)
	}
	frame, err := c.session.sealFrame(seq, 0, reqBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("seal frame: %w", err)
	}

	const chunkSize = 35
	totalParts := uint8((len(frame) + chunkSize - 1) / chunkSize)
	if totalParts == 0 {
		totalParts = 1
	}

	// Generate a 64-bit cryptographically secure random nonce for cache busting
	curOffset := cryptoRandUint64()

	resolvers := c.cfg.Resolvers
	if len(resolvers) == 0 {
		resolvers = []string{c.cfg.ResolverAddr}
	}

	startOverall := time.Now()
	var attempts []DNSQueryAttemptRecord
	var gaps []DNSInterAttemptGap

	for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
		select {
		case <-ctx.Done():
			totalDur := time.Since(startOverall)
			c.recordTimeline(startOverall, time.Now(), totalDur, attempts, gaps)
			return nil, totalDur, ctx.Err()
		default:
		}

		resolverStr := resolvers[attempt%len(resolvers)]
		resolverUDP, err := net.ResolveUDPAddr("udp", resolverStr)
		if err != nil {
			continue
		}

		perTimeout := c.cfg.PerAttemptTimeout
		if perTimeout <= 0 {
			perTimeout = 1500 * time.Millisecond
		}
		if perTimeout > c.cfg.Timeout {
			perTimeout = c.cfg.Timeout
		}

		attemptCtx, cancelAttempt := context.WithTimeout(ctx, perTimeout)
		resp, attemptRec, err := c.attemptExchangeWithRecord(attemptCtx, attempt, resolverUDP, resolverStr, curOffset, totalParts, frame, chunkSize, msg.ID, startOverall, perTimeout)
		cancelAttempt()
		attemptEnd := time.Now()

		attempts = append(attempts, attemptRec)

		if err == nil && resp != nil {
			totalDur := time.Since(startOverall)
			c.recordTimeline(startOverall, time.Now(), totalDur, attempts, gaps)
			return resp, totalDur, nil
		}

		if attempt < c.cfg.MaxRetries {
			gapStart := attemptEnd
			backoff := 50*time.Millisecond + time.Duration(cryptoRandUint64()%50)*time.Millisecond
			select {
			case <-ctx.Done():
				totalDur := time.Since(startOverall)
				c.recordTimeline(startOverall, time.Now(), totalDur, attempts, gaps)
				return nil, totalDur, ctx.Err()
			case <-time.After(backoff):
			}
			gapEnd := time.Now()
			gaps = append(gaps, DNSInterAttemptGap{
				FromAttemptIndex: attempt,
				ToAttemptIndex:   attempt + 1,
				StartMonotonicMs: float64(gapStart.Sub(startOverall).Microseconds()) / 1000.0,
				EndMonotonicMs:   float64(gapEnd.Sub(startOverall).Microseconds()) / 1000.0,
				DurationMs:       float64(gapEnd.Sub(gapStart).Microseconds()) / 1000.0,
				Reason:           "retry_backoff_and_resolver_failover",
			})
		}
	}

	totalDur := time.Since(startOverall)
	c.recordTimeline(startOverall, time.Now(), totalDur, attempts, gaps)
	return nil, totalDur, fmt.Errorf("emergency exchange timed out after %d retries across resolvers %v", c.cfg.MaxRetries, resolvers)
}

func (c *EmergencyDNSClient) attemptExchange(
	ctx context.Context,
	resolverUDP *net.UDPAddr,
	curOffset uint64,
	totalParts uint8,
	frame []byte,
	chunkSize int,
	expectedMsgID string,
) (*EmergencyResponse, error) {
	resp, _, err := c.attemptExchangeWithRecord(ctx, 0, resolverUDP, resolverUDP.String(), curOffset, totalParts, frame, chunkSize, expectedMsgID, time.Now(), c.cfg.Timeout)
	return resp, err
}

func (c *EmergencyDNSClient) attemptExchangeWithRecord(
	ctx context.Context,
	attemptIndex int,
	resolverUDP *net.UDPAddr,
	resolverStr string,
	curOffset uint64,
	totalParts uint8,
	frame []byte,
	chunkSize int,
	expectedMsgID string,
	startOverall time.Time,
	attemptTimeout time.Duration,
) (*EmergencyResponse, DNSQueryAttemptRecord, error) {
	conn, err := net.ListenUDP("udp", nil)
	attemptStart := time.Now()
	sentMonotonicMs := float64(attemptStart.Sub(startOverall).Microseconds()) / 1000.0

	rec := DNSQueryAttemptRecord{
		AttemptIndex:      attemptIndex,
		ResolverAddr:      resolverStr,
		Protocol:          "udp",
		SentAtMonotonicMs: sentMonotonicMs,
	}

	if err != nil {
		rec.Status = "ERROR"
		rec.Error = err.Error()
		rec.DurationMs = float64(time.Since(attemptStart).Microseconds()) / 1000.0
		rec.RcvdAtMonotonicMs = float64(time.Since(startOverall).Microseconds()) / 1000.0
		return nil, rec, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(attemptStart.Add(attemptTimeout))

	type pendingQuery struct {
		txID  uint16
		qname string
	}
	var queries []pendingQuery

	// Dispatch each fragment query
	for i := uint8(0); i < totalParts; i++ {
		start := int(i) * chunkSize
		end := start + chunkSize
		if end > len(frame) {
			end = len(frame)
		}
		chunk := frame[start:end]

		qname := EncodeDNSQName(c.cfg.DomainSuffix, c.cfg.ClientID, curOffset, i, totalParts, chunk)
		if len(qname) > 253 {
			rec.Status = "ERROR"
			rec.Error = "qname length exceeds 253"
			return nil, rec, fmt.Errorf("emergency client: qname length %d exceeds RFC 1035 limit (253)", len(qname))
		}

		txID := uint16(cryptoRandUint64())
		rec.TxID = txID
		queryPkt := BuildDNSQueryWithEDNS(qname, 0x0010 /* TXT */, txID, c.cfg.EDNSBufferSize)
		if _, err := conn.WriteToUDP(queryPkt, resolverUDP); err != nil {
			rec.Status = "ERROR"
			rec.Error = err.Error()
			return nil, rec, err
		}

		queries = append(queries, pendingQuery{txID: txID, qname: qname})
	}

	buf := make([]byte, 4096)
	deadline := attemptStart.Add(attemptTimeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			rec.Status = "CANCELED"
			rec.Error = ctx.Err().Error()
			rec.DurationMs = float64(time.Since(attemptStart).Microseconds()) / 1000.0
			rec.RcvdAtMonotonicMs = float64(time.Since(startOverall).Microseconds()) / 1000.0
			return nil, rec, ctx.Err()
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		respPkt := buf[:n]
		if len(respPkt) < 12 {
			continue
		}

		respTxID := binary.BigEndian.Uint16(respPkt[0:2])
		isMatched := false
		for _, q := range queries {
			if q.txID == respTxID {
				isMatched = true
				break
			}
		}
		if !isMatched {
			continue
		}

		rcvdTime := time.Now()
		rec.DurationMs = float64(rcvdTime.Sub(attemptStart).Microseconds()) / 1000.0
		rec.RcvdAtMonotonicMs = float64(rcvdTime.Sub(startOverall).Microseconds()) / 1000.0

		respFlags := binary.BigEndian.Uint16(respPkt[2:4])
		rec.RCode = int(respFlags & 0x000F)
		if respFlags&0x0200 != 0 {
			// TC (Truncation) flag is set: payload exceeded safe UDP buffer. Fall back to RFC 7766 TCP port 53!
			rec.Truncated = true
			rec.Status = "TRUNCATED_FALLBACK_TCP"
			tcpResp, tcpRec, tcpErr := c.attemptTCPExchangeWithRecord(ctx, attemptIndex, resolverStr, queries[0].qname, expectedMsgID, startOverall, attemptTimeout)
			if tcpErr == nil {
				return tcpResp, tcpRec, nil
			}
			return nil, rec, tcpErr
		}

		txtAnswer, err := ParseDNSTXTResponse(respPkt)
		if err != nil || len(txtAnswer) < AsymmetricHeaderLen {
			rec.Status = "DROP"
			rec.Error = "invalid txt response format"
			continue
		}

		// Decrypt and authenticate downstream frame with ServerID binding
		_, _, respPlaintext, serverID, err := c.session.openFrameWithServerID(txtAnswer)
		if err != nil {
			rec.Status = "AUTH_FAIL"
			rec.Error = err.Error()
			return nil, rec, err
		}

		var resp EmergencyResponse
		if err := json.Unmarshal(respPlaintext, &resp); err != nil {
			rec.Status = "AUTH_FAIL"
			rec.Error = "unmarshal json: " + err.Error()
			return nil, rec, err
		}

		if resp.ID == expectedMsgID {
			rec.Status = "SUCCESS"
			rec.Authenticated = true
			rec.ServerID = serverID
			rec.Error = "" // Explicitly clear any transient intermediate errors
			resp.ServerID = serverID
			return &resp, rec, nil
		}
	}

	rec.Status = "TIMEOUT"
	rec.Error = "timeout waiting for valid response"
	rec.DurationMs = float64(time.Since(attemptStart).Microseconds()) / 1000.0
	rec.RcvdAtMonotonicMs = float64(time.Since(startOverall).Microseconds()) / 1000.0
	return nil, rec, errors.New("timeout waiting for valid response")
}

func (c *EmergencyDNSClient) attemptTCPExchange(
	ctx context.Context,
	resolverAddr string,
	qname string,
	expectedMsgID string,
) (*EmergencyResponse, error) {
	resp, _, err := c.attemptTCPExchangeWithRecord(ctx, 0, resolverAddr, qname, expectedMsgID, time.Now(), c.cfg.Timeout)
	return resp, err
}

func (c *EmergencyDNSClient) attemptTCPExchangeWithRecord(
	ctx context.Context,
	attemptIndex int,
	resolverAddr string,
	qname string,
	expectedMsgID string,
	startOverall time.Time,
	attemptTimeout time.Duration,
) (*EmergencyResponse, DNSQueryAttemptRecord, error) {
	attemptStart := time.Now()
	sentMonotonicMs := float64(attemptStart.Sub(startOverall).Microseconds()) / 1000.0

	rec := DNSQueryAttemptRecord{
		AttemptIndex:      attemptIndex,
		ResolverAddr:      resolverAddr,
		Protocol:          "tcp",
		SentAtMonotonicMs: sentMonotonicMs,
	}

	d := &net.Dialer{Timeout: attemptTimeout}
	conn, err := d.DialContext(ctx, "tcp", resolverAddr)
	if err != nil {
		rec.Status = "ERROR"
		rec.Error = fmt.Sprintf("tcp dial: %v", err)
		return nil, rec, fmt.Errorf("tcp dns fallback dial failed: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(attemptTimeout))

	txID := uint16(cryptoRandUint64())
	rec.TxID = txID
	queryPkt := BuildDNSQueryWithEDNS(qname, 0x0010 /* TXT */, txID, c.cfg.EDNSBufferSize)

	frameBuf := make([]byte, 2+len(queryPkt))
	binary.BigEndian.PutUint16(frameBuf[0:2], uint16(len(queryPkt)))
	copy(frameBuf[2:], queryPkt)

	if _, err := conn.Write(frameBuf); err != nil {
		rec.Status = "ERROR"
		rec.Error = err.Error()
		return nil, rec, fmt.Errorf("tcp dns write: %w", err)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		rec.Status = "ERROR"
		rec.Error = err.Error()
		return nil, rec, fmt.Errorf("tcp dns read len: %w", err)
	}
	respLen := binary.BigEndian.Uint16(lenBuf[:])
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		rec.Status = "ERROR"
		rec.Error = err.Error()
		return nil, rec, fmt.Errorf("tcp dns read packet: %w", err)
	}

	rcvdTime := time.Now()
	rec.DurationMs = float64(rcvdTime.Sub(attemptStart).Microseconds()) / 1000.0
	rec.RcvdAtMonotonicMs = float64(rcvdTime.Sub(startOverall).Microseconds()) / 1000.0

	if len(respBuf) < 12 {
		rec.Status = "ERROR"
		return nil, rec, errors.New("tcp dns: response too short")
	}

	respFlags := binary.BigEndian.Uint16(respBuf[2:4])
	rec.RCode = int(respFlags & 0x000F)

	txtAnswer, err := ParseDNSTXTResponse(respBuf)
	if err != nil || len(txtAnswer) < AsymmetricHeaderLen {
		rec.Status = "DROP"
		rec.Error = "invalid txt format"
		return nil, rec, fmt.Errorf("tcp dns parse txt: %w", err)
	}

	_, _, respPlaintext, serverID, err := c.session.openFrameWithServerID(txtAnswer)
	if err != nil {
		rec.Status = "AUTH_FAIL"
		rec.Error = err.Error()
		return nil, rec, fmt.Errorf("tcp dns auth frame: %w", err)
	}

	var resp EmergencyResponse
	if err := json.Unmarshal(respPlaintext, &resp); err != nil {
		rec.Status = "AUTH_FAIL"
		rec.Error = "unmarshal json: " + err.Error()
		return nil, rec, fmt.Errorf("tcp dns unmarshal json: %w", err)
	}

	if resp.ID == expectedMsgID {
		rec.Status = "SUCCESS"
		rec.Authenticated = true
		rec.ServerID = serverID
		rec.Error = "" // Explicitly clear any transient intermediate errors
		resp.ServerID = serverID
		return &resp, rec, nil
	}

	rec.Status = "AUTH_FAIL"
	rec.Error = "unexpected message id"
	return nil, rec, fmt.Errorf("tcp dns unexpected message id: got %s, want %s", resp.ID, expectedMsgID)
}

// GenerateEmergencyKey produces a fresh 32-byte cryptographically secure random key.
func GenerateEmergencyKey() []byte {
	k := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, k)
	return k
}

// GenerateRandomMessageID creates a collision-resistant 16-byte hex request ID.
func GenerateRandomMessageID() string {
	b := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, b)
	return fmt.Sprintf("msg-%s", hex.EncodeToString(b))
}

func cryptoRandUint64() uint64 {
	nBig, _ := rand.Int(rand.Reader, big.NewInt(0x7FFFFFFFFFFFFFFF))
	return uint64(nBig.Int64())
}
