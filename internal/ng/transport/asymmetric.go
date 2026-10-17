package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arashmh13/paqet-ngv2/internal/ng/crypto"
	"github.com/arashmh13/paqet-ngv2/internal/ng/replay"
)

const (
	// AsymmetricMagic identifies legacy v2 asymmetric transport frames ("PAQA").
	AsymmetricMagic uint32 = 0x50415141

	// AsymmetricMagicV3 identifies v3 asymmetric transport frames with explicit ServerID domain separation ("PAQC").
	AsymmetricMagicV3 uint32 = 0x50415143

	// respNonceBaseSize is the per-server-instance downstream nonce stream base size (v4 only).
	respNonceBaseSize = crypto.DownstreamNonceBaseSize

	// AsymmetricMagicV4 identifies v4 asymmetric transport frames ("PAQD"):
	// v3 framing plus a 16-byte authenticated per-session random seed that
	// randomizes the key/nonce domain independent of the 64-bit session ID
	// (probabilistic session-ID collision safety).
	AsymmetricMagicV4 uint32 = 0x50415144

	// AsymmetricHeaderLen is the fixed size of unencrypted v2 frame header:
	// Magic (4) + SessionID (8) + Seq (4) + Ack (4) = 20 bytes.
	AsymmetricHeaderLen = 20

	// AsymmetricHeaderV3MinLen is the minimum size of unencrypted v3 frame header:
	// Magic (4) + SessionID (8) + Seq (4) + Ack (4) + ServerIDLen (1) = 21 bytes.
	AsymmetricHeaderV3MinLen = 21

	// AsymmetricHeaderV4MinLen is the minimum size of unencrypted v4 frame header:
	// Magic (4) + SessionID (8) + Seq (4) + Ack (4) + SeedLen (1) = 21 bytes.
	// The seed (16 bytes) and optional ServerID field follow.
	AsymmetricHeaderV4MinLen = 21

	SessionSeedMagic = uint32(0x50415144)

	// DefaultAsymmetricMTU is the maximum payload size per chunk (120 bytes for DNS, 1380 for UDP).
	DefaultAsymmetricMTU = 1380

	// AsymmetricSessionTimeout is the period of inactivity before tearing down an asymmetric session.
	AsymmetricSessionTimeout = 60 * time.Second

	// DefaultRTO is the retransmission timeout for unacknowledged frames over lossy channels.
	DefaultRTO = 600 * time.Millisecond

	// MaxRetries is the maximum retransmission attempts before marking frame dropped.
	MaxRetries = 8

	// MaxSafeSequenceNumber is the sequence number limit before terminating the session to prevent 32-bit nonce wraparound.
	MaxSafeSequenceNumber uint32 = 0xFFFFFFF0
)

var (
	ErrAsymmetricInvalidMagic   = errors.New("asymmetric: invalid magic header")
	ErrAsymmetricSessionClosed  = errors.New("asymmetric: session is closed")
	ErrAsymmetricShortFrame     = errors.New("asymmetric: frame too short")
	ErrAsymmetricWindowOverflow = errors.New("asymmetric: receive window overflow")
	ErrSequenceExhausted        = errors.New("asymmetric: sequence number space exhausted, session must terminate to prevent nonce reuse")
	ErrInvalidServerID          = errors.New("asymmetric: invalid server ID format")
	ErrEmptyServerAllowlist     = errors.New("asymmetric: authorized servers allowlist cannot be empty (fail-closed)")
	ErrLegacyProtocolDisabled   = errors.New("asymmetric: legacy v2 protocol frames are disabled by policy (v3 required)")
	ErrMissingResponseSecret    = errors.New("asymmetric: dedicated per-server response secret is required (shared PSK fallback prohibited)")
	ErrInvalidResponseSecret    = errors.New("asymmetric: response secret must be exactly 32 bytes")
	ErrProtocolVersionSignature = errors.New("asymmetric: frame protocol version unsupported (seed lengths incompatible) - PAQD explicit reject")
	ErrReplayDomainCapacity     = errors.New("asymmetric: downstream replay-domain capacity exhausted, session sealed (fail-closed; a new authenticated session is required)")
)

type unackedFrame struct {
	seq     uint32
	frame   []byte
	sentAt  time.Time
	retries int
}

// Role indicates whether the node is a client (initiator) or server (responder).
type Role uint8

const (
	RoleClient Role = 1
	RoleServer Role = 2
)

// UpstreamSender is the interface for transmitting client-to-server datagrams.
type UpstreamSender interface {
	SendUpstream(ctx context.Context, frame []byte) error
	Close() error
}

// DownstreamReceiver is the interface for receiving server-to-client datagrams.
type DownstreamReceiver interface {
	RecvDownstream(ctx context.Context) ([]byte, error)
	Close() error
}

// DownstreamSender is the server-side interface for returning datagrams to the client.
type DownstreamSender interface {
	SendDownstream(ctx context.Context, clientAddr net.Addr, frame []byte) error
	Close() error
}

// UpstreamReceiver is the server-side interface for receiving client datagrams.
type UpstreamReceiver interface {
	RecvUpstream(ctx context.Context) ([]byte, net.Addr, error)
	Close() error
}

// ValidateServerID validates that serverID is canonically formatted (3-64 chars, lowercase alphanumeric, '-', '.', or '_').
func ValidateServerID(id string) error {
	if len(id) < 3 || len(id) > 64 {
		return fmt.Errorf("%w: length %d must be between 3 and 64 characters", ErrInvalidServerID, len(id))
	}
	for i := 0; i < len(id); i++ {
		b := id[i]
		if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' || b == '.' || b == '_') {
			return fmt.Errorf("%w: invalid character %q (must be lowercase alphanumeric, '-', '.', or '_')", ErrInvalidServerID, b)
		}
	}
	return nil
}

// AsymmetricConn implements net.Conn over directionally decoupled upstream and downstream transports.
type AsymmetricConn struct {
	sessionID            uint64
	role                 Role
	serverID             string            // Cryptographic server ID (immutable once derived)
	serverSecret         []byte            // Dedicated server response secret (immutable)
	authorizedServers    map[string][]byte // Client-side map: serverID -> 32-byte response secret (immutable)
	allowLegacyV2        bool              // If false, rejects 0x50415141 frames (fail-closed)
	isLegacySingleServer bool              // If true, operates in legacy single-server mode using PSK only
	protoV4              bool              // If true, seals/verifies v4 ("PAQD") frames carrying a per-session random seed
	sessionSeed          []byte            // v4 only: 16-byte per-session random seed mixed into the HKDF salt (immutable)
	respNonceBase        []byte            // v4 server only: per-server-session random 8-byte downstream nonce/key base (immutable)
	replayDomainSealed   atomic.Bool       // v4 client only: set once replay-domain capacity is exhausted; all further downstream frames fail closed
	authEpoch            string            // v4 client only: credential epoch label from AuthorizedServerSet (safe metadata)
	mtu                  int
	psk                  []byte
	encKey               []byte
	decKey               []byte
	sendSeq              atomic.Uint32
	lastAckRcv           atomic.Uint32
	nextRecv             atomic.Uint32

	sender       UpstreamSender
	receiver     DownstreamReceiver
	replay       *replay.Filter
	serverReplay map[string]*replay.Filter
	replayMu     sync.Mutex

	pipeR *io.PipeReader
	pipeW *io.PipeWriter

	reorderMu sync.Mutex
	reorder   map[uint32][]byte // out-of-order received payloads

	localAddr  net.Addr
	remoteAddr net.Addr

	unackedMu sync.Mutex
	unacked   map[uint32]*unackedFrame
	rto       time.Duration

	ctx    context.Context
	cancel context.CancelFunc

	readDeadline  time.Time
	writeDeadline time.Time
}

// NewClientAsymmetricConn creates an asymmetric net.Conn from separate upstream and downstream channels.
func NewClientAsymmetricConn(
	sessionID uint64,
	psk []byte,
	mtu int,
	sender UpstreamSender,
	receiver DownstreamReceiver,
	localAddr net.Addr,
	remoteAddr net.Addr,
) (*AsymmetricConn, error) {
	if mtu <= 0 {
		mtu = DefaultAsymmetricMTU
	}
	if len(psk) != crypto.KeySize {
		return nil, crypto.ErrInvalidKey
	}

	salt := []byte(fmt.Sprintf("paqet-asym-%d", sessionID))
	c2s, s2c, err := crypto.DeriveLegacySingleServerTrafficKeys(psk, salt)
	if err != nil {
		return nil, fmt.Errorf("derive keys: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	pipeR, pipeW := io.Pipe()

	conn := &AsymmetricConn{
		sessionID:            sessionID,
		role:                 RoleClient,
		mtu:                  mtu,
		psk:                  psk,
		encKey:               c2s, // client encrypts with c2s
		decKey:               s2c, // client decrypts with s2c
		allowLegacyV2:        true,
		isLegacySingleServer: true,
		sender:               sender,
		receiver:             receiver,
		replay:               replay.NewFilter(30 * time.Second),
		pipeR:                pipeR,
		pipeW:                pipeW,
		reorder:              make(map[uint32][]byte),
		unacked:              make(map[uint32]*unackedFrame),
		rto:                  DefaultRTO,
		localAddr:            localAddr,
		remoteAddr:           remoteAddr,
		ctx:                  ctx,
		cancel:               cancel,
	}

	go conn.recvLoop()
	go conn.retransmitLoop()
	return conn, nil
}

// Write fragments and encrypts application data, emitting it across the upstream transport.
func (c *AsymmetricConn) Write(b []byte) (int, error) {
	select {
	case <-c.ctx.Done():
		return 0, ErrAsymmetricSessionClosed
	default:
	}

	totalSent := 0
	offset := 0

	for offset < len(b) {
		chunkSize := len(b) - offset
		if chunkSize > c.mtu {
			chunkSize = c.mtu
		}
		chunk := b[offset : offset+chunkSize]

		if c.sendSeq.Load() >= 0xFFFFFFF0 {
			return totalSent, ErrSequenceExhausted
		}
		seq := c.sendSeq.Add(1)
		if seq == 0 || seq >= 0xFFFFFFF0 {
			return totalSent, ErrSequenceExhausted
		}
		ack := c.nextRecv.Load()

		frame, err := c.sealFrame(seq, ack, chunk)
		if err != nil {
			return totalSent, fmt.Errorf("seal frame %d: %w", seq, err)
		}

		c.unackedMu.Lock()
		if c.unacked != nil {
			c.unacked[seq] = &unackedFrame{
				seq:    seq,
				frame:  frame,
				sentAt: time.Now(),
			}
		}
		c.unackedMu.Unlock()

		if err := c.sender.SendUpstream(c.ctx, frame); err != nil {
			return totalSent, fmt.Errorf("send upstream seq %d: %w", seq, err)
		}

		offset += chunkSize
		totalSent += chunkSize
	}

	return totalSent, nil
}

// Read reads in-order application payload reassembled from the downstream transport.
func (c *AsymmetricConn) Read(b []byte) (int, error) {
	return c.pipeR.Read(b)
}

// Close terminates the asymmetric session and underlying transports.
func (c *AsymmetricConn) Close() error {
	c.cancel()
	_ = c.pipeW.Close()
	_ = c.pipeR.Close()
	var errs []error
	if c.sender != nil {
		if err := c.sender.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.receiver != nil {
		if err := c.receiver.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (c *AsymmetricConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *AsymmetricConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *AsymmetricConn) SetDeadline(t time.Time) error      { return nil }
func (c *AsymmetricConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *AsymmetricConn) SetWriteDeadline(t time.Time) error { return nil }

// SealFrame provides public access to sealFrame for emergency datagram channels.
func (c *AsymmetricConn) SealFrame(seq, ack uint32, plaintext []byte) ([]byte, error) {
	return c.sealFrame(seq, ack, plaintext)
}

// OpenFrame provides public access to openFrame for emergency datagram channels.
func (c *AsymmetricConn) OpenFrame(frame []byte) (seq, ack uint32, plaintext []byte, err error) {
	return c.openFrame(frame)
}

// SessionID returns the active session ID.
func (c *AsymmetricConn) SessionID() uint64 {
	return c.sessionID
}

// NextSendSeq advances and returns the next sequence number, or returns ErrSequenceExhausted before wraparound.
func (c *AsymmetricConn) NextSendSeq() (uint32, error) {
	for {
		curr := c.sendSeq.Load()
		if curr >= MaxSafeSequenceNumber {
			return 0, ErrSequenceExhausted
		}
		next := curr + 1
		if next == 0 || next >= MaxSafeSequenceNumber {
			return 0, ErrSequenceExhausted
		}
		if c.sendSeq.CompareAndSwap(curr, next) {
			return next, nil
		}
	}
}

// SetSendSeqForTest allows deterministic testing of sequence boundaries without running billions of iterations.
func (c *AsymmetricConn) SetSendSeqForTest(seq uint32) {
	c.sendSeq.Store(seq)
}

// SetAllowLegacyV2ForTest allows explicitly enabling legacy v2 support for migration tests.
func (c *AsymmetricConn) SetAllowLegacyV2ForTest(allow bool) {
	c.allowLegacyV2 = allow
}

// ServerID returns the configured server ID for this connection.
func (c *AsymmetricConn) ServerID() string {
	return c.serverID
}

// NewServerAsymmetricSession creates an AsymmetricConn configured as RoleServer for explicit single-server legacy mode.
// For multi-authoritative deployments, use NewServerAsymmetricSessionWithID with dedicated credentials.
func NewServerAsymmetricSession(sessionID uint64, psk []byte) (*AsymmetricConn, error) {
	return NewServerLegacyAsymmetricSession(sessionID, psk)
}

// NewServerLegacyAsymmetricSession creates an AsymmetricConn for explicit single-server legacy operation using PSK only.
// This mode is visibly separate and cannot be selected implicitly by a multi-authoritative configuration.
func NewServerLegacyAsymmetricSession(sessionID uint64, psk []byte) (*AsymmetricConn, error) {
	if len(psk) != crypto.KeySize {
		return nil, crypto.ErrInvalidKey
	}
	pskClone := append([]byte(nil), psk...)
	salt := []byte(fmt.Sprintf("paqet-asym-%d", sessionID))
	c2s, s2c, err := crypto.DeriveLegacySingleServerTrafficKeys(pskClone, salt)
	if err != nil {
		return nil, fmt.Errorf("derive legacy server keys: %w", err)
	}

	return &AsymmetricConn{
		sessionID:            sessionID,
		role:                 RoleServer,
		serverID:             "legacy",
		serverSecret:         pskClone,
		psk:                  pskClone,
		encKey:               s2c,
		decKey:               c2s,
		allowLegacyV2:        true,
		isLegacySingleServer: true,
		replay:               replay.NewFilter(30 * time.Second),
	}, nil
}

// NewServerAsymmetricSessionWithID creates an AsymmetricConn configured as RoleServer for multi-authoritative operation
// with an explicit, immutable ServerID and a mandatory dedicated 32-byte response secret.
// No fallback to PSK is permitted.
func NewServerAsymmetricSessionWithID(sessionID uint64, c2sPSK []byte, serverResponseSecret []byte, serverID string) (*AsymmetricConn, error) {
	if serverID == "" {
		return nil, fmt.Errorf("server session requires non-empty serverID")
	}
	if serverID == "default" || serverID == "legacy" {
		return nil, fmt.Errorf("server session cannot use reserved ID %q in multi-server mode", serverID)
	}
	if err := ValidateServerID(serverID); err != nil {
		return nil, err
	}
	if len(c2sPSK) != crypto.KeySize {
		return nil, crypto.ErrInvalidKey
	}
	if len(serverResponseSecret) == 0 {
		return nil, ErrMissingResponseSecret
	}
	if len(serverResponseSecret) != crypto.KeySize {
		return nil, ErrInvalidResponseSecret
	}

	// Defensive copy of secret slices to prevent caller mutations after construction
	pskClone := append([]byte(nil), c2sPSK...)
	secretClone := append([]byte(nil), serverResponseSecret...)

	salt := []byte(fmt.Sprintf("paqet-asym-%d", sessionID))
	c2s, s2c, err := crypto.DeriveServerTrafficKeys(pskClone, secretClone, salt, serverID)
	if err != nil {
		return nil, fmt.Errorf("derive server keys: %w", err)
	}

	return &AsymmetricConn{
		sessionID:            sessionID,
		role:                 RoleServer,
		serverID:             serverID,
		serverSecret:         secretClone,
		psk:                  pskClone,
		encKey:               s2c, // server encrypts with s2c bound to serverResponseSecret + serverID
		decKey:               c2s, // server decrypts with c2s
		allowLegacyV2:        false,
		isLegacySingleServer: false,
		replay:               replay.NewFilter(30 * time.Second),
	}, nil
}

// AuthorizedServerEntry describes an authorized server for the client-side verification map.
type AuthorizedServerEntry struct {
	ServerID       string
	ResponseSecret []byte // 32-byte server-specific response secret (mandatory)
}

// NewClientAsymmetricSession creates an AsymmetricConn configured as RoleClient for explicit single-server legacy mode.
// For multi-authoritative deployments, use NewClientAsymmetricSessionWithServers.
func NewClientAsymmetricSession(sessionID uint64, psk []byte) (*AsymmetricConn, error) {
	return NewClientLegacyAsymmetricSession(sessionID, psk)
}

// NewClientLegacyAsymmetricSession creates an AsymmetricConn configured as RoleClient for explicit single-server legacy operation.
func NewClientLegacyAsymmetricSession(sessionID uint64, psk []byte) (*AsymmetricConn, error) {
	if len(psk) != crypto.KeySize {
		return nil, crypto.ErrInvalidKey
	}
	pskClone := append([]byte(nil), psk...)
	salt := []byte(fmt.Sprintf("paqet-asym-%d", sessionID))
	c2s, s2c, err := crypto.DeriveLegacySingleServerTrafficKeys(pskClone, salt)
	if err != nil {
		return nil, fmt.Errorf("derive legacy client keys: %w", err)
	}

	return &AsymmetricConn{
		sessionID:            sessionID,
		role:                 RoleClient,
		serverID:             "legacy",
		psk:                  pskClone,
		encKey:               c2s,
		decKey:               s2c,
		authorizedServers:    map[string][]byte{"legacy": pskClone, "default": pskClone},
		allowLegacyV2:        true,
		isLegacySingleServer: true,
		replay:               replay.NewFilter(30 * time.Second),
	}, nil
}

// NewClientAsymmetricSessionWithServers creates an AsymmetricConn configured as RoleClient with an explicit,
// nonempty set of authorized server identities and their corresponding dedicated 32-byte response secrets.
// The client will ONLY accept v3 responses from servers in this authorized set. Legacy v2 frames are rejected.
func NewClientAsymmetricSessionWithServers(sessionID uint64, c2sPSK []byte, servers []AuthorizedServerEntry) (*AsymmetricConn, error) {
	if len(servers) == 0 {
		return nil, ErrEmptyServerAllowlist
	}
	if len(c2sPSK) != crypto.KeySize {
		return nil, crypto.ErrInvalidKey
	}

	pskClone := append([]byte(nil), c2sPSK...)
	authMap := make(map[string][]byte)
	for _, s := range servers {
		if s.ServerID == "" {
			return nil, fmt.Errorf("authorized server entry has empty serverID")
		}
		if s.ServerID == "default" || s.ServerID == "legacy" {
			return nil, fmt.Errorf("authorized server cannot use reserved ID %q", s.ServerID)
		}
		if err := ValidateServerID(s.ServerID); err != nil {
			return nil, err
		}
		if len(s.ResponseSecret) == 0 {
			return nil, fmt.Errorf("server %q: %w", s.ServerID, ErrMissingResponseSecret)
		}
		if len(s.ResponseSecret) != crypto.KeySize {
			return nil, fmt.Errorf("server %q: %w", s.ServerID, ErrInvalidResponseSecret)
		}
		if _, dup := authMap[s.ServerID]; dup {
			return nil, fmt.Errorf("duplicate authorized server ID %q (fail-closed)", s.ServerID)
		}
		// Defensive copy of secret slice to prevent caller mutations after construction
		secretClone := append([]byte(nil), s.ResponseSecret...)
		authMap[s.ServerID] = secretClone
	}

	salt := []byte(fmt.Sprintf("paqet-asym-%d", sessionID))
	c2s, _, err := crypto.DeriveServerTrafficKeys(pskClone, servers[0].ResponseSecret, salt, servers[0].ServerID)
	if err != nil {
		return nil, fmt.Errorf("derive client c2s key: %w", err)
	}

	return &AsymmetricConn{
		sessionID:            sessionID,
		role:                 RoleClient,
		psk:                  pskClone,
		encKey:               c2s,
		authorizedServers:    authMap,
		allowLegacyV2:        false,
		isLegacySingleServer: false,
		replay:               replay.NewFilter(30 * time.Second),
	}, nil
}

// SessionSeed is the per-session 16-byte random keying-material seed for the
// v4 wire protocol ("PAQD"). The seed travels inside every frame as
// authenticated associated data (it is NOT a secret) and is mixed into the
// HKDF salt, so key and nonce domains are randomized independently of the
// 64-bit session identifier. This collapses the per-credential-epoch session
// collision bound from ~n^2/2^65 (v3) to ~n^2/2^129 (v4).
type SessionSeed = [crypto.SessionSeedSize]byte

// AuthorizedServerSet is the canonical immutable client-side authorization set
// used by v4 construction paths. It is validated and deep-cloned at
// construction time; later mutation of caller-owned slices cannot affect it.
type AuthorizedServerSet struct {
	Epoch      string            // Credential generation label (e.g. "epoch-2026-10-16-a")
	Generation uint64            // Monotonic configuration revision
	servers    map[string][]byte // serverID -> 32-byte cloned response secret
	order      []string          // Deterministic iteration order
}

// NewAuthorizedServerSet validates and clones a set of authorized server entries.
// Rejects empty sets, empty/reserved/duplicate/invalid server IDs, and missing
// or malformed response secrets. The shared c2s PSK is never accepted as a
// per-server response credential.
func NewAuthorizedServerSet(epoch string, servers []AuthorizedServerEntry) (*AuthorizedServerSet, error) {
	if len(servers) == 0 {
		return nil, ErrEmptyServerAllowlist
	}
	set := &AuthorizedServerSet{
		Epoch:   epoch,
		servers: make(map[string][]byte, len(servers)),
		order:   make([]string, 0, len(servers)),
	}
	for _, s := range servers {
		if s.ServerID == "" {
			return nil, fmt.Errorf("authorized server entry has empty serverID")
		}
		if s.ServerID == "default" || s.ServerID == "legacy" {
			return nil, fmt.Errorf("authorized server cannot use reserved ID %q", s.ServerID)
		}
		if err := ValidateServerID(s.ServerID); err != nil {
			return nil, err
		}
		if len(s.ResponseSecret) == 0 {
			return nil, fmt.Errorf("server %q: %w", s.ServerID, ErrMissingResponseSecret)
		}
		if len(s.ResponseSecret) != crypto.KeySize {
			return nil, fmt.Errorf("server %q: %w", s.ServerID, ErrInvalidResponseSecret)
		}
		if _, dup := set.servers[s.ServerID]; dup {
			return nil, fmt.Errorf("duplicate authorized server ID %q (fail-closed)", s.ServerID)
		}
		set.servers[s.ServerID] = append([]byte(nil), s.ResponseSecret...)
		set.order = append(set.order, s.ServerID)
	}
	return set, nil
}

// ServerIDs returns a deterministic copy of the authorized server IDs.
func (s *AuthorizedServerSet) ServerIDs() []string {
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// ServerCount returns the number of authorized servers.
func (s *AuthorizedServerSet) ServerCount() int {
	return len(s.order)
}

// aeadNonce constructs the 12-byte AES-GCM nonce for a frame sealed by senderRole.
// Behavior-preserving capture of the Phase-18 calculation (SessionID||Seq with role
// XOR); the v4 server-downstream per-session stream base is layered on later and is
// validated until the replay-after-restart regression test forces the redesign.
func (c *AsymmetricConn) aeadNonce(seq uint32, senderRole Role, streamBase []byte) [crypto.NonceSize]byte {
	var nonce [crypto.NonceSize]byte
	if senderRole == RoleServer && len(streamBase) == respNonceBaseSize {
		// v4 downstream (server->client): per-session-instance random stream base.
		copy(nonce[0:respNonceBaseSize], streamBase)
	} else {
		// Upstream and v2/v3 frames: deterministic SessionID prefix.
		binary.BigEndian.PutUint64(nonce[0:8], c.sessionID)
	}
	binary.BigEndian.PutUint32(nonce[respNonceBaseSize:12], seq)
	nonce[0] ^= byte(senderRole)
	return nonce
}

// SecretFor returns the cloned 32-byte response secret for serverID, or nil if unauthorized.
func (s *AuthorizedServerSet) SecretFor(serverID string) []byte {
	sec, ok := s.servers[serverID]
	if !ok {
		return nil
	}
	return append([]byte(nil), sec...)
}

// EpochLine renders safe, non-secret metadata: epoch label and authorized server IDs.
func (s *AuthorizedServerSet) EpochLine() string {
	return fmt.Sprintf("epoch=%s servers=%v", s.Epoch, s.ServerIDs())
}

// NewClientAsymmetricSessionV4 creates a v4 ("PAQD") client session in which:
//   - The client generates a fresh 128-bit random sessionSeed and (default)
//     full-entropy 64-bit sessionID; both travel as authenticated header data
//     and are mixed into the HKDF salt, so key and nonce domains are
//     statistically unique per session even under a 64-bit session-ID collision.
//   - Authorized servers come from an immutable AuthorizedServerSet (mandatory,
//     nonempty, validated, deep-cloned). Legacy v2 frames are rejected.
//   - The upstream key is derived from the shared c2s PSK via the v4 salt; the
//     downstream response key for a given serverID is derived on demand from
//     that server's dedicated 32-byte response secret via the v4 salt.
//
// Passing overrideSeed forces a deterministic session taxonomy for tests.
// Passing nil pskSecretForTest is invalid; a real c2s PSK is always required.
func NewClientAsymmetricSessionV4(sessionID uint64, c2sPSK []byte, set *AuthorizedServerSet, overrideSeed *[crypto.SessionSeedSize]byte) (*AsymmetricConn, error) {
	if set == nil || set.ServerCount() == 0 {
		return nil, ErrEmptyServerAllowlist
	}
	if len(c2sPSK) != crypto.KeySize {
		return nil, crypto.ErrInvalidKey
	}
	seed := [crypto.SessionSeedSize]byte{}
	if overrideSeed != nil {
		seed = *overrideSeed
	} else {
		generated, err := crypto.GenerateSessionSeed()
		if err != nil {
			return nil, fmt.Errorf("generate session seed: %w", err)
		}
		seed = generated
	}
	if sessionID == 0 {
		return nil, fmt.Errorf("asymmetric: v4 client requires explicit nonzero sessionID (full-entropy generation happens at call site)")
	}

	c2s, err := crypto.DeriveV4ClientTrafficKey(c2sPSK, seed[:], sessionID)
	if err != nil {
		return nil, fmt.Errorf("derive v4 c2s key: %w", err)
	}

	c := &AsymmetricConn{
		sessionID:            sessionID,
		role:                 RoleClient,
		psk:                  append([]byte(nil), c2sPSK...),
		encKey:               c2s,
		authorizedServers:    make(map[string][]byte, set.ServerCount()),
		allowLegacyV2:        false,
		isLegacySingleServer: false,
		protoV4:              true,
		sessionSeed:          append([]byte(nil), seed[:]...),
		authEpoch:            set.Epoch,
		replay:               replay.NewFilter(30 * time.Second),
	}
	for id, sec := range set.servers {
		c.authorizedServers[id] = append([]byte(nil), sec...)
	}
	return c, nil
}

// NewServerAsymmetricSessionWithIDV4 creates a v4 ("PAQD") server session bound
// to an immutable canonical ServerID, a mandatory dedicated 32-byte response
// secret, and the per-session random seed received from the client upstream
// frame. The response key is derived from the dedicated secret under the v4
// salt; it may not fall back to the shared PSK.
func NewServerAsymmetricSessionWithIDV4(sessionID uint64, c2sPSK []byte, serverResponseSecret []byte, sessionSeed []byte, serverID string) (*AsymmetricConn, error) {
	if serverID == "" {
		return nil, fmt.Errorf("server session requires non-empty serverID")
	}
	if serverID == "default" || serverID == "legacy" {
		return nil, fmt.Errorf("server session cannot use reserved ID %q in multi-server mode", serverID)
	}
	if err := ValidateServerID(serverID); err != nil {
		return nil, err
	}
	if len(c2sPSK) != crypto.KeySize {
		return nil, crypto.ErrInvalidKey
	}
	if len(serverResponseSecret) == 0 {
		return nil, ErrMissingResponseSecret
	}
	if len(serverResponseSecret) != crypto.KeySize {
		return nil, ErrInvalidResponseSecret
	}
	if len(sessionSeed) != crypto.SessionSeedSize {
		return nil, fmt.Errorf("asymmetric: v4 session seed must be exactly %d bytes, got %d", crypto.SessionSeedSize, len(sessionSeed))
	}

	secretClone := append([]byte(nil), serverResponseSecret...)

	// Per-server-session downstream nonce/key base: generated once here and bound
	// into BOTH the s2c HKDF salt and the response frame header, so a restarted
	// server with identical long-term credentials gets a fresh base and replayed
	// captured requests can never reproduce the previous response key/nonce domain
	// for new plaintexts.
	rnb, genErr := crypto.GenerateDownstreamNonceBase()
	if genErr != nil {
		return nil, fmt.Errorf("generate v4 server-session nonce/key base: %w", genErr)
	}
	c2s, s2c, err := crypto.DeriveServerTrafficKeysV4(c2sPSK, secretClone, sessionSeed, sessionID, serverID, rnb)
	if err != nil {
		return nil, fmt.Errorf("derive v4 server keys: %w", err)
	}

	return &AsymmetricConn{
		sessionID:            sessionID,
		role:                 RoleServer,
		serverID:             serverID,
		serverSecret:         secretClone,
		psk:                  append([]byte(nil), c2sPSK...),
		encKey:               s2c,
		decKey:               c2s,
		allowLegacyV2:        false,
		isLegacySingleServer: false,
		protoV4:              true,
		sessionSeed:          append([]byte(nil), sessionSeed...),
		respNonceBase:        rnb,
		replay:               replay.NewFilter(30 * time.Second),
	}, nil
}

// sealFrame packs Magic, SessionID, Seq, Ack, and AEAD-encrypted payload into a wire datagram.
// v4 sessions additionally authenticate a 16-byte per-session random seed (PAQD framing).
func (c *AsymmetricConn) sealFrame(seq, ack uint32, plaintext []byte) ([]byte, error) {
	if seq >= MaxSafeSequenceNumber {
		return nil, ErrSequenceExhausted
	}
	if c.protoV4 && len(c.sessionSeed) != crypto.SessionSeedSize {
		return nil, fmt.Errorf("%w: v4 session seed missing or mis-sized", ErrProtocolVersionSignature)
	}

	var header []byte
	if c.protoV4 {
		// v4 ("PAQD"): Magic(4) + SessionID(8) + Seq(4) + Ack(4) + SeedLen(1) = 21
		// then Seed(16), then ServerIDLen(1) [always present, 0 on client frames], then ServerID.
		headerLen := AsymmetricHeaderV4MinLen + crypto.SessionSeedSize + 1
		srvID := ""
		if c.role == RoleServer {
			srvID = c.serverID
			if srvID == "" {
				return nil, fmt.Errorf("v4 server frame requires an explicit serverID")
			}
			if len(srvID) > 64 {
				return nil, errors.New("asymmetric: serverID exceeds 64 bytes limit")
			}
			headerLen += len(srvID)
		}
		if c.role == RoleServer && len(c.respNonceBase) != respNonceBaseSize {
			return nil, fmt.Errorf("%w: v4 server session missing downstream nonce stream base", ErrProtocolVersionSignature)
		}
		if c.role == RoleServer {
			// Server downstream frames append the authenticated per-instance stream base.
			headerLen += 1 + respNonceBaseSize
		}
		header = make([]byte, headerLen)
		binary.BigEndian.PutUint32(header[0:4], AsymmetricMagicV4)
		binary.BigEndian.PutUint64(header[4:12], c.sessionID)
		binary.BigEndian.PutUint32(header[12:16], seq)
		binary.BigEndian.PutUint32(header[16:20], ack)
		header[20] = byte(crypto.SessionSeedSize)
		copy(header[21:21+crypto.SessionSeedSize], c.sessionSeed)
		off := 21 + crypto.SessionSeedSize
		header[off] = byte(len(srvID))
		copy(header[off+1:], srvID)
		if c.role == RoleServer {
			off += 1 + len(srvID)
			header[off] = byte(respNonceBaseSize)
			copy(header[off+1:], c.respNonceBase)
		}
	} else if c.role == RoleServer {
		srvID := c.serverID
		if srvID == "" {
			srvID = "default"
		}
		if len(srvID) > 64 {
			return nil, errors.New("asymmetric: serverID exceeds 64 bytes limit")
		}
		header = make([]byte, AsymmetricHeaderV3MinLen+len(srvID))
		binary.BigEndian.PutUint32(header[0:4], AsymmetricMagicV3)
		binary.BigEndian.PutUint64(header[4:12], c.sessionID)
		binary.BigEndian.PutUint32(header[12:16], seq)
		binary.BigEndian.PutUint32(header[16:20], ack)
		header[20] = byte(len(srvID))
		copy(header[21:], srvID)
	} else {
		// Client upstream v3 frame: ServerIDLen = 0
		header = make([]byte, AsymmetricHeaderV3MinLen)
		binary.BigEndian.PutUint32(header[0:4], AsymmetricMagicV3)
		binary.BigEndian.PutUint64(header[4:12], c.sessionID)
		binary.BigEndian.PutUint32(header[12:16], seq)
		binary.BigEndian.PutUint32(header[16:20], ack)
		header[20] = 0 // No server ID in upstream
	}

	// Nonce construction: deterministically SessionID||Seq for v2/v3 and for v4
	// client-upstream frames; v4 server-downstream frames use a per-session random
	// 8-byte stream base (see respNonceBase). Role byte XOR keeps client/server
	// nonce domains disjoint under any shared base.
	var streamBase []byte
	if c.role == RoleServer {
		streamBase = c.respNonceBase
	}
	nonce := c.aeadNonce(seq, c.role, streamBase)
	aead, err := crypto.NewAEAD(c.encKey)
	if err != nil {
		return nil, err
	}

	// Encrypt plaintext with header authenticated as AAD
	ciphertext := aead.Seal(nil, nonce[:], plaintext, header)

	frame := make([]byte, len(header)+len(ciphertext))
	copy(frame[:len(header)], header)
	copy(frame[len(header):], ciphertext)
	return frame, nil
}

// VerifyFrameWithServerID cryptographically verifies the frame's header, magic, session ID,
// and AEAD authentication tag, returning the decrypted plaintext and authenticating ServerID.
func (c *AsymmetricConn) VerifyFrameWithServerID(frame []byte) (seq, ack uint32, plaintext []byte, serverID string, err error) {
	if len(frame) < AsymmetricHeaderLen+crypto.TagSize {
		return 0, 0, nil, "", ErrAsymmetricShortFrame
	}

	magic := binary.BigEndian.Uint32(frame[0:4])
	var headerLen int
	var sessID uint64
	var frameSeed []byte
	var frameRNB []byte

	switch magic {
	case AsymmetricMagicV4:
		// v4 ("PAQD"): Magic(4)+SessionID(8)+Seq(4)+Ack(4)+SeedLen(1)=21, Seed(16), then ServerIDLen(1)+ServerID (server frames only).
		if !c.isLegacySingleServer || c.protoV4 {
			// v4 frames are only accepted by v4 sessions (multi-server mode).
			if !c.protoV4 {
				return 0, 0, nil, "", fmt.Errorf("%w: v4 frame on non-v4 session", ErrProtocolVersionSignature)
			}
		}
		if len(frame) < AsymmetricHeaderV4MinLen+crypto.TagSize {
			return 0, 0, nil, "", ErrAsymmetricShortFrame
		}
		sessID = binary.BigEndian.Uint64(frame[4:12])
		seq = binary.BigEndian.Uint32(frame[12:16])
		ack = binary.BigEndian.Uint32(frame[16:20])
		seedLen := int(frame[20])
		if seedLen != crypto.SessionSeedSize {
			return 0, 0, nil, "", fmt.Errorf("%w: v4 seed length %d (want %d)", ErrProtocolVersionSignature, seedLen, crypto.SessionSeedSize)
		}
		// Room for seed + the always-present ServerIDLen slot + AEAD tag
		headerLen = AsymmetricHeaderV4MinLen + seedLen
		if len(frame) < headerLen+1+crypto.TagSize {
			return 0, 0, nil, "", ErrAsymmetricShortFrame
		}
		frameSeed = append([]byte(nil), frame[21:21+seedLen]...)
		headerLen++ // consume the ServerIDLen slot
		srvIDLen := int(frame[headerLen-1])
		if srvIDLen > 0 {
			if len(frame) < headerLen+srvIDLen+crypto.TagSize {
				return 0, 0, nil, "", ErrAsymmetricShortFrame
			}
			serverID = string(frame[headerLen : headerLen+srvIDLen])
			headerLen += srvIDLen
		}
		if c.role == RoleClient {
			// Downstream (server->client) frames carry the per-instance nonce stream base.
			if len(frame) < headerLen+1+crypto.TagSize {
				return 0, 0, nil, "", ErrAsymmetricShortFrame
			}
			rnbLen := int(frame[headerLen])
			headerLen++
			if rnbLen != crypto.DownstreamNonceBaseSize {
				return 0, 0, nil, "", fmt.Errorf("%w: v4 downstream nonce base length %d (want %d)", ErrProtocolVersionSignature, rnbLen, crypto.DownstreamNonceBaseSize)
			}
			if len(frame) < headerLen+rnbLen+crypto.TagSize {
				return 0, 0, nil, "", ErrAsymmetricShortFrame
			}
			frameRNB = append([]byte(nil), frame[headerLen:headerLen+rnbLen]...)
			headerLen += rnbLen
			zero := true
			for _, b := range frameRNB {
				if b != 0 {
					zero = false
					break
				}
			}
			if zero {
				return 0, 0, nil, "", fmt.Errorf("%w: degenerate all-zero downstream nonce base", ErrProtocolVersionSignature)
			}
		}

	case AsymmetricMagicV3:
		if len(frame) < AsymmetricHeaderV3MinLen+crypto.TagSize {
			return 0, 0, nil, "", ErrAsymmetricShortFrame
		}
		if c.protoV4 {
			return 0, 0, nil, "", fmt.Errorf("%w: v3 frame on v4 session", ErrProtocolVersionSignature)
		}
		sessID = binary.BigEndian.Uint64(frame[4:12])
		seq = binary.BigEndian.Uint32(frame[12:16])
		ack = binary.BigEndian.Uint32(frame[16:20])
		srvIDLen := int(frame[20])
		headerLen = AsymmetricHeaderV3MinLen + srvIDLen
		if len(frame) < headerLen+crypto.TagSize {
			return 0, 0, nil, "", ErrAsymmetricShortFrame
		}
		if srvIDLen > 0 {
			serverID = string(frame[21 : 21+srvIDLen])
		}

	case AsymmetricMagic:
		// Legacy v2 frame
		if !c.allowLegacyV2 {
			return 0, 0, nil, "", ErrLegacyProtocolDisabled
		}
		sessID = binary.BigEndian.Uint64(frame[4:12])
		seq = binary.BigEndian.Uint32(frame[12:16])
		ack = binary.BigEndian.Uint32(frame[16:20])
		headerLen = AsymmetricHeaderLen
		serverID = "legacy"

	default:
		return 0, 0, nil, "", ErrAsymmetricInvalidMagic
	}

	if sessID != c.sessionID {
		return 0, 0, nil, "", fmt.Errorf("session ID mismatch: got %d, want %d", sessID, c.sessionID)
	}

	// v4 session binding: the frame's per-session seed must match the session's
	// own seed. The seed is authenticated header data (AAD), so a mismatched or
	// tampered seed cannot pass AEAD verification anyway, but rejecting early
	// keeps key derivation strictly session-scoped.
	if c.protoV4 {
		if magic != AsymmetricMagicV4 {
			return 0, 0, nil, "", fmt.Errorf("%w: non-v4 frame on v4 session", ErrProtocolVersionSignature)
		}
		if len(c.sessionSeed) != crypto.SessionSeedSize || len(frameSeed) != crypto.SessionSeedSize {
			return 0, 0, nil, "", fmt.Errorf("%w: session seed length mismatch", ErrProtocolVersionSignature)
		}
		for i := 0; i < crypto.SessionSeedSize; i++ {
			if frameSeed[i] != c.sessionSeed[i] {
				return 0, 0, nil, "", fmt.Errorf("%w: frame seed does not match session seed", ErrProtocolVersionSignature)
			}
		}
	}

	var nonce [crypto.NonceSize]byte
	if c.role == RoleClient {
		// Received frame was sealed by the server.
		nonce = c.aeadNonce(seq, RoleServer, frameRNB)
	} else {
		// Received frame was sealed by the client.
		nonce = c.aeadNonce(seq, RoleClient, nil)
	}

	var decKey []byte
	if c.role == RoleClient {
		if magic == AsymmetricMagicV4 {
			// v4 response keys are derived per session from the dedicated
			// per-server response secret under the session-seed salt.
			if serverID == "" {
				return 0, 0, nil, "", fmt.Errorf("%w: v4 server response missing server ID", ErrInvalidServerID)
			}
			if err := ValidateServerID(serverID); err != nil {
				return 0, 0, nil, serverID, err
			}
			if len(c.authorizedServers) == 0 {
				return 0, 0, nil, serverID, ErrEmptyServerAllowlist
			}
			secret, ok := c.authorizedServers[serverID]
			if !ok {
				return 0, 0, nil, serverID, fmt.Errorf("server %q is not authorized by client policy (fail-closed)", serverID)
			}
			if len(secret) != crypto.KeySize {
				return 0, 0, nil, serverID, fmt.Errorf("server %q has invalid response secret length (fail-closed)", serverID)
			}
			sKey, err := crypto.DeriveServerResponseKeyV4(secret, frameSeed, c.sessionID, serverID, frameRNB)
			if err != nil {
				return 0, 0, nil, serverID, fmt.Errorf("derive v4 server response key: %w", err)
			}
			decKey = sKey
		} else if magic == AsymmetricMagicV3 {
			if c.isLegacySingleServer {
				// Single-server legacy client decodes using pre-shared key
				decKey = c.decKey
			} else {
				if serverID == "" {
					return 0, 0, nil, "", fmt.Errorf("%w: server response missing server ID", ErrInvalidServerID)
				}
				if err := ValidateServerID(serverID); err != nil {
					return 0, 0, nil, serverID, err
				}
				// Multi-authoritative client policy check: nonempty allowlist required
				if len(c.authorizedServers) == 0 {
					return 0, 0, nil, serverID, ErrEmptyServerAllowlist
				}
				secret, ok := c.authorizedServers[serverID]
				if !ok {
					return 0, 0, nil, serverID, fmt.Errorf("server %q is not authorized by client policy (fail-closed)", serverID)
				}
				if len(secret) != crypto.KeySize {
					return 0, 0, nil, serverID, fmt.Errorf("server %q has invalid response secret length (fail-closed)", serverID)
				}
				salt := []byte(fmt.Sprintf("paqet-asym-%d", c.sessionID))
				sKey, err := crypto.DeriveServerResponseKey(secret, salt, serverID)
				if err != nil {
					return 0, 0, nil, serverID, fmt.Errorf("derive server response key: %w", err)
				}
				decKey = sKey
			}
		} else if magic == AsymmetricMagic {
			// Legacy v2 frame: strictly rejected on multi-server clients
			if !c.allowLegacyV2 || !c.isLegacySingleServer {
				return 0, 0, nil, "", ErrLegacyProtocolDisabled
			}
			decKey = c.decKey
		}
	} else {
		decKey = c.decKey
	}

	aead, err := crypto.NewAEAD(decKey)
	if err != nil {
		return 0, 0, nil, serverID, err
	}

	header := frame[:headerLen]
	ciphertext := frame[headerLen:]

	plaintext, err = aead.Open(nil, nonce[:], ciphertext, header)
	if err != nil {
		return 0, 0, nil, serverID, fmt.Errorf("aead open: %w", err)
	}

	return seq, ack, plaintext, serverID, nil
}

// VerifyFrame cryptographically verifies the frame's header, magic, session ID,
// and AEAD authentication tag, and returns the decrypted plaintext WITHOUT
// updating or checking the sliding replay window.
func (c *AsymmetricConn) VerifyFrame(frame []byte) (seq, ack uint32, plaintext []byte, err error) {
	seq, ack, plaintext, _, err = c.VerifyFrameWithServerID(frame)
	return seq, ack, plaintext, err
}

// openFrame parses, verifies replay, and decrypts an incoming wire datagram.
func (c *AsymmetricConn) openFrame(frame []byte) (seq, ack uint32, plaintext []byte, err error) {
	seq, ack, plaintext, _, err = c.openFrameWithServerID(frame)
	return seq, ack, plaintext, err
}

// openFrameWithServerID parses, verifies replay, and decrypts an incoming wire datagram, returning serverID.
func (c *AsymmetricConn) openFrameWithServerID(frame []byte) (seq, ack uint32, plaintext []byte, serverID string, err error) {
	seq, ack, plaintext, serverID, err = c.VerifyFrameWithServerID(frame)
	if err != nil {
		return 0, 0, nil, serverID, err
	}
	var frameRNB []byte
	var magic uint32
	if len(frame) >= 4 {
		magic = binary.BigEndian.Uint32(frame[0:4])
	}
	if c.role == RoleClient && magic == AsymmetricMagicV4 {
		frameRNB, _ = extractV4DownstreamRNB(frame)
	}

	// Replay verification and recording ONLY AFTER successful authentication
	c.replayMu.Lock()
	defer c.replayMu.Unlock()

	var filter *replay.Filter
	if c.role == RoleClient && serverID != "" {
		if c.serverReplay == nil {
			c.serverReplay = make(map[string]*replay.Filter)
		}
		replayKey := serverID
		if c.protoV4 && magic == AsymmetricMagicV4 && len(frameRNB) == crypto.DownstreamNonceBaseSize {
			// Replay protection is scoped to the downstream nonce/key domain: a restarted
			// server instance with a fresh per-session base gets a fresh sequence window,
			// while a replay from the OLD instance hits the OLD filter entry (per-domain
			// window isolation).
			replayKey = fmt.Sprintf("%s#%x", serverID, frameRNB)
		}
		if c.replayDomainSealed.Load() {
			// The domain budget was exhausted earlier: the session is sealed. Rejecting
			// (rather than evicting) guarantees that a previously accepted response can
			// never become acceptable again merely because replay history was dropped.
			return 0, 0, nil, serverID, ErrReplayDomainCapacity
		}
		f, ok := c.serverReplay[replayKey]
		if !ok {
			if len(c.serverReplay) >= MaxServerReplayDomainsPerConn {
				// No eviction. Seal the session permanently; the operator must establish
				// a new authenticated session. Deterministic: capacity is only consumed by
				// AEAD-authenticated frames (replay filtering runs after tag verification).
				c.replayDomainSealed.Store(true)
				return 0, 0, nil, serverID, ErrReplayDomainCapacity
			}
			f = replay.NewFilter(30 * time.Second)
			c.serverReplay[replayKey] = f
		}
		filter = f
	} else {
		filter = c.replay
	}

	if filter != nil {
		if err := filter.Validate(uint64(seq)); err != nil {
			return 0, 0, nil, serverID, fmt.Errorf("replay check seq %d for server %q: %w", seq, serverID, err)
		}
	}

	return seq, ack, plaintext, serverID, nil
}

// recvLoop processes inbound packets from the downstream receiver, reordering as needed.
func (c *AsymmetricConn) recvLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		rawFrame, err := c.receiver.RecvDownstream(c.ctx)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}

		seq, ack, payload, err := c.openFrame(rawFrame)
		if err != nil {
			continue // drop invalid, replayed, or unauthenticated datagram
		}

		c.lastAckRcv.Store(ack)
		c.unackedMu.Lock()
		if c.unacked != nil {
			for s := range c.unacked {
				if s <= ack {
					delete(c.unacked, s)
				}
			}
		}
		c.unackedMu.Unlock()

		if len(payload) == 0 {
			continue // Pure ACK frame
		}

		c.reorderMu.Lock()
		expected := c.nextRecv.Load() + 1
		if seq == expected {
			// In-order packet arrived
			_, _ = c.pipeW.Write(payload)
			c.nextRecv.Store(seq)

			// Drain consecutive buffered packets
			for {
				nextExpected := c.nextRecv.Load() + 1
				nextPayload, found := c.reorder[nextExpected]
				if !found {
					break
				}
				delete(c.reorder, nextExpected)
				_, _ = c.pipeW.Write(nextPayload)
				c.nextRecv.Store(nextExpected)
			}
		} else if seq > expected {
			// Future packet (out of order)
			if len(c.reorder) < 256 {
				c.reorder[seq] = append([]byte(nil), payload...)
			}
		}
		c.reorderMu.Unlock()
	}
}

func (c *AsymmetricConn) SetRTO(d time.Duration) {
	c.unackedMu.Lock()
	defer c.unackedMu.Unlock()
	if d > 0 {
		c.rto = d
	}
}

func (c *AsymmetricConn) getRTO() time.Duration {
	c.unackedMu.Lock()
	defer c.unackedMu.Unlock()
	if c.rto <= 0 {
		return DefaultRTO
	}
	return c.rto
}

// retransmitLoop handles automatic retransmissions of unacknowledged frames over lossy channels.
func (c *AsymmetricConn) retransmitLoop() {
	rto := c.getRTO()
	ticker := time.NewTicker(rto / 2)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			curRTO := c.getRTO()
			c.unackedMu.Lock()
			for _, entry := range c.unacked {
				if now.Sub(entry.sentAt) >= curRTO {
					if entry.retries < MaxRetries {
						entry.retries++
						entry.sentAt = now
						if c.sender != nil {
							_ = c.sender.SendUpstream(c.ctx, entry.frame)
						}
					}
				}
			}
			c.unackedMu.Unlock()
		}
	}
}

// MemoryPipeUpstream connects memory channels for testing and local simulation.
type MemoryPipeSender struct {
	ch chan []byte
}

func NewMemoryPipeSender(ch chan []byte) *MemoryPipeSender {
	return &MemoryPipeSender{ch: ch}
}

func (s *MemoryPipeSender) SendUpstream(ctx context.Context, frame []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case s.ch <- append([]byte(nil), frame...):
		return nil
	}
}

func (s *MemoryPipeSender) Close() error {
	return nil
}

type MemoryPipeReceiver struct {
	ch chan []byte
}

func NewMemoryPipeReceiver(ch chan []byte) *MemoryPipeReceiver {
	return &MemoryPipeReceiver{ch: ch}
}

func (r *MemoryPipeReceiver) RecvDownstream(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case frame, ok := <-r.ch:
		if !ok {
			return nil, io.EOF
		}
		return frame, nil
	}
}

func (r *MemoryPipeReceiver) Close() error {
	return nil
}

// MaxServerReplayDomainsPerConn caps per-connection downstream replay domains
// (authorized serverID + per-server-session nonce/key base pairs) so replay-state
// memory stays explicitly bounded. When a 33rd domain would be required, the
// connection is SEALED fail-closed (see ErrReplayDomainCapacity); domains are never
// evicted, because eviction would silently re-open an already accepted replay
// window. Capacity is consumed only by AEAD-authenticated server frames: malformed
// frames, unknown server IDs, and unauthenticated ciphertexts are rejected before
// the replay stage and therefore cannot consume domain capacity.
const MaxServerReplayDomainsPerConn = 32

// extractV4DownstreamRNB deterministically re-parses the per-instance downstream
// nonce stream base from an AEAD-verified v4 server frame. Callers must not use
// the returned bytes for security decisions without a valid AEAD tag (verified
// by VerifyFrameWithServerID first).
func extractV4DownstreamRNB(frame []byte) ([]byte, error) {
	if len(frame) < AsymmetricHeaderV4MinLen {
		return nil, ErrAsymmetricShortFrame
	}
	seedLen := int(frame[20])
	if seedLen != crypto.SessionSeedSize {
		return nil, fmt.Errorf("%w: seed length %d", ErrProtocolVersionSignature, seedLen)
	}
	headerLen := AsymmetricHeaderV4MinLen + seedLen // 37
	if len(frame) < headerLen+1 {
		return nil, ErrAsymmetricShortFrame
	}
	headerLen++ // srvIDLen slot
	srvIDLen := int(frame[headerLen-1])
	if srvIDLen < 0 || len(frame) < headerLen+srvIDLen {
		return nil, ErrAsymmetricShortFrame
	}
	headerLen += srvIDLen
	if len(frame) < headerLen+1 {
		return nil, ErrAsymmetricShortFrame
	}
	rnbLen := int(frame[headerLen])
	headerLen++
	if rnbLen != crypto.DownstreamNonceBaseSize || len(frame) < headerLen+rnbLen {
		return nil, fmt.Errorf("%w: downstream nonce base length", ErrProtocolVersionSignature)
	}
	return append([]byte(nil), frame[headerLen:headerLen+rnbLen]...), nil
}
