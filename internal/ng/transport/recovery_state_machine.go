package transport

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"github.com/arashmh13/paqet-ngv2/internal/ng/crypto"
	"github.com/arashmh13/paqet-ngv2/internal/protocol"
)

// RecoveryState represents the explicit operational phase of the transport recovery lifecycle.
type RecoveryState string

const (
	StatePrimaryHealthy              RecoveryState = "PRIMARY_HEALTHY"
	StatePrimaryDegraded             RecoveryState = "PRIMARY_DEGRADED"
	StateEmergencySignaling          RecoveryState = "EMERGENCY_SIGNALING"
	StateBootstrapReceived           RecoveryState = "BOOTSTRAP_RECEIVED"
	StateCandidateEndpointValidating RecoveryState = "CANDIDATE_ENDPOINT_VALIDATING"
	StateRecoveryReady               RecoveryState = "RECOVERY_READY"
	StateRecoveryFailed              RecoveryState = "RECOVERY_FAILED"
	StateCooldown                    RecoveryState = "COOLDOWN"
)

const (
	// MaxRecoveryHistoryEvents bounds the circular audit trail to prevent memory leaks
	MaxRecoveryHistoryEvents = 256
	// DefaultMaxBootstrapValidityWindow limits maximum validity window into the future (24 hours)
	DefaultMaxBootstrapValidityWindow = 24 * time.Hour
)

var (
	ErrStaleBootstrapData        = errors.New("recovery: bootstrap endpoint coordinates have expired")
	ErrInvalidBootstrapData      = errors.New("recovery: invalid bootstrap endpoint fields")
	ErrCandidateValidation       = errors.New("recovery: candidate endpoint failed authenticated validation handshake")
	ErrMissingCandidateValidator = errors.New("recovery: candidate validator required for fail-closed recovery; cannot activate unvalidated endpoint")
	ErrSignalingFailed           = errors.New("recovery: emergency DNS signaling channel failed")
	ErrCooldownActive            = errors.New("recovery: recovery engine is in cooldown backoff")
	ErrRecoveryOperationActive   = errors.New("recovery: recovery operation already in progress")
	ErrStaleRecoveryOperation    = errors.New("recovery: stale asynchronous recovery operation superseded by state change or rollback")
)

// RecoveryEndpointSnapshot represents an immutable, validated snapshot of an authorized recovery endpoint.
type RecoveryEndpointSnapshot struct {
	ServerIP              string               `json:"server_ip"`
	TransportPort         int                  `json:"transport_port"`
	TransportMode         TransportMode        `json:"transport_mode"`                    // ModeRawKCP, ModeAEADStream, ModeTLSStream
	IdentityType          EndpointIdentityType `json:"identity_type"`                     // "psk-id", "cert-pin", "pubkey-pin"
	IdentityValue         string               `json:"identity_value"`                    // Canonical format: "SHA256:<64 hex>"
	ExpectedPubKey        string               `json:"expected_pub_key,omitempty"`        // Legacy alias
	AuthoritativeServerID string               `json:"authoritative_server_id,omitempty"` // Authoritative server that issued this snapshot
	ValidUntil            int64                `json:"valid_until"`
	MessageID             string               `json:"message_id"`
	Generation            uint64               `json:"generation"`
	ValidatedAt           time.Time            `json:"validated_at"`
}

// GetIdentityValue returns the canonical identity fingerprint, prioritizing IdentityValue over legacy ExpectedPubKey.
func (s *RecoveryEndpointSnapshot) GetIdentityValue() string {
	if s == nil {
		return ""
	}
	if s.IdentityValue != "" {
		return s.IdentityValue
	}
	return s.ExpectedPubKey
}

// Addr returns the "host:port" address string.
func (s *RecoveryEndpointSnapshot) Addr() string {
	if s == nil {
		return ""
	}
	return net.JoinHostPort(s.ServerIP, strconv.Itoa(s.TransportPort))
}

// IsExpired returns true if ValidUntil is less than or equal to now (ValidUntil == now is treated as expired).
func (s *RecoveryEndpointSnapshot) IsExpired(now time.Time) bool {
	if s == nil || s.ValidUntil <= now.Unix() {
		return true
	}
	return false
}

// MatchesGeneration returns true if the snapshot generation matches gen.
func (s *RecoveryEndpointSnapshot) MatchesGeneration(gen uint64) bool {
	return s != nil && s.Generation == gen
}

// StateTransitionEvent records historical state movements for telemetry and auditability.
type StateTransitionEvent struct {
	FromState RecoveryState `json:"from_state"`
	ToState   RecoveryState `json:"to_state"`
	Reason    string        `json:"reason"`
	Timestamp time.Time     `json:"timestamp"`
}

// RecoveryStateMachineConfig configures the failure-detection and recovery parameters.
type RecoveryStateMachineConfig struct {
	PrimaryFailureThreshold    int           // Number of consecutive failures to declare DEGRADED (e.g. 3)
	DegradedTimeout            time.Duration // Time in DEGRADED before initiating EMERGENCY_SIGNALING (e.g. 2s)
	BootstrapValidationTimeout time.Duration // Time limit for independent candidate validation (e.g. 4s)
	CooldownDuration           time.Duration // Cooldown duration after failure before retrying (e.g. 15s)
	MaxBootstrapValidityWindow time.Duration // Maximum future validity window (default 24h)
	CandidateFailureLimit      int           // Number of recovery candidate failures before entering COOLDOWN (default 2)
	AllowPrivateEndpoints      bool          // For tests or private networks; false in production
	AllowLoopbackEndpoints     bool          // For local unit tests only; false in production
	EmergencyDialer            func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error)
	CandidateValidator         func(ctx context.Context, endpoint *BootstrapEndpointData) error
}

// RecoveryStateMachine implements the controlled, non-flapping, fail-closed recovery lifecycle.
type RecoveryStateMachine struct {
	cfg               RecoveryStateMachineConfig
	mu                sync.RWMutex
	state             RecoveryState
	consecutiveFails  int
	candidateFails    int
	lastTransition    time.Time
	cooldownExpiry    time.Time
	activeEndpoint    string
	activeSnapshot    *RecoveryEndpointSnapshot
	lastBootstrap     *BootstrapEndpointData
	history           []StateTransitionEvent
	currentGeneration uint64 // Incremented on state changes, rollback, or primary recovery to detect stale async results
	operationActive   bool   // Enforces strictly one concurrent Step() recovery attempt per machine
}

// NewRecoveryStateMachine instantiates a recovery engine starting in StatePrimaryHealthy.
func NewRecoveryStateMachine(cfg RecoveryStateMachineConfig) *RecoveryStateMachine {
	if cfg.PrimaryFailureThreshold <= 0 {
		cfg.PrimaryFailureThreshold = 3
	}
	if cfg.DegradedTimeout <= 0 {
		cfg.DegradedTimeout = 2 * time.Second
	}
	if cfg.BootstrapValidationTimeout <= 0 {
		cfg.BootstrapValidationTimeout = 4 * time.Second
	}
	if cfg.CooldownDuration <= 0 {
		cfg.CooldownDuration = 15 * time.Second
	}
	if cfg.MaxBootstrapValidityWindow <= 0 {
		cfg.MaxBootstrapValidityWindow = DefaultMaxBootstrapValidityWindow
	}
	if cfg.CandidateFailureLimit <= 0 {
		cfg.CandidateFailureLimit = 2
	}

	sm := &RecoveryStateMachine{
		cfg:            cfg,
		state:          StatePrimaryHealthy,
		lastTransition: time.Now(),
	}
	sm.recordTransitionLocked(StatePrimaryHealthy, StatePrimaryHealthy, "initialization")
	return sm
}

// CurrentState returns the active recovery state.
func (sm *RecoveryStateMachine) CurrentState() RecoveryState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.state
}

// ActiveEndpoint returns the verified recovery endpoint, or empty string if using primary.
func (sm *RecoveryStateMachine) ActiveEndpoint() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.activeEndpoint
}

// ActiveSnapshot returns a copy of the active validated recovery endpoint snapshot if in RECOVERY_READY, or nil.
func (sm *RecoveryStateMachine) ActiveSnapshot() *RecoveryEndpointSnapshot {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if sm.state != StateRecoveryReady || sm.activeSnapshot == nil {
		return nil
	}
	cp := *sm.activeSnapshot
	return &cp
}

// ReportCandidateFailure records an operational or dial error through the recovery candidate.
func (sm *RecoveryStateMachine) ReportCandidateFailure(err error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.state == StateRecoveryReady {
		sm.candidateFails++
		limit := sm.cfg.CandidateFailureLimit
		if limit <= 0 {
			limit = 2
		}
		if sm.candidateFails >= limit || errors.Is(err, ErrStaleBootstrapData) {
			sm.recordTransitionLocked(StateRecoveryReady, StateRecoveryFailed,
				fmt.Sprintf("recovery candidate failed %d times: %v", sm.candidateFails, err))
			sm.enterCooldownLocked("recovery candidate failure limit exceeded")
		}
	}
}

// CurrentGeneration returns the current state revision generation.
func (sm *RecoveryStateMachine) CurrentGeneration() uint64 {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.currentGeneration
}

// History returns a copy of state transition events for audit reporting.
func (sm *RecoveryStateMachine) History() []StateTransitionEvent {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	copied := make([]StateTransitionEvent, len(sm.history))
	copy(copied, sm.history)
	return copied
}

func (sm *RecoveryStateMachine) recordTransitionLocked(from, to RecoveryState, reason string) {
	sm.state = to
	sm.lastTransition = time.Now()
	sm.currentGeneration++
	if len(sm.history) >= MaxRecoveryHistoryEvents {
		sm.history = sm.history[1:]
	}
	sm.history = append(sm.history, StateTransitionEvent{
		FromState: from,
		ToState:   to,
		Reason:    reason,
		Timestamp: sm.lastTransition,
	})
}

// ReportPrimarySuccess signals that the primary transport handled traffic successfully.
func (sm *RecoveryStateMachine) ReportPrimarySuccess() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.consecutiveFails = 0
	if sm.state == StatePrimaryDegraded || sm.state == StateEmergencySignaling || sm.state == StateCandidateEndpointValidating {
		sm.currentGeneration++
		sm.activeEndpoint = ""
		sm.activeSnapshot = nil
		sm.candidateFails = 0
		sm.recordTransitionLocked(sm.state, StatePrimaryHealthy, "primary traffic verified healthy; hysteresis recovered")
	}
}

// ReportPrimaryFailure registers a transport error on the primary path.
func (sm *RecoveryStateMachine) ReportPrimaryFailure(err error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.consecutiveFails++
	if sm.state == StatePrimaryHealthy && sm.consecutiveFails >= sm.cfg.PrimaryFailureThreshold {
		sm.recordTransitionLocked(sm.state, StatePrimaryDegraded, fmt.Sprintf("consecutive primary failures (%d) reached threshold: %v", sm.consecutiveFails, err))
	}
}

// Step performs an autonomous evaluation cycle of the state machine.
func (sm *RecoveryStateMachine) Step(ctx context.Context) (RecoveryState, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 1. Enforce strictly one recovery operation active per machine
	if sm.operationActive {
		return sm.state, ErrRecoveryOperationActive
	}
	sm.operationActive = true
	defer func() {
		sm.operationActive = false
	}()

	now := time.Now()

	switch sm.state {
	case StatePrimaryHealthy:
		return StatePrimaryHealthy, nil

	case StatePrimaryDegraded:
		if now.Sub(sm.lastTransition) < sm.cfg.DegradedTimeout {
			// Hysteresis window: remain in DEGRADED to allow transient recovery
			return StatePrimaryDegraded, nil
		}

		// P0 FAIL-CLOSED REQUIREMENT: Candidate validator MUST be configured!
		if sm.cfg.CandidateValidator == nil {
			sm.recordTransitionLocked(StatePrimaryDegraded, StateRecoveryFailed, "fail-closed: candidate validator required for recovery but not configured")
			sm.enterCooldownLocked("missing candidate validator")
			return StateCooldown, ErrMissingCandidateValidator
		}

		// Degraded timeout elapsed: trigger emergency signaling
		sm.recordTransitionLocked(StatePrimaryDegraded, StateEmergencySignaling, "degraded timeout elapsed; requesting bootstrap failover via emergency DNS")
		fallthrough

	case StateEmergencySignaling:
		if sm.cfg.CandidateValidator == nil {
			sm.recordTransitionLocked(sm.state, StateRecoveryFailed, "fail-closed: missing candidate validator")
			sm.enterCooldownLocked("missing candidate validator")
			return StateCooldown, ErrMissingCandidateValidator
		}
		if sm.cfg.EmergencyDialer == nil {
			sm.recordTransitionLocked(sm.state, StateRecoveryFailed, "no emergency dialer configured")
			sm.enterCooldownLocked("missing emergency dialer")
			return StateCooldown, ErrSignalingFailed
		}

		req := &EmergencyMessage{
			ID:        GenerateRandomMessageID(),
			Type:      MsgTypeBootstrapRequest,
			Payload:   []byte("REQUEST_BOOTSTRAP_ENDPOINT"),
			Timestamp: now.Unix(),
		}

		startGen := sm.currentGeneration

		// Unlock mutex during external network signaling call
		sm.mu.Unlock()
		endpoint, err := sm.cfg.EmergencyDialer(ctx, req)
		sm.mu.Lock()

		// Stale operation check: verify generation has not advanced while network call was in flight
		if sm.currentGeneration != startGen || sm.state != StateEmergencySignaling {
			return sm.state, ErrStaleRecoveryOperation
		}

		if err != nil {
			sm.recordTransitionLocked(sm.state, StateRecoveryFailed, fmt.Sprintf("emergency signaling query failed: %v", err))
			sm.enterCooldownLocked("emergency signaling error")
			return StateCooldown, fmt.Errorf("%w: %v", ErrSignalingFailed, err)
		}

		// Validate received bootstrap data schema, freshness, and cryptographic identity
		maxWindow := sm.cfg.MaxBootstrapValidityWindow
		if maxWindow <= 0 {
			maxWindow = DefaultMaxBootstrapValidityWindow
		}
		if valErr := endpoint.Validate(now, maxWindow, sm.cfg.AllowPrivateEndpoints, sm.cfg.AllowLoopbackEndpoints); valErr != nil {
			sm.recordTransitionLocked(sm.state, StateRecoveryFailed, fmt.Sprintf("bootstrap validation failed: %v", valErr))
			sm.enterCooldownLocked(fmt.Sprintf("invalid bootstrap payload: %v", valErr))
			return StateCooldown, fmt.Errorf("%w: %v", ErrInvalidBootstrapData, valErr)
		}

		sm.lastBootstrap = endpoint
		sm.recordTransitionLocked(sm.state, StateBootstrapReceived, fmt.Sprintf("received authenticated bootstrap endpoint %s:%d (%s)", endpoint.ServerIP, endpoint.TransportPort, endpoint.TransportMode))
		sm.recordTransitionLocked(StateBootstrapReceived, StateCandidateEndpointValidating, "initiating independent authenticated handshake validation")

		valGen := sm.currentGeneration

		// Validate candidate endpoint independently
		valCtx, cancel := context.WithTimeout(ctx, sm.cfg.BootstrapValidationTimeout)
		defer cancel()

		sm.mu.Unlock()
		valErr := sm.cfg.CandidateValidator(valCtx, endpoint)
		sm.mu.Lock()

		// Stale operation check: verify generation has not advanced while candidate was validating
		if sm.currentGeneration != valGen || sm.state != StateCandidateEndpointValidating {
			return sm.state, ErrStaleRecoveryOperation
		}

		if valErr != nil {
			sm.recordTransitionLocked(sm.state, StateRecoveryFailed, fmt.Sprintf("candidate endpoint %s:%d failed validation handshake: %v", endpoint.ServerIP, endpoint.TransportPort, valErr))
			sm.enterCooldownLocked("candidate validation rejected")
			return StateCooldown, fmt.Errorf("%w: %v", ErrCandidateValidation, valErr)
		}

		// Validation successful! Activate recovery endpoint snapshot for new connections
		sm.recordTransitionLocked(sm.state, StateRecoveryReady, fmt.Sprintf("candidate endpoint %s:%d (%s) validated and active for new connections", endpoint.ServerIP, endpoint.TransportPort, endpoint.Mode()))
		snapshot := &RecoveryEndpointSnapshot{
			ServerIP:              endpoint.ServerIP,
			TransportPort:         endpoint.TransportPort,
			TransportMode:         endpoint.Mode(),
			IdentityType:          endpoint.GetIdentityType(),
			IdentityValue:         endpoint.GetIdentityValue(),
			ExpectedPubKey:        endpoint.GetIdentityValue(),
			AuthoritativeServerID: endpoint.AuthoritativeServerID,
			ValidUntil:            endpoint.ValidUntil,
			MessageID:             req.ID,
			Generation:            sm.currentGeneration,
			ValidatedAt:           time.Now(),
		}
		sm.activeSnapshot = snapshot
		sm.activeEndpoint = snapshot.Addr()
		sm.candidateFails = 0
		return StateRecoveryReady, nil

	case StateRecoveryReady:
		return StateRecoveryReady, nil

	case StateRecoveryFailed:
		sm.enterCooldownLocked("previous recovery failed")
		return StateCooldown, nil

	case StateCooldown:
		if now.After(sm.cooldownExpiry) {
			sm.recordTransitionLocked(StateCooldown, StatePrimaryDegraded, "cooldown duration expired; re-evaluating primary connectivity")
			return StatePrimaryDegraded, nil
		}
		return StateCooldown, ErrCooldownActive

	default:
		return sm.state, nil
	}
}

func (sm *RecoveryStateMachine) enterCooldownLocked(reason string) {
	sm.activeEndpoint = ""
	sm.activeSnapshot = nil
	sm.candidateFails = 0
	sm.cooldownExpiry = time.Now().Add(sm.cfg.CooldownDuration)
	sm.recordTransitionLocked(sm.state, StateCooldown, fmt.Sprintf("entering cooldown for %v: %s", sm.cfg.CooldownDuration, reason))
}

// ResetRollback deterministically restores the state machine to StatePrimaryHealthy and clears active recovery endpoints.
func (sm *RecoveryStateMachine) ResetRollback(reason string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.currentGeneration++
	sm.consecutiveFails = 0
	sm.candidateFails = 0
	sm.activeEndpoint = ""
	sm.activeSnapshot = nil
	sm.lastBootstrap = nil
	sm.recordTransitionLocked(sm.state, StatePrimaryHealthy, fmt.Sprintf("manual or automated rollback: %s", reason))
}

// CandidateConn is a connection interface capable of executing protocol ping/pong probes.
type CandidateConn interface {
	Ping(wait bool) error
	Close() error
}

// CandidateValidatorOptions configures cryptographic validation for candidate endpoints.
type CandidateValidatorOptions struct {
	PSK          []byte
	KCPKey       []byte
	ServerName   string
	RawKCPDialer func(ctx context.Context, targetAddr string, kcpKey []byte) (CandidateConn, error)
}

// BuildCandidateValidator constructs an authenticating validator that verifies remote cryptographic identities.
func BuildCandidateValidator(opts CandidateValidatorOptions) func(ctx context.Context, endpoint *BootstrapEndpointData) error {
	return func(ctx context.Context, endpoint *BootstrapEndpointData) error {
		if endpoint == nil {
			return errors.New("nil endpoint")
		}
		expectedDigest, err := ParseSHA256Fingerprint(endpoint.GetIdentityValue())
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidBootstrapData, err)
		}

		targetAddr := net.JoinHostPort(endpoint.ServerIP, strconv.Itoa(endpoint.TransportPort))

		switch endpoint.Mode() {
		case ModeTLSStream:
			// Enforce explicit identity type
			if endpoint.GetIdentityType() != IdentityTypeCertPin && endpoint.GetIdentityType() != IdentityTypePubKeyPin {
				return fmt.Errorf("%w: invalid identity type %q for TLS mode (must be cert-pin or pubkey-pin)",
					ErrCandidateValidation, endpoint.GetIdentityType())
			}
			serverName := opts.ServerName
			if serverName == "" {
				serverName = endpoint.ServerIP
			}
			tlsDialer := &tls.Dialer{
				NetDialer: &net.Dialer{Timeout: 3 * time.Second},
				Config: &tls.Config{
					ServerName:         serverName,
					InsecureSkipVerify: true, // Verification performed via fingerprint comparison
				},
			}
			tlsConn, err := tlsDialer.DialContext(ctx, "tcp", targetAddr)
			if err != nil {
				return fmt.Errorf("%w: tls candidate tcp dial failed: %v", ErrCandidateValidation, err)
			}
			defer tlsConn.Close()

			cs := tlsConn.(*tls.Conn).ConnectionState()
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("%w: tls candidate presented no certificates", ErrCandidateValidation)
			}
			leafCert := cs.PeerCertificates[0]
			leafDigest := sha256.Sum256(leafCert.Raw)
			if leafDigest != expectedDigest {
				return fmt.Errorf("%w: tls certificate fingerprint mismatch: got SHA256:%x, want %s",
					ErrCandidateValidation, leafDigest, endpoint.GetIdentityValue())
			}

			// Validate smux protocol handshake over TLS
			smuxCfg := smux.DefaultConfig()
			smuxCfg.Version = 2
			sess, err := smux.Client(tlsConn, smuxCfg)
			if err != nil {
				return fmt.Errorf("%w: tls smux handshake failed: %v", ErrCandidateValidation, err)
			}
			defer sess.Close()

			strm, err := sess.OpenStream()
			if err != nil {
				return fmt.Errorf("%w: tls candidate failed to open stream: %v", ErrCandidateValidation, err)
			}
			defer strm.Close()

			_ = strm.SetDeadline(time.Now().Add(2 * time.Second))
			ping := protocol.Proto{Type: protocol.PPING}
			if err := ping.Write(strm); err != nil {
				return fmt.Errorf("%w: tls candidate ping write failed: %v", ErrCandidateValidation, err)
			}
			var reply protocol.Proto
			if err := reply.Read(strm); err != nil {
				return fmt.Errorf("%w: tls candidate ping read failed: %v", ErrCandidateValidation, err)
			}
			if reply.Type != protocol.PPONG {
				return fmt.Errorf("%w: tls candidate unexpected protocol response %v", ErrCandidateValidation, reply.Type)
			}
			return nil

		case ModeAEADStream:
			// Enforce explicit identity type
			if endpoint.GetIdentityType() != IdentityTypePSKID {
				return fmt.Errorf("%w: invalid identity type %q for AEAD mode (must be psk-id)",
					ErrCandidateValidation, endpoint.GetIdentityType())
			}
			keyDigest := sha256.Sum256(opts.PSK)
			if keyDigest != expectedDigest {
				return fmt.Errorf("%w: aead-stream key fingerprint mismatch: expected %s, configured PSK fingerprint is SHA256:%x",
					ErrCandidateValidation, endpoint.GetIdentityValue(), keyDigest)
			}

			netDialer := &net.Dialer{Timeout: 3 * time.Second}
			rawConn, err := netDialer.DialContext(ctx, "tcp", targetAddr)
			if err != nil {
				return fmt.Errorf("%w: aead-stream tcp dial failed: %v", ErrCandidateValidation, err)
			}
			defer rawConn.Close()

			var salt [SaltSize]byte
			if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
				return fmt.Errorf("%w: salt generation error: %v", ErrCandidateValidation, err)
			}
			if _, err := rawConn.Write(salt[:]); err != nil {
				return fmt.Errorf("%w: salt write error: %v", ErrCandidateValidation, err)
			}
			c2sKey, s2cKey, err := crypto.DeriveKeys(opts.PSK, salt[:])
			if err != nil {
				return fmt.Errorf("%w: key derivation error: %v", ErrCandidateValidation, err)
			}
			secConn, err := newSecureConn(rawConn, c2sKey, s2cKey)
			if err != nil {
				return fmt.Errorf("%w: secure connection init error: %v", ErrCandidateValidation, err)
			}

			initFrame := make([]byte, 6)
			binary.BigEndian.PutUint32(initFrame[:4], uint32(time.Now().Unix()))
			binary.BigEndian.PutUint16(initFrame[4:6], 0)
			if _, err := secConn.Write(initFrame); err != nil {
				return fmt.Errorf("%w: handshake frame write error: %v", ErrCandidateValidation, err)
			}

			smuxCfg := smux.DefaultConfig()
			smuxCfg.Version = 2
			sess, err := smux.Client(secConn, smuxCfg)
			if err != nil {
				return fmt.Errorf("%w: aead-stream smux handshake failed: %v", ErrCandidateValidation, err)
			}
			defer sess.Close()

			strm, err := sess.OpenStream()
			if err != nil {
				return fmt.Errorf("%w: aead-stream candidate failed to open stream: %v", ErrCandidateValidation, err)
			}
			defer strm.Close()

			_ = strm.SetDeadline(time.Now().Add(2 * time.Second))
			ping := protocol.Proto{Type: protocol.PPING}
			if err := ping.Write(strm); err != nil {
				return fmt.Errorf("%w: aead-stream candidate ping write failed: %v", ErrCandidateValidation, err)
			}
			var reply protocol.Proto
			if err := reply.Read(strm); err != nil {
				return fmt.Errorf("%w: aead-stream candidate ping read failed (server did not return valid Paqet pong): %v", ErrCandidateValidation, err)
			}
			if reply.Type != protocol.PPONG {
				return fmt.Errorf("%w: aead-stream candidate unexpected protocol response %v", ErrCandidateValidation, reply.Type)
			}
			return nil

		case ModeRawKCP:
			// Enforce explicit identity type
			if endpoint.GetIdentityType() != IdentityTypePSKID {
				return fmt.Errorf("%w: invalid identity type %q for Raw-KCP mode (must be psk-id)",
					ErrCandidateValidation, endpoint.GetIdentityType())
			}
			kcpKey := opts.KCPKey
			if len(kcpKey) == 0 {
				kcpKey = opts.PSK
			}
			keyDigest := sha256.Sum256(kcpKey)
			if keyDigest != expectedDigest {
				return fmt.Errorf("%w: raw-kcp key fingerprint mismatch: expected %s, configured key is SHA256:%x",
					ErrCandidateValidation, endpoint.GetIdentityValue(), keyDigest)
			}

			// Validate remote handshake
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("%w: raw-kcp validation canceled: %v", ErrCandidateValidation, err)
			}

			if opts.RawKCPDialer == nil {
				return fmt.Errorf("%w: raw-kcp candidate validation requires RawKCPDialer; remote handshake cannot be proven without dialer", ErrCandidateValidation)
			}

			conn, err := opts.RawKCPDialer(ctx, targetAddr, kcpKey)
			if err != nil {
				return fmt.Errorf("%w: raw-kcp dial failed: %v", ErrCandidateValidation, err)
			}
			defer conn.Close()

			// Authenticated transport establishment and protocol ping/pong verification
			if err := conn.Ping(true); err != nil {
				return fmt.Errorf("%w: raw-kcp candidate ping/pong validation failed: %v", ErrCandidateValidation, err)
			}
			return nil

		default:
			return fmt.Errorf("%w: unsupported mode %q", ErrCandidateValidation, endpoint.Mode())
		}
	}
}
