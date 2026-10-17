package transport

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testValidPubKey = "SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestRecoveryStateMachine_SuccessfulTransition(t *testing.T) {
	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold:    3,
		DegradedTimeout:            50 * time.Millisecond,
		BootstrapValidationTimeout: 100 * time.Millisecond,
		CooldownDuration:           200 * time.Millisecond,
		AllowLoopbackEndpoints:     true,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "203.0.113.7",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				ServerPubKey:  testValidPubKey,
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			if endpoint.ServerIP == "203.0.113.7" && endpoint.TransportPort == 18089 && endpoint.ServerPubKey == testValidPubKey {
				return nil // Handshake and cryptographic identity validated!
			}
			return errors.New("candidate handshake failed")
		},
	}

	sm := NewRecoveryStateMachine(cfg)
	if sm.CurrentState() != StatePrimaryHealthy {
		t.Fatalf("Expected initial state PRIMARY_HEALTHY, got %s", sm.CurrentState())
	}

	// 1. Report 2 failures (below threshold 3)
	sm.ReportPrimaryFailure(errors.New("timeout 1"))
	sm.ReportPrimaryFailure(errors.New("timeout 2"))
	if sm.CurrentState() != StatePrimaryHealthy {
		t.Fatalf("Expected state to remain PRIMARY_HEALTHY, got %s", sm.CurrentState())
	}

	// 2. Report 3rd failure (reaches threshold) -> StatePrimaryDegraded
	sm.ReportPrimaryFailure(errors.New("timeout 3"))
	if sm.CurrentState() != StatePrimaryDegraded {
		t.Fatalf("Expected state PRIMARY_DEGRADED, got %s", sm.CurrentState())
	}

	// 3. Step before degraded timeout: remains in DEGRADED (hysteresis)
	state, err := sm.Step(context.Background())
	if err != nil || state != StatePrimaryDegraded {
		t.Fatalf("Expected state to remain PRIMARY_DEGRADED during hysteresis window, got %s", state)
	}

	// 4. Wait for degraded timeout to elapse
	time.Sleep(60 * time.Millisecond)

	// 5. Step: triggers emergency signaling, receives bootstrap, validates candidate, transitions to RECOVERY_READY
	state, err = sm.Step(context.Background())
	if err != nil {
		t.Fatalf("Step failed: %v", err)
	}
	if state != StateRecoveryReady {
		t.Fatalf("Expected state RECOVERY_READY, got %s", state)
	}
	if sm.ActiveEndpoint() != "203.0.113.7:18089" {
		t.Fatalf("Expected active endpoint 203.0.113.7:18089, got %s", sm.ActiveEndpoint())
	}

	// Verify transition history contains all expected phases
	history := sm.History()
	expectedStates := []RecoveryState{
		StatePrimaryHealthy,
		StatePrimaryDegraded,
		StateEmergencySignaling,
		StateBootstrapReceived,
		StateCandidateEndpointValidating,
		StateRecoveryReady,
	}
	for _, exp := range expectedStates {
		found := false
		for _, ev := range history {
			if ev.ToState == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing expected state transition to %s in history", exp)
		}
	}
}

func TestRecoveryStateMachine_MissingValidatorFailClosed(t *testing.T) {
	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         10 * time.Millisecond,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "203.0.113.7",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				ServerPubKey:  testValidPubKey,
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: nil, // Missing validator must cause fail-closed rejection!
	}
	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("primary down"))
	time.Sleep(15 * time.Millisecond)

	state, err := sm.Step(context.Background())
	if !errors.Is(err, ErrMissingCandidateValidator) {
		t.Fatalf("Expected ErrMissingCandidateValidator, got %v", err)
	}
	if state != StateCooldown {
		t.Fatalf("Expected state COOLDOWN, got %s", state)
	}
	if sm.ActiveEndpoint() != "" {
		t.Fatalf("Fail-closed violation: active endpoint must remain empty on missing validator, got %q", sm.ActiveEndpoint())
	}
}

func TestRecoveryStateMachine_ZeroOrMissingExpiryFailClosed(t *testing.T) {
	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         10 * time.Millisecond,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "203.0.113.7",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				ServerPubKey:  testValidPubKey,
				ValidUntil:    0, // Zero expiry must fail closed!
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			return nil
		},
	}
	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("down"))
	time.Sleep(15 * time.Millisecond)

	state, err := sm.Step(context.Background())
	if !errors.Is(err, ErrInvalidBootstrapData) {
		t.Fatalf("Expected ErrInvalidBootstrapData, got %v", err)
	}
	if state != StateCooldown {
		t.Fatalf("Expected state COOLDOWN, got %s", state)
	}
}

func TestRecoveryStateMachine_DistantExpiryRejected(t *testing.T) {
	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold:    1,
		DegradedTimeout:            10 * time.Millisecond,
		MaxBootstrapValidityWindow: 2 * time.Hour,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "203.0.113.7",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				ServerPubKey:  testValidPubKey,
				ValidUntil:    time.Now().Add(10 * time.Hour).Unix(), // Exceeds 2h window!
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			return nil
		},
	}
	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("down"))
	time.Sleep(15 * time.Millisecond)

	state, err := sm.Step(context.Background())
	if !errors.Is(err, ErrInvalidBootstrapData) {
		t.Fatalf("Expected ErrInvalidBootstrapData for excessively distant expiry, got %v", err)
	}
	if state != StateCooldown {
		t.Fatalf("Expected state COOLDOWN, got %s", state)
	}
}

func TestRecoveryStateMachine_UnsupportedTransportModeRejected(t *testing.T) {
	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         10 * time.Millisecond,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "203.0.113.7",
				TransportPort: 18089,
				TransportMode: "telnet-plain", // Unsupported mode!
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			return nil
		},
	}
	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("down"))
	time.Sleep(15 * time.Millisecond)

	_, err := sm.Step(context.Background())
	if !errors.Is(err, ErrInvalidBootstrapData) {
		t.Fatalf("Expected ErrInvalidBootstrapData for unsupported transport mode, got %v", err)
	}
}

func TestRecoveryStateMachine_MissingCryptographicIdentityRejected(t *testing.T) {
	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         10 * time.Millisecond,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "203.0.113.7",
				TransportPort: 8443,
				TransportMode: "tls-outer",
				ServerPubKey:  "", // Missing certificate/key identity!
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			return nil
		},
	}
	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("down"))
	time.Sleep(15 * time.Millisecond)

	_, err := sm.Step(context.Background())
	if !errors.Is(err, ErrInvalidBootstrapData) {
		t.Fatalf("Expected ErrInvalidBootstrapData for missing cryptographic identity, got %v", err)
	}
}

func TestRecoveryStateMachine_StaleAsyncDialerDiscardedOnPrimaryRecovery(t *testing.T) {
	dialerStarted := make(chan struct{})
	dialerBlock := make(chan struct{})

	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         10 * time.Millisecond,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			close(dialerStarted)
			<-dialerBlock // Pause in async network call
			return &BootstrapEndpointData{
				ServerIP:      "203.0.113.7",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				ServerPubKey:  testValidPubKey,
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			return nil
		},
	}

	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("primary down"))
	time.Sleep(15 * time.Millisecond)

	var stepErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, stepErr = sm.Step(context.Background())
	}()

	<-dialerStarted // Wait until dialer is blocked mid-flight

	// Primary recovers while dialer is in-flight!
	sm.ReportPrimarySuccess()
	if sm.CurrentState() != StatePrimaryHealthy {
		t.Fatalf("Expected state PRIMARY_HEALTHY after ReportPrimarySuccess, got %s", sm.CurrentState())
	}

	// Unblock dialer
	close(dialerBlock)
	wg.Wait()

	if !errors.Is(stepErr, ErrStaleRecoveryOperation) {
		t.Fatalf("Expected ErrStaleRecoveryOperation for superseded dialer, got %v", stepErr)
	}
	if sm.CurrentState() != StatePrimaryHealthy {
		t.Fatalf("State must remain PRIMARY_HEALTHY; got %s", sm.CurrentState())
	}
	if sm.ActiveEndpoint() != "" {
		t.Fatalf("Active endpoint must remain empty on superseded dialer, got %q", sm.ActiveEndpoint())
	}
}

func TestRecoveryStateMachine_StaleCandidateValidatorDiscardedOnRollback(t *testing.T) {
	validatorStarted := make(chan struct{})
	validatorBlock := make(chan struct{})

	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         10 * time.Millisecond,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "203.0.113.7",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				ServerPubKey:  testValidPubKey,
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			close(validatorStarted)
			<-validatorBlock // Pause in candidate validation
			return nil
		},
	}

	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("primary down"))
	time.Sleep(15 * time.Millisecond)

	var stepErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, stepErr = sm.Step(context.Background())
	}()

	<-validatorStarted

	// Operator executes ResetRollback while validation is pending
	sm.ResetRollback("operator rollback")
	if sm.CurrentState() != StatePrimaryHealthy {
		t.Fatalf("Expected state PRIMARY_HEALTHY after ResetRollback, got %s", sm.CurrentState())
	}

	close(validatorBlock)
	wg.Wait()

	if !errors.Is(stepErr, ErrStaleRecoveryOperation) {
		t.Fatalf("Expected ErrStaleRecoveryOperation for superseded validator, got %v", stepErr)
	}
	if sm.CurrentState() != StatePrimaryHealthy {
		t.Fatalf("State must remain PRIMARY_HEALTHY; got %s", sm.CurrentState())
	}
	if sm.ActiveEndpoint() != "" {
		t.Fatalf("Active endpoint must remain empty on superseded validator, got %q", sm.ActiveEndpoint())
	}
}

func TestRecoveryStateMachine_ConcurrentStepOperations(t *testing.T) {
	dialerStarted := make(chan struct{})
	dialerBlock := make(chan struct{})

	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         10 * time.Millisecond,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			close(dialerStarted)
			<-dialerBlock
			return &BootstrapEndpointData{
				ServerIP:      "203.0.113.7",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				ServerPubKey:  testValidPubKey,
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			return nil
		},
	}

	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("primary down"))
	time.Sleep(15 * time.Millisecond)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = sm.Step(context.Background())
	}()

	<-dialerStarted

	// A concurrent Step() must be rejected as already active
	_, err := sm.Step(context.Background())
	if !errors.Is(err, ErrRecoveryOperationActive) {
		t.Fatalf("Expected ErrRecoveryOperationActive for concurrent Step, got %v", err)
	}

	close(dialerBlock)
	wg.Wait()
}

func TestRecoveryStateMachine_HysteresisRecovery(t *testing.T) {
	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 2,
		DegradedTimeout:         100 * time.Millisecond,
	}
	sm := NewRecoveryStateMachine(cfg)

	sm.ReportPrimaryFailure(errors.New("error 1"))
	sm.ReportPrimaryFailure(errors.New("error 2"))
	if sm.CurrentState() != StatePrimaryDegraded {
		t.Fatalf("Expected PRIMARY_DEGRADED, got %s", sm.CurrentState())
	}

	// Primary recovers before degraded timeout!
	sm.ReportPrimarySuccess()
	if sm.CurrentState() != StatePrimaryHealthy {
		t.Fatalf("Expected state to recover to PRIMARY_HEALTHY, got %s", sm.CurrentState())
	}
}

func TestRecoveryStateMachine_MalformedFingerprintsFailClosed(t *testing.T) {
	malformedCases := []string{
		"", // empty
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // missing SHA256: prefix
		"SHA256:too-short", // too short
		"SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",   // 63 hex (one short)
		"SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", // 65 hex (one long)
		"SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",  // invalid non-hex char 'g'
	}

	for _, tc := range malformedCases {
		t.Run("Fingerprint_"+tc, func(t *testing.T) {
			b := &BootstrapEndpointData{
				ServerIP:      "203.0.113.7",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				ServerPubKey:  tc,
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}
			err := b.Validate(time.Now(), 24*time.Hour, true, true)
			if err == nil {
				t.Fatalf("Expected validation error for malformed fingerprint %q, got nil", tc)
			}
		})
	}
}

func TestRecoveryStateMachine_ValidUntilEqualToNowExpired(t *testing.T) {
	// P0 REQUIREMENT: Ensure ValidUntil == now.Unix() is treated as expired, rather than valid
	now := time.Now()
	b := &BootstrapEndpointData{
		ServerIP:      "203.0.113.7",
		TransportPort: 18089,
		TransportMode: "aead-stream",
		ServerPubKey:  testValidPubKey,
		ValidUntil:    now.Unix(), // Exactly equal to now
	}
	err := b.Validate(now, 24*time.Hour, true, true)
	if err == nil {
		t.Fatalf("Expected validation failure when ValidUntil == now.Unix(), but got nil (fail-closed violation)")
	}
}

func TestRecoveryStateMachine_CandidateValidatorFingerprintMismatch(t *testing.T) {
	// Test candidate validator rejecting mismatched key fingerprint
	differentKey := make([]byte, 32)
	differentKey[0] = 0xAA

	validator := BuildCandidateValidator(CandidateValidatorOptions{
		PSK: differentKey,
	})

	endpoint := &BootstrapEndpointData{
		ServerIP:      "203.0.113.7",
		TransportPort: 18089,
		TransportMode: "aead-stream",
		ServerPubKey:  testValidPubKey, // Does not match differentKey
		ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
	}

	err := validator(context.Background(), endpoint)
	if err == nil {
		t.Fatalf("Expected validator error for mismatched key fingerprint, got nil")
	}
	if !errors.Is(err, ErrCandidateValidation) {
		t.Fatalf("Expected ErrCandidateValidation, got %v", err)
	}
}

func TestRecoveryStateMachine_TCPListenerWithoutPaqetHandshakeRejected(t *testing.T) {
	// Start a dummy TCP listener that accepts connections but does NOT speak Paqet
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Just close or send garbage
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			_ = conn.Close()
		}
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	testPSK := []byte("01234567890123456789012345678901")
	digest := sha256.Sum256(testPSK)
	pubKey := fmt.Sprintf("SHA256:%x", digest)

	validator := BuildCandidateValidator(CandidateValidatorOptions{
		PSK: testPSK,
	})

	endpoint := &BootstrapEndpointData{
		ServerIP:      "127.0.0.1",
		TransportPort: tcpAddr.Port,
		TransportMode: "aead-stream",
		ServerPubKey:  pubKey,
		ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	valErr := validator(ctx, endpoint)
	if valErr == nil {
		t.Fatalf("A plain TCP listener with no Paqet handshake MUST NOT be accepted as a valid candidate! (P0 violation)")
	}
	if !errors.Is(valErr, ErrCandidateValidation) {
		t.Fatalf("Expected ErrCandidateValidation, got %v", valErr)
	}
}

func TestRecoveryStateMachine_RecoveryCandidateFailureLimitCooldown(t *testing.T) {
	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         10 * time.Millisecond,
		CandidateFailureLimit:   2,
		CooldownDuration:        500 * time.Millisecond,
		AllowLoopbackEndpoints:  true,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "203.0.113.7",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				ServerPubKey:  testValidPubKey,
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			return nil
		},
	}

	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("primary down"))
	time.Sleep(15 * time.Millisecond)

	state, err := sm.Step(context.Background())
	if err != nil || state != StateRecoveryReady {
		t.Fatalf("Expected StateRecoveryReady, got state %s, err %v", state, err)
	}

	// First candidate failure: below limit (2)
	sm.ReportCandidateFailure(errors.New("dial timeout 1"))
	if sm.CurrentState() != StateRecoveryReady {
		t.Fatalf("Expected StateRecoveryReady after 1 failure, got %s", sm.CurrentState())
	}

	// Second candidate failure: reaches limit (2) -> transitions to COOLDOWN!
	sm.ReportCandidateFailure(errors.New("dial timeout 2"))
	if sm.CurrentState() != StateCooldown {
		t.Fatalf("Expected StateCooldown after reaching candidate failure limit, got %s", sm.CurrentState())
	}
	if sm.ActiveSnapshot() != nil {
		t.Fatalf("Active snapshot must be cleared in COOLDOWN, got %v", sm.ActiveSnapshot())
	}
}

type mockCandidateConn struct {
	pingFunc  func(wait bool) error
	closeFunc func() error
	closed    bool
}

func (m *mockCandidateConn) Ping(wait bool) error {
	if m.pingFunc != nil {
		return m.pingFunc(wait)
	}
	return nil
}

func (m *mockCandidateConn) Close() error {
	m.closed = true
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func TestRawKCPCandidateValidation_AllNegativeAndPositiveCases(t *testing.T) {
	kcpKey := []byte("01234567890123456789012345678901")
	keyDigest := sha256.Sum256(kcpKey)
	validPin := fmt.Sprintf("SHA256:%x", keyDigest)

	baseEndpoint := &BootstrapEndpointData{
		Version:       2,
		ServerIP:      "127.0.0.1",
		TransportPort: 18088,
		TransportMode: "raw-kcp",
		IdentityType:  IdentityTypePSKID,
		IdentityValue: validPin,
		ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
	}

	// 1. Correct local key but no listening server
	t.Run("Case1_NoListeningServer", func(t *testing.T) {
		val := BuildCandidateValidator(CandidateValidatorOptions{
			KCPKey: kcpKey,
			RawKCPDialer: func(ctx context.Context, targetAddr string, key []byte) (CandidateConn, error) {
				return nil, errors.New("dial udp: connection refused / no listener")
			},
		})
		err := val(context.Background(), baseEndpoint)
		if err == nil || !errors.Is(err, ErrCandidateValidation) {
			t.Fatalf("Expected ErrCandidateValidation when no server is listening, got %v", err)
		}
	})

	// 2. Plain TCP server on candidate port (not a valid KCP/smux server)
	t.Run("Case2_PlainTCPServerOnPort", func(t *testing.T) {
		val := BuildCandidateValidator(CandidateValidatorOptions{
			KCPKey: kcpKey,
			RawKCPDialer: func(ctx context.Context, targetAddr string, key []byte) (CandidateConn, error) {
				return nil, errors.New("kcp: packet dropped (plain TCP protocol rejection)")
			},
		})
		err := val(context.Background(), baseEndpoint)
		if err == nil || !errors.Is(err, ErrCandidateValidation) {
			t.Fatalf("Expected ErrCandidateValidation when server on port is plain TCP, got %v", err)
		}
	})

	// 3. Server listening with wrong key
	t.Run("Case3_ServerListeningWithWrongKey", func(t *testing.T) {
		val := BuildCandidateValidator(CandidateValidatorOptions{
			KCPKey: kcpKey,
			RawKCPDialer: func(ctx context.Context, targetAddr string, key []byte) (CandidateConn, error) {
				mock := &mockCandidateConn{
					pingFunc: func(wait bool) error {
						return errors.New("kcp: handshake failed (decryption / auth error with wrong key)")
					},
				}
				return mock, nil
			},
		})
		err := val(context.Background(), baseEndpoint)
		if err == nil || !errors.Is(err, ErrCandidateValidation) {
			t.Fatalf("Expected ErrCandidateValidation when server uses wrong key, got %v", err)
		}
	})

	// 4. Valid server with incorrect identity pin
	t.Run("Case4_IncorrectIdentityPin", func(t *testing.T) {
		wrongPinEndpoint := *baseEndpoint
		wrongPinEndpoint.IdentityValue = "SHA256:0000000000000000000000000000000000000000000000000000000000000000"
		val := BuildCandidateValidator(CandidateValidatorOptions{
			KCPKey: kcpKey,
			RawKCPDialer: func(ctx context.Context, targetAddr string, key []byte) (CandidateConn, error) {
				t.Fatalf("Dialer should not be invoked when identity pin mismatches!")
				return nil, nil
			},
		})
		err := val(context.Background(), &wrongPinEndpoint)
		if err == nil || !errors.Is(err, ErrCandidateValidation) {
			t.Fatalf("Expected ErrCandidateValidation for pin mismatch, got %v", err)
		}
	})

	// 5. Authenticated server returning invalid protocol response
	t.Run("Case5_InvalidProtocolResponse", func(t *testing.T) {
		val := BuildCandidateValidator(CandidateValidatorOptions{
			KCPKey: kcpKey,
			RawKCPDialer: func(ctx context.Context, targetAddr string, key []byte) (CandidateConn, error) {
				mock := &mockCandidateConn{
					pingFunc: func(wait bool) error {
						return errors.New("strm pong failed: unexpected type 99")
					},
				}
				return mock, nil
			},
		})
		err := val(context.Background(), baseEndpoint)
		if err == nil || !errors.Is(err, ErrCandidateValidation) {
			t.Fatalf("Expected ErrCandidateValidation for invalid protocol response, got %v", err)
		}
	})

	// 6. Successful authenticated raw-KCP candidate
	t.Run("Case6_SuccessfulAuthenticatedCandidate", func(t *testing.T) {
		mockConn := &mockCandidateConn{
			pingFunc: func(wait bool) error {
				return nil // Protocol PPING/PPONG verified!
			},
		}
		val := BuildCandidateValidator(CandidateValidatorOptions{
			KCPKey: kcpKey,
			RawKCPDialer: func(ctx context.Context, targetAddr string, key []byte) (CandidateConn, error) {
				return mockConn, nil
			},
		})
		err := val(context.Background(), baseEndpoint)
		if err != nil {
			t.Fatalf("Expected successful validation, got %v", err)
		}
		if !mockConn.closed {
			t.Fatalf("Candidate temporary connection must be closed deterministically after validation")
		}
	})

	// 7. Cancellation and timeout during validation
	t.Run("Case7_TimeoutCancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately
		val := BuildCandidateValidator(CandidateValidatorOptions{
			KCPKey: kcpKey,
			RawKCPDialer: func(ctx context.Context, targetAddr string, key []byte) (CandidateConn, error) {
				return nil, ctx.Err()
			},
		})
		err := val(ctx, baseEndpoint)
		if err == nil || !errors.Is(err, ErrCandidateValidation) {
			t.Fatalf("Expected ErrCandidateValidation on canceled context, got %v", err)
		}
	})

	// 8. Candidate that becomes unavailable between validation and the first real connection
	t.Run("Case8_UnavailableAfterValidation", func(t *testing.T) {
		var candidateAlive atomic.Bool
		candidateAlive.Store(true)

		sm := NewRecoveryStateMachine(RecoveryStateMachineConfig{
			PrimaryFailureThreshold:    1,
			DegradedTimeout:            5 * time.Millisecond,
			BootstrapValidationTimeout: 100 * time.Millisecond,
			AllowLoopbackEndpoints:     true,
			EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
				return baseEndpoint, nil
			},
			CandidateValidator: BuildCandidateValidator(CandidateValidatorOptions{
				KCPKey: kcpKey,
				RawKCPDialer: func(ctx context.Context, targetAddr string, key []byte) (CandidateConn, error) {
					if !candidateAlive.Load() {
						return nil, errors.New("candidate server went down")
					}
					return &mockCandidateConn{
						pingFunc: func(wait bool) error { return nil },
					}, nil
				},
			}),
		})

		sm.ReportPrimaryFailure(errors.New("primary down"))
		time.Sleep(10 * time.Millisecond)

		// 1. Candidate validates successfully and enters RECOVERY_READY
		st, err := sm.Step(context.Background())
		if err != nil || st != StateRecoveryReady {
			t.Fatalf("Expected RECOVERY_READY, got %s, err %v", st, err)
		}

		// 2. Candidate becomes unavailable right after validation!
		candidateAlive.Store(false)

		// 3. First real connection dial fails -> reports candidate failure
		dialErr := errors.New("candidate dial timeout")
		sm.ReportCandidateFailure(dialErr)

		// With CandidateFailureLimit = 2 (default), 1 failure keeps RECOVERY_READY, 2nd enters COOLDOWN
		sm.ReportCandidateFailure(errors.New("candidate dial timeout 2"))
		if sm.CurrentState() != StateCooldown {
			t.Fatalf("Expected StateCooldown after candidate failure, got %s", sm.CurrentState())
		}
	})
}

func TestModeAwareIdentityValidation_SeparateRulesPerMode(t *testing.T) {
	now := time.Now()
	validPSKPin := testValidPubKey
	validCertPin := testValidPubKey

	// 1. ModeTLSStream with IdentityTypePSKID must fail closed
	t.Run("TLS_With_PSKID_Rejected", func(t *testing.T) {
		b := &BootstrapEndpointData{
			Version:       2,
			ServerIP:      "203.0.113.7",
			TransportPort: 8443,
			TransportMode: "tls-outer",
			IdentityType:  IdentityTypePSKID, // Invalid for TLS!
			IdentityValue: validPSKPin,
			ValidUntil:    now.Add(1 * time.Hour).Unix(),
		}
		err := b.Validate(now, 24*time.Hour, true, true)
		if err == nil {
			t.Fatalf("Expected validation error for TLS mode with psk-id identity type, got nil")
		}
	})

	// 2. ModeAEADStream with IdentityTypeCertPin must fail closed
	t.Run("AEAD_With_CertPin_Rejected", func(t *testing.T) {
		b := &BootstrapEndpointData{
			Version:       2,
			ServerIP:      "203.0.113.7",
			TransportPort: 18089,
			TransportMode: "aead-stream",
			IdentityType:  IdentityTypeCertPin, // Invalid for AEAD!
			IdentityValue: validCertPin,
			ValidUntil:    now.Add(1 * time.Hour).Unix(),
		}
		err := b.Validate(now, 24*time.Hour, true, true)
		if err == nil {
			t.Fatalf("Expected validation error for AEAD mode with cert-pin identity type, got nil")
		}
	})

	// 3. ModeRawKCP with IdentityTypeCertPin must fail closed
	t.Run("RawKCP_With_CertPin_Rejected", func(t *testing.T) {
		b := &BootstrapEndpointData{
			Version:       2,
			ServerIP:      "203.0.113.7",
			TransportPort: 18088,
			TransportMode: "raw-kcp",
			IdentityType:  IdentityTypeCertPin, // Invalid for raw-kcp!
			IdentityValue: validCertPin,
			ValidUntil:    now.Add(1 * time.Hour).Unix(),
		}
		err := b.Validate(now, 24*time.Hour, true, true)
		if err == nil {
			t.Fatalf("Expected validation error for raw-kcp mode with cert-pin identity type, got nil")
		}
	})

	// 4. Valid pairings pass validation
	t.Run("ValidPairings_Pass", func(t *testing.T) {
		bTLS := &BootstrapEndpointData{
			Version:       2,
			ServerIP:      "203.0.113.7",
			TransportPort: 8443,
			TransportMode: "tls-outer",
			IdentityType:  IdentityTypeCertPin,
			IdentityValue: validCertPin,
			ValidUntil:    now.Add(1 * time.Hour).Unix(),
		}
		if err := bTLS.Validate(now, 24*time.Hour, true, true); err != nil {
			t.Fatalf("Expected valid TLS endpoint to pass, got: %v", err)
		}

		bAEAD := &BootstrapEndpointData{
			Version:       2,
			ServerIP:      "203.0.113.7",
			TransportPort: 18089,
			TransportMode: "aead-stream",
			IdentityType:  IdentityTypePSKID,
			IdentityValue: validPSKPin,
			ValidUntil:    now.Add(1 * time.Hour).Unix(),
		}
		if err := bAEAD.Validate(now, 24*time.Hour, true, true); err != nil {
			t.Fatalf("Expected valid AEAD endpoint to pass, got: %v", err)
		}
	})
}

func TestBootstrapManager_RoundTripAndModeAwareGeneration(t *testing.T) {
	records := []BootstrapEndpointRecord{
		{
			ServerIP:      "203.0.113.7",
			TransportPort: 18089,
			TransportMode: "aead-stream",
			IdentityType:  IdentityTypePSKID,
			IdentityValue: testValidPubKey,
			ValiditySec:   7200,
		},
		{
			ServerIP:      "203.0.113.7",
			TransportPort: 8443,
			TransportMode: "tls-outer",
			IdentityType:  IdentityTypeCertPin,
			IdentityValue: testValidPubKey,
			ValiditySec:   3600,
		},
		{
			ServerIP:      "203.0.113.7",
			TransportPort: 18088,
			TransportMode: "raw-kcp",
			IdentityType:  IdentityTypePSKID,
			IdentityValue: testValidPubKey,
			ValiditySec:   7200,
		},
	}

	bm, err := NewBootstrapManager(records, "aead-stream", 42)
	if err != nil {
		t.Fatalf("NewBootstrapManager failed: %v", err)
	}

	// 1. Request AEAD candidate
	reqAEAD := &EmergencyMessage{ID: "msg-001", Type: MsgTypeBootstrapRequest}
	respAEAD, err := bm.GenerateResponse(reqAEAD, "aead-stream")
	if err != nil {
		t.Fatalf("GenerateResponse for aead-stream failed: %v", err)
	}
	if respAEAD.TransportPort != 18089 || respAEAD.IdentityType != IdentityTypePSKID || respAEAD.RecoveryGen != 42 || respAEAD.RequestID != "msg-001" {
		t.Fatalf("Unexpected AEAD response fields: %+v", respAEAD)
	}

	// 2. Request TLS candidate
	reqTLS := &EmergencyMessage{ID: "msg-002", Type: MsgTypeBootstrapRequest}
	respTLS, err := bm.GenerateResponse(reqTLS, "tls-outer")
	if err != nil {
		t.Fatalf("GenerateResponse for tls-outer failed: %v", err)
	}
	if respTLS.TransportPort != 8443 || respTLS.IdentityType != IdentityTypeCertPin || respTLS.RecoveryGen != 42 || respTLS.RequestID != "msg-002" {
		t.Fatalf("Unexpected TLS response fields: %+v", respTLS)
	}

	// 3. Request unconfigured mode must fail closed
	_, err = bm.GenerateResponse(reqAEAD, "quic-experimental")
	if err == nil {
		t.Fatalf("Expected error for unconfigured mode, got nil")
	}

	// 4. Update recovery generation
	bm.SetRecoveryGen(43)
	respGen, err := bm.GenerateResponse(reqAEAD, "aead-stream")
	if err != nil {
		t.Fatalf("GenerateResponse failed: %v", err)
	}
	if respGen.RecoveryGen != 43 {
		t.Fatalf("Expected updated generation 43, got %d", respGen.RecoveryGen)
	}
}
