package transport

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type mockIntegrationSession struct {
	addr string
}

func (m *mockIntegrationSession) OpenStream() (net.Conn, error)   { return nil, nil }
func (m *mockIntegrationSession) AcceptStream() (net.Conn, error) { return nil, nil }
func (m *mockIntegrationSession) Close() error                    { return nil }
func (m *mockIntegrationSession) IsClosed() bool                  { return false }
func (m *mockIntegrationSession) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1000}
}
func (m *mockIntegrationSession) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2000}
}

type mockStrategy struct {
	mode         TransportMode
	isDown       atomic.Bool
	dials        int32
	lastDialAddr string
}

func (m *mockStrategy) Mode() TransportMode { return m.mode }
func (m *mockStrategy) Capabilities() TransportCapabilities {
	return TransportCapabilities{PrerequisitesMet: true}
}
func (m *mockStrategy) CheckHealth(ctx context.Context, addr string) (time.Duration, error) {
	if m.isDown.Load() {
		return 0, errors.New("mock primary is down")
	}
	return 10 * time.Millisecond, nil
}
func (m *mockStrategy) Metrics() HealthMetrics {
	state := "closed"
	if m.isDown.Load() {
		state = "open"
	}
	return HealthMetrics{CircuitState: state}
}
func (m *mockStrategy) Dial(ctx context.Context, addr string) (Session, error) {
	atomic.AddInt32(&m.dials, 1)
	m.lastDialAddr = addr
	if m.isDown.Load() {
		return nil, errors.New("connection refused: primary server unreachable")
	}
	return &mockIntegrationSession{addr: addr}, nil
}

func TestRecoverySelectorIntegration_EndToEndFailover(t *testing.T) {
	primaryStrat := &mockStrategy{mode: ModeAEADStream}

	recoveryCandidateAddr := "203.0.113.7:18089"

	recoverySM := NewRecoveryStateMachine(RecoveryStateMachineConfig{
		PrimaryFailureThreshold:    3,
		DegradedTimeout:            20 * time.Millisecond,
		BootstrapValidationTimeout: 100 * time.Millisecond,
		CooldownDuration:           500 * time.Millisecond,
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
				return nil // Authenticated handshake validated!
			}
			return errors.New("candidate validation failed")
		},
	})

	selector := NewStrategySelector(SelectorConfig{
		Candidates:      []Strategy{primaryStrat},
		PreferredMode:   ModeAEADStream,
		CircuitCooldown: 10 * time.Millisecond,
		RecoveryEngine:  recoverySM,
	})

	ctx := context.Background()
	primaryTarget := "203.0.113.7:8089"

	// 1. Initial State: Primary is healthy
	sess, err := selector.Dial(ctx, primaryTarget)
	if err != nil {
		t.Fatalf("Initial dial should succeed, got %v", err)
	}
	if sess == nil {
		t.Fatalf("Session should not be nil")
	}
	if recoverySM.CurrentState() != StatePrimaryHealthy {
		t.Fatalf("Expected state PRIMARY_HEALTHY, got %s", recoverySM.CurrentState())
	}

	// 2. Simulate primary network failure
	primaryStrat.isDown.Store(true)

	// Call Dial 3 times to cross PrimaryFailureThreshold (3)
	for i := 1; i <= 3; i++ {
		_, err := selector.Dial(ctx, primaryTarget)
		if err == nil {
			t.Fatalf("Dial %d should have failed when primary is down", i)
		}
	}

	// Verify state machine reached PRIMARY_DEGRADED
	if recoverySM.CurrentState() != StatePrimaryDegraded {
		t.Fatalf("Expected state PRIMARY_DEGRADED after 3 failures, got %s", recoverySM.CurrentState())
	}

	// 3. Wait for DegradedTimeout (20ms) to elapse so emergency signaling is ready
	time.Sleep(30 * time.Millisecond)

	// Next dial triggers emergency signaling and candidate validation inside selector!
	_, _ = selector.Dial(ctx, primaryTarget)

	// Verify recovery state machine transitioned through signaling, validation, and reached RECOVERY_READY!
	if recoverySM.CurrentState() != StateRecoveryReady {
		t.Fatalf("Expected state RECOVERY_READY, got %s", recoverySM.CurrentState())
	}
	if recoverySM.ActiveEndpoint() != recoveryCandidateAddr {
		t.Fatalf("Expected active endpoint %s, got %s", recoveryCandidateAddr, recoverySM.ActiveEndpoint())
	}

	// 4. Candidate transport now handles the recovery address
	// Let primaryStrat accept dials to the recoveryCandidateAddr (simulating candidate server ready)
	primaryStrat.isDown.Store(false)

	recovSess, err := selector.Dial(ctx, primaryTarget)
	if err != nil {
		t.Fatalf("Dial through recovery candidate failed: %v", err)
	}
	if recovSess == nil {
		t.Fatalf("Recovery session should not be nil")
	}

	// Verify that Dial used the activated recovery endpoint address!
	if primaryStrat.lastDialAddr != recoveryCandidateAddr {
		t.Fatalf("Expected dial to recovery endpoint %s, but dial went to %s",
			recoveryCandidateAddr, primaryStrat.lastDialAddr)
	}

	// 5. Test Rollback
	recoverySM.ResetRollback("operator restored primary")
	selector.ResetCooldowns()
	if recoverySM.CurrentState() != StatePrimaryHealthy {
		t.Fatalf("Expected PRIMARY_HEALTHY after ResetRollback, got %s", recoverySM.CurrentState())
	}
	if recoverySM.ActiveEndpoint() != "" {
		t.Fatalf("Active endpoint should be cleared after rollback, got %s", recoverySM.ActiveEndpoint())
	}

	// Next dial should go back to primaryTarget
	_, err = selector.Dial(ctx, primaryTarget)
	if err != nil {
		t.Fatalf("Dial after rollback failed: %v", err)
	}
	if primaryStrat.lastDialAddr != primaryTarget {
		t.Fatalf("Expected dial to primary target %s, got %s", primaryTarget, primaryStrat.lastDialAddr)
	}
}

func TestRecoverySelectorIntegration_UnauthorizedModeFailClosed(t *testing.T) {
	// P0 REQUIREMENT: Selector must honor the explicitly validated mode.
	// If required strategy is unavailable in candidates, fail closed!
	primaryStrat := &mockStrategy{mode: ModeAEADStream} // Only AEADStream is available

	recoverySM := NewRecoveryStateMachine(RecoveryStateMachineConfig{
		PrimaryFailureThreshold:    1,
		DegradedTimeout:            10 * time.Millisecond,
		BootstrapValidationTimeout: 100 * time.Millisecond,
		CooldownDuration:           500 * time.Millisecond,
		AllowLoopbackEndpoints:     true,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "203.0.113.7",
				TransportPort: 8443,
				TransportMode: "tls-outer", // Bootstrap explicitly authorizes TLS!
				ServerPubKey:  testValidPubKey,
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			return nil
		},
	})

	selector := NewStrategySelector(SelectorConfig{
		Candidates:      []Strategy{primaryStrat}, // No TLS strategy configured!
		PreferredMode:   ModeAEADStream,
		CircuitCooldown: 10 * time.Millisecond,
		RecoveryEngine:  recoverySM,
	})

	ctx := context.Background()
	primaryTarget := "203.0.113.7:8089"

	// Trigger primary failure -> recovery state machine advances to RECOVERY_READY
	primaryStrat.isDown.Store(true)
	_, _ = selector.Dial(ctx, primaryTarget)
	time.Sleep(15 * time.Millisecond)
	_, _ = selector.Dial(ctx, primaryTarget)

	if recoverySM.CurrentState() != StateRecoveryReady {
		t.Fatalf("Expected StateRecoveryReady, got %s", recoverySM.CurrentState())
	}

	// Dialing must FAIL CLOSED because authorized mode tls-outer is not in selector candidates!
	_, dialErr := selector.Dial(ctx, primaryTarget)
	if dialErr == nil {
		t.Fatalf("Expected dial to fail closed when authorized mode is missing, but dial succeeded!")
	}
}

func TestRecoverySelectorIntegration_RecoveryDialSuccessDoesNotClearRecovery(t *testing.T) {
	// P1 REQUIREMENT: A primary success result cannot accidentally clear an active recovery endpoint
	// if the successful dial actually used the recovery endpoint.
	strat := &mockStrategy{mode: ModeAEADStream}

	recoverySM := NewRecoveryStateMachine(RecoveryStateMachineConfig{
		PrimaryFailureThreshold:    1,
		DegradedTimeout:            10 * time.Millisecond,
		BootstrapValidationTimeout: 100 * time.Millisecond,
		CooldownDuration:           500 * time.Millisecond,
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
			return nil
		},
	})

	selector := NewStrategySelector(SelectorConfig{
		Candidates:      []Strategy{strat},
		PreferredMode:   ModeAEADStream,
		CircuitCooldown: 10 * time.Millisecond,
		RecoveryEngine:  recoverySM,
	})

	ctx := context.Background()
	primaryTarget := "203.0.113.7:8089"

	strat.isDown.Store(true)
	_, _ = selector.Dial(ctx, primaryTarget)
	time.Sleep(15 * time.Millisecond)
	_, _ = selector.Dial(ctx, primaryTarget)

	if recoverySM.CurrentState() != StateRecoveryReady {
		t.Fatalf("Expected StateRecoveryReady, got %s", recoverySM.CurrentState())
	}

	// Make candidate accept dials
	strat.isDown.Store(false)

	// Dial succeeds through recovery candidate!
	sess, err := selector.Dial(ctx, primaryTarget)
	if err != nil || sess == nil {
		t.Fatalf("Dial through recovery candidate should succeed: %v", err)
	}

	// Recovery engine MUST STILL BE in RECOVERY_READY (not cleared by dial success!)
	if recoverySM.CurrentState() != StateRecoveryReady {
		t.Fatalf("Active recovery endpoint must not be cleared by successful dial through recovery, got state %s", recoverySM.CurrentState())
	}
	if recoverySM.ActiveEndpoint() != "203.0.113.7:18089" {
		t.Fatalf("Active endpoint must remain set, got %s", recoverySM.ActiveEndpoint())
	}
}

func TestRecoverySelectorIntegration_RecoveryCandidateFailureTriggersCooldown(t *testing.T) {
	// P1 REQUIREMENT: Candidate failures trigger documented state transition and cooldown.
	strat := &mockStrategy{mode: ModeAEADStream}

	recoverySM := NewRecoveryStateMachine(RecoveryStateMachineConfig{
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
	})

	selector := NewStrategySelector(SelectorConfig{
		Candidates:      []Strategy{strat},
		PreferredMode:   ModeAEADStream,
		CircuitCooldown: 10 * time.Millisecond,
		RecoveryEngine:  recoverySM,
	})

	ctx := context.Background()
	primaryTarget := "203.0.113.7:8089"

	strat.isDown.Store(true)
	_, _ = selector.Dial(ctx, primaryTarget)
	time.Sleep(15 * time.Millisecond)
	_, _ = selector.Dial(ctx, primaryTarget)

	if recoverySM.CurrentState() != StateRecoveryReady {
		t.Fatalf("Expected StateRecoveryReady, got %s", recoverySM.CurrentState())
	}

	// Candidate continues to fail (isDown = true)
	// Dial 1: candidate failure 1
	_, _ = selector.Dial(ctx, primaryTarget)
	if recoverySM.CurrentState() != StateRecoveryReady {
		t.Fatalf("Expected still StateRecoveryReady after 1 candidate failure, got %s", recoverySM.CurrentState())
	}

	// Dial 2: candidate failure 2 -> reaches limit -> enters COOLDOWN!
	_, _ = selector.Dial(ctx, primaryTarget)
	if recoverySM.CurrentState() != StateCooldown {
		t.Fatalf("Expected StateCooldown after reaching candidate failure limit, got %s", recoverySM.CurrentState())
	}
}
