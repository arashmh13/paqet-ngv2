package client

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/arashmh13/paqet-ngv2/internal/conf"
	"github.com/arashmh13/paqet-ngv2/internal/ng/transport"
	"github.com/arashmh13/paqet-ngv2/internal/tnet"
)

type dummyConn struct {
	addr   string
	closed bool
}

func (d *dummyConn) OpenStrm() (tnet.Strm, error)   { return nil, nil }
func (d *dummyConn) AcceptStrm() (tnet.Strm, error) { return nil, nil }
func (d *dummyConn) Ping(wait bool) error {
	if d.closed {
		return errors.New("connection closed")
	}
	return nil
}
func (d *dummyConn) Close() error {
	d.closed = true
	return nil
}
func (d *dummyConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}
func (d *dummyConn) RemoteAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", d.addr)
	return addr
}
func (d *dummyConn) SetDeadline(t time.Time) error      { return nil }
func (d *dummyConn) SetReadDeadline(t time.Time) error  { return nil }
func (d *dummyConn) SetWriteDeadline(t time.Time) error { return nil }

func TestConnectionIdentity_Matches(t *testing.T) {
	id1 := ConnectionIdentity{
		RemoteAddr:    "203.0.113.7:18088",
		TransportMode: transport.ModeAEADStream,
		Generation:    1,
		IdentityType:  transport.IdentityTypePSKID,
		IdentityValue: "SHA256:abcd",
		IsRecovery:    true,
	}

	id2 := id1
	if !id1.Matches(id2) {
		t.Fatalf("Identical identities must match")
	}

	// Change mode
	idModeDiff := id1
	idModeDiff.TransportMode = transport.ModeTLSStream
	if id1.Matches(idModeDiff) {
		t.Fatalf("Identities with different modes must not match")
	}

	// Change generation
	idGenDiff := id1
	idGenDiff.Generation = 2
	if id1.Matches(idGenDiff) {
		t.Fatalf("Identities with different generations must not match")
	}

	// Change recovery flag
	idRecovDiff := id1
	idRecovDiff.IsRecovery = false
	if id1.Matches(idRecovDiff) {
		t.Fatalf("Identities with different recovery flags must not match")
	}

	// Change remote address
	idAddrDiff := id1
	idAddrDiff.RemoteAddr = "203.0.113.7:18089"
	if id1.Matches(idAddrDiff) {
		t.Fatalf("Identities with different addresses must not match")
	}
}

func TestTimedConn_SameAddressModeChangeRecreates(t *testing.T) {
	u, _ := net.ResolveUDPAddr("udp", "203.0.113.7:18088")
	cfg := &conf.Conf{
		Server: conf.Server{
			Addr: u,
		},
		Transport: conf.Transport{
			Protocol: "aead-stream",
			Obfs: &conf.Obfs{
				Enabled: true,
				Key:     "01234567890123456789012345678901",
			},
		},
	}

	sm := transport.NewRecoveryStateMachine(transport.RecoveryStateMachineConfig{
		AllowLoopbackEndpoints: true,
	})

	tc := &timedConn{
		cfg:            cfg,
		index:          0,
		recoveryEngine: sm,
		conn:           &dummyConn{addr: "203.0.113.7:18088"},
		currentIdentity: ConnectionIdentity{
			RemoteAddr:    "203.0.113.7:18088",
			TransportMode: transport.ModeAEADStream,
			Generation:    1,
			IdentityType:  transport.IdentityTypePSKID,
			IsRecovery:    true,
		},
	}

	// Now state changes: candidate is at same address 203.0.113.7:18088, but mode is tls-outer!
	desired := tc.desiredIdentity()
	// Since state machine is not in RECOVERY_READY, desired is primary
	if tc.currentIdentity.Matches(desired) {
		t.Fatalf("Current recovery identity must not match primary desired identity")
	}
}

func TestTimedConn_EliminateImplicitFallbackOnCandidateFailure(t *testing.T) {
	// Candidate failure must return error and NOT fall through to primary
	primaryAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:8088")
	cfg := &conf.Conf{
		Server: conf.Server{
			Addr: primaryAddr,
		},
		Transport: conf.Transport{
			Protocol: "aead-stream",
			Obfs: &conf.Obfs{
				Enabled: true,
				Key:     "01234567890123456789012345678901",
			},
		},
	}

	validPin := "SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	sm := transport.NewRecoveryStateMachine(transport.RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         5 * time.Millisecond,
		AllowLoopbackEndpoints:  true,
		EmergencyDialer: func(ctx context.Context, msg *transport.EmergencyMessage) (*transport.BootstrapEndpointData, error) {
			return &transport.BootstrapEndpointData{
				Version:       2,
				ServerIP:      "127.0.0.1",
				TransportPort: 54321, // non-existent candidate port
				TransportMode: "aead-stream",
				IdentityType:  transport.IdentityTypePSKID,
				IdentityValue: validPin,
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *transport.BootstrapEndpointData) error {
			return nil // Mock validator succeeds
		},
	})

	sm.ReportPrimaryFailure(errors.New("primary down"))
	time.Sleep(10 * time.Millisecond)
	st, err := sm.Step(context.Background())
	if err != nil || st != transport.StateRecoveryReady {
		t.Fatalf("Expected RECOVERY_READY, got %s, err %v", st, err)
	}

	tc := &timedConn{
		cfg:            cfg,
		index:          0,
		recoveryEngine: sm,
	}

	// Dialing candidate on 127.0.0.1:54321 will fail
	conn, id, err := tc.createConn()
	if err == nil {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("Expected candidate dial error, but createConn succeeded!")
	}
	if id.RemoteAddr == "127.0.0.1:8088" {
		t.Fatalf("Fail-closed violation: createConn fell through to primary 8088 after candidate failure!")
	}
}

func TestClient_NewStrmContextCancellationStopsLoop(t *testing.T) {
	primaryAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:54322")
	cfg := &conf.Conf{
		Server: conf.Server{
			Addr: primaryAddr,
		},
		Transport: conf.Transport{
			Protocol: "aead-stream",
			Obfs: &conf.Obfs{
				Enabled: true,
				Key:     "01234567890123456789012345678901",
			},
		},
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New client failed: %v", err)
	}

	// Add timedConn to iterator
	tc := &timedConn{
		cfg:   cfg,
		index: 0,
	}
	c.iter.Items = append(c.iter.Items, tc)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = c.newStrm(ctx)
	dur := time.Since(start)

	if err == nil {
		t.Fatalf("Expected error on closed port, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Logf("Returned error: %v", err)
	}
	if dur > 1*time.Second {
		t.Fatalf("newStrm took too long (%v), must respect context cancellation quickly", dur)
	}
}

func TestTimedConn_CandidateKeyMismatchFailsClosed(t *testing.T) {
	primaryAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:8088")
	cfg := &conf.Conf{
		Server: conf.Server{
			Addr: primaryAddr,
		},
		Transport: conf.Transport{
			Protocol: "aead-stream",
			Obfs: &conf.Obfs{
				Enabled: true,
				Key:     "01234567890123456789012345678901",
			},
		},
	}

	// Snapshot expects key with a DIFFERENT fingerprint
	mismatchedPin := "SHA256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	sm := transport.NewRecoveryStateMachine(transport.RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         5 * time.Millisecond,
		AllowLoopbackEndpoints:  true,
		EmergencyDialer: func(ctx context.Context, msg *transport.EmergencyMessage) (*transport.BootstrapEndpointData, error) {
			return &transport.BootstrapEndpointData{
				Version:       2,
				ServerIP:      "127.0.0.1",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				IdentityType:  transport.IdentityTypePSKID,
				IdentityValue: mismatchedPin,
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *transport.BootstrapEndpointData) error {
			return nil
		},
	})

	sm.ReportPrimaryFailure(errors.New("primary down"))
	time.Sleep(10 * time.Millisecond)
	st, err := sm.Step(context.Background())
	if err != nil || st != transport.StateRecoveryReady {
		t.Fatalf("Expected RECOVERY_READY, got %s, err %v", st, err)
	}

	tc := &timedConn{
		cfg:            cfg,
		index:          0,
		recoveryEngine: sm,
	}

	// createConn must fail closed immediately because configured key doesn't match snapshot identity!
	conn, _, err := tc.createConn()
	if err == nil {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("expected candidate key mismatch failure, but createConn succeeded!")
	}
	t.Logf("PASS: createConn failed closed on candidate key mismatch: %v", err)
}

func TestTimedConn_GenerationChangeOrRollbackDuringDialRejectsConnection(t *testing.T) {
	configuredKey := "01234567890123456789012345678901"
	keyDigest := fmt.Sprintf("SHA256:%x", sha256.Sum256([]byte(configuredKey)))

	primaryAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:8088")
	cfg := &conf.Conf{
		Server: conf.Server{
			Addr: primaryAddr,
		},
		Transport: conf.Transport{
			Protocol: "aead-stream",
			Obfs: &conf.Obfs{
				Enabled: true,
				Key:     configuredKey,
			},
		},
	}

	sm := transport.NewRecoveryStateMachine(transport.RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         5 * time.Millisecond,
		AllowLoopbackEndpoints:  true,
		EmergencyDialer: func(ctx context.Context, msg *transport.EmergencyMessage) (*transport.BootstrapEndpointData, error) {
			return &transport.BootstrapEndpointData{
				Version:       2,
				ServerIP:      "127.0.0.1",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				IdentityType:  transport.IdentityTypePSKID,
				IdentityValue: keyDigest,
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *transport.BootstrapEndpointData) error {
			return nil
		},
	})

	sm.ReportPrimaryFailure(errors.New("primary down"))
	time.Sleep(10 * time.Millisecond)
	st, err := sm.Step(context.Background())
	if err != nil || st != transport.StateRecoveryReady {
		t.Fatalf("Expected RECOVERY_READY, got %s, err %v", st, err)
	}

	tc := &timedConn{
		cfg:            cfg,
		index:          0,
		recoveryEngine: sm,
	}

	// Simulate dialing: we have dialed candidate identity
	dialedIdentity := ConnectionIdentity{
		RemoteAddr:    "127.0.0.1:18089",
		TransportMode: transport.ModeAEADStream,
		Generation:    sm.ActiveSnapshot().Generation,
		IdentityType:  transport.IdentityTypePSKID,
		IdentityValue: keyDigest,
		IsRecovery:    true,
	}

	// Before inserting into pool, rollback occurs!
	sm.ResetRollback("test primary restored")

	// Verify that tc.desiredIdentity() now disagrees with dialedIdentity
	currentDesired := tc.desiredIdentity()
	if dialedIdentity.Matches(currentDesired) {
		t.Fatalf("dialed recovery identity must not match desired identity after rollback to primary!")
	}
	t.Logf("PASS: Post-rollback desired identity correctly rejects dialed recovery connection")
}
