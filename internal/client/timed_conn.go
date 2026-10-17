package client

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/arashmh13/paqet-ngv2/internal/conf"
	"github.com/arashmh13/paqet-ngv2/internal/flog"
	"github.com/arashmh13/paqet-ngv2/internal/ng/transport"
	"github.com/arashmh13/paqet-ngv2/internal/protocol"
	"github.com/arashmh13/paqet-ngv2/internal/tnet"
	"github.com/arashmh13/paqet-ngv2/internal/tnet/kcp"
	"github.com/arashmh13/paqet-ngv2/internal/tnet/stream"
)

// ConnectionIdentity explicitly identifies a connection's destination, transport mode, recovery generation, and identity.
type ConnectionIdentity struct {
	RemoteAddr            string
	TransportMode         transport.TransportMode
	Generation            uint64
	IdentityType          transport.EndpointIdentityType
	IdentityValue         string
	AuthoritativeServerID string
	IsRecovery            bool
}

// Matches returns true if two connection identities are equivalent across all fields.
func (id ConnectionIdentity) Matches(target ConnectionIdentity) bool {
	return id.RemoteAddr == target.RemoteAddr &&
		id.TransportMode == target.TransportMode &&
		id.Generation == target.Generation &&
		id.IdentityType == target.IdentityType &&
		id.IdentityValue == target.IdentityValue &&
		id.AuthoritativeServerID == target.AuthoritativeServerID &&
		id.IsRecovery == target.IsRecovery
}

type timedConn struct {
	cfg             *conf.Conf
	conn            tnet.Conn
	currentIdentity ConnectionIdentity
	expire          time.Time
	index           int
	recoveryEngine  *transport.RecoveryStateMachine
	mu              sync.Mutex
}

func newTimedConn(cfg *conf.Conf, index int, re *transport.RecoveryStateMachine) (*timedConn, error) {
	var err error
	tc := timedConn{cfg: cfg, index: index, recoveryEngine: re}
	tc.conn, tc.currentIdentity, err = tc.createConn()
	if err != nil {
		return nil, err
	}

	return &tc, nil
}

func (tc *timedConn) getTargetAddr() string {
	if len(tc.cfg.Server.Endpoints) > 0 {
		ep := tc.cfg.Server.Endpoints[tc.index%len(tc.cfg.Server.Endpoints)]
		return ep.String()
	}
	if tc.cfg.Server.Addr != nil {
		return tc.cfg.Server.Addr.String()
	}
	return ""
}

func (tc *timedConn) desiredIdentity() ConnectionIdentity {
	re := tc.recoveryEngine
	if re != nil && re.CurrentState() == transport.StateRecoveryReady {
		snapshot := re.ActiveSnapshot()
		if snapshot != nil && !snapshot.IsExpired(time.Now()) && snapshot.MatchesGeneration(re.CurrentGeneration()) {
			return ConnectionIdentity{
				RemoteAddr:            snapshot.Addr(),
				TransportMode:         snapshot.TransportMode,
				Generation:            snapshot.Generation,
				IdentityType:          snapshot.IdentityType,
				IdentityValue:         snapshot.GetIdentityValue(),
				AuthoritativeServerID: snapshot.AuthoritativeServerID,
				IsRecovery:            true,
			}
		}
	}

	primaryAddr := tc.getTargetAddr()
	primaryMode := transport.TransportMode(tc.cfg.Transport.Protocol)
	switch tc.cfg.Transport.Protocol {
	case "stream", "aead-stream":
		primaryMode = transport.ModeAEADStream
	case "tls", "tls-stream":
		primaryMode = transport.ModeTLSStream
	case "raw-kcp", "kcp":
		primaryMode = transport.ModeRawKCP
	}
	return ConnectionIdentity{
		RemoteAddr:    primaryAddr,
		TransportMode: primaryMode,
		Generation:    0,
		IdentityType:  transport.IdentityTypePSKID,
		IsRecovery:    false,
	}
}

func (tc *timedConn) createConn() (tnet.Conn, ConnectionIdentity, error) {
	re := tc.recoveryEngine
	if re != nil && re.CurrentState() == transport.StateRecoveryReady {
		snapshot := re.ActiveSnapshot()
		if snapshot == nil {
			err := fmt.Errorf("recovery ready but active snapshot is nil (fail-closed)")
			re.ReportCandidateFailure(err)
			return nil, ConnectionIdentity{}, err
		}

		now := time.Now()
		if snapshot.IsExpired(now) {
			re.ReportCandidateFailure(transport.ErrStaleBootstrapData)
			return nil, ConnectionIdentity{}, fmt.Errorf("recovery candidate %s expired: %w", snapshot.Addr(), transport.ErrStaleBootstrapData)
		}

		if !snapshot.MatchesGeneration(re.CurrentGeneration()) {
			re.ReportCandidateFailure(transport.ErrStaleRecoveryOperation)
			return nil, ConnectionIdentity{}, fmt.Errorf("recovery candidate %s generation mismatch (got %d, current %d): %w",
				snapshot.Addr(), snapshot.Generation, re.CurrentGeneration(), transport.ErrStaleRecoveryOperation)
		}

		flog.Infof("[RECOVERY-FAILOVER] Routing connection to validated recovery candidate %s (%s, gen=%d)",
			snapshot.Addr(), snapshot.TransportMode, snapshot.Generation)

		var candidateConn tnet.Conn
		var dialErr error

		switch snapshot.TransportMode {
		case transport.ModeAEADStream:
			// P0 Requirement: confirm that configured transport key matches authorized snapshot identity!
			var keyBytes []byte
			if tc.cfg.Transport.Obfs != nil {
				keyBytes = []byte(tc.cfg.Transport.Obfs.Key)
			}
			keyDigest := fmt.Sprintf("SHA256:%x", sha256.Sum256(keyBytes))
			if keyDigest != snapshot.GetIdentityValue() {
				dialErr = fmt.Errorf("aead-stream candidate key mismatch: local transport key fingerprint %s does not match authorized snapshot %s (fail-closed)",
					keyDigest, snapshot.GetIdentityValue())
			} else {
				candidateConn, dialErr = stream.Dial(snapshot.Addr(), tc.cfg.Transport.Obfs)
			}

		case transport.ModeTLSStream:
			// P0 Requirement: enforce certificate or pubkey pin on the live TLS connection!
			isPubKey := snapshot.IdentityType == transport.IdentityTypePubKeyPin
			candidateConn, dialErr = stream.DialTLSPinned(snapshot.Addr(), tc.cfg.Transport.Obfs, tc.cfg.Transport.TLS, snapshot.GetIdentityValue(), isPubKey)

		case transport.ModeRawKCP:
			// P0 Requirement: confirm that configured KCP key matches authorized snapshot identity!
			var kcpKey []byte
			if tc.cfg.Transport.KCP != nil && tc.cfg.Transport.KCP.Key != "" {
				kcpKey = []byte(tc.cfg.Transport.KCP.Key)
			} else if tc.cfg.Transport.Obfs != nil {
				kcpKey = []byte(tc.cfg.Transport.Obfs.Key)
			}
			keyDigest := fmt.Sprintf("SHA256:%x", sha256.Sum256(kcpKey))
			if keyDigest != snapshot.GetIdentityValue() {
				dialErr = fmt.Errorf("raw-kcp candidate key mismatch: local KCP key fingerprint %s does not match authorized snapshot %s (fail-closed)",
					keyDigest, snapshot.GetIdentityValue())
			} else {
				netCfg := tc.cfg.Network
				netCfg.SNI = tc.cfg.Transport.SNI
				udpAddr, err := net.ResolveUDPAddr("udp", snapshot.Addr())
				if err != nil {
					dialErr = err
				} else {
					candidateConn, dialErr = kcp.Dial(udpAddr, tc.cfg.Transport.KCP, tc.cfg.Transport.Obfs, netCfg)
				}
			}

		default:
			dialErr = fmt.Errorf("unsupported recovery transport mode %q (fail-closed)", snapshot.TransportMode)
		}

		if dialErr != nil {
			re.ReportCandidateFailure(dialErr)
			flog.Errorf("[RECOVERY-FAILOVER] Candidate %s (%s) dial failed: %v (fail-closed, no implicit fallback)",
				snapshot.Addr(), snapshot.TransportMode, dialErr)
			// P0 REQUIREMENT 5: Stop that recovery attempt and return error; NEVER fall through to primary!
			return nil, ConnectionIdentity{}, fmt.Errorf("recovery candidate %s (%s) dial failed: %w", snapshot.Addr(), snapshot.TransportMode, dialErr)
		}

		// Double-check generation ownership before committing
		if re.CurrentState() != transport.StateRecoveryReady || !snapshot.MatchesGeneration(re.CurrentGeneration()) {
			candidateConn.Close()
			return nil, ConnectionIdentity{}, fmt.Errorf("recovery state changed or superseded during candidate dial: %w", transport.ErrStaleRecoveryOperation)
		}

		targetID := ConnectionIdentity{
			RemoteAddr:            snapshot.Addr(),
			TransportMode:         snapshot.TransportMode,
			Generation:            snapshot.Generation,
			IdentityType:          snapshot.IdentityType,
			IdentityValue:         snapshot.GetIdentityValue(),
			AuthoritativeServerID: snapshot.AuthoritativeServerID,
			IsRecovery:            true,
		}
		return candidateConn, targetID, nil
	}

	target := tc.getTargetAddr()
	primaryID := tc.desiredIdentity()

	switch tc.cfg.Transport.Protocol {
	case "stream", "aead-stream":
		conn, err := stream.Dial(target, tc.cfg.Transport.Obfs)
		if err != nil {
			return nil, ConnectionIdentity{}, err
		}
		return conn, primaryID, nil
	case "sni-assisted":
		conn, err := stream.DialSNIAssisted(target, tc.cfg.Transport.Obfs, tc.cfg.Transport.SNI)
		if err != nil {
			return nil, ConnectionIdentity{}, err
		}
		return conn, primaryID, nil
	case "tls", "tls-stream":
		conn, err := stream.DialTLS(target, tc.cfg.Transport.Obfs, tc.cfg.Transport.TLS)
		if err != nil {
			return nil, ConnectionIdentity{}, err
		}
		return conn, primaryID, nil
	case "auto":
		if tc.cfg.Transport.Obfs != nil && tc.cfg.Transport.Obfs.Enabled {
			conn, err := stream.Dial(target, tc.cfg.Transport.Obfs)
			if err == nil {
				return conn, primaryID, nil
			}
		}
		if tc.cfg.Transport.TLS != nil && tc.cfg.Transport.TLS.Enabled {
			conn, err := stream.DialTLS(target, tc.cfg.Transport.Obfs, tc.cfg.Transport.TLS)
			if err == nil {
				return conn, primaryID, nil
			}
		}
		if tc.cfg.Transport.KCP != nil {
			netCfg := tc.cfg.Network
			netCfg.SNI = tc.cfg.Transport.SNI
			kcpConn, err := kcp.Dial(tc.cfg.Server.Addr, tc.cfg.Transport.KCP, tc.cfg.Transport.Obfs, netCfg)
			if err == nil {
				_ = tc.sendTCPF(kcpConn)
				return kcpConn, primaryID, nil
			}
		}
		return nil, ConnectionIdentity{}, fmt.Errorf("auto transport dial failed for all strategies")
	default:
		netCfg := tc.cfg.Network
		netCfg.SNI = tc.cfg.Transport.SNI
		conn, err := kcp.Dial(tc.cfg.Server.Addr, tc.cfg.Transport.KCP, tc.cfg.Transport.Obfs, netCfg)
		if err != nil {
			return nil, ConnectionIdentity{}, err
		}
		_ = tc.sendTCPF(conn)
		return conn, primaryID, nil
	}
}

func (tc *timedConn) sendTCPF(conn tnet.Conn) error {
	if conn == nil || len(tc.cfg.Network.TCP.RF) == 0 {
		return nil
	}
	strm, err := conn.OpenStrm()
	if err != nil {
		return err
	}
	defer strm.Close()

	p := protocol.Proto{Type: protocol.PTCPF, TCPF: tc.cfg.Network.TCP.RF}
	return p.Write(strm)
}

func (tc *timedConn) close() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.conn != nil {
		_ = tc.conn.Close()
		tc.conn = nil
	}
}
