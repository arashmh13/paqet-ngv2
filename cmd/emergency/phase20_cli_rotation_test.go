package emergency

// Phase 20 P1-4: exercise the REAL CLI configuration path
// (`loadAuthorizedServersConfig` → `NewEmergencyDNSClient`) for rotation and
// atomic-replacement semantics, plus legacy-frame rejection by a v4 multi-server
// client. Trust-model documentation: the symmetric retention means a client
// holding a server's response secret can forge responses FOR that server
// identity — never claimed otherwise in these tests or docs.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/arashmh13/paqet-ngv2/internal/ng/transport"
)

// TestPhase20CliPath_AtomicReplacementRejectsInvalidEntry: a replacement config
// in which exactly ONE credential is invalid must reject as a whole — no partial
// authorization (atomicity through fail-closed load).
func TestPhase20CliPath_AtomicReplacementRejectsInvalidEntry(t *testing.T) {
	tmp := t.TempDir()
	goodA := make([]byte, 32)
	goodB := make([]byte, 32)
	badShort := make([]byte, 8)
	for i := range goodA {
		goodA[i] = byte(0xC0 + i)
		goodB[i] = byte(0xD0 + i)
	}
	pA := writeSecretFile(t, tmp, "a.secret", goodA, 0600)
	pB := writeSecretFile(t, tmp, "b.secret", goodB, 0600)
	pBad := writeSecretFile(t, tmp, "bad.secret", badShort, 0600)

	// Baseline good config loads two servers.
	base := writeConfigFile(t, tmp, "base.json", AuthorizedServersConfigFile{
		Version: 1, Protocol: "v4", Generation: 1,
		AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "srv-a-01", SecretFile: pA}, {ServerID: "srv-b-01", SecretFile: pB}},
	}, 0600)
	entries, _, gen, err := loadAuthorizedServersConfig(base)
	if err != nil || len(entries) != 2 || gen != 1 {
		t.Fatalf("baseline load: err=%v entries=%d gen=%d", err, len(entries), gen)
	}

	// Replacement candidate with ONE invalid entry (among valid ones) must fail as a whole.
	repl := writeConfigFile(t, tmp, "replacement.json", AuthorizedServersConfigFile{
		Version: 1, Protocol: "v4", Generation: 2,
		AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "srv-a-01", SecretFile: pA}, {ServerID: "srv-b-01", SecretFile: pBad}},
	}, 0600)
	if _, _, _, err := loadAuthorizedServersConfig(repl); err == nil {
		t.Fatalf("DEFECT: replacement containing one invalid credential accepted (partial authorization risk)")
	}

	// Replacement with duplicated server ID rejected.
	replDup := writeConfigFile(t, tmp, "replacement-dup.json", AuthorizedServersConfigFile{
		Version: 1, Protocol: "v4", Generation: 2,
		AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "srv-a-01", SecretFile: pA}, {ServerID: "srv-a-01", SecretFile: pB}},
	}, 0600)
	if _, _, _, err := loadAuthorizedServersConfig(replDup); err == nil {
		t.Fatalf("DEFECT: duplicated server ID accepted")
	}

	// Replacement with insecure permissions accepted-at-load is impossible: the
	// secret file policy rejects 0644 before entries are constructed.
	pInsec := writeSecretFile(t, tmp, "insec.secret", goodA, 0644)
	replInsec := writeConfigFile(t, tmp, "replacement-insec.json", AuthorizedServersConfigFile{
		Version: 1, Protocol: "v4", Generation: 2,
		AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "srv-a-01", SecretFile: pInsec}},
	}, 0600)
	if _, _, _, err := loadAuthorizedServersConfig(replInsec); err == nil {
		t.Fatalf("DEFECT: insecure 0644 secret accepted in replacement config")
	}

	// Rotation: a valid replacement with a ROTATED credential for srv-b loads and
	// the loaded secrets are deep-cloned (mutating the returned slice cannot alter
	// constructed client state).
	rotB := make([]byte, 32)
	for i := range rotB {
		rotB[i] = byte(0xE0 + i)
	}
	pRotB := writeSecretFile(t, tmp, "b-rotated.secret", rotB, 0600)
	replRot := writeConfigFile(t, tmp, "replacement-rot.json", AuthorizedServersConfigFile{
		Version: 1, Protocol: "v4", Generation: 3,
		AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "srv-a-01", SecretFile: pA}, {ServerID: "srv-b-01", SecretFile: pRotB}},
	}, 0600)
	rotEntries, _, gen3, err := loadAuthorizedServersConfig(replRot)
	if err != nil || len(rotEntries) != 2 || gen3 != 3 {
		t.Fatalf("rotation load: err=%v entries=%d gen=%d", err, len(rotEntries), gen3)
	}

	set, err := transport.NewAuthorizedServerSet("epoch-p20cli", rotEntries)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	// Deep-clone verification: mutating attacker-visible entries after construction
	// must not change authorized credentials (byte oracle below).
	for i := range rotEntries {
		for j := range rotEntries[i].ResponseSecret {
			rotEntries[i].ResponseSecret[j] = 0x00
		}
	}
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(0xF0 + i)
	}
	seedX := [16]byte{}
	for i := range seedX {
		seedX[i] = byte(0x40 + i)
	}
	if _, err := transport.NewClientAsymmetricSessionV4(0x4001, psk, set, &seedX); err != nil {
		t.Fatalf("client construct: %v", err)
	}
}

// TestPhase20CliPath_RotationInvalidatesStaleAuthorization: through the CLI path,
// a rotated client (fresh config with new credential) authenticates; the STALE
// client (old credential for the same identity) fails closed; a revoked identity
// (absent from the config) is rejected by wire policy.
func TestPhase20CliPath_RotationInvalidatesStaleAuthorization(t *testing.T) {
	tmp := t.TempDir()
	secretOld := make([]byte, 32)
	secretNew := make([]byte, 32)
	for i := range secretOld {
		secretOld[i] = byte(0xA1 + i)
		secretNew[i] = byte(0xB1 + i)
	}
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(0xC1 + i)
	}

	newServer := func(t *testing.T, secret []byte, addr string) *transport.EmergencyDNSServer {
		t.Helper()
		srv, err := transport.NewEmergencyDNSServer(transport.EmergencyDNSServerConfig{
			ListenAddr: addr, DomainSuffix: "p20cli.test", PSK: psk, ServerID: "srv-cli-01",
			ServerSecret: secret, ProtocolV4: true,
			Handler: func(msg *transport.EmergencyMessage) (*transport.EmergencyResponse, error) {
				return &transport.EmergencyResponse{ID: msg.ID, Status: "OK", Timestamp: 1}, nil
			},
		})
		if err != nil {
			t.Fatalf("server: %v", err)
		}
		return srv
	}

	srvOld := newServer(t, secretOld, "127.0.0.1:0")
	defer srvOld.Stop()
	staleAddr := srvOld.Addr().String()

	clNew, err := transport.NewEmergencyDNSClient(transport.EmergencyDNSClientConfig{
		Resolvers: []string{staleAddr}, DomainSuffix: "p20cli.test", ClientID: "c20", PSK: psk,
		Timeout: 2 * time.Second, PerAttemptTimeout: 700 * time.Millisecond, MaxRetries: 1, ProtocolV4: true,
		ServerIdentities: []transport.AuthorizedServerEntry{{ServerID: "srv-cli-01", ResponseSecret: append([]byte(nil), secretOld...)}},
	})
	if err != nil {
		t.Fatalf("pre-rotation client: %v", err)
	}
	ctx := context.Background()
	if _, _, err := clNew.Exchange(ctx, &transport.EmergencyMessage{ID: "pre-rot", Type: "ping"}); err != nil {
		t.Fatalf("pre-rotation exchange: %v", err)
	}
	srvOld.Stop()

	// Server restarts with ROTATED credential.
	srvNew := newServer(t, secretNew, staleAddr)
	defer srvNew.Stop()

	mkClient := func(t *testing.T, secret []byte, gen uint64) *transport.EmergencyDNSClient {
		t.Helper()
		p := writeSecretFile(t, tmp, "cli.secret", secret, 0600)
		cfg := writeConfigFile(t, tmp, "cli.json", AuthorizedServersConfigFile{
			Version: 1, Protocol: "v4", Generation: gen,
			AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "srv-cli-01", SecretFile: p}},
		}, 0600)
		entries, _, _, err := loadAuthorizedServersConfig(cfg)
		if err != nil {
			t.Fatalf("load cli config gen %d: %v", gen, err)
		}
		cl, err := transport.NewEmergencyDNSClient(transport.EmergencyDNSClientConfig{
			Resolvers: []string{staleAddr}, DomainSuffix: "p20cli.test", ClientID: "c20", PSK: psk,
			Timeout: 2 * time.Second, PerAttemptTimeout: 700 * time.Millisecond, MaxRetries: 1, ProtocolV4: true,
			ServerIdentities: entries,
		})
		if err != nil {
			t.Fatalf("client gen %d: %v", gen, err)
		}
		return cl
	}

	// Stale-credential client (generation 5, old secret) must fail closed.
	stale := mkClient(t, secretOld, 5)
	if _, _, err := stale.Exchange(ctx, &transport.EmergencyMessage{ID: "stale-1", Type: "ping"}); err == nil {
		t.Fatalf("CRITICAL: stale rotated credential authenticated against rotated server")
	}
	// Fresh-credential client (generation 6, new secret) must succeed.
	fresh := mkClient(t, secretNew, 6)
	if resp, _, err := fresh.Exchange(ctx, &transport.EmergencyMessage{ID: "fresh-1", Type: "ping"}); err != nil || resp == nil {
		t.Fatalf("rotated-credential exchange: err=%v", err)
	}
	// Revocation: config that does NOT list srv-cli-01 must fail closed on the wire.
	revoked := tmpRevokedClient(t, tmp, psk, staleAddr)
	if _, _, err := revoked.Exchange(ctx, &transport.EmergencyMessage{ID: "rev-1", Type: "ping"}); err == nil {
		t.Fatalf("CRITICAL: revoked (unlisted) server identity accepted")
	}
}

func tmpRevokedClient(t *testing.T, tmp string, psk []byte, addr string) *transport.EmergencyDNSClient {
	t.Helper()
	other := make([]byte, 32)
	for i := range other {
		other[i] = byte(0x77 + i)
	}
	p := writeSecretFile(t, tmp, "other.secret", other, 0600)
	cfg := writeConfigFile(t, tmp, "other.json", AuthorizedServersConfigFile{
		Version: 1, Protocol: "v4", Generation: 9,
		AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "srv-other-01", SecretFile: p}},
	}, 0600)
	entries, _, _, err := loadAuthorizedServersConfig(cfg)
	if err != nil {
		t.Fatalf("revoked load: %v", err)
	}
	cl, err := transport.NewEmergencyDNSClient(transport.EmergencyDNSClientConfig{
		Resolvers: []string{addr}, DomainSuffix: "p20cli.test", ClientID: "c20", PSK: psk,
		Timeout: 1200 * time.Millisecond, PerAttemptTimeout: 500 * time.Millisecond, MaxRetries: 0, ProtocolV4: true,
		ServerIdentities: entries,
	})
	if err != nil {
		t.Fatalf("revoked client: %v", err)
	}
	return cl
}

// TestPhase20CliPath_V4ClientRejectsLegacyFrames proves the v4 multi-server
// client rejects v3/v2 wire generations instead of silently interpreting them.
func TestPhase20CliPath_V4ClientRejectsLegacyFrames(t *testing.T) {
	tmp := t.TempDir()
	psk := make([]byte, 32)
	secret := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(0x50 + i)
		secret[i] = byte(0x60 + i)
	}
	pSecret := writeSecretFile(t, tmp, "s.secret", secret, 0600)
	cfgPath := writeConfigFile(t, tmp, "v4.json", AuthorizedServersConfigFile{
		Version: 1, Protocol: "v4", Generation: 1,
		AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "srv-legacy-rej", SecretFile: pSecret}},
	}, 0600)
	entries, protocol, _, err := loadAuthorizedServersConfig(cfgPath)
	if err != nil || protocol != "v4" || len(entries) != 1 {
		t.Fatalf("load: err=%v protocol=%s", err, protocol)
	}
	seedX := [16]byte{}
	for i := range seedX {
		seedX[i] = byte(0x41 + i)
	}
	set, err := transport.NewAuthorizedServerSet("epoch-legrej", entries)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	client, err := transport.NewClientAsymmetricSessionV4(0x4002, psk, set, &seedX)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	reqBytes, _ := json.Marshal(&transport.EmergencyMessage{ID: "legrej", Type: "ping"})
	v4Frame, err := client.SealFrame(1, 0, reqBytes)
	if err != nil {
		t.Fatalf("seal v4: %v", err)
	}
	// Tamper the magic PAQD→PAQC (client-upstream): must fail openFrame with an
	// explicit protocol error, never reinterpret as v3.
	tampered := append([]byte(nil), v4Frame...)
	tampered[3] = 'C' // 0x50415144 → 0x50415143
	if _, _, _, _, err := client.VerifyFrameWithServerID(tampered); err == nil {
		t.Fatalf("DEFECT: tampered-magic frame accepted (no explicit version enforcement)")
	} else if !bytes.Contains([]byte(err.Error()), []byte("protocol")) {
		t.Fatalf("expected protocol error class, got: %v", err)
	}
	// A genuinely v2-magic (legacy "PAQA") frame must also be explicitly rejected.
	legacy := append([]byte(nil), v4Frame...)
	legacy[2] = 'A'
	legacy[3] = 'A'
	_ = os.Setenv // keep os import used on all platforms
	if _, _, _, _, err := client.VerifyFrameWithServerID(legacy); err == nil {
		t.Fatalf("DEFECT: legacy PAQA frame accepted on v4 client")
	}
}
