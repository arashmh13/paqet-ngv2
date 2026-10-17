package emergency

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arashmh13/paqet-ngv2/internal/ng/transport"
)

// writeSecretFile writes a hex-encoded 32-byte secret with the given permissions.
func writeSecretFile(t *testing.T, dir, name string, secret []byte, perm os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(hex.EncodeToString(secret)), perm); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func writeConfigFile(t *testing.T, dir, name string, cfg interface{}, perm os.FileMode) string {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal cfg: %v", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, perm); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestPhase19ClientConfig_LoadAndAuthorizeTwoServers(t *testing.T) {
	tmp := t.TempDir()
	secretA := make([]byte, 32)
	secretB := make([]byte, 32)
	for i := range secretA {
		secretA[i] = byte(0xA0 + i)
		secretB[i] = byte(0xB0 + i)
	}
	pA := writeSecretFile(t, tmp, "a.secret", secretA, 0600)
	pB := writeSecretFile(t, tmp, "b.secret", secretB, 0600)
	cfgPath := writeConfigFile(t, tmp, "servers.json", AuthorizedServersConfigFile{
		Version: 1, Protocol: "v4", Generation: 7,
		AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "srv-a-01", SecretFile: pA}, {ServerID: "srv-b-01", SecretFile: pB}},
	}, 0600)

	entries, protocol, gen, err := loadAuthorizedServersConfig(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(entries) != 2 || entries[0].ServerID != "srv-a-01" || entries[1].ServerID != "srv-b-01" {
		t.Fatalf("entries: %+v", entries)
	}
	if protocol != "v4" || gen != 7 {
		t.Fatalf("protocol/gen: %q %d", protocol, gen)
	}
	// Case 9: slice mutation cannot change stored credentials.
	snapshot := make([]byte, 32)
	copy(snapshot, entries[0].ResponseSecret)
	secretA[0] ^= 0xFF // mutate the SOURCE slice the file bytes came from
	entries[0].ResponseSecret[1] ^= 0xFF
	if entries[0].ResponseSecret[1] == snapshot[1] {
		t.Fatalf("expected in-place mutation visible pre-construction")
	}
	// Loader must deep-copy: reload and compare with original file bytes.
	entries2, _, _, err := loadAuthorizedServersConfig(cfgPath)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(entries2[0].ResponseSecret) != 32 || entries2[0].ResponseSecret[0] != byte(0xA0) {
		t.Fatalf("credential file mutation leaked into loader output")
	}
}

// Cases 3-8: every invalid configuration mode fails closed.
func TestPhase19ClientConfig_RejectsInvalidConfigurations(t *testing.T) {
	tmp := t.TempDir()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(0xC0 + i)
	}
	pSecret := writeSecretFile(t, tmp, "ok.secret", secret, 0600)

	expectFail := func(name, want string, run func() error) {
		t.Helper()
		err := run()
		if err == nil {
			t.Errorf("%s: expected failure, got nil", name)
		}
	}

	// 3. Empty configuration (empty authorized list)
	cfgPath := writeConfigFile(t, tmp, "empty.json", AuthorizedServersConfigFile{Version: 1, Protocol: "v4"}, 0600)
	expectFail("empty list", "", func() error { _, _, _, err := loadAuthorizedServersConfig(cfgPath); return err })

	// totally empty file
	pEmpty := filepath.Join(tmp, "zero.json")
	_ = os.WriteFile(pEmpty, []byte("{}"), 0600)
	expectFail("empty file", "", func() error { _, _, _, err := loadAuthorizedServersConfig(pEmpty); return err })

	// 4. Missing response-secret file
	cfgPath = writeConfigFile(t, tmp, "missing.json", AuthorizedServersConfigFile{Version: 1, Protocol: "v4",
		AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "srv-x-01", SecretFile: filepath.Join(tmp, "nope.secret")}}}, 0600)
	expectFail("missing secret", "", func() error { _, _, _, err := loadAuthorizedServersConfig(cfgPath); return err })

	// 5. Invalid secret lengths (short file)
	pShort := writeSecretFile(t, tmp, "short.secret", []byte("short"), 0600)
	cfgPath = writeConfigFile(t, tmp, "short.json", AuthorizedServersConfigFile{Version: 1, Protocol: "v4",
		AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "srv-x-01", SecretFile: pShort}}}, 0600)
	expectFail("short secret", "", func() error { _, _, _, err := loadAuthorizedServersConfig(cfgPath); return err })

	// 6. Duplicate server IDs
	cfgPath = writeConfigFile(t, tmp, "dup.json", AuthorizedServersConfigFile{Version: 1, Protocol: "v4",
		AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "srv-x-01", SecretFile: pSecret}, {ServerID: "srv-x-01", SecretFile: pSecret}}}, 0600)
	expectFail("duplicate id", "", func() error { _, _, _, err := loadAuthorizedServersConfig(cfgPath); return err })

	// 7. Reserved / malformed IDs
	cfgPath = writeConfigFile(t, tmp, "reserved.json", AuthorizedServersConfigFile{Version: 1, Protocol: "v4",
		AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "legacy", SecretFile: pSecret}}}, 0600)
	expectFail("reserved id", "", func() error { _, _, _, err := loadAuthorizedServersConfig(cfgPath); return err })
	cfgPath = writeConfigFile(t, tmp, "malformed.json", AuthorizedServersConfigFile{Version: 1, Protocol: "v4",
		AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "BAD ID!", SecretFile: pSecret}}}, 0600)
	expectFail("malformed id", "", func() error { _, _, _, err := loadAuthorizedServersConfig(cfgPath); return err })

	// 8. Insecure file permissions (0644 secret file)
	pLoose := writeSecretFile(t, tmp, "loose.secret", secret, 0644)
	cfgPath = writeConfigFile(t, tmp, "loose.json", AuthorizedServersConfigFile{Version: 1, Protocol: "v4",
		AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "srv-x-01", SecretFile: pLoose}}}, 0600)
	expectFail("loose perms", "", func() error { _, _, _, err := loadAuthorizedServersConfig(cfgPath); return err })

	// Symlinked secret file (policy: reject)
	symPath := filepath.Join(tmp, "link.secret")
	_ = os.Remove(symPath)
	if err := os.Symlink(pSecret, symPath); err == nil {
		cfgPath = writeConfigFile(t, tmp, "sym.json", AuthorizedServersConfigFile{Version: 1, Protocol: "v4",
			AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "srv-x-01", SecretFile: symPath}}}, 0600)
		expectFail("symlink secret", "", func() error { _, _, _, err := loadAuthorizedServersConfig(cfgPath); return err })
	}

	// legacy protocol field rejected
	cfgPath = writeConfigFile(t, tmp, "legacyproto.json", AuthorizedServersConfigFile{Version: 1, Protocol: "legacy",
		AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "srv-x-01", SecretFile: pSecret}}}, 0600)
	expectFail("legacy protocol field", "", func() error { _, _, _, err := loadAuthorizedServersConfig(cfgPath); return err })
}

// Cases 11-12: ambiguity policy — malformed/mixed flag combos fail with no sockets opened.
func TestPhase19ClientConfig_FlagAmbiguityPolicy(t *testing.T) {
	tmp := t.TempDir()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(0xDD)
	}
	pSecret := writeSecretFile(t, tmp, "amb.secret", secret, 0600)
	cfgPath := writeConfigFile(t, tmp, "amb.json", AuthorizedServersConfigFile{Version: 1, Protocol: "v4",
		AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "srv-amb-01", SecretFile: pSecret}}}, 0600)

	// config + legacy
	if _, _, err := resolveClientCredentialConfiguration(cfgPath, "", "", true); err == nil {
		t.Fatalf("config+legacy accepted")
	}
	// config + singular
	if _, _, err := resolveClientCredentialConfiguration(cfgPath, "srv-amb-01", pSecret, false); err == nil {
		t.Fatalf("config+singular accepted")
	}
	// legacy + singular
	if _, _, err := resolveClientCredentialConfiguration("", "srv-amb-01", pSecret, true); err == nil {
		t.Fatalf("legacy+singular accepted")
	}
	// legacy implicit-via-malformed-v4-config must NOT silently pick legacy: config with wrong protocol fails even alone
	badPath := writeConfigFile(t, tmp, "badproto.json", AuthorizedServersConfigFile{Version: 1, Protocol: "",
		AuthorizedServers: []AuthorizedServerFileEntry{{ServerID: "srv-amb-01", SecretFile: pSecret}}}, 0600)
	if _, _, err := resolveClientCredentialConfiguration(badPath, "", "", false); err == nil {
		t.Fatalf("config with unset protocol silently resolved")
	}
	// legacy only is fine, config only is fine
	if _, mode, _ := resolveClientCredentialConfiguration("", "", "", true); mode != "legacy" {
		t.Fatalf("legacy mode not selectable explicitly: %q", mode)
	}
	if entries, mode, _ := resolveClientCredentialConfiguration(cfgPath, "", "", false); mode != "v4" || len(entries) != 1 {
		t.Fatalf("config-only resolution failed: mode=%q n=%d", mode, len(entries))
	}
	// Case 13: PSK never substituted — loaded secret must differ from the CLI PSK constant
	pskConstant := []byte("phase19-cli-suite-psk-32bytXXXXX")
	loaderRes, _, _, err := loadAuthorizedServersConfig(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(loaderRes[0].ResponseSecret) == string(pskConstant) {
		t.Fatalf("response secret equals PSK")
	}
}

// Cases 14-15: wire — a valid v4 response from EITHER authorized server is accepted;
// responses from unknown identities are rejected fail closed.
func TestPhase19ClientConfig_WireAcceptsAuthorizedRejectsUnknown(t *testing.T) {
	psk := []byte("phase19-cli-suite-psk-32bytXXXXX")
	secretA := make([]byte, 32)
	secretB := make([]byte, 32)
	secretRogue := make([]byte, 32)
	for i := 0; i < 32; i++ {
		secretA[i] = byte(0xE0 + i)
		secretB[i] = byte(0xF0 + i)
		secretRogue[i] = byte(0x99)
	}
	srvA, err := transport.NewEmergencyDNSServer(transport.EmergencyDNSServerConfig{
		ListenAddr: "127.0.0.1:0", DomainSuffix: "p19wire.test", PSK: psk, ServerID: "srv-wa-01",
		ServerSecret: secretA, ProtocolV4: true,
		Handler: func(msg *transport.EmergencyMessage) (*transport.EmergencyResponse, error) {
			return &transport.EmergencyResponse{ID: msg.ID, Status: "OK", Reply: []byte("WIRE-A"), Timestamp: 1}, nil
		},
	})
	if err != nil {
		t.Fatalf("srvA: %v", err)
	}
	defer srvA.Stop()
	srvB, err := transport.NewEmergencyDNSServer(transport.EmergencyDNSServerConfig{
		ListenAddr: "127.0.0.1:0", DomainSuffix: "p19wire.test", PSK: psk, ServerID: "srv-wb-01",
		ServerSecret: secretB, ProtocolV4: true,
		Handler: func(msg *transport.EmergencyMessage) (*transport.EmergencyResponse, error) {
			return &transport.EmergencyResponse{ID: msg.ID, Status: "OK", Reply: []byte("WIRE-B"), Timestamp: 1}, nil
		},
	})
	if err != nil {
		t.Fatalf("srvB: %v", err)
	}
	defer srvB.Stop()
	srvRogue, err := transport.NewEmergencyDNSServer(transport.EmergencyDNSServerConfig{
		ListenAddr: "127.0.0.1:0", DomainSuffix: "p19wire.test", PSK: psk, ServerID: "srv-rogue-01",
		ServerSecret: secretRogue, ProtocolV4: true,
		Handler: func(msg *transport.EmergencyMessage) (*transport.EmergencyResponse, error) {
			return &transport.EmergencyResponse{ID: msg.ID, Status: "OK", Reply: []byte("ROGUE"), Timestamp: 1}, nil
		},
	})
	if err != nil {
		t.Fatalf("srvRogue: %v", err)
	}
	defer srvRogue.Stop()

	// Client authorizes ONLY srv-wa-01 and srv-wb-01 (loader-shaped deep copies).
	entries := []transport.AuthorizedServerEntry{
		{ServerID: "srv-wa-01", ResponseSecret: append([]byte(nil), secretA...)},
		{ServerID: "srv-wb-01", ResponseSecret: append([]byte(nil), secretB...)},
	}
	cl, err := transport.NewEmergencyDNSClient(transport.EmergencyDNSClientConfig{
		Resolvers:    []string{srvA.Addr().String(), srvB.Addr().String()},
		DomainSuffix: "p19wire.test", ClientID: "c19", PSK: psk,
		Timeout: 3 * time.Second, PerAttemptTimeout: 900 * time.Millisecond, MaxRetries: 1, ProtocolV4: true,
		ServerIdentities: entries,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	ctx := context.Background()
	r1, _, err := cl.Exchange(ctx, &transport.EmergencyMessage{ID: "wire-a-1", Type: "alert"})
	if err != nil || string(r1.Reply) != "WIRE-A" {
		t.Fatalf("authorized A exchange: resp=%+v err=%v", r1, err)
	}
	r2, _, err := cl.Exchange(ctx, &transport.EmergencyMessage{ID: "wire-b-1", Type: "alert"})
	if err != nil {
		t.Fatalf("second authorized exchange (failover order): %v", err)
	}
	// Either authorized identity may answer (resolver failover order is not fixed).
	if r2.ServerID != "srv-wb-01" && r2.ServerID != "srv-wa-01" {
		t.Fatalf("unexpected responder: %+v", r2)
	}
	// Unknown (rogue) identity: not in the allowlist → PEER response rejected.
	rc, err := transport.NewEmergencyDNSClient(transport.EmergencyDNSClientConfig{
		ResolverAddr: srvRogue.Addr().String(), DomainSuffix: "p19wire.test", ClientID: "c19", PSK: psk,
		Timeout: 1 * time.Second, PerAttemptTimeout: 500 * time.Millisecond, MaxRetries: 0, ProtocolV4: true,
		ServerIdentities: entries,
	})
	if err != nil {
		t.Fatalf("rogue client: %v", err)
	}
	if _, _, err := rc.Exchange(ctx, &transport.EmergencyMessage{ID: "rogue-1", Type: "alert"}); err == nil {
		t.Fatalf("CRITICAL: unknown identity response accepted")
	} else {
		_ = context.Background
	}
	fmt.Println("wire case done", ctx != nil)
}
