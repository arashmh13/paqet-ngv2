package emergency

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func resetFlags() {
	bootstrapIP = ""
	bootstrapPort = 18089
	bootstrapMode = "aead-stream"
	bootstrapCertFile = ""
	bootstrapKeyFile = ""
	bootstrapPin = ""
	bootstrapConfigFile = ""
	disableBootstrap = false
	_ = os.Unsetenv("PAQET_BOOTSTRAP_IP")
}

func TestEmergencyServerStartup_MissingRecoveryConfigFails(t *testing.T) {
	resetFlags()

	// When neither --bootstrap-config nor --bootstrap-ip is set, and --disable-bootstrap is false:
	_, err := setupBootstrapManager()
	if err == nil {
		t.Fatalf("expected startup failure when no recovery endpoint configuration is provided, got nil")
	}
	t.Logf("PASS: Startup rejected missing recovery configuration: %v", err)
}

func TestEmergencyServerStartup_DisableBootstrapMessagingOnlyMode(t *testing.T) {
	resetFlags()
	disableBootstrap = true

	bm, err := setupBootstrapManager()
	if err != nil {
		t.Fatalf("expected success with --disable-bootstrap, got error: %v", err)
	}
	if bm.RecordCount() != 0 {
		t.Fatalf("expected 0 bootstrap records in messaging-only mode, got %d", bm.RecordCount())
	}
	t.Logf("PASS: Messaging-only server initialized with 0 bootstrap records")
}

func TestEmergencyServerStartup_AEADWithoutKeyOrPinFails(t *testing.T) {
	resetFlags()
	bootstrapIP = "1.2.3.4"
	bootstrapMode = "aead-stream"
	// No key file and no pin!

	_, err := setupBootstrapManager()
	if err == nil {
		t.Fatalf("expected startup failure when aead-stream has no key or pin (emergency PSK fallback must be eliminated), got nil")
	}
	t.Logf("PASS: Startup rejected AEAD bootstrap without data-plane key: %v", err)
}

func TestEmergencyServerStartup_TLSWithoutCertOrPinFails(t *testing.T) {
	resetFlags()
	bootstrapIP = "1.2.3.4"
	bootstrapMode = "tls-outer"
	// No cert file and no pin!

	_, err := setupBootstrapManager()
	if err == nil {
		t.Fatalf("expected startup failure when tls-outer has no cert or pin, got nil")
	}
	t.Logf("PASS: Startup rejected TLS bootstrap without cert: %v", err)
}

func TestEmergencyServerStartup_DisallowedIPClassesFail(t *testing.T) {
	disallowedIPs := []string{
		"0.0.0.0",        // Unspecified
		"224.0.0.1",      // Multicast
		"169.254.1.1",    // Link-local
		"not-an-ip-addr", // Malformed
	}

	for _, badIP := range disallowedIPs {
		resetFlags()
		bootstrapIP = badIP
		bootstrapMode = "aead-stream"
		bootstrapPin = "SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

		_, err := setupBootstrapManager()
		if err == nil {
			t.Fatalf("expected startup failure for disallowed IP %q, got nil", badIP)
		}
		t.Logf("PASS: Rejected disallowed IP %s: %v", badIP, err)
	}
}

func TestEmergencyServerStartup_InvalidPortsFail(t *testing.T) {
	badPorts := []int{0, -1, 65536, 70000}

	for _, badPort := range badPorts {
		resetFlags()
		bootstrapIP = "1.2.3.4"
		bootstrapPort = badPort
		bootstrapMode = "aead-stream"
		bootstrapPin = "SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

		_, err := setupBootstrapManager()
		if err == nil {
			t.Fatalf("expected startup failure for invalid port %d, got nil", badPort)
		}
		t.Logf("PASS: Rejected invalid port %d: %v", badPort, err)
	}
}

func TestEmergencyServerStartup_ValidKeyFileTracksProvenance(t *testing.T) {
	resetFlags()

	// Write a temporary 32-byte transport key
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "transport.key")
	dummyKey := make([]byte, 32)
	for i := range dummyKey {
		dummyKey[i] = byte(i + 1)
	}
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(dummyKey)), 0600); err != nil {
		t.Fatalf("failed to write test key: %v", err)
	}

	bootstrapIP = "198.51.100.1"
	bootstrapPort = 18089
	bootstrapMode = "aead-stream"
	bootstrapKeyFile = keyPath

	bm, err := setupBootstrapManager()
	if err != nil {
		t.Fatalf("expected successful startup with valid key file, got: %v", err)
	}

	rec, ok := bm.GetRecord("aead-stream")
	if !ok {
		t.Fatalf("expected aead-stream record registered")
	}

	expectedFP := fmt.Sprintf("SHA256:%x", sha256.Sum256(dummyKey))
	if rec.IdentityValue != expectedFP {
		t.Fatalf("identity fingerprint mismatch: got %s, want %s", rec.IdentityValue, expectedFP)
	}
	if rec.Provenance != "key_file:transport.key" {
		t.Fatalf("provenance metadata mismatch: got %s, want key_file:transport.key", rec.Provenance)
	}
	t.Logf("PASS: Valid key file registered with correct fingerprint and provenance (%s)", rec.Provenance)
}

func TestEmergencyServerStartup_JSONConfigFileDeterministicValidation(t *testing.T) {
	resetFlags()

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "candidates.json")

	// Valid JSON configuration with 2 distinct modes
	jsonContent := `[
		{
			"server_ip": "198.51.100.1",
			"transport_port": 18089,
			"transport_mode": "aead-stream",
			"identity_type": "psk-id",
			"identity_value": "SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"provenance": "pin:explicit",
			"validity_sec": 3600
		},
		{
			"server_ip": "198.51.100.2",
			"transport_port": 18443,
			"transport_mode": "tls-outer",
			"identity_type": "cert-pin",
			"identity_value": "SHA256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
			"provenance": "cert_file:server.crt",
			"validity_sec": 7200
		}
	]`
	if err := os.WriteFile(cfgPath, []byte(jsonContent), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	bootstrapConfigFile = cfgPath
	bm, err := setupBootstrapManager()
	if err != nil {
		t.Fatalf("expected success from valid JSON config, got: %v", err)
	}

	if bm.RecordCount() != 2 {
		t.Fatalf("expected 2 records loaded, got %d", bm.RecordCount())
	}
	t.Logf("PASS: JSON config file parsed and validated 2 candidate records")

	// Conflicting duplicate records test
	conflictJSON := `[
		{
			"server_ip": "198.51.100.1",
			"transport_port": 18089,
			"transport_mode": "aead-stream",
			"identity_type": "psk-id",
			"identity_value": "SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"validity_sec": 3600
		},
		{
			"server_ip": "198.51.100.1",
			"transport_port": 18090,
			"transport_mode": "aead-stream",
			"identity_type": "psk-id",
			"identity_value": "SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"validity_sec": 3600
		}
	]`
	conflictPath := filepath.Join(tmpDir, "conflict.json")
	_ = os.WriteFile(conflictPath, []byte(conflictJSON), 0600)

	resetFlags()
	bootstrapConfigFile = conflictPath
	_, err = setupBootstrapManager()
	if err == nil {
		t.Fatalf("expected failure on conflicting duplicate records for same mode, got nil")
	}
	t.Logf("PASS: Conflicting duplicate records rejected: %v", err)
}

func TestEmergencyServerStartup_MultiServerCredentialValidation(t *testing.T) {
	tmpDir := t.TempDir()
	validSecret := make([]byte, 32)
	for i := range validSecret {
		validSecret[i] = byte(i + 1)
	}
	validSecretPath := filepath.Join(tmpDir, "server_valid.key")
	_ = os.WriteFile(validSecretPath, []byte(hex.EncodeToString(validSecret)), 0600)

	shortSecretPath := filepath.Join(tmpDir, "server_short.key")
	_ = os.WriteFile(shortSecretPath, []byte("short-secret"), 0600)

	// 1. Missing server-id in multi-server mode fails
	_, err := validateServerStartupConfig("", validSecretPath, false)
	if err == nil {
		t.Fatalf("expected startup failure for empty server-id in multi-server mode, got nil")
	}
	t.Logf("PASS: Missing server-id rejected: %v", err)

	// 2. Reserved server-id "default" or "legacy" in multi-server mode fails
	_, err = validateServerStartupConfig("default", validSecretPath, false)
	if err == nil {
		t.Fatalf("expected startup failure for reserved server-id 'default', got nil")
	}
	_, err = validateServerStartupConfig("legacy", validSecretPath, false)
	if err == nil {
		t.Fatalf("expected startup failure for reserved server-id 'legacy', got nil")
	}
	t.Logf("PASS: Reserved server-id rejected")

	// 3. Missing server-secret-file in multi-server mode fails
	_, err = validateServerStartupConfig("ns-de-01", "", false)
	if err == nil {
		t.Fatalf("expected startup failure for missing server-secret-file, got nil")
	}
	t.Logf("PASS: Missing server-secret-file rejected: %v", err)

	// 4. Short server-secret-file fails
	_, err = validateServerStartupConfig("ns-de-01", shortSecretPath, false)
	if err == nil {
		t.Fatalf("expected startup failure for short server secret, got nil")
	}
	t.Logf("PASS: Short server secret rejected: %v", err)

	// 5. Valid server-id and server-secret-file succeeds
	secret, err := validateServerStartupConfig("ns-de-01", validSecretPath, false)
	if err != nil {
		t.Fatalf("expected success for valid multi-server credentials, got: %v", err)
	}
	if len(secret) != 32 {
		t.Fatalf("expected 32-byte secret, got %d", len(secret))
	}
	t.Logf("PASS: Valid multi-server credentials parsed successfully")

	// 6. Explicit legacy single-server mode succeeds without secret file
	legacySecret, err := validateServerStartupConfig("", "", true)
	if err != nil {
		t.Fatalf("expected success in legacy single-server mode, got: %v", err)
	}
	if legacySecret != nil {
		t.Fatalf("expected nil secret in legacy single-server mode, got %v", legacySecret)
	}
	t.Logf("PASS: Explicit legacy mode validated safely")
}

func TestEmergencyClientStartup_MultiServerCredentialValidation(t *testing.T) {
	tmpDir := t.TempDir()
	validSecret := make([]byte, 32)
	for i := range validSecret {
		validSecret[i] = byte(i + 1)
	}
	validSecretPath := filepath.Join(tmpDir, "client_server_valid.key")
	_ = os.WriteFile(validSecretPath, []byte(hex.EncodeToString(validSecret)), 0600)

	// 1. Missing server-id in client fails
	_, err := validateClientStartupConfig("", validSecretPath, false)
	if err == nil {
		t.Fatalf("expected client failure for empty server-id, got nil")
	}

	// 2. Missing server-secret-file in client fails
	_, err = validateClientStartupConfig("ns-de-01", "", false)
	if err == nil {
		t.Fatalf("expected client failure for missing server-secret-file, got nil")
	}

	// 3. Valid credentials succeed
	entries, err := validateClientStartupConfig("ns-de-01", validSecretPath, false)
	if err != nil {
		t.Fatalf("expected success for valid client credentials, got: %v", err)
	}
	if len(entries) != 1 || entries[0].ServerID != "ns-de-01" || len(entries[0].ResponseSecret) != 32 {
		t.Fatalf("unexpected client entries: %+v", entries)
	}

	// 4. Legacy single-server client succeeds without secret
	entries, err = validateClientStartupConfig("", "", true)
	if err != nil || entries != nil {
		t.Fatalf("expected nil entries for legacy client, got %v (err: %v)", entries, err)
	}
	t.Logf("PASS: Client multi-server vs legacy credentials validated")
}
