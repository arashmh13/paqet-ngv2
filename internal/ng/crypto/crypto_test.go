package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKeys(t *testing.T) {
	psk := []byte("super-secret-password-1234567890123456")
	c2s, s2c, err := DeriveKeys(psk, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(c2s) != KeySize || len(s2c) != KeySize {
		t.Fatalf("invalid key lengths: c2s=%d, s2c=%d", len(c2s), len(s2c))
	}

	if bytes.Equal(c2s, s2c) {
		t.Fatal("directional keys must be distinct")
	}

	// Deterministic derivation test
	c2s2, s2c2, _ := DeriveKeys(psk, nil)
	if !bytes.Equal(c2s, c2s2) || !bytes.Equal(s2c, s2c2) {
		t.Fatal("key derivation must be deterministic for identical PSK and salt")
	}

	// Empty PSK must fail
	if _, _, err := DeriveKeys(nil, nil); err == nil {
		t.Fatal("expected error for empty PSK")
	}
}

func TestAEADEncryptDecrypt(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	aead, err := NewAEAD(key)
	if err != nil {
		t.Fatalf("failed to create AEAD: %v", err)
	}

	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}

	plaintext := []byte("Hello, Paqet-NG authenticated world!")
	aad := []byte("metadata-aad-1234")

	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)

	// Valid decrypt
	decrypted, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted text mismatch: got %s, want %s", string(decrypted), string(plaintext))
	}

	// Tampered ciphertext must fail
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := aead.Open(nil, nonce[:], tampered, aad); err == nil {
		t.Fatal("expected authentication failure on tampered ciphertext")
	}

	// Mismatched AAD must fail
	if _, err := aead.Open(nil, nonce[:], ciphertext, []byte("wrong-aad")); err == nil {
		t.Fatal("expected authentication failure on mismatched AAD")
	}
}

func TestDeriveServerTrafficKeys(t *testing.T) {
	c2sPSK := []byte("super-secret-password-1234567890")  // exactly 32 bytes
	secretA := []byte("server-a-response-secret-1111111") // exactly 32 bytes
	secretB := []byte("server-b-response-secret-2222222") // exactly 32 bytes
	salt := []byte("session-salt-12345")

	// Deriving for server A with secretA
	c2sA, s2cA, err := DeriveServerTrafficKeys(c2sPSK, secretA, salt, "ns-de-01")
	if err != nil {
		t.Fatalf("DeriveServerTrafficKeys ns-de-01 failed: %v", err)
	}

	// Deriving for server B with secretB
	c2sB, s2cB, err := DeriveServerTrafficKeys(c2sPSK, secretB, salt, "ns2-nl-01")
	if err != nil {
		t.Fatalf("DeriveServerTrafficKeys ns2-nl-01 failed: %v", err)
	}

	// c2s keys (client-to-server) MUST be identical so any server can process the query
	if !bytes.Equal(c2sA, c2sB) {
		t.Fatalf("client-to-server keys must be identical across server instances")
	}

	// s2c keys (server-to-client) MUST be distinct
	if bytes.Equal(s2cA, s2cB) {
		t.Fatalf("server-to-client response keys for distinct server IDs must be distinct")
	}

	// Security Invariant: Server A (holding secretA) attempting to derive Server B's key CANNOT match Server B
	forgedB, err := DeriveServerResponseKey(secretA, salt, "ns2-nl-01")
	if err != nil {
		t.Fatalf("DeriveServerResponseKey failed: %v", err)
	}
	if bytes.Equal(forgedB, s2cB) {
		t.Fatalf("CRITICAL SECURITY DEFECT: Server A forged Server B's response key!")
	}

	// Genuine derivation for Server B
	genuineB, err := DeriveServerResponseKey(secretB, salt, "ns2-nl-01")
	if err != nil {
		t.Fatalf("DeriveServerResponseKey failed: %v", err)
	}
	if !bytes.Equal(genuineB, s2cB) {
		t.Fatalf("Genuine derivation for Server B must match DeriveServerTrafficKeys")
	}

	// Missing response secret MUST fail closed (NO fallback to PSK!)
	_, _, err = DeriveServerTrafficKeys(c2sPSK, nil, salt, "ns-de-01")
	if err != ErrMissingResponseSecret {
		t.Fatalf("expected ErrMissingResponseSecret for nil response secret, got %v", err)
	}
	_, _, err = DeriveServerTrafficKeys(c2sPSK, []byte(""), salt, "ns-de-01")
	if err != ErrMissingResponseSecret {
		t.Fatalf("expected ErrMissingResponseSecret for empty response secret, got %v", err)
	}

	// Short or malformed response secret MUST fail closed
	_, _, err = DeriveServerTrafficKeys(c2sPSK, []byte("short-secret"), salt, "ns-de-01")
	if err != ErrInvalidResponseSecret {
		t.Fatalf("expected ErrInvalidResponseSecret for short response secret, got %v", err)
	}

	// Missing serverID in multi-server derivation MUST fail closed
	_, _, err = DeriveServerTrafficKeys(c2sPSK, secretA, salt, "")
	if err == nil {
		t.Fatalf("expected error for empty serverID in multi-server derivation")
	}

	// DeriveLegacySingleServerTrafficKeys explicit legacy mode
	legacyC2S, legacyS2C, err := DeriveLegacySingleServerTrafficKeys(c2sPSK, salt)
	if err != nil {
		t.Fatalf("DeriveLegacySingleServerTrafficKeys failed: %v", err)
	}
	if len(legacyC2S) != KeySize || len(legacyS2C) != KeySize {
		t.Fatalf("invalid legacy key sizes")
	}
}
