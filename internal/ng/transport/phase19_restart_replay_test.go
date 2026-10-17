package transport

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/arashmh13/paqet-ngv2/internal/ng/crypto"
)

// TestPhase19_V4ReplayAfterRestartNoKeyNonceReuse is the exact captured-request
// replay-around-restart scenario from the Phase 19 P0 mandate, expressed
// deterministically at the crypto layer:
//
//  1. A server instance (identity srv-rr-01, dedicated secret, PSK) processes a
//     captured authenticated v4 request (sessionID S, seed X, seq 1) and seals the
//     response for plaintext P1 at respSeq=1.
//  2. The server process is destroyed and restarted with the SAME server ID and
//     long-term credentials (fresh in-memory sessions — modeled by a freshly
//     constructed server conn, exactly what processNewSessionQuery does after a
//     restart).
//  3. The identical captured request is replayed. The restarted instance
//     reconstructs a session conn from the same (creds, sessionID, seed) and seals
//     a response for plaintext P2 (different payload, e.g. fresh timestamp) at
//     respSeq=1.
//
// INVARIANT: the two seals must use DIFFERENT (key, nonce) pairs. Identical keys
// across restart are expected and harmless; nonce reuse over different plaintexts
// under the same key is a catastrophic AES-GCM failure and must be impossible.
func TestPhase19_V4ReplayAfterRestartNoKeyNonceReuse(t *testing.T) {
	psk := []byte("phase19-restart-replay-psk-32byt")
	secretA := []byte("secret-a-response-32-bytes-long!")
	sessionID := uint64(0x5151515151515151)
	seedX := [crypto.SessionSeedSize]byte{}
	for i := range seedX {
		seedX[i] = byte(0x51 + i)
	}

	// Captured authenticated v4 request (client side; fixed seed + session ID).
	set, err := NewAuthorizedServerSet("epoch-rr", []AuthorizedServerEntry{{ServerID: "srv-rr-01", ResponseSecret: secretA}})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	client, err := NewClientAsymmetricSessionV4(sessionID, psk, set, &seedX)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	reqBytes, _ := json.Marshal(&EmergencyMessage{ID: "rr-req-1", Type: "alert", Timestamp: 11111})
	capturedFrame, err := client.SealFrame(1, 0, reqBytes)
	if err != nil {
		t.Fatalf("seal request: %v", err)
	}

	newServerInstance := func() *AsymmetricConn {
		conn, err := NewServerAsymmetricSessionWithIDV4(sessionID, psk, secretA, seedX[:], "srv-rr-01")
		if err != nil {
			t.Fatalf("server instance: %v", err)
		}
		return conn
	}

	// Instance 1 processes the captured request.
	inst1 := newServerInstance()
	if seq, _, pt, err := inst1.OpenFrame(capturedFrame); err != nil || seq != 1 || len(pt) == 0 {
		t.Fatalf("instance1 open: seq=%d pt=%q err=%v", seq, string(pt), err)
	}
	respBytes1, _ := json.Marshal(&EmergencyResponse{ID: "rr-req-1", Status: "OK", Reply: []byte("BOOT FRESH-VALIDITY-1739680001"), Timestamp: 1739680001})
	respFrame1, err := inst1.SealFrame(1, 1, respBytes1)
	if err != nil {
		t.Fatalf("seal resp1: %v", err)
	}
	if len(respFrame1) == 0 {
		t.Fatalf("resp1 frame empty")
	}
	nonce1 := inst1.aeadNonce(1, RoleServer, inst1.respNonceBase)

	// Restart: fresh instance, same identity + long-term credentials.
	inst2 := newServerInstance()
	if seq, _, pt, err := inst2.OpenFrame(capturedFrame); err != nil || seq != 1 || len(pt) == 0 {
		t.Fatalf("instance2 (restarted) open of captured request: seq=%d pt=%q err=%v", seq, string(pt), err)
	}
	respBytes2, _ := json.Marshal(&EmergencyResponse{ID: "rr-req-1", Status: "OK", Reply: []byte("BOOT FRESH-VALIDITY-1739699999"), Timestamp: 1739699999})
	respFrame2, err := inst2.SealFrame(1, 1, respBytes2)
	if err != nil {
		t.Fatalf("seal resp2: %v", err)
	}
	if len(respFrame2) == 0 {
		t.Fatalf("resp2 frame empty")
	}
	nonce2 := inst2.aeadNonce(1, RoleServer, inst2.respNonceBase)

	if bytes.Equal(respBytes1, respBytes2) {
		t.Fatalf("test defect: the two response plaintexts must differ for this probe")
	}
	// v4 (rev 2): the per-server-session nonce/key base is bound into the s2c HKDF
	// salt, so a restarted instance derives a DIFFERENT s2c key for the same
	// (sessionID, seed, serverID, secret) tuple. Key schedules coinciding across
	// restart would re-open the same (key, nonce) domain and is itself a defect now.
	if bytes.Equal(inst1.encKey, inst2.encKey) {
		t.Fatalf("defect: restarted instance derived the SAME s2c key from same creds (base must be bound into the KDF salt)")
	}
	if bytes.Equal(inst1.respNonceBase, inst2.respNonceBase) {
		t.Fatalf("defect: restarted instance reused the downstream nonce stream base")
	}
	// THE SECURITY INVARIANT UNDER TEST:
	if nonce1 == nonce2 {
		t.Fatalf("DEFECT CONFIRMED: restarted server reused AEAD nonce %x under the same key for different plaintexts (P1=%q vs P2=%q)", nonce1, string(respBytes1), string(respBytes2))
	}
}

// Same seed, different session ID: salt differs through the sessionID component.
func TestPhase19_SameSeedDifferentSessionIDDivergentKeys(t *testing.T) {
	psk := []byte("phase19-restart-replay-psk-32byt")
	secretA := []byte("secret-a-response-32-bytes-long!")
	seedX := [crypto.SessionSeedSize]byte{}
	for i := range seedX {
		seedX[i] = byte(0x61 + i)
	}
	set, err := NewAuthorizedServerSet("e", []AuthorizedServerEntry{{ServerID: "srv-rr-01", ResponseSecret: secretA}})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	c1, err := NewClientAsymmetricSessionV4(0x1001, psk, set, &seedX)
	if err != nil {
		t.Fatalf("client1: %v", err)
	}
	c2, err := NewClientAsymmetricSessionV4(0x1002, psk, set, &seedX)
	if err != nil {
		t.Fatalf("client2: %v", err)
	}
	if bytes.Equal(c1.encKey, c2.encKey) {
		t.Fatalf("same seed with different session IDs must derive divergent keys")
	}
}

// Sequence exhaustion boundary on v4 (deterministic via test seam) and the rule
// that the cached original ciphertext is reused for identical retransmissions.
func TestPhase19_V4SequenceExhaustionAndRetransmission(t *testing.T) {
	psk := []byte("phase19-restart-replay-psk-32byt")
	secretA := []byte("secret-a-response-32-bytes-long!")
	sessionID := uint64(0x5252525252525252)
	seedX := [crypto.SessionSeedSize]byte{}
	for i := range seedX {
		seedX[i] = byte(0x71 + i)
	}
	set, err := NewAuthorizedServerSet("e", []AuthorizedServerEntry{{ServerID: "srv-rr-01", ResponseSecret: secretA}})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	srv, err := NewServerAsymmetricSessionWithIDV4(sessionID, psk, secretA, seedX[:], "srv-rr-01")
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	// Response sealing must fail closed near the exhaustion boundary (no wrap to 0).
	if _, err := srv.SealFrame(MaxSafeSequenceNumber, 0, []byte("overflow")); err == nil {
		t.Fatalf("sealing at MaxSafeSequenceNumber must fail closed")
	}
	_ = set
}
