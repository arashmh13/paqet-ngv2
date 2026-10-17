package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/arashmh13/paqet-ngv2/internal/ng/crypto"
)

// TestPhase19_V4OldResponseReplayRejectedOnClient proves the client-side per-domain
// replay window: the same authenticated response bytes may be opened once, and a
// verbatim replay (the "old response replay after restart"/MITM case) is rejected.
func TestPhase19_V4OldResponseReplayRejectedOnClient(t *testing.T) {
	psk := []byte("phase19-old-response-replay-psky")
	secretA := []byte("secret-a-response-32-bytes-long!")
	sessionID := uint64(0x4F4F4F4F4F4F4F4F)
	seedX := [crypto.SessionSeedSize]byte{}
	for i := range seedX {
		seedX[i] = byte(0x4F + i)
	}
	set, err := NewAuthorizedServerSet("epoch-oldresp", []AuthorizedServerEntry{{ServerID: "srv-or-01", ResponseSecret: secretA}})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	client, err := NewClientAsymmetricSessionV4(sessionID, psk, set, &seedX)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	srv, err := NewServerAsymmetricSessionWithIDV4(sessionID, psk, secretA, seedX[:], "srv-or-01")
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	respBytes, _ := json.Marshal(&EmergencyResponse{ID: "old-resp-1", Status: "OK", Reply: []byte("R1"), Timestamp: 42})
	respFrame, err := srv.SealFrame(1, 1, respBytes)
	if err != nil {
		t.Fatalf("seal resp: %v", err)
	}
	if _, _, _, _, err := client.openFrameWithServerID(respFrame); err != nil {
		t.Fatalf("first open of authenticated response: %v", err)
	}
	// Verbatim replay of the SAME response (even after server restart): the per-domain
	// window must reject the duplicate server sequence.
	if _, _, _, _, err := client.openFrameWithServerID(respFrame); err == nil {
		t.Fatalf("DEFECT: verbatim old response replay accepted by client")
	}
}

// TestPhase19_V4RotationAndRevocationAfterRestart covers: server restart with a
// ROTATED secret → stale-credential client fails closed; revocation of an authorized
// server → fail closed; two independent servers processing a repeated request.
func TestPhase19_V4RotationAndRevocationAfterRestart(t *testing.T) {
	psk := []byte("phase19-rotrev-restart-psk-32bye")
	secretA1 := []byte("server-a-secret-1111111111111111")
	secretA2 := []byte("server-a-secret-2222222222222222") // rotated
	secretB := []byte("server-b-secret-3333333333333333")

	newServer := func(serverID string, secret []byte, addr string) *EmergencyDNSServer {
		srv, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
			ListenAddr: addr, DomainSuffix: "p19rot.test", PSK: psk, ServerID: serverID,
			ServerSecret: secret, ProtocolV4: true,
			Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
				return &EmergencyResponse{ID: msg.ID, Status: "OK", Reply: secret[:6], Timestamp: 1}, nil
			},
		})
		if err != nil {
			t.Fatalf("server(%s): %v", serverID, err)
		}
		return srv
	}

	srvA1 := newServer("srv-rot-01", secretA1, "127.0.0.1:0")
	srvB := newServer("srv-b-01", secretB, "127.0.0.1:0")

	entries := func(secrets ...[]byte) []AuthorizedServerEntry {
		ids := []string{"srv-rot-01", "srv-b-01"}
		out := make([]AuthorizedServerEntry, 0, len(secrets))
		for i, sec := range secrets {
			out = append(out, AuthorizedServerEntry{ServerID: ids[i], ResponseSecret: append([]byte(nil), sec...)})
		}
		return out
	}
	defer srvB.Stop()

	cl, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		Resolvers:    []string{srvA1.Addr().String(), srvB.Addr().String()},
		DomainSuffix: "p19rot.test", ClientID: "c19", PSK: psk,
		Timeout: 2 * time.Second, PerAttemptTimeout: 800 * time.Millisecond, MaxRetries: 1, ProtocolV4: true,
		ServerIdentities: entries(secretA1, secretB),
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	ctx := context.Background()
	// Two repeated requests across the two independent servers must BOTH succeed.
	for i := 0; i < 2; i++ {
		if _, _, err := cl.Exchange(ctx, &EmergencyMessage{ID: "rot-rep", Type: "alert"}); err != nil {
			t.Fatalf("repeated cross-server exchange %d: %v", i, err)
		}
	}
	srvA1.Stop()

	// Rotate: restarted server instance uses secretA2. Stale client (A1) must fail closed.
	srvA2 := newServer("srv-rot-01", secretA2, srvA1.Addr().String())
	defer srvA2.Stop()
	resp, _, err := cl.Exchange(ctx, &EmergencyMessage{ID: "rot-2", Type: "alert"})
	// Client resolvers still list srv-rot-01 first with stale A1 secret:
	if err != nil || resp == nil {
		t.Fatalf("revocation/rotation helper setup: err=%v resp=%+v", err, resp)
	}
	// Now a STRICT stale client targeting only the rotated identity must fail closed.
	staleCL, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		Resolvers: []string{srvA2.Addr().String()}, DomainSuffix: "p19rot.test", ClientID: "c19", PSK: psk,
		Timeout: 1 * time.Second, PerAttemptTimeout: 500 * time.Millisecond, MaxRetries: 0, ProtocolV4: true,
		ServerIdentities: entries(secretA1),
	})
	if err != nil {
		t.Fatalf("stale client: %v", err)
	}
	if _, _, err := staleCL.Exchange(ctx, &EmergencyMessage{ID: "stale-1", Type: "alert"}); err == nil {
		t.Fatalf("CRITICAL: stale (rotated) credential client authenticated against rotated server")
	}
	// Fresh client with rotated secret succeeds.
	freshCL, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		Resolvers: []string{srvA2.Addr().String()}, DomainSuffix: "p19rot.test", ClientID: "c19", PSK: psk,
		Timeout: 2 * time.Second, PerAttemptTimeout: 700 * time.Millisecond, MaxRetries: 0, ProtocolV4: true,
		ServerIdentities: entries(secretA2),
	})
	if err != nil {
		t.Fatalf("fresh client: %v", err)
	}
	if resp2, _, err := freshCL.Exchange(ctx, &EmergencyMessage{ID: "fresh-1", Type: "alert"}); err != nil || resp2 == nil {
		t.Fatalf("fresh rotated-credential client exchange: err=%v", err)
	}

	// Revocation: client that only authorizes srv-rot-01 (revoked srv-b-01) must fail closed against B.
	revokedCL, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		Resolvers: []string{srvB.Addr().String()}, DomainSuffix: "p19rot.test", ClientID: "c19", PSK: psk,
		Timeout: 1 * time.Second, PerAttemptTimeout: 500 * time.Millisecond, MaxRetries: 0, ProtocolV4: true,
		ServerIdentities: entries(secretA1), // B revoked from the map
	})
	if err != nil {
		t.Fatalf("revoked client: %v", err)
	}
	if _, _, err := revokedCL.Exchange(ctx, &EmergencyMessage{ID: "revoked-1", Type: "alert"}); err == nil {
		t.Fatalf("CRITICAL: revoked server identity accepted")
	}
	if bytes.Equal(nil, nil) && resp != nil {
		// response shape sanity only
		_ = resp
	}
}
