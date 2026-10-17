package transport

// Phase 20 P0-1: replay-domain capacity exhaustion semantics.
//
// INVARIANT (Acceptance Criterion 1): exceeding the replay-domain capacity must
// NEVER make a previously accepted response replayable again. The Phase 19
// implementation evicted an arbitrary (map-iteration-order) domain at capacity,
// silently re-opening an already accepted replay window. The Phase 20 fix seals
// the whole connection fail-closed (ErrReplayDomainCapacity) when a 33rd domain
// would be required; domains are never evicted. Capacity is consumed only by
// AEAD-authenticated v4 server frames (replay filtering runs strictly after tag
// verification), so malformed frames and unauthorized server IDs cannot consume
// domain capacity.

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/arashmh13/paqet-ngv2/internal/ng/crypto"
)

// fixed32 returns a deterministic exactly-32-byte secret from a printable seed
// (keeps test literals readable while satisfying the 32-byte constructors).
func fixed32(seed string) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = seed[i%len(seed)]
	}
	return out
}

// newV4PairForCapacity builds an authenticated client/server session pair with a
// fresh server identity, plus a helper to seal a downstream response frame in a
// distinct replay domain (distinct random nonce/key base per server session).
func newV4PairForCapacity(t *testing.T, sessionID uint64, serverID string, secret []byte) (*AsymmetricConn, *AsymmetricConn) {
	t.Helper()
	psk := fixed32("phase20-capacity-psk")
	seedX := [crypto.SessionSeedSize]byte{}
	for i := range seedX {
		seedX[i] = byte(0x20 + i)
	}
	set, err := NewAuthorizedServerSet("epoch-p20cap", []AuthorizedServerEntry{{ServerID: serverID, ResponseSecret: secret}})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	client, err := NewClientAsymmetricSessionV4(sessionID, psk, set, &seedX)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	srv, err := NewServerAsymmetricSessionWithIDV4(sessionID, psk, secret, seedX[:], serverID)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	return client, srv
}

// TestPhase20_DomainCapacity_FirstDomainAcceptedThenReplayRejected is requirement 1+3+4:
// accept a valid response in domain 1, exhaust capacity with distinct domains,
// then replay the ORIGINAL domain-1 response — it must still be rejected (never
// re-accepted via eviction) and the session must now be sealed.
func TestPhase20_DomainCapacity_FirstDomainAcceptedThenReplayRejected(t *testing.T) {
	const serverID = "srv-cap-01"
	client, srv := newV4PairForCapacity(t, 0x2001, serverID, fixed32("capacity-test-secret-A"))

	respBytes, _ := json.Marshal(&EmergencyResponse{ID: "cap-1", Status: "OK", Reply: []byte("R1"), Timestamp: 1})
	domain1Frame, err := srv.SealFrame(1, 1, respBytes)
	if err != nil {
		t.Fatalf("seal domain1: %v", err)
	}
	if _, _, _, _, err := client.openFrameWithServerID(domain1Frame); err != nil {
		t.Fatalf("domain-1 first open: %v", err)
	}
	// Verbatim replay of the domain-1 response must be rejected even BEFORE exhaustion.
	if _, _, _, _, err := client.openFrameWithServerID(domain1Frame); err == nil {
		t.Fatalf("DEFECT: domain-1 verbatim replay accepted before exhaustion")
	}

	// Create exactly enough DISTINCT authenticated domains to reach capacity, then one more.
	for d := 2; d <= MaxServerReplayDomainsPerConn; d++ {
		_, srvD := newV4PairForCapacity(t, 0x2001, serverID, fixed32("capacity-test-secret-A"))
		_ = srvD // distinct server sessions carry distinct random bases; frames share (sessionID, seed)
		frame, err := srvD.SealFrame(uint32(d), 1, respBytes)
		if err != nil {
			t.Fatalf("seal domain %d: %v", d, err)
		}
		if _, _, _, _, err := client.openFrameWithServerID(frame); err != nil {
			t.Fatalf("domain %d first open: %v", d, err)
		}
	}
	if len(client.serverReplay) != MaxServerReplayDomainsPerConn {
		t.Fatalf("expected exactly %d domains, got %d", MaxServerReplayDomainsPerConn, len(client.serverReplay))
	}

	// Domain 33: a fresh server session (fresh authenticated base) must be REJECTED,
	// the session sealed, and no eviction may occur.
	_, srv33 := newV4PairForCapacity(t, 0x2001, serverID, fixed32("capacity-test-secret-A"))
	frame33, err := srv33.SealFrame(999, 1, respBytes)
	if err != nil {
		t.Fatalf("seal domain33: %v", err)
	}
	if _, _, _, _, err := client.openFrameWithServerID(frame33); err == nil {
		t.Fatalf("DEFECT: 33rd replay domain accepted (capacity exceeded silently)")
	} else if !isReplayDomainCapacityErr(err) {
		t.Fatalf("expected ErrReplayDomainCapacity, got %v", err)
	}
	if !client.replayDomainSealed.Load() {
		t.Fatalf("session must be sealed after capacity exhaustion")
	}
	if len(client.serverReplay) != MaxServerReplayDomainsPerConn {
		t.Fatalf("no eviction allowed: expected %d domains retained, got %d", MaxServerReplayDomainsPerConn, len(client.serverReplay))
	}

	// Requirement 3+4: replay the ORIGINAL domain-1 response after exhaustion —
	// still rejected (its filter was never evicted).
	if _, _, _, _, err := client.openFrameWithServerID(domain1Frame); err == nil {
		t.Fatalf("CRITICAL: domain-1 response became replayable after capacity exhaustion")
	}
	// And any further frame on the sealed session is rejected fail-closed.
	frame34, _ := srv33.SealFrame(1000, 1, respBytes)
	if _, _, _, _, err := client.openFrameWithServerID(frame34); err == nil {
		t.Fatalf("sealed session accepted a further frame")
	}
}

func isReplayDomainCapacityErr(err error) bool {
	if err == nil {
		return false
	}
	type causer interface{ Error() string }
	_ = causer(nil)
	return containsErrString(err.Error(), "replay-domain capacity exhausted")
}

func containsErrString(hay, needle string) bool {
	return len(hay) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(hay); i++ {
			if hay[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// TestPhase20_DomainCapacity_TwoAuthorizedServerIDs is requirement 5: two distinct
// authorized server identities each consume their own domain; replay from either
// is rejected; exhaustion behavior is identical per identity.
func TestPhase20_DomainCapacity_TwoAuthorizedServerIDs(t *testing.T) {
	psk := fixed32("phase20-capacity-psk")
	secretA := fixed32("two-identity-secret-A")
	secretB := fixed32("two-identity-secret-B")
	seedX := [crypto.SessionSeedSize]byte{}
	for i := range seedX {
		seedX[i] = byte(0x21 + i)
	}
	set, err := NewAuthorizedServerSet("epoch-p20cap2", []AuthorizedServerEntry{
		{ServerID: "srv-cap-a", ResponseSecret: secretA},
		{ServerID: "srv-cap-b", ResponseSecret: secretB},
	})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	client, err := NewClientAsymmetricSessionV4(0x2002, psk, set, &seedX)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	srvA, err := NewServerAsymmetricSessionWithIDV4(0x2002, psk, secretA, seedX[:], "srv-cap-a")
	if err != nil {
		t.Fatalf("srvA: %v", err)
	}
	srvB, err := NewServerAsymmetricSessionWithIDV4(0x2002, psk, secretB, seedX[:], "srv-cap-b")
	if err != nil {
		t.Fatalf("srvB: %v", err)
	}
	respBytes, _ := json.Marshal(&EmergencyResponse{ID: "two-id", Status: "OK", Reply: []byte("R"), Timestamp: 1})
	frameA, _ := srvA.SealFrame(1, 1, respBytes)
	frameB, _ := srvB.SealFrame(1, 1, respBytes)
	if _, _, _, _, err := client.openFrameWithServerID(frameA); err != nil {
		t.Fatalf("server A open: %v", err)
	}
	if _, _, _, _, err := client.openFrameWithServerID(frameB); err != nil {
		t.Fatalf("server B open: %v", err)
	}
	// Distinct domains per identity even at the same seq.
	if _, _, _, _, err := client.openFrameWithServerID(frameA); err == nil {
		t.Fatalf("DEFECT: server A replay accepted")
	}
	if _, _, _, _, err := client.openFrameWithServerID(frameB); err == nil {
		t.Fatalf("DEFECT: server B replay accepted")
	}
	// Same server, different seq → different base needed for a NEW domain; re-sealing
	// under the SAME server session at a new seq must be accepted (in-order stream).
	frameA2, err := srvA.SealFrame(2, 2, respBytes)
	if err != nil {
		t.Fatalf("seal A2: %v", err)
	}
	if _, _, _, _, err := client.openFrameWithServerID(frameA2); err != nil {
		t.Fatalf("server A seq2 same-domain: %v", err)
	}
}

// TestPhase20_DomainCapacity_MalformedFramesDoNotConsumeCapacity is requirement 6:
// invalid credentials and malformed frames must be rejected BEFORE the replay
// stage and must not consume replay-domain capacity.
func TestPhase20_DomainCapacity_MalformedFramesDoNotConsumeCapacity(t *testing.T) {
	const serverID = "srv-cap-mal"
	client, srv := newV4PairForCapacity(t, 0x2003, serverID, fixed32("malformed-probe-secret"))

	respBytes, _ := json.Marshal(&EmergencyResponse{ID: "mal-1", Status: "OK", Reply: []byte("R"), Timestamp: 1})
	goodFrame, err := srv.SealFrame(1, 1, respBytes)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, _, _, _, err := client.openFrameWithServerID(goodFrame); err != nil {
		t.Fatalf("domain-1 open: %v", err)
	}
	baseDomains := len(client.serverReplay)

	// Flood with malformed / unauthenticated frames.
	floods := 0
	// (a) unknown server ID
	badID := append([]byte(nil), goodFrame...)
	// locate srvID bytes: after fixed 21-byte prefix + 16 seed + 1 len byte
	idLen := int(badID[37])
	copy(badID[38:38+idLen], []byte("srv-UNKNOWN-XX"))
	for i := 0; i < 200; i++ {
		if _, _, _, _, err := client.openFrameWithServerID(badID); err == nil {
			t.Fatalf("unknown server ID accepted")
		}
		floods++
	}
	// (b) corrupted ciphertext (AEAD failure)
	badCT := append([]byte(nil), goodFrame...)
	badCT[len(badCT)-1] ^= 0xFF
	for i := 0; i < 200; i++ {
		if _, _, _, _, err := client.openFrameWithServerID(badCT); err == nil {
			t.Fatalf("corrupted ciphertext accepted")
		}
		floods++
	}
	// (c) truncated frame
	for i := 0; i < 100; i++ {
		if _, _, _, _, err := client.openFrameWithServerID(goodFrame[:20+i%30]); err == nil {
			t.Fatalf("truncated frame accepted")
		}
		floods++
	}
	// (d) degenerate all-zero RNB with valid-looking structure
	zeroRNB := append([]byte(nil), goodFrame...)
	// RNB sits at the tail before the tag: copy zeros over it
	zeroRNB[len(zeroRNB)-crypto.TagSize-8] = 0
	copy(zeroRNB[len(zeroRNB)-crypto.TagSize-7:], make([]byte, 7))
	if _, _, _, _, err := client.openFrameWithServerID(zeroRNB); err == nil {
		t.Fatalf("all-zero RNB accepted")
	}
	floods += 501

	if got := len(client.serverReplay); got != baseDomains {
		t.Fatalf("DEFECT: floods consumed replay-domain capacity: %d -> %d after %d floods", baseDomains, got, floods)
	}
	if client.replayDomainSealed.Load() {
		t.Fatalf("session must NOT be sealed by unauthenticated floods")
	}
	// The session still accepts a legitimately authenticated NEW domain.
	_, srvNew := newV4PairForCapacity(t, 0x2003, serverID, fixed32("malformed-probe-secret"))
	frameNew, err := srvNew.SealFrame(7, 1, respBytes)
	if err != nil {
		t.Fatalf("seal new domain: %v", err)
	}
	if _, _, _, _, err := client.openFrameWithServerID(frameNew); err != nil {
		t.Fatalf("legitimate new domain after floods: %v", err)
	}
}

// TestPhase20_DomainCapacity_ConcurrentExhaustionDeterministic is requirement 7:
// concurrent domain creation plus replay checks must end deterministically sealed
// with NO eviction, under -race.
func TestPhase20_DomainCapacity_ConcurrentExhaustionDeterministic(t *testing.T) {
	const serverID = "srv-cap-conc"
	client, _ := newV4PairForCapacity(t, 0x2004, serverID, fixed32("concurrent-capacity-secret"))

	respBytes, _ := json.Marshal(&EmergencyResponse{ID: "conc", Status: "OK", Reply: []byte("R"), Timestamp: 1})
	// Pre-build MaxServerReplayDomainsPerConn distinct authenticated domain frames
	// plus many extras beyond capacity.
	frames := make([][]byte, 0, MaxServerReplayDomainsPerConn+64)
	for d := 0; d < MaxServerReplayDomainsPerConn+64; d++ {
		_, srvD := newV4PairForCapacity(t, 0x2004, serverID, fixed32("concurrent-capacity-secret"))
		f, err := srvD.SealFrame(uint32(d+1), 1, respBytes)
		if err != nil {
			t.Fatalf("seal %d: %v", d, err)
		}
		frames = append(frames, f)
	}

	var wg sync.WaitGroup
	var accepted int32
	var mu sync.Mutex
	errs := make([]error, 0)
	for _, f := range frames {
		f := f
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, _, err := client.openFrameWithServerID(f)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				accepted++
			} else {
				errs = append(errs, err)
			}
		}()
	}
	wg.Wait()

	if int(accepted) != MaxServerReplayDomainsPerConn {
		t.Fatalf("exactly %d domains must be accepted, got %d", MaxServerReplayDomainsPerConn, accepted)
	}
	if len(errs) != len(frames)-MaxServerReplayDomainsPerConn {
		t.Fatalf("all overflow frames must be rejected: got %d rejections, want %d", len(errs), len(frames)-MaxServerReplayDomainsPerConn)
	}
	for _, err := range errs {
		if !isReplayDomainCapacityErr(err) {
			t.Fatalf("overflow rejection must be ErrReplayDomainCapacity, got %v", err)
		}
	}
	if len(client.serverReplay) != MaxServerReplayDomainsPerConn {
		t.Fatalf("deterministic final state expected: %d domains, got %d", MaxServerReplayDomainsPerConn, len(client.serverReplay))
	}
	if !client.replayDomainSealed.Load() {
		t.Fatalf("session must be sealed after concurrent exhaustion")
	}
	_ = fmt.Sprintf("deterministic seal verified")
}
