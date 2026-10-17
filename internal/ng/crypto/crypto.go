package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	KeySize   = 32
	NonceSize = 12
	TagSize   = 16
)

var (
	ErrInvalidKey            = errors.New("crypto: invalid key length")
	ErrDecrypt               = errors.New("crypto: decryption failed or authentication tag mismatch")
	ErrMissingResponseSecret = errors.New("crypto: dedicated server response secret is required")
	ErrInvalidResponseSecret = errors.New("crypto: server response secret must be exactly 32 bytes")
)

// DeriveKeys derives directional 32-byte subkeys from a pre-shared master secret (PSK).
// It returns (clientToServerKey, serverToClientKey, error).
func DeriveKeys(psk []byte, salt []byte) ([]byte, []byte, error) {
	if len(psk) == 0 {
		return nil, nil, ErrInvalidKey
	}
	if len(salt) == 0 {
		salt = []byte("paqet-ng-v2-hkdf-salt")
	}

	extractor := hkdf.New(sha256.New, psk, salt, []byte("paqet-ng-directional-v2"))

	c2s := make([]byte, KeySize)
	s2c := make([]byte, KeySize)

	if _, err := io.ReadFull(extractor, c2s); err != nil {
		return nil, nil, fmt.Errorf("crypto: failed to derive c2s key: %w", err)
	}
	if _, err := io.ReadFull(extractor, s2c); err != nil {
		return nil, nil, fmt.Errorf("crypto: failed to derive s2c key: %w", err)
	}

	return c2s, s2c, nil
}

// DeriveLegacySingleServerTrafficKeys derives directional keys for explicit legacy single-server operation.
func DeriveLegacySingleServerTrafficKeys(psk []byte, salt []byte) ([]byte, []byte, error) {
	return DeriveKeys(psk, salt)
}

// DeriveServerTrafficKeys derives server-specific directional keys using HKDF (RFC 5869)
// with explicit domain separation.
// c2sKey is derived from c2sPSK (shared root secret allowing authorized servers to decrypt queries).
// s2cKey is derived from serverResponseSecret (unique per-server response secret held exclusively by serverID).
// Both c2sPSK and serverResponseSecret must be exactly 32 bytes. No implicit fallback to c2sPSK is permitted.
func DeriveServerTrafficKeys(c2sPSK []byte, serverResponseSecret []byte, salt []byte, serverID string) ([]byte, []byte, error) {
	if len(c2sPSK) != KeySize {
		return nil, nil, ErrInvalidKey
	}
	if len(serverResponseSecret) == 0 {
		return nil, nil, ErrMissingResponseSecret
	}
	if len(serverResponseSecret) != KeySize {
		return nil, nil, ErrInvalidResponseSecret
	}
	if serverID == "" {
		return nil, nil, fmt.Errorf("crypto: serverID cannot be empty in multi-server derivation")
	}
	if len(salt) == 0 {
		salt = []byte("paqet-ng-v3-hkdf-salt")
	}

	c2sExtractor := hkdf.New(sha256.New, c2sPSK, salt, []byte("paqet-ng-v3-c2s"))
	c2s := make([]byte, KeySize)
	if _, err := io.ReadFull(c2sExtractor, c2s); err != nil {
		return nil, nil, fmt.Errorf("crypto: failed to derive c2s v3 key: %w", err)
	}

	s2cInfo := []byte(fmt.Sprintf("paqet-ng-v3-s2c:%s", serverID))
	s2cExtractor := hkdf.New(sha256.New, serverResponseSecret, salt, s2cInfo)
	s2c := make([]byte, KeySize)
	if _, err := io.ReadFull(s2cExtractor, s2c); err != nil {
		return nil, nil, fmt.Errorf("crypto: failed to derive s2c v3 key: %w", err)
	}

	return c2s, s2c, nil
}

// DeriveServerResponseKey derives only the server-to-client response key from serverResponseSecret and serverID.
func DeriveServerResponseKey(serverResponseSecret []byte, salt []byte, serverID string) ([]byte, error) {
	if len(serverResponseSecret) == 0 {
		return nil, ErrMissingResponseSecret
	}
	if len(serverResponseSecret) != KeySize {
		return nil, ErrInvalidResponseSecret
	}
	if serverID == "" {
		return nil, fmt.Errorf("crypto: serverID cannot be empty in response key derivation")
	}
	if len(salt) == 0 {
		salt = []byte("paqet-ng-v3-hkdf-salt")
	}

	s2cInfo := []byte(fmt.Sprintf("paqet-ng-v3-s2c:%s", serverID))
	extractor := hkdf.New(sha256.New, serverResponseSecret, salt, s2cInfo)
	s2c := make([]byte, KeySize)
	if _, err := io.ReadFull(extractor, s2c); err != nil {
		return nil, fmt.Errorf("crypto: failed to derive s2c v3 key for server %s: %w", serverID, err)
	}
	return s2c, nil
}

// SessionSeedSize is the size of the per-session random keying-material seed
// used by the v4 wire protocol ("PAQD"). The seed is transported as
// authenticated associated data in every frame and mixed into the HKDF salt,
// so the traffic-key schedule is randomized independently of the 64-bit
// session identifier.
const SessionSeedSize = 16

// V4Salt returns the v4 key-derivation salt:
//
//	salt = "paqet-v4-" || sessionSeed(16B) || sessionID(8B BE)
//
// This guarantees that a session-ID collision alone (64-bit space) cannot
// recreate a matching key and nonce domain: the 128-bit random sessionSeed is
// an independent entropy source. Reusing the same key+nonce pair requires a
// collision of the full (seed, sessionID) pair (~2^(128+63) space), reducing
// the birthday bound from n^2/2^65 (v3) to n^2/2^129 (v4).
func V4Salt(sessionSeed []byte, sessionID uint64) []byte {
	if len(sessionSeed) != SessionSeedSize {
		sessionSeed = make([]byte, SessionSeedSize) // deterministic zero salt for malformed input (construction paths validate length beforehand)
	}
	salt := make([]byte, 0, len("paqet-v4-")+SessionSeedSize+8)
	salt = append(salt, "paqet-v4-"...)
	salt = append(salt, sessionSeed...)
	var sessIDBE [8]byte
	binary.BigEndian.PutUint64(sessIDBE[:], sessionID)
	salt = append(salt, sessIDBE[:]...)
	return salt
}

// DeriveV4ClientTrafficKey derives the client-to-server upstream key for the v4 protocol.
// The upstream key remains bound to the shared c2s PSK (all authorized servers can decrypt
// queries), but is independently re-keyed per session via the random sessionSeed salt.
func DeriveV4ClientTrafficKey(c2sPSK []byte, sessionSeed []byte, sessionID uint64) ([]byte, error) {
	if len(c2sPSK) != KeySize {
		return nil, ErrInvalidKey
	}
	extractor := hkdf.New(sha256.New, c2sPSK, V4Salt(sessionSeed, sessionID), []byte("paqet-v4-c2s"))
	c2s := make([]byte, KeySize)
	if _, err := io.ReadFull(extractor, c2s); err != nil {
		return nil, fmt.Errorf("crypto: failed to derive v4 c2s key: %w", err)
	}
	return c2s, nil
}

// DeriveServerTrafficKeysV4 derives v4 directional keys:
//   - c2sKey: HKDF-SHA256(ikm=c2sPSK, salt=V4Salt(seed, sessionID), info="paqet-v4-c2s")
//   - s2cKey: HKDF-SHA256(ikm=serverResponseSecret, salt=V4Salt(seed, sessionID), info="paqet-v4-s2c:"+serverID)
//
// No implicit fallback to the shared PSK is permitted anywhere in v4 derivation.
// DeriveServerTrafficKeysV4 derives both directions for a v4 server session. The
// per-server-session nonce/key base (serverSessionBase, 8 bytes) is bound into the
// s2c HKDF salt (NOT the c2s salt, which must stay derivable from the cleartext
// request alone) so each session reconstruction has key-disjoint downstream traffic.
func DeriveServerTrafficKeysV4(c2sPSK []byte, serverResponseSecret []byte, sessionSeed []byte, sessionID uint64, serverID string, serverSessionBase []byte) ([]byte, []byte, error) {
	if len(c2sPSK) != KeySize {
		return nil, nil, ErrInvalidKey
	}
	if len(serverResponseSecret) == 0 {
		return nil, nil, ErrMissingResponseSecret
	}
	if len(serverResponseSecret) != KeySize {
		return nil, nil, ErrInvalidResponseSecret
	}
	if serverID == "" {
		return nil, nil, fmt.Errorf("crypto: serverID cannot be empty in v4 derivation")
	}
	if len(serverSessionBase) != DownstreamNonceBaseSize {
		return nil, nil, fmt.Errorf("crypto: server session base must be %d bytes", DownstreamNonceBaseSize)
	}
	salt := V4Salt(sessionSeed, sessionID)

	c2sExtractor := hkdf.New(sha256.New, c2sPSK, salt, []byte("paqet-v4-c2s"))
	c2s := make([]byte, KeySize)
	if _, err := io.ReadFull(c2sExtractor, c2s); err != nil {
		return nil, nil, fmt.Errorf("crypto: failed to derive v4 c2s key: %w", err)
	}

	s2cInfo := []byte(fmt.Sprintf("paqet-v4-s2c:%s", serverID))
	s2cSalt := append(append([]byte(nil), salt...), serverSessionBase...)
	s2cExtractor := hkdf.New(sha256.New, serverResponseSecret, s2cSalt, s2cInfo)
	s2c := make([]byte, KeySize)
	if _, err := io.ReadFull(s2cExtractor, s2c); err != nil {
		return nil, nil, fmt.Errorf("crypto: failed to derive v4 s2c key: %w", err)
	}

	return c2s, s2c, nil
}

// DeriveServerResponseKeyV4 derives only the v4 server-to-client response key
// from the dedicated server response secret, the per-session random seed, the
// server identity, and the per-server-session nonce/key base carried in the
// response frame header (bound into the HKDF salt so each server-session
// reconstruction is key-disjoint).
func DeriveServerResponseKeyV4(serverResponseSecret []byte, sessionSeed []byte, sessionID uint64, serverID string, serverSessionBase []byte) ([]byte, error) {
	if len(serverResponseSecret) == 0 {
		return nil, ErrMissingResponseSecret
	}
	if len(serverResponseSecret) != KeySize {
		return nil, ErrInvalidResponseSecret
	}
	if serverID == "" {
		return nil, fmt.Errorf("crypto: serverID cannot be empty in v4 response key derivation")
	}
	if len(serverSessionBase) != DownstreamNonceBaseSize {
		return nil, fmt.Errorf("crypto: server session base must be %d bytes", DownstreamNonceBaseSize)
	}
	salt := append(V4Salt(sessionSeed, sessionID), serverSessionBase...)
	s2cInfo := []byte(fmt.Sprintf("paqet-v4-s2c:%s", serverID))
	extractor := hkdf.New(sha256.New, serverResponseSecret, salt, s2cInfo)
	s2c := make([]byte, KeySize)
	if _, err := io.ReadFull(extractor, s2c); err != nil {
		return nil, fmt.Errorf("crypto: failed to derive v4 s2c key for server %s: %w", serverID, err)
	}
	return s2c, nil
}

// DownstreamNonceBaseSize is the size of the per-server-instance random nonce
// stream base used for v4 ("PAQD") server-downstream frames. Because it is
// regenerated at each server (re)start with fresh session instances, a replayed
// captured request answered by a restarted server can never reproduce the
// original (key, nonce) domain for new plaintexts.
const DownstreamNonceBaseSize = 8

// GenerateDownstreamNonceBase returns a fresh cryptographically random,
// guaranteed-nonzero 8-byte downstream nonce stream base.
func GenerateDownstreamNonceBase() ([]byte, error) {
	b := make([]byte, DownstreamNonceBaseSize)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	zero := true
	for _, x := range b {
		if x != 0 {
			zero = false
			break
		}
	}
	if zero {
		return nil, errors.New("crypto: degenerate all-zero downstream nonce base")
	}
	return b, nil
}

// GenerateSessionSeed returns a fresh cryptographically random 128-bit per-session seed.
func GenerateSessionSeed() ([SessionSeedSize]byte, error) {
	var s [SessionSeedSize]byte
	_, err := io.ReadFull(rand.Reader, s[:])
	return s, err
}

// GenerateFullRandomUint64 returns a full-entropy 64-bit value from crypto/rand.
func GenerateFullRandomUint64() (uint64, error) {
	var v uint64
	if err := binary.Read(rand.Reader, binary.BigEndian, &v); err != nil {
		return 0, fmt.Errorf("crypto: full 64-bit random read failed: %w", err)
	}
	return v, nil
}

// NewAEAD returns an AES-256-GCM cipher from a 32-byte key.
func NewAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes init error: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: gcm init error: %w", err)
	}
	return aead, nil
}

// GenerateNonce creates a secure 12-byte random nonce.
func GenerateNonce() ([NonceSize]byte, error) {
	var n [NonceSize]byte
	_, err := io.ReadFull(rand.Reader, n[:])
	return n, err
}
