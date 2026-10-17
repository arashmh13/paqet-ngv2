// Package obfs adds a transparent obfuscation layer on top of a
// net.PacketConn.
//
// paqet tunnels KCP over raw TCP packets that it injects below the host
// TCP/IP stack. KCP already encrypts the payload it produces, but the
// encrypted datagrams still carry a transport specific shape: the smallest
// packets (pure ACKs) always have exactly the same length, and the packet
// length correlates one to one with the application payload. Deep packet
// inspection boxes exploit exactly those properties to flag, throttle or
// block KCP/raw-packet tunnels.
//
// This package removes that signal. Every datagram written to the
// underlying connection is authenticated with AES-256-GCM, prefixed with a
// fresh random nonce and padded with random bytes to a length that is
// uniformly distributed within a configurable window. To a passive
// observer the wire bytes are indistinguishable from random noise, there
// is no stable header to fingerprint, and the packet sizes no longer leak
// the size of the tunneled traffic.
//
// Datagrams that fail authentication (active probes, corrupted or injected
// traffic) are dropped silently and never surface to the transport, so a
// prober observes exactly the same behaviour as a closed port.
package obfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// nonceSize is the AES-GCM nonce length.
	nonceSize = 12
	// tagSize is the AES-GCM authentication tag length.
	tagSize = 16
	// lenSize is the length of the plaintext payload length prefix.
	lenSize = 2

	// Overhead is the number of bytes this layer adds to every datagram
	// on the wire (nonce + authentication tag + length prefix).
	Overhead = nonceSize + tagSize + lenSize

	// MaxFrame is the largest obfuscated frame that still fits in a
	// 1500 byte path MTU once the IPv4 (20) and TCP (20) headers have been
	// accounted for. Keeping frames at or below this value prevents the
	// raw packet injector from emitting packets that would be fragmented
	// or dropped because of the don't-fragment flag it sets.
	MaxFrame = 1500 - 20 - 20

	// keySalt is mixed into the shared secret when deriving the AEAD key.
	// It is intentionally different from the KCP salt so the two layers
	// never share key material.
	keySalt = "paqet-obfs-v1"
	// keyIterations is the PBKDF2 iteration count used for key derivation.
	keyIterations = 100_000
	// keySize is the AES-256 key size in bytes.
	keySize = 32
	// maxMaxPad bounds the configurable padding window. Larger windows
	// waste more bandwidth for very little additional protection.
	maxMaxPad = 512
)

// Conn wraps a net.PacketConn and obfuscates every datagram that passes
// through it. It implements net.PacketConn so it can be handed to the
// transport unchanged.
type Conn struct {
	net.PacketConn

	aead   cipher.AEAD
	maxPad int

	recvPool sync.Pool

	replayMu sync.Mutex
	recent   map[[nonceSize]byte]struct{}
	ring     [][nonceSize]byte
	ringIdx  int
}

// New wraps conn with the obfuscation layer. key is the shared secret that
// must be identical on both peers; maxPad is the width of the random
// padding window in bytes (0 disables padding).
func New(conn net.PacketConn, key []byte, maxPad int) (*Conn, error) {
	if conn == nil {
		return nil, errors.New("obfs: underlying connection is nil")
	}
	if len(key) == 0 {
		return nil, errors.New("obfs: an encryption key is required")
	}
	if maxPad < 0 {
		maxPad = 0
	}
	if maxPad > maxMaxPad {
		maxPad = maxMaxPad
	}

	dk := pbkdf2.Key(key, []byte(keySalt), keyIterations, keySize, sha256.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, fmt.Errorf("obfs: failed to create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("obfs: failed to create AEAD: %w", err)
	}

	c := &Conn{
		PacketConn: conn,
		aead:       aead,
		maxPad:     maxPad,
		recent:     make(map[[nonceSize]byte]struct{}, 16384),
		ring:       make([][nonceSize]byte, 16384),
	}
	c.recvPool.New = func() any {
		return make([]byte, MaxFrame)
	}

	return c, nil
}

// WriteTo encrypts, authenticates and pads payload before writing it to
// the underlying connection.
func (c *Conn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	if len(payload) > 0xFFFF {
		return 0, fmt.Errorf("obfs: payload of %d bytes is too large", len(payload))
	}

	pad := c.padding(len(payload))
	frame := make([]byte, nonceSize, Overhead+len(payload)+pad)
	if _, err := rand.Read(frame); err != nil {
		return 0, fmt.Errorf("obfs: failed to generate nonce: %w", err)
	}

	plain := make([]byte, lenSize+len(payload)+pad)
	binary.BigEndian.PutUint16(plain[:lenSize], uint16(len(payload)))
	copy(plain[lenSize:], payload)
	if pad > 0 {
		if _, err := rand.Read(plain[lenSize+len(payload):]); err != nil {
			return 0, fmt.Errorf("obfs: failed to generate padding: %w", err)
		}
	}

	frame = c.aead.Seal(frame, frame[:nonceSize], plain, nil)
	if _, err := c.PacketConn.WriteTo(frame, addr); err != nil {
		return 0, err
	}

	return len(payload), nil
}

// ReadFrom reads a datagram from the underlying connection, authenticates
// it, strips the padding and copies the original payload into buf.
// Datagrams that cannot be authenticated are dropped silently, which also
// makes the endpoint resistant to active probing.
func (c *Conn) ReadFrom(buf []byte) (int, net.Addr, error) {
	tmp := c.recvPool.Get().([]byte)
	defer c.recvPool.Put(tmp)

	for {
		n, addr, err := c.PacketConn.ReadFrom(tmp)
		if err != nil {
			return 0, addr, err
		}
		if n < Overhead {
			continue
		}

		nonce := tmp[:nonceSize]
		ciphertext := tmp[nonceSize:n]

		var nonceArr [nonceSize]byte
		copy(nonceArr[:], nonce)
		c.replayMu.Lock()
		if _, seen := c.recent[nonceArr]; seen {
			c.replayMu.Unlock()
			continue // Drop replayed packet silently!
		}
		c.replayMu.Unlock()

		plain, err := c.aead.Open(ciphertext[:0], nonce, ciphertext, nil)
		if err != nil {
			continue
		}
		if len(plain) < lenSize {
			continue
		}

		c.replayMu.Lock()
		if len(c.recent) >= len(c.ring) {
			oldest := c.ring[c.ringIdx]
			delete(c.recent, oldest)
		}
		c.recent[nonceArr] = struct{}{}
		c.ring[c.ringIdx] = nonceArr
		c.ringIdx = (c.ringIdx + 1) % len(c.ring)
		c.replayMu.Unlock()

		size := int(binary.BigEndian.Uint16(plain[:lenSize]))
		if size > len(plain)-lenSize || size > len(buf) {
			continue
		}

		return copy(buf, plain[lenSize:lenSize+size]), addr, nil
	}
}

// Close closes the underlying connection.
func (c *Conn) Close() error {
	return c.PacketConn.Close()
}

// padding returns a random padding length for a payload of plainLen bytes.
// The result is bounded by maxPad and by the space that is left before the
// on-wire frame would exceed MaxFrame.
func (c *Conn) padding(plainLen int) int {
	limit := c.maxPad
	if budget := MaxFrame - Overhead - plainLen; budget < limit {
		limit = budget
	}
	if limit <= 0 {
		return 0
	}

	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(b[:])) % (limit + 1)
}
