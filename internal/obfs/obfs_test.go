package obfs

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// datagram models a single datagram travelling over the test link.
type datagram struct {
	data []byte
	addr net.Addr
}

// memConn is an in-memory net.PacketConn used to exercise the obfuscation
// layer without touching real sockets.
type memConn struct {
	in     chan datagram
	out    chan datagram
	local  net.Addr
	closed chan struct{}
	once   sync.Once
	rd     atomic.Value
	wr     atomic.Value
}

func newMemConn(in, out chan datagram, local net.Addr) *memConn {
	return &memConn{in: in, out: out, local: local, closed: make(chan struct{})}
}

// newMemPair returns two connected endpoints. A datagram written by one is
// delivered to the other with the sender's local address as its source.
func newMemPair() (client, server *memConn) {
	toServer := make(chan datagram, 1024)
	toClient := make(chan datagram, 1024)
	cAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40001}
	sAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 9999}
	return newMemConn(toClient, toServer, cAddr), newMemConn(toServer, toClient, sAddr)
}

func (c *memConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := c.rd.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case d := <-c.in:
		return copy(p, d.data), d.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case <-deadline:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *memConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case c.out <- datagram{data: append([]byte(nil), p...), addr: c.local}:
		return len(p), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *memConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *memConn) LocalAddr() net.Addr { return c.local }

func (c *memConn) SetDeadline(t time.Time) error {
	c.rd.Store(t)
	c.wr.Store(t)
	return nil
}

func (c *memConn) SetReadDeadline(t time.Time) error {
	c.rd.Store(t)
	return nil
}

func (c *memConn) SetWriteDeadline(t time.Time) error {
	c.wr.Store(t)
	return nil
}

func mustConn(t *testing.T, conn net.PacketConn, key []byte, maxPad int) *Conn {
	t.Helper()
	c, err := New(conn, key, maxPad)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return c
}

func randomPayload(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	return b
}

func TestRoundTrip(t *testing.T) {
	client, server := newMemPair()
	key := []byte("correct horse battery staple")
	ca := mustConn(t, client, key, 64)
	sb := mustConn(t, server, key, 64)

	for _, size := range []int{0, 1, 24, 44, 500, 1350} {
		want := randomPayload(t, size)
		if _, err := ca.WriteTo(want, server.local); err != nil {
			t.Fatalf("WriteTo(%d) error = %v", size, err)
		}

		got := make([]byte, 2048)
		n, addr, err := sb.ReadFrom(got)
		if err != nil {
			t.Fatalf("ReadFrom(%d) error = %v", size, err)
		}
		if !bytes.Equal(got[:n], want) {
			t.Fatalf("payload mismatch for size %d: got %d bytes, want %d", size, n, len(want))
		}
		if addr.String() != client.local.String() {
			t.Fatalf("source address = %v, want %v", addr, client.local)
		}
	}
}

func TestWrongKeyIsDropped(t *testing.T) {
	client, server := newMemPair()
	ca := mustConn(t, client, []byte("client-key"), 32)
	sb := mustConn(t, server, []byte("server-key"), 32)

	if _, err := ca.WriteTo([]byte("hello"), server.local); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}

	if err := sb.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	_, _, err := sb.ReadFrom(make([]byte, 2048))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFrom() error = %v, want deadline exceeded (frame must be dropped)", err)
	}
}

func TestTamperedFrameIsDropped(t *testing.T) {
	client, server := newMemPair()
	key := []byte("shared-secret")
	ca := mustConn(t, client, key, 32)
	sb := mustConn(t, server, key, 32)

	if _, err := ca.WriteTo([]byte("authenticated payload"), server.local); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}

	// Flip one bit in the middle of the captured frame before delivery.
	frame := <-server.in
	frame.data[len(frame.data)/2] ^= 0x40
	server.in <- frame

	if err := sb.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	_, _, err := sb.ReadFrom(make([]byte, 2048))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFrom() error = %v, want deadline exceeded (tampered frame must be dropped)", err)
	}
}

func TestTruncatedFrameIsDropped(t *testing.T) {
	client, server := newMemPair()
	key := []byte("shared-secret")
	ca := mustConn(t, client, key, 32)
	sb := mustConn(t, server, key, 32)

	if _, err := ca.WriteTo([]byte("payload"), server.local); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}

	frame := <-server.in
	frame.data = frame.data[:Overhead-1] // shorter than the minimum frame
	server.in <- frame

	if err := sb.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	_, _, err := sb.ReadFrom(make([]byte, 2048))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFrom() error = %v, want deadline exceeded (short frame must be dropped)", err)
	}
}

func TestReplayedDatagramIsDropped(t *testing.T) {
	client, server := newMemPair()
	key := []byte("shared-secret")
	ca := mustConn(t, client, key, 32)
	sb := mustConn(t, server, key, 32)

	if _, err := ca.WriteTo([]byte("authenticated payload"), server.local); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}

	// Capture the valid frame
	frame := <-server.in
	// Duplicate the frame into server.in twice
	duplicateFrame := datagram{
		data: append([]byte(nil), frame.data...),
		addr: frame.addr,
	}
	server.in <- frame
	server.in <- duplicateFrame

	// First read must succeed
	buf := make([]byte, 2048)
	n, _, err := sb.ReadFrom(buf)
	if err != nil {
		t.Fatalf("first ReadFrom failed: %v", err)
	}
	if string(buf[:n]) != "authenticated payload" {
		t.Fatalf("unexpected content: %s", string(buf[:n]))
	}

	// Second read (replay of identical frame) must be dropped silently
	if err := sb.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	_, _, err = sb.ReadFrom(buf)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline exceeded on replayed frame, got: %v", err)
	}
}

// captureFrames writes n identical payloads through the obfuscation layer
// and returns the raw frames that reached the wire.
func captureFrames(t *testing.T, n int, payload, key []byte, maxPad int) [][]byte {
	t.Helper()
	out := make(chan datagram, n+1)
	conn := newMemConn(make(chan datagram), out, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1})
	c := mustConn(t, conn, key, maxPad)

	for i := 0; i < n; i++ {
		if _, err := c.WriteTo(payload, conn.local); err != nil {
			t.Fatalf("WriteTo() error = %v", err)
		}
	}

	frames := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		select {
		case d := <-out:
			frames = append(frames, d.data)
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for frame %d", i)
		}
	}
	return frames
}

func TestPaddingRandomisesLength(t *testing.T) {
	const maxPad = 64
	payload := randomPayload(t, 100)
	base := Overhead + len(payload)
	frames := captureFrames(t, 300, payload, []byte("shared"), maxPad)

	lengths := make(map[int]int)
	nonces := make(map[string]struct{})
	maxLen := 0
	for _, f := range frames {
		l := len(f)
		if l < base || l > base+maxPad {
			t.Fatalf("frame length %d outside [%d, %d]", l, base, base+maxPad)
		}
		lengths[l]++
		nonces[string(f[:nonceSize])] = struct{}{}
		if l > maxLen {
			maxLen = l
		}
	}

	if len(lengths) < 5 {
		t.Fatalf("expected padding to spread frame lengths, got %d distinct lengths", len(lengths))
	}
	if maxLen == base {
		t.Fatalf("padding was never applied")
	}
	if len(nonces) != len(frames) {
		t.Fatalf("nonces are not unique: %d unique out of %d", len(nonces), len(frames))
	}
	if bytes.Equal(frames[0], frames[1]) {
		t.Fatalf("identical payloads produced identical frames, encryption is deterministic")
	}
}

func TestFrameStaysWithinMaxFrame(t *testing.T) {
	frames := captureFrames(t, 100, randomPayload(t, 1350), []byte("shared"), 512)
	for _, f := range frames {
		if len(f) > MaxFrame {
			t.Fatalf("frame length %d exceeds MaxFrame %d", len(f), MaxFrame)
		}
	}
}

func TestPaddingDisabled(t *testing.T) {
	payload := randomPayload(t, 60)
	frames := captureFrames(t, 20, payload, []byte("shared"), 0)
	for _, f := range frames {
		if len(f) != Overhead+len(payload) {
			t.Fatalf("frame length = %d, want %d when padding is disabled", len(f), Overhead+len(payload))
		}
	}
}

func TestFrameDoesNotLeakPayload(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x01}, 40)
	frames := captureFrames(t, 1, payload, []byte("shared"), 16)
	if bytes.Contains(frames[0], payload) {
		t.Fatalf("wire frame leaks the plaintext payload")
	}
}

func TestMaxPadIsClamped(t *testing.T) {
	sink := newMemConn(make(chan datagram), make(chan datagram, 1), &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1})
	c := mustConn(t, sink, []byte("k"), 1<<20)
	if c.maxPad != maxMaxPad {
		t.Fatalf("maxPad = %d, want %d", c.maxPad, maxMaxPad)
	}
}

func TestNewRejectsInvalidInput(t *testing.T) {
	conn := newMemConn(make(chan datagram), make(chan datagram, 1), &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1})

	if _, err := New(conn, nil, 0); err == nil {
		t.Fatalf("New() with empty key should fail")
	}
	if _, err := New(nil, []byte("key"), 0); err == nil {
		t.Fatalf("New() with nil connection should fail")
	}
}
