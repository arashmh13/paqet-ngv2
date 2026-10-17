package replay

import (
	"errors"
	"sync"
	"time"
)

const (
	// WindowSize is the number of packets tracked in the sliding bitmap (2048 packets).
	WindowSize  = 2048
	bitmapWords = WindowSize / 64

	// DefaultMaxClockSkew is the maximum acceptable timestamp difference (30 seconds).
	DefaultMaxClockSkew = 30 * time.Second
)

var (
	ErrReplayDetected = errors.New("replay: duplicate or replayed sequence number")
	ErrTimestampSkew  = errors.New("replay: packet timestamp exceeds maximum allowed clock skew")
	ErrWindowOverflow = errors.New("replay: packet sequence is older than sliding window threshold")
)

// Filter provides sliding-window anti-replay and timestamp verification.
type Filter struct {
	mu           sync.Mutex
	maxClockSkew time.Duration
	initialized  bool
	maxSeq       uint64
	bitmap       [bitmapWords]uint64
}

// NewFilter creates an anti-replay filter with the specified maximum clock skew.
func NewFilter(skew time.Duration) *Filter {
	if skew <= 0 {
		skew = DefaultMaxClockSkew
	}
	return &Filter{
		maxClockSkew: skew,
	}
}

// CheckTimestamp verifies that packetTime is within the acceptable clock skew window.
func (f *Filter) CheckTimestamp(packetUnixSec uint32, now time.Time) error {
	pTime := time.Unix(int64(packetUnixSec), 0)
	diff := now.Sub(pTime)
	if diff < 0 {
		diff = -diff
	}
	if diff > f.maxClockSkew {
		return ErrTimestampSkew
	}
	return nil
}

// Validate verifies that sequence number seq has not been previously seen.
// If valid, it records the sequence in the sliding window and returns nil.
// If it is a duplicate or older than the window, an error is returned.
func (f *Filter) Validate(seq uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.initialized {
		f.initialized = true
		f.maxSeq = seq
		f.bitmap[0] = 1 // bit 0 corresponds to maxSeq
		return nil
	}

	if seq > f.maxSeq {
		diff := seq - f.maxSeq
		if diff >= WindowSize {
			// Sequence jumped forward beyond the entire window
			for i := range f.bitmap {
				f.bitmap[i] = 0
			}
		} else {
			f.shift(diff)
		}
		f.maxSeq = seq
		f.bitmap[0] |= 1 // mark maxSeq
		return nil
	}

	// seq <= f.maxSeq
	offset := f.maxSeq - seq
	if offset >= WindowSize {
		return ErrWindowOverflow
	}

	wordIndex := offset / 64
	bitIndex := offset % 64
	mask := uint64(1) << bitIndex

	if (f.bitmap[wordIndex] & mask) != 0 {
		return ErrReplayDetected
	}

	f.bitmap[wordIndex] |= mask
	return nil
}

// shift moves the bitmap by n positions to the right (older sequence space).
func (f *Filter) shift(n uint64) {
	if n == 0 {
		return
	}
	if n >= WindowSize {
		for i := range f.bitmap {
			f.bitmap[i] = 0
		}
		return
	}

	wordShift := int(n / 64)
	bitShift := n % 64

	if wordShift > 0 {
		for i := bitmapWords - 1; i >= 0; i-- {
			if i >= wordShift {
				f.bitmap[i] = f.bitmap[i-wordShift]
			} else {
				f.bitmap[i] = 0
			}
		}
	}

	if bitShift > 0 {
		for i := bitmapWords - 1; i > 0; i-- {
			f.bitmap[i] = (f.bitmap[i] << bitShift) | (f.bitmap[i-1] >> (64 - bitShift))
		}
		f.bitmap[0] <<= bitShift
	}
}

// Reset clears the filter state.
func (f *Filter) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.initialized = false
	f.maxSeq = 0
	for i := range f.bitmap {
		f.bitmap[i] = 0
	}
}
