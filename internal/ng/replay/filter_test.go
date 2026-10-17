package replay

import (
	"errors"
	"testing"
	"time"
)

func TestFilterSequential(t *testing.T) {
	f := NewFilter(30 * time.Second)

	for i := uint64(1); i <= 1000; i++ {
		if err := f.Validate(i); err != nil {
			t.Fatalf("unexpected error for seq %d: %v", i, err)
		}
	}

	// Any repeat of these 1000 packets must fail
	for i := uint64(1); i <= 1000; i++ {
		if err := f.Validate(i); !errors.Is(err, ErrReplayDetected) {
			t.Fatalf("expected ErrReplayDetected for duplicate seq %d, got: %v", i, err)
		}
	}
}

func TestFilterOutOfOrder(t *testing.T) {
	f := NewFilter(30 * time.Second)

	// Insert in non-sequential order: 10, 5, 8, 12, 1, 11
	seqs := []uint64{10, 5, 8, 12, 1, 11}
	for _, s := range seqs {
		if err := f.Validate(s); err != nil {
			t.Fatalf("unexpected error for out-of-order seq %d: %v", s, err)
		}
	}

	// Repeated insertion of any of them must fail
	for _, s := range seqs {
		if err := f.Validate(s); !errors.Is(err, ErrReplayDetected) {
			t.Fatalf("expected ErrReplayDetected for replayed seq %d, got: %v", s, err)
		}
	}

	// A new unseen out-of-order packet in window (e.g. 7) must pass
	if err := f.Validate(7); err != nil {
		t.Fatalf("unseen packet 7 should succeed: %v", err)
	}
	// Second time must fail
	if err := f.Validate(7); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected for second insertion of 7")
	}
}

func TestFilterWindowThreshold(t *testing.T) {
	f := NewFilter(30 * time.Second)

	// Establish sequence 10,000
	if err := f.Validate(10000); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Packet at 10000 - WindowSize + 1 should succeed
	validOld := uint64(10000 - WindowSize + 1)
	if err := f.Validate(validOld); err != nil {
		t.Fatalf("seq %d should be within window: %v", validOld, err)
	}

	// Duplicate of validOld must fail
	if err := f.Validate(validOld); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected replay detection for %d", validOld)
	}

	// Packet at 10000 - WindowSize or older must fail with ErrWindowOverflow
	tooOld := uint64(10000 - WindowSize)
	if err := f.Validate(tooOld); !errors.Is(err, ErrWindowOverflow) {
		t.Fatalf("expected ErrWindowOverflow for %d, got %v", tooOld, err)
	}
}

func TestFilterLargeJump(t *testing.T) {
	f := NewFilter(30 * time.Second)

	if err := f.Validate(100); err != nil {
		t.Fatal(err)
	}

	// Jump by 5000 (larger than WindowSize)
	if err := f.Validate(5100); err != nil {
		t.Fatalf("jump forward failed: %v", err)
	}

	// Old sequence 100 must now be rejected as overflow
	if err := f.Validate(100); !errors.Is(err, ErrWindowOverflow) {
		t.Fatalf("expected overflow for 100 after large jump, got: %v", err)
	}

	// 5100 duplicate must be rejected
	if err := f.Validate(5100); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected replay for 5100")
	}
}

func TestTimestampCheck(t *testing.T) {
	f := NewFilter(10 * time.Second)
	now := time.Now()

	// Current time: ok
	if err := f.CheckTimestamp(uint32(now.Unix()), now); err != nil {
		t.Fatalf("current time should pass: %v", err)
	}

	// 5 seconds in past: ok
	if err := f.CheckTimestamp(uint32(now.Add(-5*time.Second).Unix()), now); err != nil {
		t.Fatalf("5s in past should pass: %v", err)
	}

	// 5 seconds in future: ok (clock skew allowance)
	if err := f.CheckTimestamp(uint32(now.Add(5*time.Second).Unix()), now); err != nil {
		t.Fatalf("5s in future should pass: %v", err)
	}

	// 15 seconds in past: FAIL
	if err := f.CheckTimestamp(uint32(now.Add(-15*time.Second).Unix()), now); !errors.Is(err, ErrTimestampSkew) {
		t.Fatalf("expected ErrTimestampSkew for -15s, got: %v", err)
	}

	// 15 seconds in future: FAIL
	if err := f.CheckTimestamp(uint32(now.Add(15*time.Second).Unix()), now); !errors.Is(err, ErrTimestampSkew) {
		t.Fatalf("expected ErrTimestampSkew for +15s, got: %v", err)
	}
}
