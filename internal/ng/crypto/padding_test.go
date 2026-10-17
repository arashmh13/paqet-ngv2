package crypto

import (
	"testing"
)

func TestSamplePadding(t *testing.T) {
	maxFrame := 1460
	maxPad := 128

	// Test bounds across 100 trials
	for i := 0; i < 100; i++ {
		plainLen := 30 + (i * 10)
		if plainLen > 1400 {
			plainLen = 1400
		}

		padUniform := SamplePadding(plainLen, maxPad, maxFrame, PaddingStrategyUniform)
		if padUniform < 0 || padUniform > maxPad {
			t.Fatalf("Uniform padding out of bounds: %d (maxPad=%d)", padUniform, maxPad)
		}
		if plainLen+padUniform > maxFrame {
			t.Fatalf("Uniform total length exceeds maxFrame: %d > %d", plainLen+padUniform, maxFrame)
		}

		padBucketed := SamplePadding(plainLen, maxPad, maxFrame, PaddingStrategyBucketed)
		if padBucketed < 0 || padBucketed > maxPad {
			t.Fatalf("Bucketed padding out of bounds: %d (maxPad=%d)", padBucketed, maxPad)
		}
		if plainLen+padBucketed > maxFrame {
			t.Fatalf("Bucketed total length exceeds maxFrame: %d > %d", plainLen+padBucketed, maxFrame)
		}
	}
}

func TestSamplePaddingBucketAlignment(t *testing.T) {
	// A 50-byte plain payload with maxPad=32 should pad into the 64-byte bucket
	plainLen := 50
	maxPad := 32
	maxFrame := 1460

	pad := SamplePadding(plainLen, maxPad, maxFrame, PaddingStrategyBucketed)
	total := plainLen + pad
	if total < 64 {
		t.Errorf("Expected padded total >= 64, got %d", total)
	}
}
