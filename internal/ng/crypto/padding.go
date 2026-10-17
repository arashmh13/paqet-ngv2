package crypto

import (
	"crypto/rand"
	"encoding/binary"
)

// PaddingStrategy defines how payload padding lengths are chosen.
type PaddingStrategy string

const (
	// PaddingStrategyUniform selects a uniform random padding length between 0 and maxPad.
	PaddingStrategyUniform PaddingStrategy = "uniform"

	// PaddingStrategyBucketed aligns total frame length to discrete size boundaries
	// (64, 128, 256, 512, 1024, 1420 bytes) plus small random jitter.
	// NOTE: This operates strictly on inner payload length to reduce traffic analysis
	// correlation. It does NOT generate or mimic TLS record layer headers.
	PaddingStrategyBucketed PaddingStrategy = "bucketed"
)

// SamplePadding calculates the padding bytes to append to an application payload.
// It guarantees that:
//  1. 0 <= padLen <= maxPad
//  2. (plainLen + padLen) <= maxFrame
//
// Technical Note: This function operates strictly on payload framing inside the
// obfuscated datagram or stream chunk. It does NOT provide HTTPS protocol mimicry.
func SamplePadding(plainLen, maxPad, maxFrame int, strategy PaddingStrategy) int {
	if maxPad <= 0 || maxFrame <= plainLen {
		return 0
	}

	budget := maxFrame - plainLen
	if budget > maxPad {
		budget = maxPad
	}
	if budget <= 0 {
		return 0
	}

	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	randVal := int(binary.BigEndian.Uint16(b[:]))

	switch strategy {
	case PaddingStrategyBucketed:
		// Target discrete size boundaries to reduce size-correlation attack fidelity
		targetBuckets := []int{64, 128, 256, 512, 1024, 1420}
		for _, bucket := range targetBuckets {
			if bucket >= plainLen {
				needed := bucket - plainLen
				if needed <= budget {
					// Add small random jitter (0 to 15 bytes) to prevent exact static length matching
					jitter := (randVal % 16)
					if needed+jitter <= budget {
						return needed + jitter
					}
					return needed
				}
				break
			}
		}
		// For larger frames exceeding bucket steps, fallback to bounded random
		return randVal % (budget + 1)

	default: // Uniform random
		return randVal % (budget + 1)
	}
}
