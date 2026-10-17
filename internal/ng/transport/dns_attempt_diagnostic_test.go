package transport

import (
	"testing"
)

func TestDNSQueryAttemptRecord_Validation(t *testing.T) {
	// Case 1: Valid SUCCESS record
	validRec := DNSQueryAttemptRecord{
		AttemptIndex:      0,
		ResolverAddr:      "8.8.8.8:53",
		Protocol:          "udp",
		TxID:              1234,
		SentAtMonotonicMs: 10.0,
		RcvdAtMonotonicMs: 150.0,
		DurationMs:        140.0,
		RCode:             0,
		Truncated:         false,
		Authenticated:     true,
		ServerID:          "ns-de-01",
		Status:            DNSAttemptStatusSuccess,
		Error:             "", // must be empty
	}
	if err := validRec.Validate(); err != nil {
		t.Fatalf("Valid attempt record failed validation: %v", err)
	}

	// Case 2: Contradictory SUCCESS record with non-empty error (Phase 16 anomaly)
	badSuccessRec := validRec
	badSuccessRec.Error = "invalid txt response format"
	if err := badSuccessRec.Validate(); err == nil {
		t.Fatalf("Expected validation error for SUCCESS attempt with non-empty error, got nil")
	}

	// Case 3: SUCCESS record missing authentication
	unauthSuccessRec := validRec
	unauthSuccessRec.Authenticated = false
	if err := unauthSuccessRec.Validate(); err == nil {
		t.Fatalf("Expected validation error for unauthenticated SUCCESS attempt, got nil")
	}

	// Case 4: SUCCESS record missing ServerID
	noServerSuccessRec := validRec
	noServerSuccessRec.ServerID = ""
	if err := noServerSuccessRec.Validate(); err == nil {
		t.Fatalf("Expected validation error for SUCCESS attempt missing ServerID, got nil")
	}

	// Case 5: Negative duration
	negDurationRec := validRec
	negDurationRec.DurationMs = -5.0
	if err := negDurationRec.Validate(); err == nil {
		t.Fatalf("Expected validation error for negative duration, got nil")
	}

	// Case 6: Non-monotonic timing (rcvd < sent)
	nonMonotonicRec := validRec
	nonMonotonicRec.SentAtMonotonicMs = 150.0
	nonMonotonicRec.RcvdAtMonotonicMs = 100.0
	if err := nonMonotonicRec.Validate(); err == nil {
		t.Fatalf("Expected validation error for non-monotonic timing, got nil")
	}

	// Case 7: Valid TIMEOUT record
	validTimeoutRec := DNSQueryAttemptRecord{
		AttemptIndex:      0,
		ResolverAddr:      "1.1.1.1:53",
		Protocol:          "udp",
		TxID:              5678,
		SentAtMonotonicMs: 0.0,
		RcvdAtMonotonicMs: 1500.0,
		DurationMs:        1500.0,
		Status:            DNSAttemptStatusTimeout,
		Error:             "timeout waiting for valid response",
	}
	if err := validTimeoutRec.Validate(); err != nil {
		t.Fatalf("Valid TIMEOUT record failed validation: %v", err)
	}
}

func TestDNSExchangeTimeline_ReconcileSuite(t *testing.T) {
	// 1. Single attempt success: Attempts(120ms) + Gaps(0ms) == Total(120ms)
	tl1 := DNSExchangeTimeline{
		StartMonotonicMs: 0.0,
		EndMonotonicMs:   120.0,
		TotalDurationMs:  120.0,
		Attempts: []DNSQueryAttemptRecord{
			{
				AttemptIndex:      0,
				ResolverAddr:      "8.8.8.8:53",
				Protocol:          "udp",
				TxID:              1001,
				SentAtMonotonicMs: 0.0,
				RcvdAtMonotonicMs: 120.0,
				DurationMs:        120.0,
				Authenticated:     true,
				ServerID:          "srv-de-01",
				Status:            DNSAttemptStatusSuccess,
			},
		},
		Gaps: []DNSInterAttemptGap{},
	}
	if err := tl1.Reconcile(1.0); err != nil {
		t.Fatalf("Single attempt timeline failed reconciliation: %v", err)
	}
	if tl1.UnaccountedMs != 0.0 {
		t.Fatalf("Expected 0.0 unaccounted, got %f", tl1.UnaccountedMs)
	}

	// 2. Multi-attempt failover: Attempt 0 (1500ms timeout) + Gap (75ms backoff) + Attempt 1 (140ms success) == Total (1715ms)
	tl2 := DNSExchangeTimeline{
		StartMonotonicMs: 0.0,
		EndMonotonicMs:   1715.0,
		TotalDurationMs:  1715.0,
		Attempts: []DNSQueryAttemptRecord{
			{
				AttemptIndex:      0,
				ResolverAddr:      "8.8.8.8:53",
				Protocol:          "udp",
				TxID:              2001,
				SentAtMonotonicMs: 0.0,
				RcvdAtMonotonicMs: 1500.0,
				DurationMs:        1500.0,
				Status:            DNSAttemptStatusTimeout,
				Error:             "timeout waiting for valid response",
			},
			{
				AttemptIndex:      1,
				ResolverAddr:      "1.1.1.1:53",
				Protocol:          "udp",
				TxID:              2002,
				SentAtMonotonicMs: 1575.0,
				RcvdAtMonotonicMs: 1715.0,
				DurationMs:        140.0,
				Authenticated:     true,
				ServerID:          "srv-nl-01",
				Status:            DNSAttemptStatusSuccess,
			},
		},
		Gaps: []DNSInterAttemptGap{
			{
				FromAttemptIndex: 0,
				ToAttemptIndex:   1,
				StartMonotonicMs: 1500.0,
				EndMonotonicMs:   1575.0,
				DurationMs:       75.0,
				Reason:           "retry_backoff_and_resolver_failover",
			},
		},
	}
	if err := tl2.Reconcile(1.0); err != nil {
		t.Fatalf("Multi-attempt timeline failed reconciliation: %v", err)
	}
	if tl2.UnaccountedMs != 0.0 {
		t.Fatalf("Expected 0.0 unaccounted, got %f", tl2.UnaccountedMs)
	}

	// 3. Unaccounted overhead exceeding tolerance (e.g., 50ms unaccounted gap not tracked)
	tlBad := tl2
	tlBad.TotalDurationMs = 1800.0 // 85ms unaccounted
	if err := tlBad.Reconcile(2.0); err == nil {
		t.Fatalf("Expected reconciliation error for 85ms unaccounted overhead, got nil")
	}

	// 4. Negative duration gap fails
	tlNegGap := tl2
	tlNegGap.Gaps = []DNSInterAttemptGap{
		{
			FromAttemptIndex: 0,
			ToAttemptIndex:   1,
			StartMonotonicMs: 1500.0,
			EndMonotonicMs:   1450.0,
			DurationMs:       -50.0,
			Reason:           "invalid_negative",
		},
	}
	if err := tlNegGap.Reconcile(2.0); err == nil {
		t.Fatalf("Expected reconciliation error for negative gap, got nil")
	}
}
