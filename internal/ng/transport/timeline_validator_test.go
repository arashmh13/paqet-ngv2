package transport

import (
	"testing"
)

func TestTimelineValidator_ValidTimelineReconciles(t *testing.T) {
	tl := MonotonicEventTimeline{
		T0_PrimaryFailureInjectedMs:       0.0,
		T1_FailureThresholdCrossedMs:      35.0,
		T2_DegradedHysteresisEndedMs:      95.0,
		T3_DNSRequestStartedMs:            96.0,
		T4_DNSResponseReceivedMs:          350.0,
		T5_CandidateValidationStartedMs:   351.0,
		T6_CandidateValidationCompletedMs: 520.0,
		T7_RecoveryStateActivatedMs:       521.0,
		T8_FirstAppConnStartedMs:          522.0,
		T9_FirstAppResponseVerifiedMs:     610.0,
		T10_RollbackCompletedMs:           611.0,
		T11_PrimaryRestorationCompletedMs: 650.0,
	}

	intervals, err := ValidateAndReconcileTimeline(tl, 0.1)
	if err != nil {
		t.Fatalf("ValidateAndReconcileTimeline failed: %v", err)
	}

	if intervals.TotalFailoverDurationMs != 610.0 {
		t.Fatalf("Total failover duration mismatch: got %.2f, want 610.0", intervals.TotalFailoverDurationMs)
	}
	if intervals.DNSExchangeRTTMs != 254.0 {
		t.Fatalf("DNS exchange RTT mismatch: got %.2f, want 254.0", intervals.DNSExchangeRTTMs)
	}
	if intervals.CandidateValidationRTTMs != 169.0 {
		t.Fatalf("Candidate validation RTT mismatch: got %.2f, want 169.0", intervals.CandidateValidationRTTMs)
	}
	if intervals.UnaccountedOverheadMs > 0.001 {
		t.Fatalf("Unaccounted overhead must be ~0, got %.4f", intervals.UnaccountedOverheadMs)
	}
	t.Logf("PASS: Valid timeline reconciled all intervals with zero overhead")
}

func TestTimelineValidator_NonMonotonicRejected(t *testing.T) {
	tl := MonotonicEventTimeline{
		T0_PrimaryFailureInjectedMs:       0.0,
		T1_FailureThresholdCrossedMs:      35.0,
		T2_DegradedHysteresisEndedMs:      20.0, // Non-monotonic! T2 < T1
		T3_DNSRequestStartedMs:            96.0,
		T4_DNSResponseReceivedMs:          350.0,
		T5_CandidateValidationStartedMs:   351.0,
		T6_CandidateValidationCompletedMs: 520.0,
		T7_RecoveryStateActivatedMs:       521.0,
		T8_FirstAppConnStartedMs:          522.0,
		T9_FirstAppResponseVerifiedMs:     610.0,
		T10_RollbackCompletedMs:           611.0,
		T11_PrimaryRestorationCompletedMs: 650.0,
	}

	_, err := ValidateAndReconcileTimeline(tl, 0.1)
	if err == nil {
		t.Fatalf("Expected monotonicity error when T2 < T1, got nil")
	}
	t.Logf("PASS: Non-monotonic timeline correctly rejected: %v", err)
}
