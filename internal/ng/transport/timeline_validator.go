package transport

import (
	"fmt"
	"math"
)

// MonotonicEventTimeline captures monotonic timestamps for all critical recovery milestones.
type MonotonicEventTimeline struct {
	T0_PrimaryFailureInjectedMs       float64 `json:"t0_primary_failure_injected_ms"`
	T1_FailureThresholdCrossedMs      float64 `json:"t1_failure_threshold_crossed_ms"`
	T2_DegradedHysteresisEndedMs      float64 `json:"t2_degraded_hysteresis_ended_ms"`
	T3_DNSRequestStartedMs            float64 `json:"t3_dns_request_started_ms"`
	T4_DNSResponseReceivedMs          float64 `json:"t4_dns_response_received_ms"`
	T5_CandidateValidationStartedMs   float64 `json:"t5_candidate_validation_started_ms"`
	T6_CandidateValidationCompletedMs float64 `json:"t6_candidate_validation_completed_ms"`
	T7_RecoveryStateActivatedMs       float64 `json:"t7_recovery_state_activated_ms"`
	T8_FirstAppConnStartedMs          float64 `json:"t8_first_app_conn_started_ms"`
	T9_FirstAppResponseVerifiedMs     float64 `json:"t9_first_app_response_verified_ms"`
	T10_RollbackCompletedMs           float64 `json:"t10_rollback_completed_ms"`
	T11_PrimaryRestorationCompletedMs float64 `json:"t11_primary_restoration_completed_ms"`
}

// ReconciledIntervals represents computed interval durations with explicit accounting.
type ReconciledIntervals struct {
	DetectionDurationMs          float64 `json:"detection_duration_ms"`           // T1 - T0
	DegradedHysteresisDurationMs float64 `json:"degraded_hysteresis_duration_ms"` // T2 - T1
	SignalingDispatchDelayMs     float64 `json:"signaling_dispatch_delay_ms"`     // T3 - T2
	DNSExchangeRTTMs             float64 `json:"dns_exchange_rtt_ms"`             // T4 - T3
	ValidationDispatchDelayMs    float64 `json:"validation_dispatch_delay_ms"`    // T5 - T4
	CandidateValidationRTTMs     float64 `json:"candidate_validation_rtt_ms"`     // T6 - T5
	StateActivationDelayMs       float64 `json:"state_activation_delay_ms"`       // T7 - T6
	AppConnDispatchDelayMs       float64 `json:"app_conn_dispatch_delay_ms"`      // T8 - T7
	PostActivationAppRTTMs       float64 `json:"post_activation_app_rtt_ms"`      // T9 - T8
	TotalFailoverDurationMs      float64 `json:"total_failover_duration_ms"`      // T9 - T0
	RollbackDurationMs           float64 `json:"rollback_duration_ms"`            // T10 - T9
	RestorationDurationMs        float64 `json:"restoration_duration_ms"`         // T11 - T10
	UnaccountedOverheadMs        float64 `json:"unaccounted_overhead_ms"`         // Discrepancy between component sum and total
}

// ValidateAndReconcileTimeline recomputes all intervals from event timestamps and verifies monotonicity and reconciliation.
func ValidateAndReconcileTimeline(tl MonotonicEventTimeline, toleranceMs float64) (ReconciledIntervals, error) {
	if toleranceMs <= 0 {
		toleranceMs = 0.5 // Default 0.5ms tolerance
	}

	events := []struct {
		name string
		val  float64
	}{
		{"T0_PrimaryFailureInjected", tl.T0_PrimaryFailureInjectedMs},
		{"T1_FailureThresholdCrossed", tl.T1_FailureThresholdCrossedMs},
		{"T2_DegradedHysteresisEnded", tl.T2_DegradedHysteresisEndedMs},
		{"T3_DNSRequestStarted", tl.T3_DNSRequestStartedMs},
		{"T4_DNSResponseReceived", tl.T4_DNSResponseReceivedMs},
		{"T5_CandidateValidationStarted", tl.T5_CandidateValidationStartedMs},
		{"T6_CandidateValidationCompleted", tl.T6_CandidateValidationCompletedMs},
		{"T7_RecoveryStateActivated", tl.T7_RecoveryStateActivatedMs},
		{"T8_FirstAppConnStarted", tl.T8_FirstAppConnStartedMs},
		{"T9_FirstAppResponseVerified", tl.T9_FirstAppResponseVerifiedMs},
		{"T10_RollbackCompleted", tl.T10_RollbackCompletedMs},
		{"T11_PrimaryRestorationCompleted", tl.T11_PrimaryRestorationCompletedMs},
	}

	// 1. Monotonicity check
	for i := 0; i < len(events)-1; i++ {
		if events[i+1].val < events[i].val {
			return ReconciledIntervals{}, fmt.Errorf("timeline monotonicity violation: %s (%.3f ms) > %s (%.3f ms)",
				events[i].name, events[i].val, events[i+1].name, events[i+1].val)
		}
	}

	intervals := ReconciledIntervals{
		DetectionDurationMs:          tl.T1_FailureThresholdCrossedMs - tl.T0_PrimaryFailureInjectedMs,
		DegradedHysteresisDurationMs: tl.T2_DegradedHysteresisEndedMs - tl.T1_FailureThresholdCrossedMs,
		SignalingDispatchDelayMs:     tl.T3_DNSRequestStartedMs - tl.T2_DegradedHysteresisEndedMs,
		DNSExchangeRTTMs:             tl.T4_DNSResponseReceivedMs - tl.T3_DNSRequestStartedMs,
		ValidationDispatchDelayMs:    tl.T5_CandidateValidationStartedMs - tl.T4_DNSResponseReceivedMs,
		CandidateValidationRTTMs:     tl.T6_CandidateValidationCompletedMs - tl.T5_CandidateValidationStartedMs,
		StateActivationDelayMs:       tl.T7_RecoveryStateActivatedMs - tl.T6_CandidateValidationCompletedMs,
		AppConnDispatchDelayMs:       tl.T8_FirstAppConnStartedMs - tl.T7_RecoveryStateActivatedMs,
		PostActivationAppRTTMs:       tl.T9_FirstAppResponseVerifiedMs - tl.T8_FirstAppConnStartedMs,
		TotalFailoverDurationMs:      tl.T9_FirstAppResponseVerifiedMs - tl.T0_PrimaryFailureInjectedMs,
		RollbackDurationMs:           tl.T10_RollbackCompletedMs - tl.T9_FirstAppResponseVerifiedMs,
		RestorationDurationMs:        tl.T11_PrimaryRestorationCompletedMs - tl.T10_RollbackCompletedMs,
	}

	// 2. Exact component sum reconciliation
	componentSum := intervals.DetectionDurationMs +
		intervals.DegradedHysteresisDurationMs +
		intervals.SignalingDispatchDelayMs +
		intervals.DNSExchangeRTTMs +
		intervals.ValidationDispatchDelayMs +
		intervals.CandidateValidationRTTMs +
		intervals.StateActivationDelayMs +
		intervals.AppConnDispatchDelayMs +
		intervals.PostActivationAppRTTMs

	discrepancy := math.Abs(componentSum - intervals.TotalFailoverDurationMs)
	intervals.UnaccountedOverheadMs = discrepancy
	if discrepancy > toleranceMs {
		return intervals, fmt.Errorf("timeline reconciliation failed: component sum (%.3f ms) != total (%.3f ms), discrepancy=%.3f ms exceeds tolerance %.3f ms",
			componentSum, intervals.TotalFailoverDurationMs, discrepancy, toleranceMs)
	}

	return intervals, nil
}
