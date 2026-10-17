package dns

import (
	"math"
	"path/filepath"
	"testing"
)

func TestComputePercentileEdgeCases(t *testing.T) {
	// 1. Empty slice
	if p := ComputePercentile(nil, 0.95); p != 0.0 {
		t.Fatalf("Expected 0.0 for nil slice, got %f", p)
	}
	if p := ComputePercentile([]float64{}, 0.50); p != 0.0 {
		t.Fatalf("Expected 0.0 for empty slice, got %f", p)
	}

	// 2. Single element
	single := []float64{142.5}
	if p := ComputePercentile(single, 0.95); p != 142.5 {
		t.Fatalf("Expected 142.5 for single element, got %f", p)
	}
	if p := ComputePercentile(single, 0.0); p != 142.5 {
		t.Fatalf("Expected 142.5 for p=0, got %f", p)
	}
	if p := ComputePercentile(single, 1.0); p != 142.5 {
		t.Fatalf("Expected 142.5 for p=1, got %f", p)
	}

	// 3. Two elements: [100.0, 200.0]
	two := []float64{100.0, 200.0}
	if p := ComputePercentile(two, 0.50); p != 150.0 {
		t.Fatalf("Expected 150.0 for median of 2 elements, got %f", p)
	}
	if p := ComputePercentile(two, 0.95); math.Abs(p-195.0) > 1e-6 {
		t.Fatalf("Expected 195.0 for p=0.95 of [100, 200], got %f", p)
	}

	// 4. Exactly 12 elements modeling Quad9's successful trials
	// Sorted: 126.84, 133.54, 140.10, 140.38, 140.84, 143.66, 147.70, 153.95, 154.14, 160.82, 196.34, 2558.48
	quad9Sample := []float64{
		126.84, 133.54, 140.10, 140.38, 140.84, 143.66,
		147.70, 153.95, 154.14, 160.82, 196.34, 2558.48,
	}

	// Median (p=0.50): rank r = 0.5 * 11 = 5.5 -> (143.66 + 147.70)/2 = 145.68
	med := ComputePercentile(quad9Sample, 0.50)
	if math.Abs(med-145.68) > 0.01 {
		t.Fatalf("Expected median 145.68, got %f", med)
	}

	// P95 (p=0.95): rank r = 0.95 * 11 = 10.45 -> x[10] + 0.45 * (x[11] - x[10])
	// 196.34 + 0.45 * (2558.48 - 196.34) = 196.34 + 1062.963 = 1259.30
	p95 := ComputePercentile(quad9Sample, 0.95)
	if math.Abs(p95-1259.30) > 0.05 {
		t.Fatalf("Expected P95 ~1259.30 ms, got %f", p95)
	}
}

func TestAnalyzeTrialsSyntheticGroups(t *testing.T) {
	trials := []BenchmarkTrial{
		// Resolver A (all successful)
		{Trial: 1, Resolver: "8.8.8.8:53", PayloadBytes: 16, RTTMs: 100.0, Success: true, EchoVerified: true},
		{Trial: 2, Resolver: "8.8.8.8:53", PayloadBytes: 16, RTTMs: 120.0, Success: true, EchoVerified: true},
		{Trial: 3, Resolver: "8.8.8.8:53", PayloadBytes: 64, RTTMs: 150.0, Success: true, EchoVerified: true},

		// Resolver B (mixed with timeout failure)
		{Trial: 4, Resolver: "1.1.1.1:53", PayloadBytes: 16, RTTMs: 110.0, Success: true, EchoVerified: true},
		{Trial: 5, Resolver: "1.1.1.1:53", PayloadBytes: 64, RTTMs: 4000.0, Success: false, EchoVerified: false},

		// Resolver C (all failed)
		{Trial: 6, Resolver: "0.0.0.0:53", PayloadBytes: 16, RTTMs: 5000.0, Success: false, EchoVerified: false},
	}

	report := AnalyzeTrials(trials)

	// Verify Resolver A
	resA := report.SummaryByResolver["8.8.8.8:53"]
	if resA == nil || resA.TotalTrials != 3 || resA.SuccessCount != 3 || resA.SuccessRatio != "3/3" {
		t.Fatalf("Unexpected summary for Resolver A: %+v", resA)
	}
	if resA.SuccessfulRTT.MinMs != 100.0 || resA.SuccessfulRTT.MaxMs != 150.0 {
		t.Fatalf("Unexpected latency for Resolver A: %+v", resA.SuccessfulRTT)
	}

	// Verify Resolver B
	resB := report.SummaryByResolver["1.1.1.1:53"]
	if resB == nil || resB.TotalTrials != 2 || resB.SuccessCount != 1 || resB.SuccessRatio != "1/2" {
		t.Fatalf("Unexpected summary for Resolver B: %+v", resB)
	}
	if resB.SuccessfulRTT.Count != 1 || resB.SuccessfulRTT.MedianMs != 110.0 {
		t.Fatalf("Successful RTT must reflect only successful trials: %+v", resB.SuccessfulRTT)
	}
	if resB.AllAttemptElapsed.Count != 2 || resB.AllAttemptElapsed.MaxMs != 4000.0 {
		t.Fatalf("AllAttemptElapsed must include failed timeout: %+v", resB.AllAttemptElapsed)
	}

	// Verify Resolver C (all failed)
	resC := report.SummaryByResolver["0.0.0.0:53"]
	if resC == nil || resC.SuccessCount != 0 || resC.SuccessRatePct != 0.0 {
		t.Fatalf("Unexpected summary for Resolver C: %+v", resC)
	}
	if resC.SuccessfulRTT.Count != 0 {
		t.Fatalf("SuccessfulRTT count must be 0 for all-failed group: %+v", resC.SuccessfulRTT)
	}
	if resC.AllAttemptElapsed.Count != 1 || resC.AllAttemptElapsed.MinMs != 5000.0 {
		t.Fatalf("AllAttemptElapsed must reflect the 5000ms timeout: %+v", resC.AllAttemptElapsed)
	}
}

func TestReconcileRealBenchmarkFile(t *testing.T) {
	repoDir := filepath.Join("..", "..", "..")
	jsonPath := filepath.Join(repoDir, "docs", "research", "emergency_dns_hardened_soak_stats.json")

	report, err := LoadAndReconcileBenchmarkFile(jsonPath)
	if err != nil {
		t.Skipf("Benchmark file not available in relative path %s: %v", jsonPath, err)
		return
	}

	if len(report.Trials) != 45 {
		t.Fatalf("Expected 45 trials in real benchmark file, got %d", len(report.Trials))
	}

	// Check Quad9
	q9 := report.SummaryByResolver["9.9.9.9:53"]
	if q9 == nil {
		t.Fatalf("Quad9 summary missing")
	}
	if q9.SuccessCount != 12 || q9.TotalTrials != 15 {
		t.Fatalf("Expected 12/15 for Quad9, got %d/%d", q9.SuccessCount, q9.TotalTrials)
	}
	if q9.SuccessfulRTT.P95Ms < 1000.0 {
		t.Fatalf("Mathematically reconciled P95 must be ~1259ms, got %f", q9.SuccessfulRTT.P95Ms)
	}
}
