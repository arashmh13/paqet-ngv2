package dns

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
)

// BenchmarkTrial represents a single empirical query measurement record.
type BenchmarkTrial struct {
	Trial        int     `json:"trial"`
	Resolver     string  `json:"resolver"`
	PayloadBytes int     `json:"payload_bytes"`
	RTTMs        float64 `json:"rtt_ms"`
	Success      bool    `json:"success"`
	EchoVerified bool    `json:"echo_verified"`
	Retries      int     `json:"retries,omitempty"`
	QueriesSent  int     `json:"queries_sent,omitempty"`
}

// LatencyDistribution contains deterministic parametric and non-parametric dispersion metrics.
type LatencyDistribution struct {
	Count    int     `json:"count"`
	MinMs    float64 `json:"min_ms"`
	MedianMs float64 `json:"median_ms"`
	MeanMs   float64 `json:"mean_ms"`
	P95Ms    float64 `json:"p95_ms"`
	MaxMs    float64 `json:"max_ms"`
}

// GroupSummary aggregates reliability and latency distributions for a tested group.
type GroupSummary struct {
	TotalTrials         int                 `json:"total_trials"`
	SuccessCount        int                 `json:"success_count"`
	SuccessRatio        string              `json:"success_ratio"` // e.g. "12/15"
	SuccessRatePct      float64             `json:"success_rate_pct"`
	EchoVerifiedCount   int                 `json:"echo_verified_count"`
	EchoVerifiedRatio   string              `json:"echo_verified_ratio"` // e.g. "12/15"
	EchoVerifiedRatePct float64             `json:"echo_verified_rate_pct"`
	SuccessfulRTT       LatencyDistribution `json:"successful_rtt"`
	AllAttemptElapsed   LatencyDistribution `json:"all_attempt_elapsed"`
}

// ReconciledBenchmarkReport contains the verified summaries across resolvers and sizes.
type ReconciledBenchmarkReport struct {
	StatisticalMethod        string                           `json:"statistical_method"`
	SummaryByResolver        map[string]*GroupSummary         `json:"summary_by_resolver"`
	SummaryByResolverAndSize map[string]map[int]*GroupSummary `json:"summary_by_resolver_and_size"`
	Trials                   []BenchmarkTrial                 `json:"trials"`
}

// ComputePercentile calculates the p-th percentile (0.0 <= p <= 1.0) using
// Hyndman-Fan Type 7 continuous linear interpolation (standard in NIST, Python statistics, and NumPy).
func ComputePercentile(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0.0
	}
	if n == 1 || p <= 0.0 {
		return sorted[0]
	}
	if p >= 1.0 {
		return sorted[n-1]
	}

	r := p * float64(n-1)
	i := int(math.Floor(r))
	f := r - float64(i)

	if i >= n-1 {
		return sorted[n-1]
	}
	return sorted[i] + f*(sorted[i+1]-sorted[i])
}

// ComputeDistribution computes Min, Median, Mean, P95, and Max from a slice of measurements.
func ComputeDistribution(values []float64) LatencyDistribution {
	if len(values) == 0 {
		return LatencyDistribution{}
	}

	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)

	var sum float64
	for _, v := range sorted {
		sum += v
	}

	return LatencyDistribution{
		Count:    len(sorted),
		MinMs:    round2(sorted[0]),
		MedianMs: round2(ComputePercentile(sorted, 0.50)),
		MeanMs:   round2(sum / float64(len(sorted))),
		P95Ms:    round2(ComputePercentile(sorted, 0.95)),
		MaxMs:    round2(sorted[len(sorted)-1]),
	}
}

// AnalyzeTrials computes group statistics grouped by resolver and by (resolver, size).
func AnalyzeTrials(trials []BenchmarkTrial) *ReconciledBenchmarkReport {
	report := &ReconciledBenchmarkReport{
		StatisticalMethod:        "NIST/Hyndman-Fan Type 7 linear interpolation (rank r = p*(n-1))",
		SummaryByResolver:        make(map[string]*GroupSummary),
		SummaryByResolverAndSize: make(map[string]map[int]*GroupSummary),
		Trials:                   trials,
	}

	// 1. Group by resolver
	resolverGroups := make(map[string][]BenchmarkTrial)
	// 2. Group by resolver and size
	resSizeGroups := make(map[string]map[int][]BenchmarkTrial)

	for _, t := range trials {
		resolverGroups[t.Resolver] = append(resolverGroups[t.Resolver], t)
		if resSizeGroups[t.Resolver] == nil {
			resSizeGroups[t.Resolver] = make(map[int][]BenchmarkTrial)
		}
		resSizeGroups[t.Resolver][t.PayloadBytes] = append(resSizeGroups[t.Resolver][t.PayloadBytes], t)
	}

	for res, gTrials := range resolverGroups {
		report.SummaryByResolver[res] = summarizeGroup(gTrials)
	}

	for res, sizeMap := range resSizeGroups {
		report.SummaryByResolverAndSize[res] = make(map[int]*GroupSummary)
		for sz, gTrials := range sizeMap {
			report.SummaryByResolverAndSize[res][sz] = summarizeGroup(gTrials)
		}
	}

	return report
}

func summarizeGroup(trials []BenchmarkTrial) *GroupSummary {
	total := len(trials)
	if total == 0 {
		return &GroupSummary{}
	}

	var successfulRTTs []float64
	var allElapsed []float64
	successCount := 0
	echoCount := 0

	for _, t := range trials {
		allElapsed = append(allElapsed, t.RTTMs)
		if t.Success {
			successCount++
			successfulRTTs = append(successfulRTTs, t.RTTMs)
		}
		if t.EchoVerified {
			echoCount++
		}
	}

	return &GroupSummary{
		TotalTrials:         total,
		SuccessCount:        successCount,
		SuccessRatio:        fmt.Sprintf("%d/%d", successCount, total),
		SuccessRatePct:      round2((float64(successCount) / float64(total)) * 100.0),
		EchoVerifiedCount:   echoCount,
		EchoVerifiedRatio:   fmt.Sprintf("%d/%d", echoCount, total),
		EchoVerifiedRatePct: round2((float64(echoCount) / float64(total)) * 100.0),
		SuccessfulRTT:       ComputeDistribution(successfulRTTs),
		AllAttemptElapsed:   ComputeDistribution(allElapsed),
	}
}

// LoadAndReconcileBenchmarkFile reads a JSON benchmark file and produces a reconciled report.
func LoadAndReconcileBenchmarkFile(filePath string) (*ReconciledBenchmarkReport, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read benchmark file %s: %w", filePath, err)
	}

	var raw struct {
		Trials []BenchmarkTrial `json:"trials"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal trials from %s: %w", filePath, err)
	}

	if len(raw.Trials) == 0 {
		return nil, errors.New("no trials found in benchmark file")
	}

	return AnalyzeTrials(raw.Trials), nil
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
