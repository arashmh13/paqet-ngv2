package transport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrNoEligibleStrategy = errors.New("selector: no eligible transport strategy available")
)

// SelectorConfig configures the evidence-based strategy selector.
type SelectorConfig struct {
	Candidates          []Strategy
	PreferredMode       TransportMode
	HealthCheckInterval time.Duration
	CircuitFailureLimit int
	CircuitCooldown     time.Duration
	HysteresisRatio     float64               // Required performance margin to switch (e.g. 0.25 = 25%)
	RecoveryEngine      *RecoveryStateMachine // Optional integrated recovery state machine
}

// StrategySelector dynamically chooses and monitors the most resilient transport strategy.
type StrategySelector struct {
	cfg        SelectorConfig
	mu         sync.RWMutex
	current    Strategy
	lastSwitch time.Time
	cooldowns  map[string]time.Time
	stopChan   chan struct{}
	activeLog  []string

	lastFallbackReason string
	lastSuccessMode    TransportMode
}

func stratKey(s Strategy) string {
	return fmt.Sprintf("%p:%s", s, s.Mode())
}

func NewStrategySelector(cfg SelectorConfig) *StrategySelector {
	if cfg.HealthCheckInterval <= 0 {
		cfg.HealthCheckInterval = 30 * time.Second
	}
	if cfg.CircuitFailureLimit <= 0 {
		cfg.CircuitFailureLimit = 3
	}
	if cfg.CircuitCooldown <= 0 {
		cfg.CircuitCooldown = 45 * time.Second
	}
	if cfg.HysteresisRatio <= 0 {
		cfg.HysteresisRatio = 0.25
	}

	var initial Strategy
	for _, strat := range cfg.Candidates {
		if strat.Mode() == cfg.PreferredMode && strat.Capabilities().PrerequisitesMet {
			initial = strat
			break
		}
	}
	if initial == nil && len(cfg.Candidates) > 0 {
		for _, strat := range cfg.Candidates {
			if strat.Capabilities().PrerequisitesMet {
				initial = strat
				break
			}
		}
	}

	sel := &StrategySelector{
		cfg:        cfg,
		current:    initial,
		lastSwitch: time.Now(),
		cooldowns:  make(map[string]time.Time),
		stopChan:   make(chan struct{}),
	}

	return sel
}

func (s *StrategySelector) Current() Strategy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

func (s *StrategySelector) Mode() TransportMode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current != nil {
		return s.current.Mode()
	}
	return ModeAuto
}

// SetRecoveryEngine attaches or updates an integrated recovery controller.
func (s *StrategySelector) SetRecoveryEngine(re *RecoveryStateMachine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.RecoveryEngine = re
}

// RecoveryEngine returns the attached recovery controller.
func (s *StrategySelector) RecoveryEngine() *RecoveryStateMachine {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.RecoveryEngine
}

// Dial establishes a session using the best available strategy with automatic resilient fallback.
func (s *StrategySelector) Dial(ctx context.Context, addr string) (Session, error) {
	s.mu.RLock()
	re := s.cfg.RecoveryEngine
	s.mu.RUnlock()

	// 1. If recovery state machine is active and in RECOVERY_READY, use authorized recovery endpoint snapshot
	if re != nil && re.CurrentState() == StateRecoveryReady {
		snapshot := re.ActiveSnapshot()
		if snapshot != nil {
			now := time.Now()
			// Expiration check (P0 Requirement: ValidUntil <= now is expired)
			if snapshot.IsExpired(now) {
				re.ReportCandidateFailure(ErrStaleBootstrapData)
				s.mu.Lock()
				s.lastFallbackReason = fmt.Sprintf("recovery candidate %s expired at %d (now %d)", snapshot.Addr(), snapshot.ValidUntil, now.Unix())
				s.mu.Unlock()
				return nil, fmt.Errorf("recovery candidate %s expired: %w", snapshot.Addr(), ErrStaleBootstrapData)
			}

			// Generation/revision check (prevents superseded attempts from activating)
			if !snapshot.MatchesGeneration(re.CurrentGeneration()) {
				re.ReportCandidateFailure(ErrStaleRecoveryOperation)
				s.mu.Lock()
				s.lastFallbackReason = fmt.Sprintf("recovery candidate %s generation mismatch (got %d, current %d)",
					snapshot.Addr(), snapshot.Generation, re.CurrentGeneration())
				s.mu.Unlock()
				return nil, fmt.Errorf("recovery candidate generation mismatch: %w", ErrStaleRecoveryOperation)
			}

			// P0 REQUIREMENT: Select EXACTLY the transport mode authorized by the bootstrap.
			// Do not blindly try unrelated or weaker modes!
			s.mu.RLock()
			var authorizedStrat Strategy
			for _, strat := range s.cfg.Candidates {
				if strat.Mode() == snapshot.TransportMode {
					authorizedStrat = strat
					break
				}
			}
			s.mu.RUnlock()

			if authorizedStrat == nil {
				err := fmt.Errorf("authorized recovery transport mode %s is unavailable in selector candidates (fail-closed)", snapshot.TransportMode)
				re.ReportCandidateFailure(err)
				s.mu.Lock()
				s.lastFallbackReason = err.Error()
				s.mu.Unlock()
				return nil, err
			}

			if !authorizedStrat.Capabilities().PrerequisitesMet {
				err := fmt.Errorf("prerequisites not met for authorized recovery mode %s: %s (fail-closed)",
					snapshot.TransportMode, authorizedStrat.Capabilities().PrerequisiteNotice)
				re.ReportCandidateFailure(err)
				s.mu.Lock()
				s.lastFallbackReason = err.Error()
				s.mu.Unlock()
				return nil, err
			}

			// Dial the authorized recovery candidate endpoint
			sess, err := authorizedStrat.Dial(ctx, snapshot.Addr())
			if err != nil {
				re.ReportCandidateFailure(err)
				s.recordFailure(authorizedStrat, err)
				s.mu.Lock()
				s.lastFallbackReason = fmt.Sprintf("authorized recovery candidate %s (%s) dial failed: %v",
					snapshot.Addr(), snapshot.TransportMode, err)
				s.mu.Unlock()
				return nil, fmt.Errorf("recovery dial to %s (%s) failed: %w", snapshot.Addr(), snapshot.TransportMode, err)
			}

			// Recovery dial succeeded! Record telemetry without clearing recovery state
			s.mu.Lock()
			s.current = authorizedStrat
			s.lastSuccessMode = authorizedStrat.Mode()
			s.lastSwitch = time.Now()
			s.mu.Unlock()
			// Note: Do NOT call re.ReportPrimarySuccess() here, as this connection traversed the recovery path!
			return sess, nil
		}
	}

	s.mu.Lock()
	candidates := make([]Strategy, len(s.cfg.Candidates))
	copy(candidates, s.cfg.Candidates)
	cur := s.current
	s.mu.Unlock()

	// 2. Try current best strategy first
	if cur != nil && s.isEligible(cur) {
		sess, err := cur.Dial(ctx, addr)
		if err == nil {
			s.mu.Lock()
			s.lastSuccessMode = cur.Mode()
			s.mu.Unlock()
			if re != nil {
				re.ReportPrimarySuccess()
			}
			return sess, nil
		}
		s.recordFailure(cur, err)
		s.mu.Lock()
		s.lastFallbackReason = fmt.Sprintf("strategy %s dial failed: %v", cur.Mode(), err)
		s.mu.Unlock()
	}

	// 3. Fall back to other eligible strategies in order of resilience
	for _, strat := range candidates {
		if cur != nil && strat == cur {
			continue // Already tried this candidate
		}
		if !s.isEligible(strat) {
			continue
		}

		sess, err := strat.Dial(ctx, addr)
		if err == nil {
			s.mu.Lock()
			s.current = strat
			s.lastSwitch = time.Now()
			s.lastSuccessMode = strat.Mode()
			s.mu.Unlock()
			if re != nil {
				re.ReportPrimarySuccess()
			}
			return sess, nil
		}
		s.recordFailure(strat, err)
		s.mu.Lock()
		s.lastFallbackReason = fmt.Sprintf("fallback candidate %s dial failed: %v", strat.Mode(), err)
		s.mu.Unlock()
	}

	// All primary strategies failed! Report failure to recovery state machine
	if re != nil {
		re.ReportPrimaryFailure(ErrNoEligibleStrategy)
		// Trigger an evaluation step of the recovery lifecycle
		_, _ = re.Step(ctx)
	}

	return nil, ErrNoEligibleStrategy
}

// ResetCooldowns clears active circuit cooldowns across all candidate strategies.
func (s *StrategySelector) ResetCooldowns() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cooldowns = make(map[string]time.Time)
}

func (s *StrategySelector) isEligible(strat Strategy) bool {
	caps := strat.Capabilities()
	if !caps.PrerequisitesMet {
		return false
	}

	s.mu.RLock()
	cooldownUntil, hasCooldown := s.cooldowns[stratKey(strat)]
	s.mu.RUnlock()

	if hasCooldown && time.Now().Before(cooldownUntil) {
		return false
	}

	metrics := strat.Metrics()
	if metrics.CircuitState == "open" && hasCooldown && time.Now().Before(cooldownUntil) {
		return false
	}

	return true
}

func (s *StrategySelector) recordFailure(strat Strategy, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cooldowns[stratKey(strat)] = time.Now().Add(s.cfg.CircuitCooldown)
}

// StatusReport returns a comprehensive diagnostic report of all candidate modes.
func (s *StrategySelector) StatusReport() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	activeMode := "none"
	if s.current != nil {
		activeMode = string(s.current.Mode())
	}

	report := map[string]interface{}{
		"active_mode":          activeMode,
		"last_switch":          s.lastSwitch.Format(time.RFC3339),
		"last_fallback_reason": s.lastFallbackReason,
		"last_success_mode":    string(s.lastSuccessMode),
		"candidates":           make([]map[string]interface{}, 0, len(s.cfg.Candidates)),
	}

	for _, strat := range s.cfg.Candidates {
		metrics := strat.Metrics()
		caps := strat.Capabilities()
		cMap := map[string]interface{}{
			"mode":              string(strat.Mode()),
			"prerequisites_met": caps.PrerequisitesMet,
			"prerequisite_note": caps.PrerequisiteNotice,
			"available":         metrics.Available,
			"latency_ema_ms":    float64(metrics.LatencyEMA.Microseconds()) / 1000.0,
			"success_rate":      metrics.SuccessRate,
			"failure_streak":    metrics.FailureStreak,
			"circuit_state":     metrics.CircuitState,
			"last_error":        metrics.LastErrorReason,
		}
		report["candidates"] = append(report["candidates"].([]map[string]interface{}), cMap)
	}

	return report
}
