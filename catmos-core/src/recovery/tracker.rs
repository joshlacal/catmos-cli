//! `RecoveryTracker` and `GroupInfo404Tracker` — process-wide bookkeeping for
//! External Commit rejoin attempts.
//!
//! Mirrors `catbird-mls/src/orchestrator/recovery.rs`'s `RecoveryTracker` and
//! `GroupInfo404Tracker` so that catmos-cli (which uses `MLSContext` directly,
//! not `MLSOrchestrator`) enforces the same invariants:
//!
//! - Process-wide minimum interval between any two rejoin attempts
//!   (`MIN_REJOIN_INTERVAL`, spec §10), enforced across ALL conversations to
//!   bound epoch inflation when several conversations need recovery at once.
//! - Per-conversation backoff from `REJOIN_BACKOFF`, indexed by attempt count.
//! - Per-conversation max-attempts cap (`MAX_REJOIN_ATTEMPTS`); exceeding it
//!   is the trigger for transitioning to `UNRECOVERABLE_LOCAL` (§8.2 / §8.6).
//! - Per-conversation 404 circuit breaker on GroupInfo fetches
//!   (`GROUPINFO_404_CIRCUIT_BREAKER`, spec §8.3).
//! - Per-conversation success cooldown (`SUCCESSFUL_REJOIN_COOLDOWN`) that
//!   suppresses sync-triggered rejoins after a successful one — prevents
//!   spirals where merge-persistence bugs replay rejoins indefinitely.
//!
//! Trackers are **in-memory only**. App restart = natural cooldown.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::constants;

/// Tracks per-conversation rejoin attempt state plus the global "last attempt"
/// floor that gates ALL conversations.
pub struct RecoveryTracker {
    /// Per-conversation (failed_attempt_count, last_attempt_instant).
    failed_rejoins: HashMap<String, (u32, Instant)>,
    /// Per-conversation last successful rejoin time. Used to suppress
    /// sync-triggered rejoins for `SUCCESSFUL_REJOIN_COOLDOWN`.
    successful_rejoins: HashMap<String, Instant>,
    /// Last attempt across ANY conversation (success or failure). Drives the
    /// `MIN_REJOIN_INTERVAL` global floor.
    last_global_rejoin_at: Option<Instant>,
}

impl Default for RecoveryTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RecoveryTracker {
    pub fn new() -> Self {
        Self {
            failed_rejoins: HashMap::new(),
            successful_rejoins: HashMap::new(),
            last_global_rejoin_at: None,
        }
    }

    /// Backoff duration for the given (1-based) attempt count. Attempts beyond
    /// the table use the last entry.
    pub fn cooldown_for_attempts(&self, attempts: u32) -> Duration {
        if attempts == 0 {
            return Duration::ZERO;
        }
        let idx = (attempts as usize).saturating_sub(1);
        constants::REJOIN_BACKOFF
            .get(idx)
            .copied()
            .unwrap_or_else(|| {
                *constants::REJOIN_BACKOFF
                    .last()
                    .expect("REJOIN_BACKOFF is non-empty")
            })
    }

    /// Whether the conversation has hit `MAX_REJOIN_ATTEMPTS`.
    pub fn is_maxed_out(&self, convo_id: &str) -> bool {
        self.failed_rejoins
            .get(convo_id)
            .is_some_and(|(n, _)| *n >= constants::MAX_REJOIN_ATTEMPTS)
    }

    /// Per-attempt-count cooldown remaining for this conversation, or `None`
    /// if no failure recorded / cap exceeded / cooldown elapsed.
    pub fn cooldown_remaining(&self, convo_id: &str) -> Option<Duration> {
        let (attempts, last_attempt) = self.failed_rejoins.get(convo_id)?;
        if *attempts == 0 || *attempts >= constants::MAX_REJOIN_ATTEMPTS {
            return None;
        }
        let cooldown = self.cooldown_for_attempts(*attempts);
        let elapsed = last_attempt.elapsed();
        if elapsed >= cooldown {
            None
        } else {
            Some(cooldown - elapsed)
        }
    }

    /// Global `MIN_REJOIN_INTERVAL` remaining since the last attempt anywhere.
    pub fn global_interval_remaining(&self) -> Option<Duration> {
        let last = self.last_global_rejoin_at?;
        let elapsed = last.elapsed();
        if elapsed >= constants::MIN_REJOIN_INTERVAL {
            None
        } else {
            Some(constants::MIN_REJOIN_INTERVAL - elapsed)
        }
    }

    /// Composite gate: returns `true` when a rejoin attempt should be skipped
    /// because of max-attempts, per-convo cooldown, or the global floor.
    pub fn should_skip(&self, convo_id: &str) -> bool {
        self.is_maxed_out(convo_id)
            || self.cooldown_remaining(convo_id).is_some()
            || self.global_interval_remaining().is_some()
    }

    /// Per-conversation success cooldown (sync-triggered-rejoin spiral guard).
    pub fn success_cooldown_remaining(&self, convo_id: &str) -> Option<Duration> {
        let last = self.successful_rejoins.get(convo_id)?;
        let elapsed = last.elapsed();
        if elapsed >= constants::SUCCESSFUL_REJOIN_COOLDOWN {
            None
        } else {
            Some(constants::SUCCESSFUL_REJOIN_COOLDOWN - elapsed)
        }
    }

    /// Current attempt count for `convo_id` (0 if no failures recorded).
    pub fn attempts(&self, convo_id: &str) -> u32 {
        self.failed_rejoins
            .get(convo_id)
            .map(|(n, _)| *n)
            .unwrap_or(0)
    }

    /// Record a failed attempt and bump the global floor.
    pub fn record_failure(&mut self, convo_id: &str) {
        let now = Instant::now();
        let entry = self
            .failed_rejoins
            .entry(convo_id.to_string())
            .or_insert((0, now));
        entry.0 += 1;
        entry.1 = now;
        self.last_global_rejoin_at = Some(now);
    }

    /// Record a successful rejoin: clear failure count, set the success
    /// cooldown for this conversation, bump the global floor (so the
    /// MIN_REJOIN_INTERVAL applies even after success).
    pub fn record_success(&mut self, convo_id: &str) {
        let now = Instant::now();
        self.failed_rejoins.remove(convo_id);
        self.successful_rejoins.insert(convo_id.to_string(), now);
        self.last_global_rejoin_at = Some(now);
    }

    /// Clear all per-conversation state for `convo_id`. Used on RESET_PENDING
    /// adoption — the server reset is a fresh start, not a continuation of
    /// the local retry loop. Does NOT clear the global floor.
    pub fn clear_convo(&mut self, convo_id: &str) {
        self.failed_rejoins.remove(convo_id);
        self.successful_rejoins.remove(convo_id);
    }
}

/// Tracks consecutive GroupInfo 404 responses per conversation. After
/// `GROUPINFO_404_CIRCUIT_BREAKER` consecutive 404s, External Commit attempts
/// against that conversation are skipped (spec §8.3).
pub struct GroupInfo404Tracker {
    counts: HashMap<String, u32>,
}

impl Default for GroupInfo404Tracker {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupInfo404Tracker {
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    pub fn record_404(&mut self, convo_id: &str) {
        *self.counts.entry(convo_id.to_string()).or_insert(0) += 1;
    }

    pub fn is_tripped(&self, convo_id: &str) -> bool {
        self.counts
            .get(convo_id)
            .is_some_and(|c| *c >= constants::GROUPINFO_404_CIRCUIT_BREAKER)
    }

    pub fn clear(&mut self, convo_id: &str) {
        self.counts.remove(convo_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_failure_increments_attempts_and_bumps_global() {
        let mut t = RecoveryTracker::new();
        assert_eq!(t.attempts("c"), 0);
        t.record_failure("c");
        assert_eq!(t.attempts("c"), 1);
        assert!(t.last_global_rejoin_at.is_some());
    }

    #[test]
    fn maxed_out_after_max_attempts() {
        let mut t = RecoveryTracker::new();
        for _ in 0..constants::MAX_REJOIN_ATTEMPTS {
            t.record_failure("c");
        }
        assert!(t.is_maxed_out("c"));
    }

    #[test]
    fn record_success_clears_failures_and_sets_cooldown() {
        let mut t = RecoveryTracker::new();
        t.record_failure("c");
        t.record_success("c");
        assert_eq!(t.attempts("c"), 0);
        assert!(t.success_cooldown_remaining("c").is_some());
    }

    #[test]
    fn global_interval_blocks_other_convos_after_attempt() {
        let mut t = RecoveryTracker::new();
        t.record_failure("a");
        // "b" has no per-convo failures, but the global floor still applies.
        assert!(t.global_interval_remaining().is_some());
        assert!(t.should_skip("b"));
    }

    #[test]
    fn circuit_breaker_trips_at_threshold() {
        let mut t = GroupInfo404Tracker::new();
        for _ in 0..constants::GROUPINFO_404_CIRCUIT_BREAKER {
            t.record_404("c");
        }
        assert!(t.is_tripped("c"));
        t.clear("c");
        assert!(!t.is_tripped("c"));
    }
}
