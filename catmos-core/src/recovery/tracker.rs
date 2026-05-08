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

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use super::constants;
use super::state::QuarantineReason;

// ── Quarantine accounting (Layer 3, mirrors catbird-mls f363fd1) ──────
//
// catbird-mls/src/orchestrator/recovery.rs §3.2:
//   trigger conditions —
//     C1: one peer DID accumulates ≥3 peer-bad failures (any window)
//     C2: ≥2 distinct peer DIDs produce peer-bad failures within 60s
//     C3: ≥3 distinct message IDs fail framing within 120s (Signal D)
//
// Constants are local (not in `super::constants`) because they are
// quarantine-specific and not part of the spec §10 surface. They match the
// values in the orchestrator's recovery.rs exactly.
const QUARANTINE_PEER_BAD_THRESHOLD: u32 = 3;
const QUARANTINE_MULTI_PEER_WINDOW: Duration = Duration::from_secs(60);
const QUARANTINE_FRAMING_WINDOW: Duration = Duration::from_secs(120);

/// Outcome of feeding a peer-bad observation into the tracker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineDecision {
    /// No threshold tripped; carry on.
    Stay,
    /// Threshold tripped; caller should mark this convo quarantined with
    /// the supplied reason + suspected DID list (clone-and-passed for
    /// callers that need to persist + emit the event).
    Quarantine {
        reason: QuarantineReason,
        suspected_dids: Vec<String>,
    },
}

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
    /// Per-conversation, per-DID peer-bad failure counts (C1/C2 trigger).
    /// `(count, first_seen_instant)` — first_seen is used for the 60s window.
    peer_bad_by_sender: HashMap<String, HashMap<String, (u32, Instant)>>,
    /// Per-conversation rolling buffer of recent peer-bad message IDs (C3).
    /// Bounded length so we never grow unbounded under sustained load.
    peer_bad_messages: HashMap<String, VecDeque<(String, Instant)>>,
    /// Per-conversation in-memory quarantine flag mirroring the persisted
    /// state. Used by `is_quarantined` so `should_skip` can short-circuit
    /// without a DB hit.
    quarantined: HashMap<String, ()>,
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
            peer_bad_by_sender: HashMap::new(),
            peer_bad_messages: HashMap::new(),
            quarantined: HashMap::new(),
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
    /// because of max-attempts, per-convo cooldown, the global floor, OR an
    /// active quarantine. Quarantined conversations never auto-EC — that's
    /// the whole point of Layer 3.
    pub fn should_skip(&self, convo_id: &str) -> bool {
        self.is_quarantined(convo_id)
            || self.is_maxed_out(convo_id)
            || self.cooldown_remaining(convo_id).is_some()
            || self.global_interval_remaining().is_some()
    }

    /// Whether `convo_id` has been quarantined in this process.
    pub fn is_quarantined(&self, convo_id: &str) -> bool {
        self.quarantined.contains_key(convo_id)
    }

    /// Mark `convo_id` quarantined in-memory. Counters that are no longer
    /// actionable (we won't auto-rejoin a quarantined convo) are cleared.
    /// The caller is responsible for DB persistence + event emission.
    pub fn mark_quarantined(&mut self, convo_id: &str) {
        self.quarantined.insert(convo_id.to_string(), ());
        self.failed_rejoins.remove(convo_id);
        // peer-bad counters are kept for diagnostics; a manual reset clears
        // them via `clear_quarantine`.
    }

    /// Clear in-memory quarantine state for `convo_id` and the peer-bad
    /// counters so a fresh window begins after the exit.
    pub fn clear_quarantine(&mut self, convo_id: &str) -> bool {
        let was_quarantined = self.quarantined.remove(convo_id).is_some();
        self.peer_bad_by_sender.remove(convo_id);
        self.peer_bad_messages.remove(convo_id);
        was_quarantined
    }

    /// Record a peer-bad failure: a process-message error we've classified as
    /// the *peer's* fault (invalid commit, framing corruption, leaf
    /// validation). Returns whether the trigger thresholds (C1/C2/C3 in
    /// `catbird-mls/src/orchestrator/recovery.rs §3.2`) are tripped.
    ///
    /// `sender_did` is best-effort — `None` for framing failures we can't
    /// attribute (Signal D path). `message_id` is the sequencer message ID.
    pub fn record_peer_bad_commit(
        &mut self,
        convo_id: &str,
        sender_did: Option<&str>,
        message_id: &str,
    ) -> QuarantineDecision {
        let now = Instant::now();

        // Update C1/C2 — per-DID counts.
        if let Some(did) = sender_did {
            let by_sender = self
                .peer_bad_by_sender
                .entry(convo_id.to_string())
                .or_default();
            let entry = by_sender.entry(did.to_string()).or_insert((0, now));
            entry.0 += 1;
            // first_seen is set on insert; do not move it forward.
        }

        // Update C3 — rolling message-id buffer (cap at 32 entries).
        let buf = self
            .peer_bad_messages
            .entry(convo_id.to_string())
            .or_default();
        if !buf.iter().any(|(id, _)| id == message_id) {
            buf.push_back((message_id.to_string(), now));
        }
        while buf.len() > 32 {
            buf.pop_front();
        }
        // Drop entries older than the C3 window so they stop counting.
        while buf
            .front()
            .is_some_and(|(_, t)| now.duration_since(*t) > QUARANTINE_FRAMING_WINDOW)
        {
            buf.pop_front();
        }

        // ── Evaluate triggers ───────────────────────────────────────────
        if let Some(by_sender) = self.peer_bad_by_sender.get(convo_id) {
            // C1: any single DID at or above threshold
            for (did, (count, _)) in by_sender {
                if *count >= QUARANTINE_PEER_BAD_THRESHOLD {
                    return QuarantineDecision::Quarantine {
                        reason: QuarantineReason::PeerBadCommit,
                        suspected_dids: vec![did.clone()],
                    };
                }
            }
            // C2: ≥2 distinct DIDs within the 60s window
            let recent: Vec<String> = by_sender
                .iter()
                .filter(|(_, (_, t))| now.duration_since(*t) <= QUARANTINE_MULTI_PEER_WINDOW)
                .map(|(did, _)| did.clone())
                .collect();
            if recent.len() >= 2 {
                return QuarantineDecision::Quarantine {
                    reason: QuarantineReason::MultiPeerBadCommits,
                    suspected_dids: recent,
                };
            }
        }

        // C3: ≥3 distinct messages in the 120s window
        if let Some(buf) = self.peer_bad_messages.get(convo_id) {
            let in_window = buf
                .iter()
                .filter(|(_, t)| now.duration_since(*t) <= QUARANTINE_FRAMING_WINDOW)
                .count();
            if in_window >= 3 {
                let suspected = self
                    .peer_bad_by_sender
                    .get(convo_id)
                    .map(|m| m.keys().cloned().collect::<Vec<_>>())
                    .unwrap_or_default();
                return QuarantineDecision::Quarantine {
                    reason: QuarantineReason::RepeatedFramingFailures,
                    suspected_dids: suspected,
                };
            }
        }

        QuarantineDecision::Stay
    }

    /// Reset the per-DID peer-bad counters when a healthy peer commit lands.
    /// Mirrors `recordHealthyPeerCommit` from the iOS spec.
    pub fn record_healthy_peer_commit(&mut self, convo_id: &str) {
        self.peer_bad_by_sender.remove(convo_id);
        self.peer_bad_messages.remove(convo_id);
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
        let _ = self.clear_quarantine(convo_id);
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

    // ── Quarantine tracker tests (Layer 3) ───────────────────────────────

    #[test]
    fn peer_bad_below_threshold_stays() {
        let mut t = RecoveryTracker::new();
        let d1 = t.record_peer_bad_commit("c", Some("did:plc:peer1"), "m1");
        let d2 = t.record_peer_bad_commit("c", Some("did:plc:peer1"), "m2");
        assert_eq!(d1, QuarantineDecision::Stay);
        assert_eq!(d2, QuarantineDecision::Stay);
        assert!(!t.is_quarantined("c"));
    }

    #[test]
    fn peer_bad_one_did_at_three_trips_c1() {
        let mut t = RecoveryTracker::new();
        t.record_peer_bad_commit("c", Some("did:plc:peer1"), "m1");
        t.record_peer_bad_commit("c", Some("did:plc:peer1"), "m2");
        let d = t.record_peer_bad_commit("c", Some("did:plc:peer1"), "m3");
        assert!(matches!(
            d,
            QuarantineDecision::Quarantine {
                reason: QuarantineReason::PeerBadCommit,
                ..
            }
        ));
    }

    #[test]
    fn two_distinct_peers_within_window_trips_c2() {
        let mut t = RecoveryTracker::new();
        t.record_peer_bad_commit("c", Some("did:plc:peer1"), "m1");
        let d = t.record_peer_bad_commit("c", Some("did:plc:peer2"), "m2");
        assert!(matches!(
            d,
            QuarantineDecision::Quarantine {
                reason: QuarantineReason::MultiPeerBadCommits,
                ..
            }
        ));
    }

    #[test]
    fn three_distinct_messages_with_no_did_trips_c3() {
        let mut t = RecoveryTracker::new();
        t.record_peer_bad_commit("c", None, "m1");
        t.record_peer_bad_commit("c", None, "m2");
        let d = t.record_peer_bad_commit("c", None, "m3");
        assert!(matches!(
            d,
            QuarantineDecision::Quarantine {
                reason: QuarantineReason::RepeatedFramingFailures,
                ..
            }
        ));
    }

    #[test]
    fn duplicate_message_id_does_not_double_count_for_c3() {
        let mut t = RecoveryTracker::new();
        t.record_peer_bad_commit("c", None, "m1");
        t.record_peer_bad_commit("c", None, "m1"); // duplicate
        let d = t.record_peer_bad_commit("c", None, "m2");
        assert_eq!(d, QuarantineDecision::Stay);
    }

    #[test]
    fn mark_quarantined_makes_should_skip_true() {
        let mut t = RecoveryTracker::new();
        assert!(!t.should_skip("c") || t.global_interval_remaining().is_some());
        t.mark_quarantined("c");
        assert!(t.is_quarantined("c"));
        assert!(t.should_skip("c"));
    }

    #[test]
    fn clear_quarantine_resets_state() {
        let mut t = RecoveryTracker::new();
        t.record_peer_bad_commit("c", Some("did:plc:peer1"), "m1");
        t.mark_quarantined("c");
        t.clear_quarantine("c");
        assert!(!t.is_quarantined("c"));
        // peer-bad counters should be cleared so the window starts fresh
        let d = t.record_peer_bad_commit("c", Some("did:plc:peer1"), "m1");
        assert_eq!(d, QuarantineDecision::Stay);
    }

    #[test]
    fn record_healthy_clears_peer_bad_counters() {
        let mut t = RecoveryTracker::new();
        t.record_peer_bad_commit("c", Some("did:plc:peer1"), "m1");
        t.record_peer_bad_commit("c", Some("did:plc:peer1"), "m2");
        t.record_healthy_peer_commit("c");
        // We should now need 3 fresh failures, not 1.
        let d = t.record_peer_bad_commit("c", Some("did:plc:peer1"), "m3");
        assert_eq!(d, QuarantineDecision::Stay);
    }
}
