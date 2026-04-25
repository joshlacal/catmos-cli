//! Recovery state machine wiring for `ChatService` (spec §8).
//!
//! This file holds the platform-layer pieces that sit on top of the in-memory
//! trackers in `crate::recovery::tracker` and the persisted flags on the
//! `conversations` table. The orchestrator-equivalent shape lives in
//! `catbird-mls/src/orchestrator/recovery.rs`; we mirror it here because
//! catmos-cli talks to `MLSContext` directly.
//!
//! Public surface added by this file:
//! - `ChatService::external_commit_rejoin(convo_id)` — the canonical spec §8.4
//!   rejoin path, gated by `RecoveryTracker` and the GroupInfo 404 circuit
//!   breaker.
//! - `ChatService::flag_needs_rejoin(convo_id)` — flip the persisted flag and
//!   reset the in-memory threshold counters.
//! - `ChatService::report_unrecoverable_local(convo_id, reason)` — POST
//!   `reportRecoveryFailure` (§8.6).
//! - `ChatService::run_deferred_recovery()` — Phase 1 (RESET_PENDING) before
//!   Phase 2 (NEEDS_REJOIN), with the `DEFERRED_RECOVERY_PAUSE` between
//!   conversations (§8.5).
//! - Threshold helpers: `note_decrypt_failure`, `note_epoch_divergence`,
//!   `note_decrypt_success` for the receive paths.

use serde::Serialize;
use tracing::{debug, error, info, warn};

use super::service::ChatService;
use crate::error::{CatmosError, Result};
use crate::mls::MlsManager;
use crate::recovery::{constants, RecoveryState};

/// `failureType` strings the server understands (§8.6).
const FAILURE_EXTERNAL_COMMIT_EXHAUSTED: &str = "external_commit_exhausted";
const FAILURE_REMOTE_DATA_ERROR: &str = "remote_data_error";

/// Classify an error string as a §9.2 remote data error (malformed
/// server-side data — must NOT wipe local state, MUST mark
/// UNRECOVERABLE_LOCAL immediately). Mirrors
/// `catbird_mls::orchestrator::error::OrchestratorError::is_remote_data_error`.
fn is_remote_data_error_str(msg: &str) -> bool {
    let m = msg.to_lowercase();
    m.contains("invalidvectorlength")
        || m.contains("endofstream")
        || m.contains("truncated")
        || m.contains("malformed")
        || m.contains("deseriali")
}

/// Classify an error string as a §9.3 transient error (network / 429 / 5xx —
/// retry without burning a counter slot).
fn is_transient_error_str(msg: &str) -> bool {
    msg.contains("returned 429")
        || msg.contains("RateLimited")
        || msg.contains("returned 500")
        || msg.contains("returned 502")
        || msg.contains("returned 503")
        || msg.contains("returned 504")
        || msg.contains("timed out")
        || msg.contains("timeout")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportRecoveryFailureReq<'a> {
    convo_id: &'a str,
    failure_type: &'a str,
    /// ADR-008 D1 (spec §8.6.1): `"local_state_loss"` (Mode A, self-heal,
    /// SHOULD NOT count toward quorum) or `"group_state_unrecoverable"`
    /// (Mode B, counts toward quorum). `None` is forward-compat for older
    /// servers that don't read the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_mode: Option<&'a str>,
    /// Best-effort epoch authenticator hint (hex). `None` keeps pre-A7
    /// behavior; servers that accept the hint use it to reject stale votes.
    #[serde(skip_serializing_if = "Option::is_none")]
    epoch_authenticator: Option<String>,
}

impl ChatService {
    // ── Threshold counters ─────────────────────────────────────────────

    /// Reset both threshold counters (decrypt-failure + epoch-divergence) on a
    /// successful decrypt or merge. Called from the receive paths.
    pub(crate) async fn reset_recovery_counters(&self, convo_id: &str) {
        self.decrypt_fail_counts.lock().await.remove(convo_id);
        self.epoch_divergence_counts.lock().await.remove(convo_id);
    }

    /// Bump the per-convo decrypt-failure counter and, on threshold, flag
    /// `NEEDS_REJOIN`. Returns `true` if the threshold was hit (caller can
    /// then bail out of the current decrypt loop).
    pub(crate) async fn note_decrypt_failure(&self, convo_id: &str) -> bool {
        let count = {
            let mut counts = self.decrypt_fail_counts.lock().await;
            let c = counts.entry(convo_id.to_string()).or_insert(0);
            *c += 1;
            *c
        };
        if count >= constants::DECRYPTION_FAILURE_THRESHOLD {
            warn!(
                convo = %&convo_id[..12.min(convo_id.len())],
                count,
                "Decryption failure threshold reached — flagging NEEDS_REJOIN"
            );
            self.flag_needs_rejoin(convo_id).await;
            return true;
        }
        false
    }

    /// Bump the per-convo epoch-divergence counter (WrongEpoch /
    /// `merge_incoming_commit` failure). Returns `true` if the threshold was
    /// hit, in which case `NEEDS_REJOIN` is flagged and the caller should
    /// abort the sync for this conversation.
    pub(crate) async fn note_epoch_divergence(&self, convo_id: &str) -> bool {
        let count = {
            let mut counts = self.epoch_divergence_counts.lock().await;
            let c = counts.entry(convo_id.to_string()).or_insert(0);
            *c += 1;
            *c
        };
        if count >= constants::EPOCH_DIVERGENCE_THRESHOLD {
            warn!(
                convo = %&convo_id[..12.min(convo_id.len())],
                count,
                "Epoch divergence threshold reached — flagging NEEDS_REJOIN"
            );
            self.flag_needs_rejoin(convo_id).await;
            return true;
        }
        false
    }

    /// Persist the `NEEDS_REJOIN` flag and reset the in-memory threshold
    /// counters. Idempotent.
    pub async fn flag_needs_rejoin(&self, convo_id: &str) {
        if let Err(e) = self.db.mark_needs_rejoin(convo_id).await {
            warn!(
                convo = %&convo_id[..12.min(convo_id.len())],
                error = %e,
                "Failed to persist NEEDS_REJOIN flag"
            );
        }
        // Reset thresholds — the state machine has accepted the trigger and
        // moved to NEEDS_REJOIN; we don't want stale counts to retrigger.
        self.reset_recovery_counters(convo_id).await;
    }

    // ── §8.6 reportRecoveryFailure ─────────────────────────────────────

    /// POST `blue.catbird.mlsChat.reportRecoveryFailure` (§8.6). Best-effort:
    /// if the call fails we log and swallow — the local state has already
    /// transitioned to `UNRECOVERABLE_LOCAL`, so failing the report serves no
    /// recovery purpose (server can re-derive via other clients' reports).
    pub async fn report_recovery_failure(&self, convo_id: &str, failure_type: &str) {
        let authenticator = self.epoch_authenticator_hex(convo_id);
        // ADR-008 D1 (spec §8.6.1): classify by failure_type — mirrors
        // catbird-mls/src/orchestrator/recovery.rs:858-864 and the iOS
        // MLSRecoveryManager classifier.
        let failure_mode: Option<&str> = match failure_type {
            FAILURE_REMOTE_DATA_ERROR => Some("group_state_unrecoverable"),
            FAILURE_EXTERNAL_COMMIT_EXHAUSTED => Some("local_state_loss"),
            _ => None,
        };
        let convo_label = &convo_id[..12.min(convo_id.len())];
        warn!(
            convo = %convo_label,
            failure_type,
            failure_mode = ?failure_mode,
            has_authenticator = authenticator.is_some(),
            "Reporting recovery failure to server (§8.6)"
        );
        let req = ReportRecoveryFailureReq {
            convo_id,
            failure_type,
            failure_mode,
            epoch_authenticator: authenticator,
        };
        match self
            .xrpc_procedure::<_, serde_json::Value>(
                "blue.catbird.mlsChat.reportRecoveryFailure",
                &req,
            )
            .await
        {
            Ok(_) => info!(convo = %convo_label, "reportRecoveryFailure accepted"),
            Err(e) => warn!(
                convo = %convo_label,
                error = %e,
                "reportRecoveryFailure failed (best-effort, swallowed)"
            ),
        }
    }

    /// Best-effort hex-encoded epoch authenticator for `convo_id`. Returns
    /// `None` if the local group is missing or the API is unavailable.
    pub(crate) fn epoch_authenticator_hex(&self, convo_id: &str) -> Option<String> {
        let gid = hex::decode(convo_id).ok()?;
        self.mls
            .with_context(|ctx| ctx.epoch_authenticator(gid))
            .ok()
            .map(hex::encode)
    }

    // ── §8.4 EXTERNAL_COMMIT_REJOIN ────────────────────────────────────

    /// Spec §8.4 External Commit rejoin, gated by `RecoveryTracker` (global
    /// MIN_REJOIN_INTERVAL + per-convo backoff + max-attempts) and the
    /// GroupInfo 404 circuit breaker (§8.3).
    ///
    /// On success: `RecoveryTracker::record_success`, clear NEEDS_REJOIN flag.
    /// On failure (non-rate-limited): `RecoveryTracker::record_failure`,
    /// persist attempt count + timestamp; if attempts hit
    /// `MAX_REJOIN_ATTEMPTS`, transition to `UNRECOVERABLE_LOCAL` and fire
    /// `reportRecoveryFailure`.
    pub async fn external_commit_rejoin(&self, convo_id: &str) -> Result<()> {
        let convo_label = &convo_id[..12.min(convo_id.len())];

        // 1. Gate on tracker (max-attempts / per-convo cooldown / global floor)
        {
            let tracker = self.recovery_tracker.lock().await;
            if tracker.is_maxed_out(convo_id) {
                drop(tracker);
                warn!(
                    convo = %convo_label,
                    "External Commit rejoin suppressed: max attempts reached → UNRECOVERABLE_LOCAL"
                );
                self.transition_unrecoverable_local(convo_id).await;
                return Err(CatmosError::Other(format!(
                    "Rejoin suppressed for {convo_label}: max attempts reached"
                )));
            }
            if let Some(remaining) = tracker.cooldown_remaining(convo_id) {
                debug!(
                    convo = %convo_label,
                    remaining_s = remaining.as_secs(),
                    "Rejoin suppressed: per-convo cooldown active"
                );
                return Err(CatmosError::Other(format!(
                    "Rejoin cooldown active for {convo_label} ({}s remaining)",
                    remaining.as_secs()
                )));
            }
            if let Some(remaining) = tracker.global_interval_remaining() {
                debug!(
                    convo = %convo_label,
                    remaining_s = remaining.as_secs(),
                    "Rejoin suppressed: global MIN_REJOIN_INTERVAL not elapsed"
                );
                return Err(CatmosError::Other(format!(
                    "Global rejoin interval not elapsed ({}s remaining)",
                    remaining.as_secs()
                )));
            }
        }

        // 2. Gate on GroupInfo 404 circuit breaker (§8.3)
        if self
            .groupinfo_404_tracker
            .lock()
            .await
            .is_tripped(convo_id)
        {
            warn!(
                convo = %convo_label,
                "External Commit rejoin suppressed: GroupInfo 404 circuit breaker tripped"
            );
            return Err(CatmosError::Other(format!(
                "GroupInfo 404 circuit breaker tripped for {convo_label}"
            )));
        }

        // 3. Fetch GroupInfo FIRST (spec §8.4 step 1). Local state is preserved
        //    until we know we have a valid GroupInfo blob to External-Commit
        //    against — that way a transient fetch failure doesn't leave the
        //    conversation undecryptable until the next sync cycle.
        //
        //    Classify the fetch error per spec §9.2 / §9.3:
        //      - 404 / missing groupInfo → bump GroupInfo circuit breaker, return.
        //        Do NOT call recovery_tracker.record_failure (404 has its own
        //        breaker; spec §8.4 step 1 keeps the two separate).
        //      - remote data error (malformed, deserialization)  → §9.2:
        //        do NOT delete local state, transition straight to
        //        UNRECOVERABLE_LOCAL with failureType="remote_data_error",
        //        return.
        //      - transient (429 / 5xx / timeout) → §9.3: return without
        //        incrementing any counters.
        //      - anything else → record_failure + persist + maybe-maxed.
        let group_info_b64 = match self.mls.fetch_group_info(self, convo_id).await {
            Ok(gi) => {
                // Successful fetch resets the GroupInfo 404 breaker for this
                // conversation (mirrors catbird-mls::orchestrator::recovery).
                self.groupinfo_404_tracker.lock().await.clear(convo_id);
                gi
            }
            Err(e) => {
                let msg = e.to_string();
                if MlsManager::is_group_info_unavailable(&e) || msg.contains("returned 404") {
                    self.groupinfo_404_tracker
                        .lock()
                        .await
                        .record_404(convo_id);
                    warn!(
                        convo = %convo_label,
                        error = %e,
                        "External Commit rejoin failed: GroupInfo unavailable (404 / missing) — local state preserved"
                    );
                    return Err(e);
                }
                if is_remote_data_error_str(&msg) {
                    error!(
                        convo = %convo_label,
                        error = %e,
                        "External Commit rejoin failed: remote data error (§9.2) — marking UNRECOVERABLE_LOCAL, local state preserved"
                    );
                    self.transition_unrecoverable_local_with_reason(
                        convo_id,
                        FAILURE_REMOTE_DATA_ERROR,
                    )
                    .await;
                    return Err(e);
                }
                if is_transient_error_str(&msg) {
                    warn!(
                        convo = %convo_label,
                        error = %e,
                        "External Commit rejoin transient failure (not counted) — GroupInfo fetch"
                    );
                    return Err(e);
                }
                // Other errors during fetch — burn an attempt slot.
                let mut tracker = self.recovery_tracker.lock().await;
                tracker.record_failure(convo_id);
                let attempts = tracker.attempts(convo_id);
                let maxed = tracker.is_maxed_out(convo_id);
                drop(tracker);
                let now_ms = chrono::Utc::now().timestamp_millis();
                if let Err(db_err) = self
                    .db
                    .record_rejoin_attempt(convo_id, attempts, now_ms)
                    .await
                {
                    warn!(
                        convo = %convo_label,
                        error = %db_err,
                        "Failed to persist rejoin attempt count"
                    );
                }
                error!(
                    convo = %convo_label,
                    attempts,
                    max = constants::MAX_REJOIN_ATTEMPTS,
                    error = %e,
                    "External Commit rejoin failed: GroupInfo fetch error — local state preserved"
                );
                if maxed {
                    self.transition_unrecoverable_local(convo_id).await;
                }
                return Err(e);
            }
        };

        // 4. GroupInfo fetched successfully — now safe to delete the existing
        //    local group state (spec §8.4 step 2) and create the External
        //    Commit. `external_commit_with_group_info` handles
        //    `discard_pending_external_join` on failure (spec §8.4.1).
        let gid = hex::decode(convo_id)
            .map_err(|e| CatmosError::Other(format!("Invalid group ID hex: {e}")))?;
        let _ = self.mls.with_context(|ctx| {
            let _ = ctx.delete_group(gid.clone());
            Ok::<_, catbird_mls::MLSError>(())
        });

        let did = self.did().to_string();
        let result = self
            .mls
            .external_commit_with_group_info(self, convo_id, &did, &group_info_b64)
            .await;

        // 5. Update trackers + DB based on commit-send / merge result.
        match &result {
            Ok(()) => {
                {
                    let mut tracker = self.recovery_tracker.lock().await;
                    tracker.record_success(convo_id);
                }
                self.groupinfo_404_tracker
                    .lock()
                    .await
                    .clear(convo_id);
                self.reset_recovery_counters(convo_id).await;
                if let Err(e) = self.db.clear_needs_rejoin(convo_id).await {
                    warn!(
                        convo = %convo_label,
                        error = %e,
                        "Failed to clear NEEDS_REJOIN flag after success"
                    );
                }
                info!(convo = %convo_label, "External Commit rejoin succeeded");
            }
            Err(e) => {
                let msg = e.to_string();
                // Post-fetch path: a 404 here would be unusual (the fetch
                // succeeded), but keep the breaker arm wired in case the
                // server returns one on commitGroupChange.
                let is_gi_404 = msg.contains("GroupInfoUnavailable")
                    || msg.contains("missing groupInfo")
                    || msg.contains("returned 404");
                if is_gi_404 {
                    self.groupinfo_404_tracker
                        .lock()
                        .await
                        .record_404(convo_id);
                }
                // Remote data error during create_external_commit / merge =
                // §9.2: malformed GroupInfo we already fetched. Transition
                // to UNRECOVERABLE_LOCAL without burning further attempts.
                if is_remote_data_error_str(&msg) {
                    error!(
                        convo = %convo_label,
                        error = %e,
                        "External Commit rejoin failed: remote data error (§9.2) during commit — marking UNRECOVERABLE_LOCAL"
                    );
                    self.transition_unrecoverable_local_with_reason(
                        convo_id,
                        FAILURE_REMOTE_DATA_ERROR,
                    )
                    .await;
                } else if is_transient_error_str(&msg) {
                    warn!(
                        convo = %convo_label,
                        error = %e,
                        "External Commit rejoin transient failure (not counted)"
                    );
                } else {
                    let mut tracker = self.recovery_tracker.lock().await;
                    tracker.record_failure(convo_id);
                    let attempts = tracker.attempts(convo_id);
                    let maxed = tracker.is_maxed_out(convo_id);
                    drop(tracker);
                    let now_ms = chrono::Utc::now().timestamp_millis();
                    if let Err(db_err) = self
                        .db
                        .record_rejoin_attempt(convo_id, attempts, now_ms)
                        .await
                    {
                        warn!(
                            convo = %convo_label,
                            error = %db_err,
                            "Failed to persist rejoin attempt count"
                        );
                    }
                    error!(
                        convo = %convo_label,
                        attempts,
                        max = constants::MAX_REJOIN_ATTEMPTS,
                        error = %e,
                        "External Commit rejoin failed"
                    );
                    if maxed {
                        self.transition_unrecoverable_local(convo_id).await;
                    }
                }
            }
        }

        result
    }

    /// Move `convo_id` to `UNRECOVERABLE_LOCAL` and fire `reportRecoveryFailure`
    /// with `failureType: "external_commit_exhausted"` (spec §8.6).
    async fn transition_unrecoverable_local(&self, convo_id: &str) {
        self.transition_unrecoverable_local_with_reason(
            convo_id,
            FAILURE_EXTERNAL_COMMIT_EXHAUSTED,
        )
        .await;
    }

    /// Variant of `transition_unrecoverable_local` that lets the caller pick
    /// the §8.6 `failureType`. Used by §9.2 remote-data classification, which
    /// reports `"remote_data_error"` instead of `"external_commit_exhausted"`.
    async fn transition_unrecoverable_local_with_reason(
        &self,
        convo_id: &str,
        failure_type: &str,
    ) {
        if let Err(e) = self.db.mark_unrecoverable_local(convo_id).await {
            warn!(
                convo = %&convo_id[..12.min(convo_id.len())],
                error = %e,
                "Failed to persist UNRECOVERABLE_LOCAL flag"
            );
        }
        self.report_recovery_failure(convo_id, failure_type).await;
    }

    // ── §8.5 Deferred Recovery ─────────────────────────────────────────

    /// Run after each sync cycle. Phase 1 (RESET_PENDING) before Phase 2
    /// (NEEDS_REJOIN), with `DEFERRED_RECOVERY_PAUSE` between conversations
    /// (§8.5).
    pub async fn run_deferred_recovery(&self) {
        // Snapshot the conversation list to avoid holding the read lock
        // across awaits.
        let convo_ids: Vec<String> = {
            let convos = self.conversations.read().await;
            convos.iter().map(|c| c.conversation_id.clone()).collect()
        };

        // Phase 1: RESET_PENDING (highest priority). The server has already
        // re-keyed the group; all retry counters reset.
        for convo_id in &convo_ids {
            let flags = match self.db.get_recovery_flags(convo_id).await {
                Ok(f) => f,
                Err(e) => {
                    debug!(
                        convo = %&convo_id[..12.min(convo_id.len())],
                        error = %e,
                        "deferred_recovery: get_recovery_flags failed"
                    );
                    continue;
                }
            };
            if !matches!(
                RecoveryState::from_flags(&flags),
                RecoveryState::ResetPending(_)
            ) {
                continue;
            }
            // Server reset = fresh start: clear our local retry counters.
            self.recovery_tracker.lock().await.clear_convo(convo_id);
            self.groupinfo_404_tracker
                .lock()
                .await
                .clear(convo_id);
            match self.external_commit_rejoin(convo_id).await {
                Ok(()) => {
                    if let Err(e) = self.db.clear_reset_pending(convo_id).await {
                        warn!(
                            convo = %&convo_id[..12.min(convo_id.len())],
                            error = %e,
                            "deferred_recovery: failed to clear RESET_PENDING after success"
                        );
                    }
                    info!(
                        convo = %&convo_id[..12.min(convo_id.len())],
                        "deferred_recovery: RESET_PENDING adopted"
                    );
                }
                Err(e) => warn!(
                    convo = %&convo_id[..12.min(convo_id.len())],
                    error = %e,
                    "deferred_recovery: RESET_PENDING adoption failed (will retry next cycle)"
                ),
            }
            tokio::time::sleep(constants::DEFERRED_RECOVERY_PAUSE).await;
        }

        // Phase 2: NEEDS_REJOIN. Skipped automatically by
        // `external_commit_rejoin` if cooldown / max-attempts apply.
        for convo_id in &convo_ids {
            let flags = match self.db.get_recovery_flags(convo_id).await {
                Ok(f) => f,
                Err(_) => continue,
            };
            if !matches!(
                RecoveryState::from_flags(&flags),
                RecoveryState::NeedsRejoin
            ) {
                continue;
            }
            match self.external_commit_rejoin(convo_id).await {
                Ok(()) => info!(
                    convo = %&convo_id[..12.min(convo_id.len())],
                    "deferred_recovery: NEEDS_REJOIN cleared"
                ),
                Err(e) => debug!(
                    convo = %&convo_id[..12.min(convo_id.len())],
                    error = %e,
                    "deferred_recovery: NEEDS_REJOIN attempt skipped or failed"
                ),
            }
            tokio::time::sleep(constants::DEFERRED_RECOVERY_PAUSE).await;
        }
    }

    // ── Group reset event handling (§8.6 / §A.6) ──────────────────────

    /// Persist a `RESET_PENDING` payload received via `GroupResetEvent`.
    /// Called from the WebSocket layer when a `WsEvent::GroupReset` arrives.
    pub async fn handle_group_reset_event(
        &self,
        convo_id: &str,
        new_group_id: &str,
        reset_generation: u64,
    ) {
        let notified_at_ms = chrono::Utc::now().timestamp_millis();
        if let Err(e) = self
            .db
            .mark_reset_pending(
                convo_id,
                new_group_id,
                reset_generation as i64,
                notified_at_ms,
            )
            .await
        {
            warn!(
                convo = %&convo_id[..12.min(convo_id.len())],
                error = %e,
                "handle_group_reset_event: failed to persist RESET_PENDING"
            );
            return;
        }
        // Server reset clears all local retry counters and the unrecoverable
        // flag — this is a fresh start (§8.6).
        self.recovery_tracker.lock().await.clear_convo(convo_id);
        self.groupinfo_404_tracker
            .lock()
            .await
            .clear(convo_id);
        self.reset_recovery_counters(convo_id).await;
        if let Err(e) = self.db.clear_unrecoverable_local(convo_id).await {
            warn!(
                convo = %&convo_id[..12.min(convo_id.len())],
                error = %e,
                "handle_group_reset_event: failed to clear UNRECOVERABLE_LOCAL"
            );
        }
        info!(
            convo = %&convo_id[..12.min(convo_id.len())],
            new_group = %&new_group_id[..12.min(new_group_id.len())],
            generation = reset_generation,
            "Persisted RESET_PENDING from GroupResetEvent"
        );
    }
}

