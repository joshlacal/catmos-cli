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
use crate::recovery::{constants, RecoveryState, ResetPendingPayload};

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

/// Whether an error represents a `createConvo` race-loss: the server returned
/// 409 with the `ConvoAlreadyExists` lexicon error code, meaning a different
/// DID won the first-responder bootstrap race for the same `groupId`.
///
/// Mirrors `catbird_mls::OrchestratorError::is_create_convo_race_loss`. We
/// re-implement here because catmos-cli surfaces XRPC errors as
/// `CatmosError::Xrpc("{nsid} returned {status}: {body}")` rather than as a
/// structured `ServerError { status, body }` variant — substring-matching the
/// flattened message is the cheapest reliable detection on this platform.
pub(crate) fn is_create_convo_race_loss(err: &CatmosError) -> bool {
    let msg = err.to_string();
    msg.contains("returned 409") && msg.contains("ConvoAlreadyExists")
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
        //
        // Spec §8.5 Phase 1 ladder: try Welcome first (cheapest, no MLS state
        // mutation), then External Commit (needs server-published GroupInfo),
        // then first-responder bootstrap (creates the empty group locally and
        // claims it server-side via createConvo at the predetermined
        // newGroupId — the race is resolved by the server's primary-key
        // collision check returning 409 ConvoAlreadyExists for the loser).
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
            let payload = match RecoveryState::from_flags(&flags) {
                RecoveryState::ResetPending(p) => p,
                _ => continue,
            };
            // Server reset = fresh start: clear our local retry counters.
            self.recovery_tracker.lock().await.clear_convo(convo_id);
            self.groupinfo_404_tracker
                .lock()
                .await
                .clear(convo_id);

            // Step 1: try Welcome. Cheapest, no MLS state mutation.
            if self.try_pending_welcome(convo_id).await {
                if let Err(e) = self.db.clear_reset_pending(convo_id).await {
                    warn!(
                        convo = %&convo_id[..12.min(convo_id.len())],
                        error = %e,
                        "deferred_recovery: failed to clear RESET_PENDING after Welcome"
                    );
                }
                info!(
                    convo = %&convo_id[..12.min(convo_id.len())],
                    "deferred_recovery: RESET_PENDING adopted via Welcome"
                );
                tokio::time::sleep(constants::DEFERRED_RECOVERY_PAUSE).await;
                continue;
            }

            // Step 2: try External Commit. Internally fetches GroupInfo;
            // returns Err with `is_group_info_unavailable` when the server has
            // none yet (post-reset window before any responder publishes).
            match self.external_commit_rejoin(convo_id).await {
                Ok(()) => {
                    if let Err(e) = self.db.clear_reset_pending(convo_id).await {
                        warn!(
                            convo = %&convo_id[..12.min(convo_id.len())],
                            error = %e,
                            "deferred_recovery: failed to clear RESET_PENDING after External Commit"
                        );
                    }
                    info!(
                        convo = %&convo_id[..12.min(convo_id.len())],
                        "deferred_recovery: RESET_PENDING adopted via External Commit"
                    );
                    tokio::time::sleep(constants::DEFERRED_RECOVERY_PAUSE).await;
                    continue;
                }
                Err(e) if MlsManager::is_group_info_unavailable(&e) => {
                    debug!(
                        convo = %&convo_id[..12.min(convo_id.len())],
                        "deferred_recovery: GroupInfo unavailable — attempting first-responder bootstrap"
                    );
                    // Fall through to bootstrap.
                }
                Err(e) => {
                    warn!(
                        convo = %&convo_id[..12.min(convo_id.len())],
                        error = %e,
                        "deferred_recovery: RESET_PENDING External Commit failed (will retry next cycle)"
                    );
                    tokio::time::sleep(constants::DEFERRED_RECOVERY_PAUSE).await;
                    continue;
                }
            }

            // Step 3: first-responder bootstrap. Creates an empty MLS group at
            // payload.new_group_id and submits via createConvo. Race-winner
            // clears reset_pending; race-loser keeps it set so the next cycle
            // re-enters Step 1 to pick up the winner's Welcome.
            self.try_first_responder_bootstrap(convo_id, &payload).await;
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

    // ── §8.5 Phase 1 ladder helpers (Welcome → ExternalCommit → Bootstrap) ──

    /// Try to adopt the post-reset group via a server-published Welcome.
    /// Returns `true` if a Welcome existed and was processed successfully.
    /// Returns `false` if no Welcome is available or processing failed (the
    /// caller falls through to the next ladder step in either case — a
    /// processing failure here is not fatal because External Commit and
    /// bootstrap remain as fallbacks).
    async fn try_pending_welcome(&self, convo_id: &str) -> bool {
        let convo_label = &convo_id[..12.min(convo_id.len())];
        let welcome_b64 = match self.mls.fetch_pending_welcome(self, convo_id).await {
            Ok(Some(w)) => w,
            Ok(None) => return false,
            Err(e) => {
                debug!(
                    convo = %convo_label,
                    error = %e,
                    "try_pending_welcome: getGroupState include=welcome failed"
                );
                return false;
            }
        };

        let did = self.did().to_string();
        match self.mls.process_welcome_b64(&welcome_b64, &did) {
            Ok(group_id) => {
                info!(
                    convo = %convo_label,
                    group = %hex::encode(&group_id),
                    "try_pending_welcome: adopted post-reset group via Welcome"
                );
                true
            }
            Err(e) => {
                warn!(
                    convo = %convo_label,
                    error = %e,
                    "try_pending_welcome: process_welcome failed (will retry next cycle)"
                );
                false
            }
        }
    }

    /// First-responder bootstrap (spec §8.5 Phase 1, Plan Task 23).
    ///
    /// Creates the MLS group locally at `payload.new_group_id` and submits via
    /// `createConvo`. Server's primary-key idempotency on `(group_id)` plus
    /// the `ConvoAlreadyExists` 409 (lexicon task #16) lets the loser detect
    /// "someone else won" and drop their pre-bootstrap MLS group cleanly.
    ///
    /// Race-winner: clears `reset_pending`, transitions to Active.
    /// Race-loser: keeps `reset_pending` set; next cycle re-enters the ladder
    /// at Step 1 (Welcome) and picks up the winner's published Welcome.
    /// Other failures: drop the local group so the next attempt starts clean.
    async fn try_first_responder_bootstrap(
        &self,
        convo_id: &str,
        payload: &ResetPendingPayload,
    ) {
        let convo_label = &convo_id[..12.min(convo_id.len())];

        let new_group_id_bytes = match hex::decode(&payload.new_group_id) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    convo = %convo_label,
                    new_group = %payload.new_group_id,
                    error = %e,
                    "bootstrap: ResetPending.new_group_id is not valid hex; cannot bootstrap"
                );
                return;
            }
        };

        // Fetch fresh roster — post-reset, the server clears the membership
        // table atomically with the reset transaction (Phase 0 Q3). Local
        // cached members would be the pre-reset roster.
        let roster = match self.fetch_member_roster_for_bootstrap(convo_id).await {
            Ok(r) if !r.is_empty() => r,
            Ok(_) => {
                warn!(
                    convo = %convo_label,
                    "bootstrap: server roster is empty; cannot bootstrap"
                );
                return;
            }
            Err(e) => {
                warn!(
                    convo = %convo_label,
                    error = %e,
                    "bootstrap: getConvos roster fetch failed; will retry next cycle"
                );
                return;
            }
        };

        // Cipher suite the original convo used (the orchestrator stores this on
        // the Conversation; we read it from our local cache).
        let cipher_suite = {
            let convos = self.conversations.read().await;
            convos
                .iter()
                .find(|c| c.conversation_id == convo_id)
                .map(|c| c.cipher_suite.clone())
        };
        let cipher_suite = cipher_suite.unwrap_or_else(|| {
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string()
        });

        info!(
            convo = %convo_label,
            new_group = %payload.new_group_id,
            roster_size = roster.len(),
            cipher_suite = %cipher_suite,
            "bootstrap: creating local MLS group at predetermined id"
        );

        // 1. Create local MLS group AT the predetermined id.
        let did = self.did().to_string();
        let identity_bytes = did.as_bytes().to_vec();
        if let Err(e) = self.mls.with_context(|ctx| {
            let _ = ctx.create_group_with_id(
                identity_bytes.clone(),
                new_group_id_bytes.clone(),
                None,
            )?;
            Ok(())
        }) {
            warn!(
                convo = %convo_label,
                error = %e,
                "bootstrap: create_group_with_id failed; will retry next cycle"
            );
            return;
        }

        // 2. Submit to server. Filter creator's DID from initial members
        // (server records the caller as a member implicitly).
        let did_lower = did.to_lowercase();
        let initial_members: Vec<String> = roster
            .iter()
            .filter(|m| m.to_lowercase() != did_lower)
            .cloned()
            .collect();

        let submit_result = self
            .create_convo_at_group_id(&payload.new_group_id, &cipher_suite, &initial_members)
            .await;

        match submit_result {
            Ok(()) => {
                info!(
                    convo = %convo_label,
                    new_group = %payload.new_group_id,
                    reset_generation = payload.reset_generation,
                    "bootstrap: race won — clearing RESET_PENDING"
                );
                if let Err(e) = self.db.clear_reset_pending(convo_id).await {
                    warn!(
                        convo = %convo_label,
                        error = %e,
                        "bootstrap: failed to clear RESET_PENDING after winning bootstrap"
                    );
                }
            }
            Err(e) if is_create_convo_race_loss(&e) => {
                info!(
                    convo = %convo_label,
                    new_group = %payload.new_group_id,
                    reset_generation = payload.reset_generation,
                    "bootstrap: race lost (ConvoAlreadyExists) — dropping local pre-bootstrap group; next cycle will retry Welcome"
                );
                // Discard the local pre-bootstrap MLS group so the next cycle
                // can welcome-join the winner's group cleanly.
                if let Err(e) = self.mls.with_context(|ctx| {
                    let _ = ctx.delete_group(new_group_id_bytes.clone());
                    Ok(())
                }) {
                    warn!(
                        convo = %convo_label,
                        error = %e,
                        "bootstrap: delete_group for race-lost bootstrap failed (non-fatal)"
                    );
                }
                // Do NOT clear reset_pending — next deferred-recovery cycle
                // re-enters the ladder at Step 1 (Welcome).
            }
            Err(e) => {
                warn!(
                    convo = %convo_label,
                    error = %e,
                    "bootstrap: createConvo failed; dropping local group, will retry next cycle"
                );
                if let Err(e) = self.mls.with_context(|ctx| {
                    let _ = ctx.delete_group(new_group_id_bytes.clone());
                    Ok(())
                }) {
                    warn!(
                        convo = %convo_label,
                        error = %e,
                        "bootstrap: delete_group for failed bootstrap failed (non-fatal)"
                    );
                }
            }
        }
    }

    /// Fetch the current member roster for `convo_id` via `getConvos`.
    /// Returns the unique set of `user_did`s. Spec §8.5 Phase 1 / Phase 0 Q3:
    /// `groupResetEvent` carries no roster, so bootstrap MUST refetch fresh.
    async fn fetch_member_roster_for_bootstrap(
        &self,
        convo_id: &str,
    ) -> Result<Vec<String>> {
        let resp: super::messages::GetConvosResp = self
            .xrpc_query(catbird_atproto::catbird::mls_chat::get_convos::NSID, &[])
            .await?;

        let mut roster: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for c in &resp.conversations {
            let id = c.conversation_id.as_deref().unwrap_or(&c.group_id);
            if id != convo_id {
                continue;
            }
            for m in &c.members {
                if seen.insert(m.user_did.clone()) {
                    roster.push(m.user_did.clone());
                }
            }
        }
        Ok(roster)
    }
}

#[cfg(test)]
mod bootstrap_classifier_tests {
    use super::*;

    /// Server returns HTTP 409 with `{"error":"ConvoAlreadyExists",...}` when
    /// a different DID won the first-responder bootstrap race for the same
    /// `groupId`. catmos-cli flattens that into
    /// `CatmosError::Xrpc("blue.catbird.mlsChat.createConvo returned 409
    /// Conflict: {...}")`. The classifier must detect this exact shape — and
    /// must NOT mis-classify other 409s or other lexicon error codes.
    #[test]
    fn is_create_convo_race_loss_matches_real_xrpc_shape() {
        let err = CatmosError::Xrpc(
            "blue.catbird.mlsChat.createConvo returned 409 Conflict: \
             {\"error\":\"ConvoAlreadyExists\",\"message\":\"caller lost first-responder race\"}"
                .to_string(),
        );
        assert!(
            is_create_convo_race_loss(&err),
            "409 with ConvoAlreadyExists in body must classify as race loss"
        );
    }

    #[test]
    fn is_create_convo_race_loss_rejects_other_409_codes() {
        let err = CatmosError::Xrpc(
            "blue.catbird.mlsChat.commitGroupChange returned 409 Conflict: \
             {\"error\":\"EpochMismatch\",\"message\":\"...\"}"
                .to_string(),
        );
        assert!(
            !is_create_convo_race_loss(&err),
            "409 with non-ConvoAlreadyExists code must not classify"
        );
    }

    #[test]
    fn is_create_convo_race_loss_rejects_non_409_statuses() {
        // Same body string, wrong status: must not classify.
        let err = CatmosError::Xrpc(
            "blue.catbird.mlsChat.createConvo returned 500 Internal Server Error: \
             {\"error\":\"ConvoAlreadyExists\"}"
                .to_string(),
        );
        assert!(
            !is_create_convo_race_loss(&err),
            "non-409 statuses must not classify even with matching body"
        );

        let err = CatmosError::Network("connection refused".into());
        assert!(
            !is_create_convo_race_loss(&err),
            "non-Xrpc variants must not classify"
        );
    }
}
