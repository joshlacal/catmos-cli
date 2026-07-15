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
use crate::recovery::{
    constants, QuarantineDecision, QuarantineExitReason, QuarantineReason, RecoveryState,
    ResetPendingPayload,
};

/// `failureType` strings the server understands (§8.6).
const FAILURE_EXTERNAL_COMMIT_EXHAUSTED: &str = "external_commit_exhausted";
const FAILURE_REMOTE_DATA_ERROR: &str = "remote_data_error";
const FAILURE_USER_INITIATED_QUARANTINE: &str = "user_initiated_quarantine";

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

/// Phase 2.5 (`docs/plans/phase-2-5-indirect-funneling.md` §3): resolve the
/// candidate `new_group_id` that this client will race-bootstrap to. Mirrors
/// `MLSOrchestrator::record_reset_requested` in
/// `catbird-mls/src/orchestrator/recovery.rs:1430-1456`.
///
/// - When the server supplied a non-empty `expected_new_mls_group_id` (the
///   admin/bootstrap direct flow), use it as-is — the server has authority.
/// - When the server omitted it (the dominant indirect case per locked
///   decision §1: server NEVER mints `mls_group_id` outside the chokepoint),
///   mint a fresh UUIDv4-style 32-hex-char id locally. The
///   `crypto_sessions UNIQUE (conversation_id, generation)` constraint
///   serializes the race winner; losers get `AlreadyBootstrapped` and fall
///   back to Welcome on the next deferred-recovery cycle.
///
/// Returns `(new_group_id, was_minted)`. `was_minted = true` indicates we
/// generated the id locally (use this for telemetry / log fidelity).
fn resolve_reset_candidate_group_id(expected: Option<&str>) -> (String, bool) {
    match expected {
        Some(hex_id) if !hex_id.is_empty() => (hex_id.to_string(), false),
        _ => (format!("{:032x}", uuid::Uuid::new_v4().as_u128()), true),
    }
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

/// Whether an error represents a `bootstrapResetGroup` race-loss: the server
/// returned 409 with the `AlreadyBootstrapped` lexicon error code, meaning
/// another caller already populated `group_info` on the post-reset row for
/// `(originalConvoId, newGroupId)` (mls-ds task #17).
///
/// Race-losers MUST discard their local pre-bootstrap MLS group and fall back
/// to Welcome on the next deferred-recovery cycle. They MUST NOT clear
/// `reset_pending` — leaving it set keeps the convo in the ladder so step 1
/// (Welcome) picks up the winner's published Welcome.
///
/// Substring-matching the flattened `CatmosError::Xrpc("{nsid} returned
/// {status}: {body}")` is the cheapest reliable detection on this platform.
/// See the parallel orchestrator-side helper (likely renamed during the
/// catmos-impl fix-forward — task #18) for the structured-variant version
/// FFI clients use.
pub(crate) fn is_bootstrap_already_bootstrapped(err: &CatmosError) -> bool {
    let msg = err.to_string();
    msg.contains("returned 409") && msg.contains("AlreadyBootstrapped")
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
    // ── Layer 3 quarantine ─────────────────────────────────────────────

    /// True when the conversation is quarantined in memory or in persisted
    /// flags. The persisted read keeps send/rejoin gates effective after a
    /// process restart before any new bad commit rehydrates the tracker.
    pub(crate) async fn is_quarantined(&self, convo_id: &str) -> bool {
        if self.recovery_tracker.lock().await.is_quarantined(convo_id) {
            return true;
        }
        self.db
            .get_recovery_flags(convo_id)
            .await
            .ok()
            .and_then(|flags| flags.quarantine)
            .is_some()
    }

    /// Classify a commit-processing error as peer-bad (Layer 3 Signal A/B).
    /// If local state is behind the message context, treat it as catch-up
    /// instead of peer poisoning.
    pub(crate) fn classify_peer_bad_error(
        err: &CatmosError,
        local_epoch: Option<u64>,
        message_epoch: u64,
    ) -> bool {
        if let Some(local) = local_epoch {
            if local < message_epoch {
                return false;
            }
        }
        let CatmosError::Mls(mls_err) = err else {
            return false;
        };
        if mls_err.is_wrong_epoch() {
            return false;
        }
        match mls_err {
            catbird_mls::MLSError::InvalidCommit
            | catbird_mls::MLSError::WireFormatPolicyViolation { .. }
            | catbird_mls::MLSError::InvalidProposalRef
            | catbird_mls::MLSError::TlsCodec(_) => true,
            catbird_mls::MLSError::CommitProcessingFailed { message }
            | catbird_mls::MLSError::OpenMLS(message) => {
                let m = message.to_lowercase();
                m.contains("leafnodevalidation")
                    || m.contains("invalidgroupinfo")
                    || m.contains("authenticationfailed")
                    || m.contains("invalidcredential")
                    || m.contains("proposalvalidationerror")
            }
            _ => false,
        }
    }

    /// Record a peer-bad commit observation. Returns true when this call put
    /// the conversation into quarantine.
    pub(crate) async fn note_peer_bad_commit(
        &self,
        convo_id: &str,
        message_id: &str,
        sender_did: Option<&str>,
    ) -> bool {
        let decision = {
            let mut tracker = self.recovery_tracker.lock().await;
            tracker.record_peer_bad_commit(convo_id, sender_did, message_id)
        };
        let QuarantineDecision::Quarantine {
            reason,
            suspected_dids,
        } = decision
        else {
            return false;
        };
        self.enter_quarantine(convo_id, reason, suspected_dids)
            .await;
        true
    }

    pub(crate) async fn enter_quarantine(
        &self,
        convo_id: &str,
        reason: QuarantineReason,
        suspected_dids: Vec<String>,
    ) {
        if self.is_quarantined(convo_id).await {
            return;
        }
        let since_ms = chrono::Utc::now().timestamp_millis();
        {
            let mut tracker = self.recovery_tracker.lock().await;
            tracker.mark_quarantined(convo_id);
        }
        self.reset_recovery_counters(convo_id).await;
        if let Err(e) = self
            .db
            .mark_quarantined(convo_id, reason, since_ms, &suspected_dids)
            .await
        {
            warn!(
                convo = %&convo_id[..12.min(convo_id.len())],
                error = %e,
                "Failed to persist quarantine state"
            );
        }
        let _ = self
            .quarantine_events
            .send(super::service::QuarantineEvent::Entered {
                convo_id: convo_id.to_string(),
                reason,
                suspected_dids: suspected_dids.clone(),
                since_ms,
            });
        warn!(
            convo = %&convo_id[..12.min(convo_id.len())],
            reason = reason.tag(),
            suspected_count = suspected_dids.len(),
            "Conversation quarantined; suppressing auto-rejoin"
        );
    }

    pub(crate) async fn exit_quarantine(&self, convo_id: &str, via: QuarantineExitReason) {
        let was_persisted = self
            .db
            .get_recovery_flags(convo_id)
            .await
            .ok()
            .and_then(|flags| flags.quarantine)
            .is_some();
        let was_quarantined = {
            let mut tracker = self.recovery_tracker.lock().await;
            tracker.clear_quarantine(convo_id)
        };
        if let Err(e) = self.db.clear_quarantine(convo_id).await {
            warn!(
                convo = %&convo_id[..12.min(convo_id.len())],
                error = %e,
                "Failed to clear persisted quarantine state"
            );
        }
        if was_quarantined || was_persisted {
            let _ = self
                .quarantine_events
                .send(super::service::QuarantineEvent::Cleared {
                    convo_id: convo_id.to_string(),
                    via,
                });
            info!(
                convo = %&convo_id[..12.min(convo_id.len())],
                via = via.tag(),
                "Conversation quarantine cleared"
            );
        }
    }

    pub(crate) async fn note_healthy_peer_commit(&self, convo_id: &str) {
        if self.is_quarantined(convo_id).await {
            self.exit_quarantine(convo_id, QuarantineExitReason::PeerCommitSucceeded)
                .await;
        } else {
            self.recovery_tracker
                .lock()
                .await
                .record_healthy_peer_commit(convo_id);
        }
    }

    /// User-confirmed manual reset for a quarantined conversation. This feeds
    /// the server reset-vote path, then clears local quarantine so the deferred
    /// reset ladder can proceed from the next server event.
    pub async fn user_confirmed_manual_reset(&self, convo_id: &str) -> Result<()> {
        self.report_recovery_failure(convo_id, FAILURE_USER_INITIATED_QUARANTINE)
            .await;
        self.exit_quarantine(convo_id, QuarantineExitReason::UserConfirmedReset)
            .await;
        Ok(())
    }

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
        if self.is_quarantined(convo_id).await {
            return false;
        }
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
        if self.is_quarantined(convo_id).await {
            return false;
        }
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
        if self.is_quarantined(convo_id).await {
            debug!(
                convo = %&convo_id[..12.min(convo_id.len())],
                "Suppressing NEEDS_REJOIN because conversation is quarantined"
            );
            return;
        }
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
            FAILURE_USER_INITIATED_QUARANTINE => Some("group_state_unrecoverable"),
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
        self.external_commit_rejoin_with_policy(convo_id, true)
            .await
    }

    async fn external_commit_rejoin_with_policy(
        &self,
        convo_id: &str,
        clear_needs_rejoin_on_success: bool,
    ) -> Result<()> {
        let convo_label = &convo_id[..12.min(convo_id.len())];

        // 1. Gate on tracker (max-attempts / per-convo cooldown / global floor)
        {
            let tracker = self.recovery_tracker.lock().await;
            if tracker.is_quarantined(convo_id) {
                return Err(CatmosError::Other(format!(
                    "Rejoin suppressed for {convo_label}: conversation quarantined"
                )));
            }
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
        if self.groupinfo_404_tracker.lock().await.is_tripped(convo_id) {
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
                    self.groupinfo_404_tracker.lock().await.record_404(convo_id);
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
                self.groupinfo_404_tracker.lock().await.clear(convo_id);
                self.reset_recovery_counters(convo_id).await;
                if clear_needs_rejoin_on_success {
                    if let Err(e) = self.db.clear_needs_rejoin(convo_id).await {
                        warn!(
                            convo = %convo_label,
                            error = %e,
                            "Failed to clear NEEDS_REJOIN flag after success"
                        );
                    }
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
                    self.groupinfo_404_tracker.lock().await.record_404(convo_id);
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
    async fn transition_unrecoverable_local_with_reason(&self, convo_id: &str, failure_type: &str) {
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
            self.groupinfo_404_tracker.lock().await.clear(convo_id);

            // Step 1: try Welcome. Cheapest, no MLS state mutation.
            if let Some((winner_group_id, landed_epoch)) = self.try_pending_welcome(convo_id).await
            {
                let adopted = match self
                    .db
                    .adopt_reset_pending_target(
                        convo_id,
                        payload.reset_generation,
                        &payload.new_group_id,
                        &winner_group_id,
                    )
                    .await
                {
                    Ok(true) => true,
                    Ok(false) => self
                        .db
                        .reset_pending_matches(convo_id, payload.reset_generation, &winner_group_id)
                        .await
                        .unwrap_or(false),
                    Err(e) => {
                        warn!(
                            convo = %&convo_id[..12.min(convo_id.len())],
                            error = %e,
                            "deferred_recovery: winner-target CAS errored; rereading commit-ambiguous authority"
                        );
                        self.db
                            .reset_pending_matches(
                                convo_id,
                                payload.reset_generation,
                                &winner_group_id,
                            )
                            .await
                            .unwrap_or(false)
                    }
                };
                if adopted {
                    match self
                        .db
                        .complete_reset_pending(
                            convo_id,
                            payload.reset_generation,
                            &winner_group_id,
                            landed_epoch,
                        )
                        .await
                    {
                        Ok(true) => info!(
                            convo = %&convo_id[..12.min(convo_id.len())],
                            group = %winner_group_id,
                            "deferred_recovery: RESET_PENDING adopted via verified Welcome"
                        ),
                        Ok(false) => warn!(
                            convo = %&convo_id[..12.min(convo_id.len())],
                            "deferred_recovery: exact RESET_PENDING completion lost its CAS"
                        ),
                        Err(e) => warn!(
                            convo = %&convo_id[..12.min(convo_id.len())],
                            error = %e,
                            "deferred_recovery: exact RESET_PENDING completion errored"
                        ),
                    }
                }
                tokio::time::sleep(constants::DEFERRED_RECOVERY_PAUSE).await;
                continue;
            }

            // Step 2: try External Commit. Internally fetches GroupInfo;
            // returns Err with `is_group_info_unavailable` when the server has
            // none yet (post-reset window before any responder publishes).
            match self
                .external_commit_rejoin_with_policy(convo_id, false)
                .await
            {
                Ok(()) => {
                    let authoritative = self.fetch_authoritative_group_id(convo_id).await;
                    if matches!(&authoritative, Ok(Some(group)) if group == &payload.new_group_id) {
                        let landed_epoch = match hex::decode(&payload.new_group_id)
                            .map_err(|e| e.to_string())
                            .and_then(|group_id| {
                                self.mls
                                    .with_context(|ctx| ctx.get_epoch(group_id))
                                    .map_err(|e| e.to_string())
                            }) {
                            Ok(epoch) => epoch,
                            Err(error) => {
                                warn!(
                                    convo = %&convo_id[..12.min(convo_id.len())],
                                    error = %error,
                                    "deferred_recovery: refusing External Commit completion without target epoch"
                                );
                                tokio::time::sleep(constants::DEFERRED_RECOVERY_PAUSE).await;
                                continue;
                            }
                        };
                        match self
                            .db
                            .complete_reset_pending(
                                convo_id,
                                payload.reset_generation,
                                &payload.new_group_id,
                                landed_epoch,
                            )
                            .await
                        {
                            Ok(true) => {}
                            Ok(false) => warn!(
                                convo = %&convo_id[..12.min(convo_id.len())],
                                "deferred_recovery: External Commit completion lost its exact reset CAS"
                            ),
                            Err(e) => warn!(
                                convo = %&convo_id[..12.min(convo_id.len())],
                                error = %e,
                                "deferred_recovery: External Commit completion errored"
                            ),
                        }
                    } else {
                        warn!(
                            convo = %&convo_id[..12.min(convo_id.len())],
                            expected_group = %payload.new_group_id,
                            "deferred_recovery: preserving RESET_PENDING because fresh server view did not bind External Commit target"
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
        self.groupinfo_404_tracker.lock().await.clear(convo_id);
        self.reset_recovery_counters(convo_id).await;
        self.exit_quarantine(convo_id, QuarantineExitReason::ServerReset)
            .await;
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

    /// Phase 2.5 (`docs/plans/phase-2-5-indirect-funneling.md` §3, §5 Stage 2):
    /// persist a `RESET_PENDING` payload received via the new
    /// `resetRequestedEvent` SSE event. Called from the WebSocket layer when a
    /// `WsEvent::ResetRequested` arrives.
    ///
    /// **Architectural note.** catmos-cli does not instantiate
    /// `MLSOrchestrator`; it talks to `MLSContext` directly via
    /// `MlsManager::with_context`. The orchestrator-side equivalent of this
    /// function is `MLSOrchestrator::record_reset_requested` in
    /// `catbird-mls/src/orchestrator/recovery.rs:1387`. We mirror its
    /// observable contract here (idempotency on `(convo_id, generation)`,
    /// candidate-id minting when `expected_new_mls_group_id` is `None`,
    /// `RESET_PENDING` persistence + tracker clears) so a future refactor
    /// that introduces an orchestrator instance can drop in
    /// `record_reset_requested` and delete this helper.
    ///
    /// **`expected_new_mls_group_id == None` is the Phase 2.5 case** — the
    /// server never mints group ids for indirect triggers (locked decision
    /// §1). When `None`, mint a fresh UUIDv4-style 32-hex-char id locally as
    /// our race-bootstrap candidate (matches
    /// `recovery.rs:1444`). When `Some(_)` (admin/bootstrap direct flow),
    /// use it directly (matches `recovery.rs:1431-1442`).
    ///
    /// **Stage 1 dual-emission safety**: during the migration window the
    /// server emits BOTH `groupResetEvent` AND `resetRequestedEvent` for the
    /// same trigger (plan §5 Stage 1). Both handlers write to the same
    /// `(reset_new_group_id, reset_generation)` columns, so receiving them
    /// in either order at the same generation is safe — the persisted state
    /// converges. Within this handler, idempotency guards against a single
    /// `resetRequestedEvent` arriving twice (SSE reconnect, cursor replay)
    /// at the same generation: we skip the write.
    pub async fn handle_reset_requested_event(
        &self,
        convo_id: &str,
        crypto_session_id: &str,
        generation: i64,
        trigger: &str,
        request_event_id: &str,
        expected_new_mls_group_id: Option<&str>,
    ) {
        // Idempotency check: if we already persisted RESET_PENDING at this
        // generation, drop the duplicate. Mirrors
        // `MLSOrchestrator::record_reset_requested` recovery.rs:1400-1411.
        match self.db.get_recovery_flags(convo_id).await {
            Ok(flags) => {
                if let Some(payload) = flags.reset.as_ref() {
                    if payload.reset_generation == generation {
                        info!(
                            convo = %&convo_id[..12.min(convo_id.len())],
                            crypto_session = %&crypto_session_id[..12.min(crypto_session_id.len())],
                            generation,
                            trigger,
                            request_event_id = %&request_event_id[..16.min(request_event_id.len())],
                            existing_new_group_id = %payload.new_group_id,
                            "resetRequestedEvent: already in RESET_PENDING at this generation, idempotent no-op"
                        );
                        return;
                    }
                    info!(
                        convo = %&convo_id[..12.min(convo_id.len())],
                        old_generation = payload.reset_generation,
                        new_generation = generation,
                        trigger,
                        "resetRequestedEvent: superseding existing RESET_PENDING at different generation"
                    );
                }
            }
            Err(e) => {
                warn!(
                    convo = %&convo_id[..12.min(convo_id.len())],
                    error = %e,
                    "handle_reset_requested_event: failed to read recovery flags for idempotency check; proceeding"
                );
            }
        }

        // Resolve new_group_id eagerly. Mirrors recovery.rs:1430-1456:
        // server-supplied id (admin path) wins; otherwise mint a fresh
        // UUIDv4-style 32-hex-char id locally for our race-bootstrap
        // candidate. The chokepoint's `crypto_sessions UNIQUE
        // (conversation_id, generation)` constraint serializes the winner;
        // race losers see HTTP 409 `AlreadyBootstrapped` and drop their
        // pre-bootstrap MLS group cleanly via the existing
        // `try_first_responder_bootstrap` race-loser branch.
        let (new_group_id, was_minted) =
            resolve_reset_candidate_group_id(expected_new_mls_group_id);
        if was_minted {
            info!(
                convo = %&convo_id[..12.min(convo_id.len())],
                crypto_session = %&crypto_session_id[..12.min(crypto_session_id.len())],
                generation,
                trigger,
                new_group_id = %new_group_id,
                "resetRequestedEvent: no expected_new_mls_group_id from server, minting client-side candidate for first-responder bootstrap"
            );
        } else {
            info!(
                convo = %&convo_id[..12.min(convo_id.len())],
                crypto_session = %&crypto_session_id[..12.min(crypto_session_id.len())],
                generation,
                trigger,
                new_group_id = %new_group_id,
                "resetRequestedEvent: server-supplied expected_new_mls_group_id, using it directly"
            );
        }

        let notified_at_ms = chrono::Utc::now().timestamp_millis();
        if let Err(e) = self
            .db
            .mark_reset_pending(convo_id, &new_group_id, generation, notified_at_ms)
            .await
        {
            warn!(
                convo = %&convo_id[..12.min(convo_id.len())],
                error = %e,
                "handle_reset_requested_event: failed to persist RESET_PENDING"
            );
            return;
        }

        // Mirrors handle_group_reset_event: server reset clears all local
        // retry counters and the unrecoverable flag — this is a fresh
        // start (§8.6).
        self.recovery_tracker.lock().await.clear_convo(convo_id);
        self.groupinfo_404_tracker.lock().await.clear(convo_id);
        self.reset_recovery_counters(convo_id).await;
        self.exit_quarantine(convo_id, QuarantineExitReason::ServerReset)
            .await;
        if let Err(e) = self.db.clear_unrecoverable_local(convo_id).await {
            warn!(
                convo = %&convo_id[..12.min(convo_id.len())],
                error = %e,
                "handle_reset_requested_event: failed to clear UNRECOVERABLE_LOCAL"
            );
        }
        info!(
            phase_2_5_path = "request_only",
            convo = %&convo_id[..12.min(convo_id.len())],
            crypto_session = %&crypto_session_id[..12.min(crypto_session_id.len())],
            new_group = %&new_group_id[..12.min(new_group_id.len())],
            generation,
            trigger,
            request_event_id = %&request_event_id[..16.min(request_event_id.len())],
            "Persisted RESET_PENDING from resetRequestedEvent"
        );
    }

    // ── §8.5 Phase 1 ladder helpers (Welcome → ExternalCommit → Bootstrap) ──

    /// Try to adopt the post-reset group via a server-published Welcome.
    /// Returns the processed group only when a fresh server conversation view
    /// binds it to this stable conversation. Returns `None` if no Welcome is
    /// available, processing failed, or the authoritative binding is absent
    /// (the
    /// caller falls through to the next ladder step in either case — a
    /// processing failure here is not fatal because External Commit and
    /// bootstrap remain as fallbacks).
    async fn try_pending_welcome(&self, convo_id: &str) -> Option<(String, u64)> {
        let convo_label = &convo_id[..12.min(convo_id.len())];
        let welcome_b64 = match self.mls.fetch_pending_welcome(self, convo_id).await {
            Ok(Some(w)) => w,
            Ok(None) => return None,
            Err(e) => {
                debug!(
                    convo = %convo_label,
                    error = %e,
                    "try_pending_welcome: getGroupState include=welcome failed"
                );
                return None;
            }
        };

        let did = self.did().to_string();
        match self.mls.process_welcome_b64(&welcome_b64, &did) {
            Ok(group_id) => {
                let group_id_hex = hex::encode(&group_id);
                match self.fetch_authoritative_group_id(convo_id).await {
                    Ok(Some(authoritative_group)) if authoritative_group == group_id_hex => {}
                    Ok(Some(authoritative_group)) => {
                        warn!(
                            convo = %convo_label,
                            processed_group = %group_id_hex,
                            authoritative_group = %authoritative_group,
                            "try_pending_welcome: processed Welcome is not the authoritative server group"
                        );
                        let _ = self.mls.with_context(|ctx| {
                            let _ = ctx.delete_group(group_id.clone());
                            Ok::<_, catbird_mls::MLSError>(())
                        });
                        return None;
                    }
                    Ok(None) => {
                        warn!(
                            convo = %convo_label,
                            group = %group_id_hex,
                            "try_pending_welcome: stable conversation absent from fresh server view; preserving local group and reset authority"
                        );
                        return None;
                    }
                    Err(e) => {
                        warn!(
                            convo = %convo_label,
                            group = %group_id_hex,
                            error = %e,
                            "try_pending_welcome: authoritative server binding unavailable; preserving local group and reset authority"
                        );
                        return None;
                    }
                }
                info!(
                    convo = %convo_label,
                    group = %group_id_hex,
                    "try_pending_welcome: adopted post-reset group via Welcome"
                );
                // Encrypted-bootstrap: the post-reset group has a fresh
                // exporter; the resetter has re-published metadata under
                // (convoId, resetGeneration, kind) and we can pick it up
                // immediately via bootstrap_group_metadata.
                if let Err(e) = self.bootstrap_group_metadata(convo_id, &group_id_hex).await {
                    warn!(
                        convo = %convo_label,
                        error = %e,
                        "try_pending_welcome: bootstrap_group_metadata failed (non-fatal; will retry next cycle)"
                    );
                }
                let landed_epoch = match self.mls.with_context(|ctx| ctx.get_epoch(group_id)) {
                    Ok(epoch) => epoch,
                    Err(e) => {
                        warn!(
                            convo = %convo_label,
                            group = %group_id_hex,
                            error = %e,
                            "try_pending_welcome: refusing reset completion without target epoch"
                        );
                        return None;
                    }
                };
                Some((group_id_hex, landed_epoch))
            }
            Err(e) => {
                warn!(
                    convo = %convo_label,
                    error = %e,
                    "try_pending_welcome: process_welcome failed (will retry next cycle)"
                );
                None
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
    async fn try_first_responder_bootstrap(&self, convo_id: &str, payload: &ResetPendingPayload) {
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
        let cipher_suite = cipher_suite.unwrap_or_else(|| crate::mls::MLS_CIPHER_SUITE.to_string());

        info!(
            convo = %convo_label,
            new_group = %payload.new_group_id,
            roster_size = roster.len(),
            cipher_suite = %cipher_suite,
            "bootstrap: creating local MLS group at predetermined id"
        );

        // 1. Create local MLS group AT the predetermined id, then export its
        // GroupInfo so the server-side row at (originalConvoId, newGroupId)
        // can be UPDATEd in place with our genesis blob.
        let did = self.did().to_string();
        let identity_bytes = did.as_bytes().to_vec();
        if let Err(e) = self.mls.with_context(|ctx| {
            let _ =
                ctx.create_group_with_id(identity_bytes.clone(), new_group_id_bytes.clone(), None)?;
            Ok(())
        }) {
            warn!(
                convo = %convo_label,
                error = %e,
                "bootstrap: create_group_with_id failed; will retry next cycle"
            );
            return;
        }

        let group_info_bytes = match self.mls.with_context(|ctx| {
            ctx.export_group_info(new_group_id_bytes.clone(), identity_bytes.clone())
        }) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    convo = %convo_label,
                    error = %e,
                    "bootstrap: export_group_info failed; dropping local group, will retry next cycle"
                );
                let _ = self.mls.with_context(|ctx| {
                    let _ = ctx.delete_group(new_group_id_bytes.clone());
                    Ok(())
                });
                return;
            }
        };

        // 2a. Republish encrypted metadata against the new group epoch so the
        // declared locator on `bootstrapResetGroup` matches a live blob the
        // server can serve to joiners. Best-effort: if there's nothing to
        // re-encrypt (no prior local metadata) we skip and pass None on to
        // the bootstrap call. Per Phase E of the metadata cutover plan.
        let (republished_locator, republished_version) = match self
            .republish_metadata_after_reset(convo_id, &new_group_id_bytes, payload.reset_generation)
            .await
        {
            Ok(out) => out,
            Err(e) => {
                warn!(
                    convo = %convo_label,
                    error = %e,
                    "bootstrap: republish_metadata_after_reset failed; bootstrapping without metadata declaration"
                );
                (None, None)
            }
        };

        // 2b. Submit to server via bootstrapResetGroup. The bootstrap roster
        // ships the FULL membership including the caller — server uses the
        // persisted members table (preserved across reset) as the
        // authoritative roster and treats this list as a diagnostic/audit
        // hint per the lexicon's `members` field doc.
        let submit_result = self
            .bootstrap_reset_group(
                convo_id,
                &payload.new_group_id,
                &cipher_suite,
                &roster,
                group_info_bytes,
                republished_locator.as_deref(),
                republished_version,
            )
            .await;

        let landed_epoch = match self
            .mls
            .with_context(|ctx| ctx.get_epoch(new_group_id_bytes.clone()))
        {
            Ok(epoch) => epoch,
            Err(e) => {
                warn!(
                    convo = %convo_label,
                    error = %e,
                    "bootstrap: refusing reset completion without target epoch"
                );
                return;
            }
        };

        match submit_result {
            Ok(()) => {
                info!(
                    convo = %convo_label,
                    new_group = %payload.new_group_id,
                    reset_generation = payload.reset_generation,
                    "bootstrap: race won — clearing RESET_PENDING"
                );
                match self
                    .db
                    .complete_reset_pending(
                        convo_id,
                        payload.reset_generation,
                        &payload.new_group_id,
                        landed_epoch,
                    )
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => warn!(
                        convo = %convo_label,
                        "bootstrap: exact RESET_PENDING completion lost its CAS"
                    ),
                    Err(e) => warn!(
                        convo = %convo_label,
                        error = %e,
                        "bootstrap: exact RESET_PENDING completion errored"
                    ),
                }
            }
            Err(e) if is_bootstrap_already_bootstrapped(&e) => {
                info!(
                    convo = %convo_label,
                    new_group = %payload.new_group_id,
                    reset_generation = payload.reset_generation,
                    "bootstrap: race lost (AlreadyBootstrapped) — dropping local pre-bootstrap group; next cycle will retry Welcome"
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
                    "bootstrap: bootstrapResetGroup failed; dropping local group, will retry next cycle"
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
    async fn fetch_member_roster_for_bootstrap(&self, convo_id: &str) -> Result<Vec<String>> {
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

    /// Fetch the unique current group bound to a stable conversation ID.
    /// Ambiguous duplicate rows fail closed.
    async fn fetch_authoritative_group_id(&self, convo_id: &str) -> Result<Option<String>> {
        let resp: super::messages::GetConvosResp = self
            .xrpc_query(catbird_atproto::catbird::mls_chat::get_convos::NSID, &[])
            .await?;
        let mut matches = resp.conversations.into_iter().filter(|conversation| {
            conversation
                .conversation_id
                .as_deref()
                .unwrap_or(&conversation.group_id)
                == convo_id
        });
        let Some(first) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            return Err(CatmosError::Other(format!(
                "ambiguous authoritative conversation rows for {convo_id}"
            )));
        }
        Ok(Some(first.group_id))
    }
}

#[cfg(test)]
mod bootstrap_classifier_tests {
    use super::*;

    /// Server returns HTTP 409 with `{"error":"AlreadyBootstrapped",...}` when
    /// another caller already populated `group_info` on the post-reset row
    /// for `(originalConvoId, newGroupId)` (mls-ds task #17 endpoint).
    /// catmos-cli flattens that into
    /// `CatmosError::Xrpc("blue.catbird.mlsChat.bootstrapResetGroup returned
    /// 409 Conflict: {...}")`. The classifier must detect this exact shape
    /// and must NOT mis-classify other 409s or non-409 statuses.
    #[test]
    fn is_bootstrap_already_bootstrapped_matches_real_xrpc_shape() {
        let err = CatmosError::Xrpc(
            "blue.catbird.mlsChat.bootstrapResetGroup returned 409 Conflict: \
             {\"error\":\"AlreadyBootstrapped\",\"message\":\"caller lost first-responder race\"}"
                .to_string(),
        );
        assert!(
            is_bootstrap_already_bootstrapped(&err),
            "409 with AlreadyBootstrapped in body must classify as race loss"
        );
    }

    #[test]
    fn is_bootstrap_already_bootstrapped_rejects_other_409_codes() {
        // Sibling lexicon errors on the same endpoint (BootstrapTargetNotFound,
        // NotMember, InvalidCipherSuite) MUST NOT trigger the race-loss path.
        let err = CatmosError::Xrpc(
            "blue.catbird.mlsChat.bootstrapResetGroup returned 409 Conflict: \
             {\"error\":\"BootstrapTargetNotFound\",\"message\":\"...\"}"
                .to_string(),
        );
        assert!(
            !is_bootstrap_already_bootstrapped(&err),
            "409 with sibling lexicon error must not classify as race loss"
        );

        let err = CatmosError::Xrpc(
            "blue.catbird.mlsChat.commitGroupChange returned 409 Conflict: \
             {\"error\":\"EpochMismatch\",\"message\":\"...\"}"
                .to_string(),
        );
        assert!(
            !is_bootstrap_already_bootstrapped(&err),
            "409 from a different endpoint with a different code must not classify"
        );
    }

    #[test]
    fn is_bootstrap_already_bootstrapped_rejects_non_409_statuses() {
        // Same body string, wrong status: must not classify.
        let err = CatmosError::Xrpc(
            "blue.catbird.mlsChat.bootstrapResetGroup returned 500 Internal Server Error: \
             {\"error\":\"AlreadyBootstrapped\"}"
                .to_string(),
        );
        assert!(
            !is_bootstrap_already_bootstrapped(&err),
            "non-409 statuses must not classify even with matching body"
        );

        let err = CatmosError::Network("connection refused".into());
        assert!(
            !is_bootstrap_already_bootstrapped(&err),
            "non-Xrpc variants must not classify"
        );
    }

    #[test]
    fn peer_bad_classifier_accepts_invalid_commit_when_local_is_current() {
        let err = CatmosError::Mls(catbird_mls::MLSError::InvalidCommit);
        assert!(ChatService::classify_peer_bad_error(&err, Some(10), 10));
    }

    #[test]
    fn peer_bad_classifier_rejects_catchup_and_wrong_epoch() {
        let invalid_commit = CatmosError::Mls(catbird_mls::MLSError::InvalidCommit);
        assert!(!ChatService::classify_peer_bad_error(
            &invalid_commit,
            Some(9),
            10
        ));

        let wrong_epoch = CatmosError::Mls(catbird_mls::MLSError::OpenMLS(
            "ValidationError(WrongEpoch)".to_string(),
        ));
        assert!(!ChatService::classify_peer_bad_error(
            &wrong_epoch,
            Some(10),
            10
        ));
    }

    /// Phase 2.5 indirect case (locked decision §1): server omits
    /// `expectedNewMlsGroupId` so the client mints a candidate id locally.
    /// Mirrors orchestrator behavior at
    /// `catbird-mls/src/orchestrator/recovery.rs:1444`.
    #[test]
    fn resolve_reset_candidate_mints_when_no_expected_group_id() {
        let (id, was_minted) = resolve_reset_candidate_group_id(None);
        assert!(was_minted, "indirect trigger must mint a candidate id");
        assert_eq!(id.len(), 32, "minted id must be 32 hex chars (UUIDv4 u128)");
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "minted id must be lowercase hex: {id}"
        );

        // Two consecutive mints must produce different ids — the
        // first-responder bootstrap race relies on each client picking a
        // unique candidate.
        let (id2, _) = resolve_reset_candidate_group_id(None);
        assert_ne!(id, id2, "minted ids must be unique per call");
    }

    /// Empty-string `expectedNewMlsGroupId` is treated as "not provided" —
    /// mirrors the orchestrator-side check `if !hex_id.is_empty()` at
    /// `catbird-mls/src/orchestrator/recovery.rs:1431`. Defends against
    /// a malformed / placeholder server payload.
    #[test]
    fn resolve_reset_candidate_treats_empty_string_as_none() {
        let (id, was_minted) = resolve_reset_candidate_group_id(Some(""));
        assert!(
            was_minted,
            "empty-string expected_new_mls_group_id must fall through to mint"
        );
        assert_eq!(id.len(), 32);
    }

    /// Direct flow (admin reset, legacy bootstrap path): server-supplied id
    /// passes through unchanged. The chokepoint enforces the "admin path
    /// must always set expected_new_mls_group_id" invariant on the server
    /// side (plan §7 R1 mitigation 1); this client trusts the wire value.
    #[test]
    fn resolve_reset_candidate_passes_through_server_supplied_id() {
        let server_id = "deadbeefcafebabe0011223344556677";
        let (id, was_minted) = resolve_reset_candidate_group_id(Some(server_id));
        assert!(!was_minted, "server-supplied id must not be re-minted");
        assert_eq!(
            id, server_id,
            "server-supplied id must pass through verbatim"
        );
    }
}
