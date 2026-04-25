//! `RecoveryState` — the spec §8.1 conversation recovery state machine.
//!
//! Mirrors iOS `ConversationRecoveryState`: persisted states are derived from
//! boolean+payload columns on `conversations` (see
//! `catmos-core/src/storage/db.rs`); transient states (`Recovering`,
//! `GroupMissing`) live in-memory only.

/// Persisted recovery flags loaded from the `conversations` row.
///
/// All fields are populated from the DB columns added by the
/// recovery-state-machine migration. The order of precedence when collapsing
/// these into a `RecoveryState` is:
///
/// 1. `RESET_PENDING` (most urgent — Phase 1 of deferred recovery)
/// 2. `UNRECOVERABLE_LOCAL` (terminal local — only server reset can rescue)
/// 3. `NEEDS_REJOIN` (Phase 2 of deferred recovery)
/// 4. `HEALTHY` (default)
#[derive(Debug, Clone, Default)]
pub struct PersistedRecoveryFlags {
    pub needs_rejoin: bool,
    pub unrecoverable_local: bool,
    /// Set when the server has notified us via `GroupResetEvent` and we have
    /// not yet adopted the new group. The triple is only meaningful when
    /// `needs_reset` is true.
    pub reset: Option<ResetPendingPayload>,
    pub recovery_attempt_count: u32,
    pub last_rejoin_attempt_ms: Option<i64>,
}

/// Server-initiated group-reset payload that survives restart (spec §8.2,
/// §8.6). `notified_at_ms` is `chrono::Utc::now().timestamp_millis()` at the
/// moment the WS event was received.
#[derive(Debug, Clone)]
pub struct ResetPendingPayload {
    pub new_group_id: String,
    pub reset_generation: i64,
    pub notified_at_ms: i64,
}

/// Spec §8.1 conversation states. catmos-cli persists three of them
/// (`NeedsRejoin`, `UnrecoverableLocal`, `ResetPending`); the rest are
/// transient.
#[derive(Debug, Clone)]
pub enum RecoveryState {
    /// Default. Not persisted.
    Healthy,
    /// Sync detected the local MLS group is gone. Transient.
    GroupMissing,
    /// External Commit in flight (we hold the rejoin lock). Transient.
    Recovering,
    /// Persisted. Awaiting deferred recovery.
    NeedsRejoin,
    /// Persisted, terminal locally. Only a server `GroupResetEvent` can
    /// transition out of this state.
    UnrecoverableLocal,
    /// Persisted, with payload. Highest deferred-recovery priority.
    ResetPending(ResetPendingPayload),
}

impl RecoveryState {
    /// Derive the spec state from the persisted flags. Mirrors the iOS
    /// `MLSConversationModel.persistedRecoveryState` computed property.
    pub fn from_flags(flags: &PersistedRecoveryFlags) -> Self {
        if let Some(ref payload) = flags.reset {
            return RecoveryState::ResetPending(payload.clone());
        }
        if flags.unrecoverable_local {
            return RecoveryState::UnrecoverableLocal;
        }
        if flags.needs_rejoin {
            return RecoveryState::NeedsRejoin;
        }
        RecoveryState::Healthy
    }

    pub fn is_persisted(&self) -> bool {
        matches!(
            self,
            RecoveryState::NeedsRejoin
                | RecoveryState::UnrecoverableLocal
                | RecoveryState::ResetPending(_)
        )
    }
}
