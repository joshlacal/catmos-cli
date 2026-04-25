//! MLS Client Protocol §10 constants — single source of truth for catmos-cli.
//!
//! These values MUST match `catbird-mls/src/orchestrator/constants.rs` exactly
//! (catmos-cli uses `MLSContext` directly rather than the orchestrator, so the
//! constants are duplicated by necessity, not by design). Spec §10 is the
//! authoritative source — any divergence between this file and the spec is a
//! bug.
//!
//! Spec: docs/MLS_CLIENT_PROTOCOL.md §8 (Recovery), §10 (Constants).

use std::time::Duration;

// ── §10 Recovery ────────────────────────────────────────────────────────

/// Consecutive `WrongEpoch` / merge-failure events that flip a conversation
/// to `NEEDS_REJOIN` (spec §8.2).
pub const EPOCH_DIVERGENCE_THRESHOLD: u32 = 5;

/// Consecutive decryption failures at the same epoch that flip a conversation
/// to `NEEDS_REJOIN` (spec §8.2).
pub const DECRYPTION_FAILURE_THRESHOLD: u32 = 3;

/// Per-conversation rejoin attempt cap before transitioning to
/// `UNRECOVERABLE_LOCAL` and reporting to the server (§8.6).
pub const MAX_REJOIN_ATTEMPTS: u32 = 3;

/// Consecutive 404s on `getGroupState`/groupInfo that suspend rejoin attempts
/// for a conversation (§8.3 circuit breaker).
pub const GROUPINFO_404_CIRCUIT_BREAKER: u32 = 3;

/// Hard global floor on the interval between any two External Commit rejoin
/// attempts across ALL conversations. Process-wide. Enforced even when prior
/// attempts succeeded — the goal is to bound epoch inflation from concurrent
/// recoveries (§8.4 / §10).
pub const MIN_REJOIN_INTERVAL: Duration = Duration::from_secs(30);

/// After a SUCCESSFUL External Commit rejoin, suppress sync-triggered rejoin
/// attempts on the same conversation for this duration. Prevents spirals where
/// a successful rejoin loses local state (transactional rollback, etc.) and
/// each subsequent sync re-rejoins, advancing the server epoch on every loop.
pub const SUCCESSFUL_REJOIN_COOLDOWN: Duration = Duration::from_secs(300);

// ── §10 Own-Commit TTL ──────────────────────────────────────────────────

/// SHA-256 own-commit dedup entries expire after this duration (spec §10).
pub const OWN_COMMIT_TTL: Duration = Duration::from_secs(300);

// ── §10 Send Recovery ──────────────────────────────────────────────────

pub const SEND_SYNC_BATCH_SIZE: u32 = 50;
pub const SEND_SYNC_MAX_ROUNDS: u32 = 3;

// ── §10 Rejoin Backoff ─────────────────────────────────────────────────

/// Per-conversation rejoin backoff, indexed by 1-based attempt number:
/// attempt 1 → 30s, attempt 2 → 2m, attempt 3 → 10m. After
/// `MAX_REJOIN_ATTEMPTS` attempts the conversation transitions to
/// `UNRECOVERABLE_LOCAL` and stops retrying locally.
pub const REJOIN_BACKOFF: [Duration; 3] = [
    Duration::from_secs(30),
    Duration::from_secs(120),
    Duration::from_secs(600),
];

// ── §8.5 Deferred Recovery Cadence ─────────────────────────────────────

/// Pause between conversations during deferred recovery to avoid thundering
/// herd against the DS (spec §8.5).
pub const DEFERRED_RECOVERY_PAUSE: Duration = Duration::from_millis(200);
