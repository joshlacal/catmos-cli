//! Recovery state machine for catmos-cli (spec §8).
//!
//! This is the platform-layer implementation of the 7-state conversation
//! recovery machine described in `docs/MLS_CLIENT_PROTOCOL.md §8`. catmos-cli
//! uses `MLSContext` directly (no `MLSOrchestrator`), so the invariants the
//! Rust orchestrator enforces internally for catmos / WASM clients are
//! reimplemented here in the catmos-core layer.
//!
//! The shape mirrors:
//! - iOS: `MLSRecoveryManager` + `MLSConversationModel.persistedRecoveryState`
//! - Rust orchestrator: `RecoveryTracker`, `GroupInfo404Tracker`
//!
//! Constants come from [`constants`]; values match
//! `catbird-mls/src/orchestrator/constants.rs` exactly.

pub mod constants;
pub mod state;
pub mod tracker;

pub use state::{PersistedRecoveryFlags, RecoveryState, ResetPendingPayload};
pub use tracker::{GroupInfo404Tracker, RecoveryTracker};
