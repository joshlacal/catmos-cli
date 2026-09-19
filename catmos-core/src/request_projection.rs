//! Atomic, account-scoped UI projection. Shared Rust verifies protocol authority;
//! these transactions recheck durable host identity, incarnation and lifecycle.
use super::SqliteStorage;
use catbird_mls::orchestrator::{
    AliasRetirementAuthority, ConversationProjectionCommitMode as Mode,
    ConversationProjectionCommitOutcome as Outcome, ConversationProjectionCommitRequest,
    ConversationView, ProjectionLifecycleFence,
};
use rusqlite::{params, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq)]
struct RetiredAlias {
    owner: String,
    canonical: String,
    group: String,
    alias: String,
    canonical_epoch: u64,
    alias_epoch: u64,
    canonical_fence: serde_json::Value,
    alias_fence: serde_json::Value,
}
fn fence_value(f: &ProjectionLifecycleFence) -> serde_json::Value {
    serde_json::json!({"generation":f.generation,"version":f.state_version,"resetGeneration":f.reset_generation,"resetTarget":f.reset_pending_target_group_id})
}
impl From<&AliasRetirementAuthority> for RetiredAlias {
    fn from(a: &AliasRetirementAuthority) -> Self {
        Self {
            owner: a.owner_user_did.clone(),
            canonical: a.canonical_conversation_id.clone(),
            group: a.canonical_group_id.clone(),
            alias: a.alias_conversation_id.clone(),
            canonical_epoch: a.canonical_incarnation,
            alias_epoch: a.alias_incarnation,
            canonical_fence: fence_value(&a.canonical_lifecycle),
            alias_fence: fence_value(&a.alias_lifecycle),
        }
    }
}
struct HostRow {
    group: String,
    epoch: u64,
    state: String,
    reset: Option<String>,
    reset_generation: Option<i32>,
}
fn host(tx: &Transaction<'_>, owner: &str, id: &str) -> Result<Option<HostRow>, String> {
    tx.query_row("SELECT group_id,epoch,state,reset_new_group_id,reset_generation FROM conversations WHERE user_did=?1 AND conversation_id=?2",params![owner,id],|r|Ok(HostRow{group:r.get(0)?,epoch:r.get(1)?,state:r.get(2)?,reset:r.get(3)?,reset_generation:r.get(4)?})).optional().map_err(|_|"Projection host lookup failed".into())
}
fn lifecycle_matches(
    row: &HostRow,
    view: Option<&ConversationView>,
    f: &ProjectionLifecycleFence,
) -> bool {
    let coordinates = view
        .and_then(|v| v.canonical_state.as_ref())
        .map(|s| &s.coordinates);
    if f.generation
        .is_some_and(|v| coordinates.map(|c| c.generation) != Some(v))
        || f.state_version
            .is_some_and(|v| coordinates.map(|c| c.state_version) != Some(v))
        || f.reset_generation
            .is_some_and(|v| row.reset_generation != Some(v))
        || f.reset_pending_target_group_id
            .as_ref()
            .is_some_and(|v| row.reset.as_ref() != Some(v))
    {
        return false;
    }
    !(row.state.contains("ResetPending") || row.reset.is_some())
        || (f.reset_generation.is_some() && f.reset_pending_target_group_id.is_some())
}
impl SqliteStorage {
    fn read_projection_tx(
        &self,
        tx: &Transaction<'_>,
        owner: &str,
        id: &str,
    ) -> Result<Option<ConversationView>, String> {
        let key = format!("canonical:{id}");
        let bytes:Option<Vec<u8>>=tx.query_row("SELECT payload FROM encrypted_request_projection WHERE owner_did=?1 AND record_kind='view' AND record_id=?2",params![owner,key],|r|r.get(0)).optional().map_err(|_|"Projection read failed")?;
        bytes
            .map(|data| self.decode_request(owner, "view", &key, data))
            .transpose()
    }
    pub(super) fn canonical_projection(
        &self,
        owner: &str,
        id: &str,
    ) -> Result<Option<ConversationView>, String> {
        let scope = self
            .request_owner
            .read()
            .map_err(|_| "Account scope unavailable")?;
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| "Projection storage unavailable")?;
        let tx = conn
            .transaction()
            .map_err(|_| "Projection transaction unavailable")?;
        let key = format!("canonical:{id}");
        let present: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM encrypted_request_projection WHERE owner_did=?1 AND record_kind='view' AND record_id=?2)", params![owner,key], |r|r.get(0)).map_err(|_| "Projection lookup failed")?;
        if present && scope.as_deref() != Some(owner) {
            return Err("Account changed".into());
        }
        self.read_projection_tx(&tx, owner, id)
    }
    pub(super) fn commit_live_projection(
        &self,
        request: &ConversationProjectionCommitRequest,
    ) -> Result<Outcome, String> {
        if request.owner_user_did.is_empty()
            || (request.mode == Mode::Live) != request.canonical.is_some()
        {
            return Err("Projection mode or owner invalid".into());
        }
        let owner = &request.owner_user_did;
        let _scope = self.request_owner_guard(owner)?;
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| "Projection storage unavailable")?;
        let tx = conn
            .transaction()
            .map_err(|_| "Projection transaction unavailable")?;
        let id = request
            .canonical
            .as_ref()
            .map(|v| v.conversation_id.as_str())
            .or_else(|| {
                request
                    .aliases
                    .first()
                    .map(|a| a.canonical_conversation_id.as_str())
            })
            .ok_or("Missing canonical identity")?;
        if uuid::Uuid::parse_str(id).is_err() {
            return Err("Invalid canonical identity".into());
        }
        let previous = self.read_projection_tx(&tx, owner, id)?;
        let view = request
            .canonical
            .as_ref()
            .or(previous.as_ref())
            .ok_or("Replay requires a durable canonical projection")?;
        let group = &view.group_id;
        if hex::decode(group).map_or(true, |v| v.len() != 32) {
            return Err("Invalid MLS group identity".into());
        }
        if let Some(canonical) = &view.canonical_state {
            let c = &canonical.coordinates;
            if c.conversation_id != id
                || hex::encode(c.group_id.as_ref()) != *group
                || c.epoch < 0
                || c.epoch as u64 > view.epoch
                || !canonical
                    .participants
                    .iter()
                    .any(|p| p.user_did.to_string() == *owner)
            {
                return Err("Canonical projection identity mismatch".into());
            }
            if request.mode == Mode::Live
                && (request.canonical_lifecycle.generation != Some(c.generation)
                    || request.canonical_lifecycle.state_version != Some(c.state_version))
            {
                return Err("Canonical coordinate fence mismatch".into());
            }
        } else if !request.canonical_lifecycle.is_unknown() {
            return Err("Missing canonical policy for supplied lifecycle fence".into());
        }
        let canonical_host = host(&tx, owner, id)?;
        let mut group_advance = false;
        if let Some(old) = previous.as_ref().and_then(|v| v.canonical_state.as_ref()) {
            let new = view
                .canonical_state
                .as_ref()
                .ok_or("Cannot discard retained canonical policy")?;
            let a = &old.coordinates;
            let b = &new.coordinates;
            if (a.generation, a.state_version) > (b.generation, b.state_version)
                || ((a.generation, a.state_version) == (b.generation, b.state_version)
                    && old != new)
                || (a.generation == b.generation && a.group_id != b.group_id)
                || (a.lifecycle != "active" && b.lifecycle == "active")
            {
                return Ok(Outcome::FenceMismatch { affected_rows: 0 });
            }
            group_advance = b.generation > a.generation;
        }
        if let Some(row) = &canonical_host {
            let pending = row.reset.is_some() || row.state.contains("ResetPending");
            let reset_authorized = pending
                && request.canonical_lifecycle.reset_generation == row.reset_generation
                && request.canonical_lifecycle.reset_generation.is_some()
                && request.canonical_lifecycle.reset_pending_target_group_id == row.reset
                && row.reset.as_deref() == Some(group.as_str());
            if (pending && !reset_authorized)
                || (row.group == *group && row.epoch > view.epoch)
                || (row.group != *group && !group_advance && !reset_authorized)
                || ((row.state.contains("Closed") || row.state.contains("DeviceRemoved"))
                    && view
                        .canonical_state
                        .as_ref()
                        .is_none_or(|v| v.coordinates.lifecycle == "active"))
            {
                return Ok(Outcome::FenceMismatch { affected_rows: 0 });
            }
            if request.mode == Mode::Replay
                && (row.group != *group
                    || row.epoch != view.epoch
                    || !lifecycle_matches(row, previous.as_ref(), &request.canonical_lifecycle))
            {
                return Ok(Outcome::FenceMismatch { affected_rows: 0 });
            }
        } else if request.mode == Mode::Replay {
            return Ok(Outcome::FenceMismatch { affected_rows: 0 });
        }
        let ids = {
            let mut stmt=tx.prepare("SELECT conversation_id FROM conversations WHERE user_did=?1 AND group_id=?2 AND conversation_id<>?3").map_err(|_|"Projection owner query failed")?;
            let rows = stmt
                .query_map(params![owner, group, id], |r| r.get::<_, String>(0))
                .map_err(|_| "Projection owner query failed")?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|_| "Projection owner query failed")?
        };
        let mut canonical_ids = ids
            .into_iter()
            .filter(|id| uuid::Uuid::parse_str(id).is_ok())
            .collect::<Vec<_>>();
        if !canonical_ids.is_empty() {
            canonical_ids.push(id.to_string());
            canonical_ids.sort();
            return Ok(Outcome::Ambiguous {
                canonical_ids,
                affected_rows: 0,
            });
        }
        if request.mode == Mode::Replay || !request.aliases.is_empty() {
            let incarnation:Option<u64>=tx.query_row("SELECT epoch FROM conversation_projection_incarnations WHERE owner_did=?1 AND group_id=?2",params![owner,group],|r|r.get(0)).optional().map_err(|_|"Canonical incarnation lookup failed")?;
            if incarnation != Some(view.epoch) {
                return Ok(Outcome::FenceMismatch { affected_rows: 0 });
            }
        }
        let context = self
            .mls_context_snapshot()
            .ok_or("Protected projection storage unavailable")?;
        let mut retire = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for authority in &request.aliases {
            if authority.owner_user_did != *owner
                || authority.canonical_conversation_id != id
                || authority.canonical_group_id != *group
                || authority.alias_group_id != *group
                || authority.alias_conversation_id != *group
                || authority.alias_conversation_id == id
                || authority.canonical_incarnation != view.epoch
                || !seen.insert(authority.alias_conversation_id.clone())
            {
                return Err("Invalid alias retirement identity".into());
            }
            let proof = RetiredAlias::from(authority);
            let alias = &authority.alias_conversation_id;
            let key = format!("alias:{alias}");
            let retired:Option<Vec<u8>>=tx.query_row("SELECT payload FROM conversation_projection_aliases WHERE owner_did=?1 AND alias_id=?2",params![owner,alias],|r|r.get(0)).optional().map_err(|_|"Alias proof lookup failed")?;
            if let Some(bytes) = retired {
                let old: RetiredAlias = self.decode_request(owner, "view", &key, bytes)?;
                if old != proof {
                    return Ok(Outcome::FenceMismatch { affected_rows: 0 });
                }
                continue;
            }
            let Some(row) = host(&tx, owner, alias)? else {
                return Ok(Outcome::FenceMismatch { affected_rows: 0 });
            };
            let alias_view = self.read_projection_tx(&tx, owner, alias)?;
            let native_epoch:Option<u64>=tx.query_row("SELECT epoch FROM conversation_projection_incarnations WHERE owner_did=?1 AND group_id=?2",params![owner,authority.alias_group_id],|r|r.get(0)).optional().map_err(|_|"Native incarnation lookup failed")?;
            if row.group != authority.alias_group_id
                || row.epoch != authority.alias_incarnation
                || authority.alias_incarnation > authority.canonical_incarnation
                || native_epoch != Some(authority.canonical_incarnation)
                || !lifecycle_matches(&row, alias_view.as_ref(), &authority.alias_lifecycle)
            {
                return Ok(Outcome::FenceMismatch { affected_rows: 0 });
            }
            // Live claims bind the candidate coordinate; replay binds durable canonical state.
            if fence_value(&authority.canonical_lifecycle)
                != fence_value(&request.canonical_lifecycle)
            {
                return Ok(Outcome::FenceMismatch { affected_rows: 0 });
            }
            let data = context
                .encrypt_message_payload(
                    Self::request_scope(owner, "view", &key),
                    serde_json::to_vec(&proof).map_err(|_| "Invalid alias proof")?,
                )
                .map_err(|_| "Alias proof encryption unavailable")?;
            retire.push((alias.clone(), data));
        }
        if request.mode == Mode::Live {
            if let Some(old) = &canonical_host {
                tx.execute("INSERT OR IGNORE INTO conversation_group_aliases(conversation_id,user_did,group_id) VALUES(?1,?2,?3)",params![id,owner,old.group]).map_err(|_|"Historical group binding failed")?;
            }
            tx.execute("INSERT OR IGNORE INTO conversation_group_aliases(conversation_id,user_did,group_id) VALUES(?1,?2,?3)",params![id,owner,group]).map_err(|_|"Current group binding failed")?;
            let key = format!("canonical:{id}");
            let bytes = context
                .encrypt_message_payload(
                    Self::request_scope(owner, "view", &key),
                    serde_json::to_vec(view).map_err(|_| "Invalid canonical projection")?,
                )
                .map_err(|_| "Protected projection storage locked")?;
            let state = if view
                .canonical_state
                .as_ref()
                .is_some_and(|v| v.coordinates.lifecycle != "active")
            {
                "\"Closed\""
            } else {
                "\"Active\""
            };
            let members = serde_json::to_string(&view.members).map_err(|_| "Invalid roster")?;
            tx.execute("INSERT INTO conversations(conversation_id,user_did,group_id,epoch,state,members_json,sequencer_did) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(conversation_id,user_did) DO UPDATE SET group_id=excluded.group_id,epoch=excluded.epoch,state=excluded.state,members_json=excluded.members_json,sequencer_did=excluded.sequencer_did,reset_new_group_id=NULL,reset_notified_at_ms=NULL",params![id,owner,group,view.epoch,state,members,view.sequencer_did]).map_err(|_|"Canonical row write failed")?;
            tx.execute("INSERT INTO encrypted_request_projection(owner_did,record_kind,record_id,payload) VALUES(?1,'view',?2,?3) ON CONFLICT(owner_did,record_kind,record_id) DO UPDATE SET payload=excluded.payload",params![owner,key,bytes]).map_err(|_|"Protected projection write failed")?;
        }
        for (alias, bytes) in &retire {
            // Retain original rows and ciphertext/history; only inventory visibility changes.
            tx.execute("INSERT INTO conversation_projection_aliases(owner_did,alias_id,canonical_id,group_id,payload) VALUES(?1,?2,?3,?4,?5)",params![owner,alias,id,group,bytes]).map_err(|_|"Alias proof write failed")?;
        }
        tx.commit().map_err(|_| "Projection commit failed")?;
        let affected_rows = retire.len() as u32 + u32::from(request.mode == Mode::Live);
        if retire.is_empty() {
            Ok(Outcome::AlreadyAbsent { affected_rows })
        } else {
            Ok(Outcome::Retired { affected_rows })
        }
    }
}

impl SqliteStorage {
    pub(super) fn create_request_tables(&self) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute_batch("CREATE TABLE IF NOT EXISTS encrypted_request_projection (owner_did TEXT NOT NULL, record_kind TEXT NOT NULL CHECK(record_kind IN ('draft','view')), record_id TEXT NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(owner_did,record_kind,record_id)); CREATE TABLE IF NOT EXISTS conversation_projection_aliases(owner_did TEXT NOT NULL,alias_id TEXT NOT NULL,canonical_id TEXT NOT NULL,group_id TEXT NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(owner_did,alias_id)); CREATE TABLE IF NOT EXISTS conversation_projection_group_history(owner_did TEXT NOT NULL,conversation_id TEXT NOT NULL,group_id TEXT NOT NULL,epoch INTEGER NOT NULL,PRIMARY KEY(owner_did,conversation_id,group_id)); CREATE TABLE IF NOT EXISTS conversation_projection_incarnations(owner_did TEXT NOT NULL,group_id TEXT NOT NULL,epoch INTEGER NOT NULL,PRIMARY KEY(owner_did,group_id));")
    }
    pub(super) fn request_scope(owner: &str, kind: &str, id: &str) -> String {
        format!("catmos-cli-request:{owner}:{kind}:{id}")
    }
    pub(super) fn decode_request<T: serde::de::DeserializeOwned>(
        &self,
        owner: &str,
        kind: &str,
        id: &str,
        sealed: Vec<u8>,
    ) -> Result<T, String> {
        let context = self
            .mls_context_snapshot()
            .ok_or("Protected request storage unavailable")?;
        let plain = context
            .decrypt_message_payload(Self::request_scope(owner, kind, id), sealed)
            .map_err(|_| "Request storage is locked or belongs to another account")?;
        serde_json::from_slice(&plain).map_err(|_| "Invalid protected request projection".into())
    }
}
