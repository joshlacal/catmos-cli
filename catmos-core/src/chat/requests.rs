//! Presentation commands over the shared protected request authority.
use super::ChatService;
use crate::error::{CatmosError, Result};
use catbird_mls::{
    DirectRequestInput, DirectRequestOutcome, DirectRequestView, GroupInvitationReference,
};
pub use catbird_mls::{
    DirectRequestInput as RequestInput, DirectRequestView as RequestView,
    GroupInvitationReference as InvitationReference, RequestConsent, RequestPreview,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestDraft {
    pub owner_did: String,
    pub input: DirectRequestInput,
    pub attempted: bool,
    pub outcome: Option<DirectRequestOutcome>,
    #[serde(default)]
    pub note_started: bool,
    #[serde(default)]
    pub note_message_id: Option<String>,
}
#[derive(Clone, Debug)]
pub enum RequestDraftCancellation {
    LocalDraftDeleted { draft_id: String },
    Native(DirectRequestOutcome),
}
pub fn new_draft_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
impl ChatService {
    pub(crate) async fn require_ordinary_effects(&self, cid: &str) -> Result<()> {
        let authority = self.request_authority().await?;
        let stable = self.resolve_conversation_ids(cid).await?.0;
        let ready = authority
            .ensure_conversation_ready(&stable)
            .await
            .map_err(|_| CatmosError::RequestEffectsNotAuthorized)?;
        if !ready.send_allowed {
            return Err(CatmosError::RequestEffectsNotAuthorized);
        }
        Ok(())
    }

    pub async fn request_authority(&self) -> Result<std::sync::Arc<crate::CliOrchestrator>> {
        self.orchestrator()
            .await
            .ok_or_else(|| CatmosError::Other("Shared request authority is not initialized".into()))
    }
    pub async fn save_request_draft(&self, input: DirectRequestInput) -> Result<RequestDraft> {
        catbird_mls::chat_v2::ids::BareDid::parse(&input.recipient_did)
            .map_err(|_| CatmosError::Other("Invalid recipient DID".into()))?;
        if !input.text.is_empty() {
            catbird_mls::orchestrator::direct_requests::validate_direct_request_input(&input)
                .map_err(|e| CatmosError::Other(e.to_string()))?;
        }
        let draft = RequestDraft {
            owner_did: self.did().into(),
            input,
            attempted: false,
            outcome: None,
            note_started: false,
            note_message_id: None,
        };
        self.db.create_request_draft(&draft).await?;
        Ok(draft)
    }
    pub async fn edit_request_draft(&self, id: &str, text: String) -> Result<()> {
        let (mut draft, raw) = self
            .db
            .read_request_draft(self.did(), id)
            .await?
            .ok_or_else(|| CatmosError::Other("Unknown draft".into()))?;
        if draft.attempted {
            return Err(CatmosError::Other(
                "An attempted draft is immutable; resume its exact content".into(),
            ));
        }
        if text.len() > 16384 {
            return Err(CatmosError::Other(
                "Request text exceeds16384 UTF-8 bytes".into(),
            ));
        }
        draft.input.text = text;
        self.db.replace_request_draft(&draft, &raw).await?;
        Ok(())
    }
    pub async fn send_request_draft(&self, draft_id: &str) -> Result<DirectRequestOutcome> {
        let (mut draft, raw) = self
            .db
            .read_request_draft(self.did(), draft_id)
            .await?
            .ok_or_else(|| CatmosError::Other("Unknown local request draft".into()))?;
        if draft.note_started {
            return Err(CatmosError::Other(
                "Ordinary note already attempted; inspect its native outbox/history".into(),
            ));
        }
        catbird_mls::orchestrator::direct_requests::validate_direct_request_input(&draft.input)
            .map_err(|e| CatmosError::Other(e.to_string()))?;
        draft.attempted = true;
        let raw = self.db.replace_request_draft(&draft, &raw).await?;
        // Same-full-input start is the shared idempotent resume seam, including
        // a crash after native custody but before host outcome projection.
        let result = self
            .request_authority()
            .await?
            .start_direct_request(draft.input.clone())
            .await
            .map_err(|e| CatmosError::Other(e.to_string()))?;
        draft.outcome = Some(result.clone());
        self.db.replace_request_draft(&draft, &raw).await?;
        Ok(result)
    }
    pub async fn cancel_request_draft(&self, id: &str) -> Result<RequestDraftCancellation> {
        let (mut draft, raw) = self
            .db
            .read_request_draft(self.did(), id)
            .await?
            .ok_or_else(|| CatmosError::Other("Unknown local draft".into()))?;
        if !draft.attempted {
            self.db
                .delete_request_draft(&draft.owner_did, &draft.input.draft_id, &raw)
                .await?;
            return Ok(RequestDraftCancellation::LocalDraftDeleted {
                draft_id: id.to_owned(),
            });
        }
        let outcome = self
            .request_authority()
            .await?
            .cancel_direct_request(id)
            .await
            .map_err(|e| CatmosError::Other(e.to_string()))?;
        draft.outcome = Some(outcome.clone());
        self.db.replace_request_draft(&draft, &raw).await?;
        Ok(RequestDraftCancellation::Native(outcome))
    }
    pub async fn send_accepted_invitation_note(
        &self,
        draft_id: &str,
        conversation_id: &str,
    ) -> Result<String> {
        let (mut draft, raw) = self
            .db
            .read_request_draft(self.did(), draft_id)
            .await?
            .ok_or_else(|| CatmosError::Other("Unknown draft".into()))?;
        if let Some(id) = draft.note_message_id {
            return Ok(id);
        }
        if draft.note_started {
            return Err(CatmosError::Other("Note outcome requires inspection of native outbox/history; it will not be sent again".into()));
        }
        if !matches!(
            draft.outcome,
            Some(DirectRequestOutcome::ExistingDirect { .. })
        ) {
            return Err(CatmosError::Other("An ordinary invitation note requires a proven existing-direct outcome; published or uncertain introductions must not be resent".into()));
        }
        let reference = draft.input.invitation.clone().ok_or_else(|| {
            CatmosError::Other("Draft has no authenticated group invitation".into())
        })?;
        let authority = self.request_authority().await?;
        let payload = catbird_mls::orchestrator::MLSMessagePayload::text_with_embed(
            &draft.input.text,
            catbird_mls::orchestrator::MLSEmbedData::group_invitation(reference.clone())?,
        );
        // The shared send revalidates accepted direct/recipient and live group
        // reference. Mark before calling; ambiguous ordinary outbox operations
        // require inspection rather than allocating a duplicate message ID.
        draft.note_started = true;
        draft.attempted = true;
        let next = self.db.replace_request_draft(&draft, &raw).await?;
        let message = authority
            .send_payload_json(
                conversation_id,
                &String::from_utf8(payload.encode()?)
                    .map_err(|e| CatmosError::Other(e.to_string()))?,
            )
            .await
            .map_err(|e| CatmosError::Other(e.to_string()))?;
        draft.note_message_id = Some(message.id.clone());
        self.db.replace_request_draft(&draft, &next).await?;
        self.db
            .store_message(&crate::types::Message {
                id: message.id.clone(),
                convo_id: message.conversation_id,
                sender_did: Some(message.sender_did),
                content: crate::types::MessageContent::GroupInvitation {
                    text: message.text,
                    reference,
                },
                epoch: message.epoch,
                seq: message.sequence_number,
                created_at: message.timestamp,
            })
            .await?;
        Ok(message.id)
    }
    pub async fn request_views(&self, refresh: bool) -> Result<Vec<DirectRequestView>> {
        let authority = self.request_authority().await?;
        if refresh {
            self.refresh_authenticated_inventory().await?;
        }
        authority
            .list_direct_request_views()
            .await
            .map_err(|e| CatmosError::Other(e.to_string()))
    }
    pub async fn request_view(&self, cid: &str) -> Result<DirectRequestView> {
        self.request_authority()
            .await?
            .refresh_request_preview(cid)
            .await
            .map_err(|e| CatmosError::Other(e.to_string()))
    }
    pub async fn accept_request(&self, cid: &str) -> Result<DirectRequestView> {
        let authority = self.request_authority().await?;
        authority
            .refresh_request_preview(cid)
            .await
            .map_err(|e| CatmosError::Other(e.to_string()))?;
        authority
            .accept_conversation(cid)
            .await
            .map_err(|e| CatmosError::Other(e.to_string()))?;
        authority
            .refresh_request_preview(cid)
            .await
            .map_err(|e| CatmosError::Other(e.to_string()))
    }
    pub async fn close_request(&self, cid: &str) -> Result<DirectRequestView> {
        self.request_authority()
            .await?
            .close_direct_request(cid)
            .await
            .map_err(|e| CatmosError::Other(e.to_string()))
    }
    pub async fn invitation_note_reference(
        &self,
        cid: &str,
        recipient: &str,
    ) -> Result<GroupInvitationReference> {
        self.request_authority()
            .await?
            .get_group_invitation_reference(cid, recipient)
            .await
            .map_err(|e| CatmosError::Other(e.to_string()))?
            .ok_or_else(|| CatmosError::Other("No eligible pending group invitation".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::Database;
    #[tokio::test]
    async fn protected_draft_reopens_and_rejects_cross_account_and_stale_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("drafts.db");
        let db = Database::open_unencrypted(&path).await.unwrap();
        db.set_content_root_key(vec![31; 32]);
        let draft = RequestDraft {
            owner_did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            input: DirectRequestInput {
                draft_id: new_draft_id(),
                recipient_did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(),
                text: "private introduction sentinel".into(),
                invitation: None,
            },
            attempted: false,
            outcome: None,
            note_started: false,
            note_message_id: None,
        };
        db.create_request_draft(&draft).await.unwrap();
        let (mut loaded, raw) = db
            .read_request_draft(&draft.owner_did, &draft.input.draft_id)
            .await
            .unwrap()
            .unwrap();
        assert!(!raw
            .windows(draft.input.text.len())
            .any(|w| w == draft.input.text.as_bytes()));
        assert!(db
            .read_request_draft("did:plc:cccccccccccccccccccccccc", &draft.input.draft_id)
            .await
            .unwrap()
            .is_none());
        loaded.attempted = true;
        db.replace_request_draft(&loaded, &raw).await.unwrap();
        assert!(db.replace_request_draft(&draft, &raw).await.is_err());
        let mut replacement = draft.clone();
        replacement.input.text = "different".into();
        assert!(db.create_request_draft(&replacement).await.is_err());
        drop(db);
        let db = Database::open_unencrypted(&path).await.unwrap();
        db.set_content_root_key(vec![31; 32]);
        let retained = db
            .read_request_draft(&draft.owner_did, &draft.input.draft_id)
            .await
            .unwrap()
            .unwrap()
            .0;
        assert!(retained.attempted);
        assert_eq!(retained.input, draft.input);
        db.set_content_root_key(vec![32; 32]);
        assert!(db
            .read_request_draft(&draft.owner_did, &draft.input.draft_id)
            .await
            .is_err());
    }
    #[tokio::test]
    async fn all_retained_draft_outcomes_remain_selectable_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("retained.db");
        let db = Database::open_unencrypted(&path).await.unwrap();
        db.set_content_root_key(vec![19; 32]);
        let outcomes = vec![
            None,
            Some(DirectRequestOutcome::OutcomeUnknown {
                request_id: new_draft_id(),
            }),
            Some(DirectRequestOutcome::Retryable {
                code: "Offline".into(),
            }),
            Some(DirectRequestOutcome::ExistingDirect {
                conversation_id: new_draft_id(),
                requires_acceptance: false,
            }),
        ];
        let mut inputs = Vec::new();
        for outcome in &outcomes {
            let input = DirectRequestInput {
                draft_id: new_draft_id(),
                recipient_did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(),
                text: "immutable retained text".into(),
                invitation: None,
            };
            inputs.push(input.clone());
            db.create_request_draft(&RequestDraft {
                owner_did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
                input,
                attempted: outcome.is_some(),
                outcome: outcome.clone(),
                note_started: false,
                note_message_id: None,
            })
            .await
            .unwrap();
        }
        drop(db);
        let db = Database::open_unencrypted(&path).await.unwrap();
        db.set_content_root_key(vec![19; 32]);
        let retained = db
            .list_request_drafts("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
            .await
            .unwrap();
        assert_eq!(retained.len(), 4);
        for (input, outcome) in inputs.iter().zip(outcomes.iter()) {
            let row = retained
                .iter()
                .find(|d| d.input.draft_id == input.draft_id)
                .unwrap();
            assert_eq!(&row.input, input);
            assert_eq!(&row.outcome, outcome);
        }
        assert!(db
            .list_request_drafts("did:plc:cccccccccccccccccccccccc")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn request_drafts_never_fall_back_to_plaintext_before_key_installation() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_unencrypted(&dir.path().join("draft.db"))
            .await
            .unwrap();
        let draft = RequestDraft {
            owner_did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            input: DirectRequestInput {
                draft_id: new_draft_id(),
                recipient_did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(),
                text: "never plaintext".into(),
                invitation: None,
            },
            attempted: false,
            outcome: None,
            note_started: false,
            note_message_id: None,
        };
        assert!(db.create_request_draft(&draft).await.is_err());
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM request_drafts")
            .fetch_one(db.pool_for_test())
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
    #[tokio::test]
    async fn retained_inventory_is_encrypted_and_owner_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_unencrypted(&dir.path().join("inventory.db"))
            .await
            .unwrap();
        assert!(db
            .retain_authenticated_inventory("did:plc:alice", b"exact snapshot sentinel")
            .await
            .is_err());
        db.set_content_root_key(vec![21; 32]);
        db.retain_authenticated_inventory("did:plc:alice", b"exact snapshot sentinel")
            .await
            .unwrap();
        let raw: Vec<u8> =
            sqlx::query_scalar("SELECT protected FROM authenticated_inventory WHERE owner_did=?")
                .bind("did:plc:alice")
                .fetch_one(db.pool_for_test())
                .await
                .unwrap();
        assert!(!raw.windows(8).any(|w| w == b"snapshot"));
        assert_eq!(
            catbird_mls::field_encryption::decrypt_payload(
                &[21; 32],
                "inventory-snapshot/v2/did:plc:alice",
                &raw
            )
            .unwrap(),
            b"exact snapshot sentinel"
        );
        assert!(catbird_mls::field_encryption::decrypt_payload(
            &[21; 32],
            "inventory-snapshot/v2/did:plc:bob",
            &raw
        )
        .is_err());
    }
}
