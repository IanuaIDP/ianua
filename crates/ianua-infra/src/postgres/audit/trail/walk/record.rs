//! A stretch of a tenant's audit chain as its rows hold it, the anchor a
//! purge left, and the sealed head, read back to be rehashed.

use ianua_domain::shared::events::data::EventData;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::{AuditChainSeals, ChainLink};
use crate::postgres::audit::payload::opened;
use crate::postgres::audit::trail::chain::{Hashed, entry_hash};
use crate::postgres::foundation::audit_chain::anchor_holds;

/// One record of the stretch, with every column its hash covers.
pub(super) struct StretchRecord {
    pub(super) id: Uuid,
    pub(super) seq: i64,
    pub(super) organization_id: Option<Uuid>,
    pub(super) actor: String,
    pub(super) actor_kind: String,
    pub(super) actor_id: Option<Uuid>,
    pub(super) event_type: String,
    pub(super) target_id: Option<String>,
    pub(super) ip_address: Option<String>,
    pub(super) user_agent: Option<String>,
    pub(super) payload: Value,
    pub(super) acted_through: String,
    pub(super) through_operator_id: Option<Uuid>,
    pub(super) through_admin_id: Option<Uuid>,
    pub(super) as_user_id: Option<Uuid>,
    pub(super) support_impersonation_id: Option<Uuid>,
    pub(super) through_execution_id: Option<Uuid>,
    pub(super) occurred_at: OffsetDateTime,
    pub(super) prev_hash: Vec<u8>,
    pub(super) entry_hash: Vec<u8>,
}

/// A link of the chain: a place and its hash.
pub(super) struct LinkRecord {
    pub(super) seq: i64,
    pub(super) entry_hash: Vec<u8>,
}

/// The sealed head of the chain.
pub(super) struct HeadRecord {
    pub(super) seq: i64,
    pub(super) entry_hash: Vec<u8>,
    pub(super) seal: Vec<u8>,
}

/// The sealed anchor a retention purge left.
pub(super) struct AnchorRecord {
    pub(super) seq: i64,
    pub(super) entry_hash: Vec<u8>,
    pub(super) seal: Vec<u8>,
}

impl AnchorRecord {
    /// The link the anchor names when the platform sealed it for
    /// `tenant_id`, or `None` when its seal does not hold.
    pub(super) fn into_sealed_link(
        self,
        tenant_id: Uuid,
        heads: &AuditChainSeals,
    ) -> Option<LinkRecord> {
        let link = ChainLink {
            seq: self.seq,
            hash: &self.entry_hash,
        };
        anchor_holds(heads, tenant_id, link, &self.seal).then_some(LinkRecord {
            seq: self.seq,
            entry_hash: self.entry_hash,
        })
    }
}

impl StretchRecord {
    /// The link this record makes when it holds as the record after `link`
    /// in `tenant_id`'s chain: at the next place, naming `link` as the one
    /// before it, and hashing with it to its own hash. `None` when it does
    /// not hold, its payload no longer reading among the ways it cannot.
    pub(super) fn into_link_after(
        mut self,
        link: &LinkRecord,
        tenant_id: Uuid,
    ) -> Option<LinkRecord> {
        if self.seq != link.seq.saturating_add(1) || self.prev_hash != link.entry_hash {
            return None;
        }
        let payload = opened(std::mem::take(&mut self.payload)).ok()?;
        let rehashed = entry_hash(&link.entry_hash, &self.hashed(tenant_id, &payload));
        (rehashed == self.entry_hash).then_some(LinkRecord {
            seq: self.seq,
            entry_hash: self.entry_hash,
        })
    }

    fn hashed<'a>(&'a self, tenant_id: Uuid, payload: &'a EventData) -> Hashed<'a> {
        Hashed {
            id: self.id,
            tenant_id,
            organization_id: self.organization_id,
            actor: &self.actor,
            actor_kind: &self.actor_kind,
            actor_id: self.actor_id,
            event_type: &self.event_type,
            target_id: self.target_id.as_deref(),
            ip_address: self.ip_address.as_deref(),
            user_agent: self.user_agent.as_deref(),
            payload,
            acted_through: &self.acted_through,
            through_operator_id: self.through_operator_id,
            through_admin_id: self.through_admin_id,
            as_user_id: self.as_user_id,
            support_impersonation_id: self.support_impersonation_id,
            through_execution_id: self.through_execution_id,
            occurred_at: self.occurred_at,
        }
    }
}
