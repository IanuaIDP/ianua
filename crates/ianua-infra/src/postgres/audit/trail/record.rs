//! Audit records as their rows are written, many in one statement, and the
//! link a tenant's next record is chained to, read back from storage.

use ianua_domain::domains::audit::builder::ActedThrough;
use ianua_domain::domains::audit::checkpoint::ChainHash;
use ianua_domain::domains::audit::record::AuditRecord;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::data::EventData;
use ianua_domain::types::{IpAddress, UserAgent};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::audit::actors::actor_parts;
use crate::postgres::audit::payload::sealed;
use crate::postgres::audit::trail::chain::{Hashed, entry_hash};

/// The link a tenant's next record is chained to, as storage answers it:
/// the newest record, the anchor a purge left, or the genesis link at 0.
pub(super) struct HeadRecord {
    pub(super) seq: i64,
    pub(super) entry_hash: Vec<u8>,
}

/// The link a tenant's next record is chained to.
pub(super) struct Link {
    seq: i64,
    hash: ChainHash,
}

impl HeadRecord {
    /// The link the record holds, its hash checked.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the hash is not a
    /// SHA-256 digest.
    pub(super) fn into_link(self) -> Result<Link, DomainError> {
        Ok(Link {
            seq: self.seq,
            hash: ChainHash::from_stored(&self.entry_hash)?,
        })
    }
}

/// Who acted through whom, as four columns keep it.
struct Through {
    word: &'static str,
    operator: Option<Uuid>,
    admin: Option<Uuid>,
    as_user: Option<Uuid>,
    impersonation: Option<Uuid>,
    execution: Option<Uuid>,
}

impl Through {
    /// Empty attribution columns for an actor who did not act through another identity.
    fn directly() -> Self {
        Self {
            word: "directly",
            operator: None,
            admin: None,
            as_user: None,
            impersonation: None,
            execution: None,
        }
    }

    /// Maps only the attribution columns belonging to the actor's route.
    fn of(acted: ActedThrough) -> Self {
        let directly = Self::directly();
        match acted {
            ActedThrough::Directly => directly,
            ActedThrough::Impersonation {
                operator_id,
                as_user,
            } => Self {
                word: "impersonation",
                operator: Some(*operator_id.as_uuid()),
                as_user: Some(*as_user.as_uuid()),
                ..directly
            },
            ActedThrough::SupportImpersonation {
                admin,
                as_user,
                impersonation,
            } => Self {
                word: "support_impersonation",
                admin: Some(*admin.as_uuid()),
                as_user: Some(*as_user.as_uuid()),
                impersonation: Some(*impersonation.as_uuid()),
                ..directly
            },
            ActedThrough::WorkflowRun { execution } => Self {
                word: "workflow_run",
                execution: Some(*execution.as_uuid()),
                ..directly
            },
        }
    }
}

/// One record's columns, as they are written.
pub(super) struct RecordColumns<'a> {
    id: Uuid,
    organization_id: Option<Uuid>,
    actor: String,
    actor_kind: &'static str,
    actor_id: Option<Uuid>,
    event_type: &'static str,
    target_id: Option<&'a str>,
    ip_address: Option<&'a str>,
    user_agent: Option<&'a str>,
    payload: &'a EventData,
    stored_payload: Value,
    through: Through,
    occurred_at: OffsetDateTime,
    chain_depth: i16,
}

impl<'a> RecordColumns<'a> {
    /// The columns `record` is written to, its time cut to the microsecond
    /// the column keeps, so the time hashed is the time stored, queued for
    /// the bus with the depth of the workflow chain whose work raised it,
    /// 0 for none.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its payload cannot be
    /// written out.
    pub(super) fn of(record: &'a AuditRecord, chain_depth: i16) -> Result<Self, DomainError> {
        let (actor_kind, actor_id) = actor_parts(&record.actor);
        Ok(Self {
            chain_depth,
            id: *record.id.as_uuid(),
            organization_id: record.scope.organization_id().map(|id| *id.as_uuid()),
            actor: record.actor.audit_label(),
            actor_kind,
            actor_id,
            event_type: record.event_type.as_str(),
            target_id: record.target.id(),
            ip_address: record.ip_address.known().map(IpAddress::as_str),
            user_agent: record.user_agent.known().map(UserAgent::as_str),
            payload: &record.payload,
            stored_payload: sealed(&record.payload)?,
            through: Through::of(record.acted_through),
            occurred_at: record
                .occurred_at
                .replace_microsecond(record.occurred_at.microsecond())
                .unwrap_or(record.occurred_at),
        })
    }

    fn hashed(&self, tenant_id: Uuid) -> Hashed<'_> {
        Hashed {
            id: self.id,
            tenant_id,
            organization_id: self.organization_id,
            actor: &self.actor,
            actor_kind: self.actor_kind,
            actor_id: self.actor_id,
            event_type: self.event_type,
            target_id: self.target_id,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            payload: self.payload,
            acted_through: self.through.word,
            through_operator_id: self.through.operator,
            through_admin_id: self.through.admin,
            as_user_id: self.through.as_user,
            support_impersonation_id: self.through.impersonation,
            through_execution_id: self.through.execution,
            occurred_at: self.occurred_at,
        }
    }
}

/// Many records' columns, one list per column and one place per record,
/// as one statement writes them.
#[derive(Default)]
pub(super) struct Batch {
    pub(super) ids: Vec<Uuid>,
    pub(super) organization_ids: Vec<Option<Uuid>>,
    pub(super) actors: Vec<String>,
    pub(super) actor_kinds: Vec<String>,
    pub(super) actor_ids: Vec<Option<Uuid>>,
    pub(super) event_types: Vec<String>,
    pub(super) target_ids: Vec<Option<String>>,
    pub(super) ip_addresses: Vec<Option<String>>,
    pub(super) user_agents: Vec<Option<String>>,
    pub(super) payloads: Vec<Value>,
    pub(super) acted_through: Vec<String>,
    pub(super) through_operator_ids: Vec<Option<Uuid>>,
    pub(super) through_admin_ids: Vec<Option<Uuid>>,
    pub(super) as_user_ids: Vec<Option<Uuid>>,
    pub(super) support_impersonation_ids: Vec<Option<Uuid>>,
    pub(super) through_execution_ids: Vec<Option<Uuid>>,
    pub(super) occurred_at: Vec<OffsetDateTime>,
    pub(super) seqs: Vec<i64>,
    pub(super) prev_hashes: Vec<Vec<u8>>,
    pub(super) entry_hashes: Vec<Vec<u8>>,
    pub(super) chain_depths: Vec<i16>,
}

impl Batch {
    /// The columns of `records`, unchained, as an organization's or the
    /// platform's records are written.
    pub(super) fn unchained(records: Vec<RecordColumns<'_>>) -> Self {
        let mut batch = Self::default();
        for record in records {
            batch.push(record);
        }
        batch
    }

    /// The columns of `records`, each linked to the one before it, the
    /// first to `link`, in `tenant_id`'s chain.
    pub(super) fn chained(tenant_id: Uuid, link: &Link, records: Vec<RecordColumns<'_>>) -> Self {
        let mut batch = Self::default();
        let mut seq = link.seq;
        let mut prev = link.hash.as_bytes().to_vec();
        for record in records {
            seq = seq.saturating_add(1);
            let hash = entry_hash(&prev, &record.hashed(tenant_id));
            batch.seqs.push(seq);
            batch
                .prev_hashes
                .push(std::mem::replace(&mut prev, hash.clone()));
            batch.entry_hashes.push(hash);
            batch.push(record);
        }
        batch
    }

    fn push(&mut self, record: RecordColumns<'_>) {
        self.ids.push(record.id);
        self.organization_ids.push(record.organization_id);
        self.actors.push(record.actor);
        self.actor_kinds.push(record.actor_kind.to_owned());
        self.actor_ids.push(record.actor_id);
        self.event_types.push(record.event_type.to_owned());
        self.target_ids.push(record.target_id.map(str::to_owned));
        self.ip_addresses.push(record.ip_address.map(str::to_owned));
        self.user_agents.push(record.user_agent.map(str::to_owned));
        self.payloads.push(record.stored_payload);
        self.acted_through.push(record.through.word.to_owned());
        self.through_operator_ids.push(record.through.operator);
        self.through_admin_ids.push(record.through.admin);
        self.as_user_ids.push(record.through.as_user);
        self.support_impersonation_ids
            .push(record.through.impersonation);
        self.through_execution_ids.push(record.through.execution);
        self.occurred_at.push(record.occurred_at);
        self.chain_depths.push(record.chain_depth);
    }
}
