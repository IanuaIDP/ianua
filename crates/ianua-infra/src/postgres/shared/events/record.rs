//! A tenant's audit record as its row holds it, read back whole: who acted,
//! through whom, and what the event said.

use ianua_domain::domains::audit::builder::ActedThrough;
use ianua_domain::domains::audit::record::{AuditRecord, AuditScope, AuditTarget};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    ActorRef, AuditRecordId, EventType, Fact, IpAddress, OrganizationId, TenantId, UserAgent,
};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::audit::payload::opened;
use crate::postgres::audit::through::KeptThrough;
use crate::postgres::foundation::stored::Stored;

const RECORD: Stored = Stored("audit record");

/// A record as it is read. The store's checked query fills it.
pub(super) struct RecordedRecord {
    pub(super) id: Uuid,
    pub(super) organization_id: Option<Uuid>,
    pub(super) actor: String,
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
}

impl RecordedRecord {
    /// The record of `tenant` the row holds, every value read back through
    /// its rules.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the actor, event type,
    /// address, client, payload or who it acted through no longer reads.
    pub(super) fn into_record(self, tenant: TenantId) -> Result<AuditRecord, DomainError> {
        let acted_through = self.acted_through()?;
        let event_type = EventType::parse(&self.event_type)
            .ok_or_else(|| DomainError::corrupt_row(RECORD.0, "an unknown event type"))?;
        Ok(AuditRecord {
            id: AuditRecordId::from_uuid(self.id),
            scope: AuditScope::Tenant {
                organization: Fact::from_option(
                    self.organization_id.map(OrganizationId::from_uuid),
                ),
                tenant,
            },
            actor: ActorRef::from_recorded_label(&self.actor)?,
            event_type,
            target: self
                .target_id
                .map_or(AuditTarget::Untargeted, AuditTarget::Entity),
            ip_address: Fact::from_option(
                self.ip_address
                    .map(|ip| RECORD.value("ip address", IpAddress::new(ip)))
                    .transpose()?,
            ),
            user_agent: Fact::from_option(
                self.user_agent
                    .map(|agent| RECORD.value("user agent", UserAgent::new(agent)))
                    .transpose()?,
            ),
            payload: opened(self.payload)?,
            acted_through,
            occurred_at: self.occurred_at,
        })
    }

    /// Who the actor acted through, from its word and the ids beside it.
    fn acted_through(&self) -> Result<ActedThrough, DomainError> {
        KeptThrough {
            word: &self.acted_through,
            operator: self.through_operator_id,
            admin: self.through_admin_id,
            as_user: self.as_user_id,
            impersonation: self.support_impersonation_id,
            execution: self.through_execution_id,
        }
        .read(RECORD.0)
    }
}
