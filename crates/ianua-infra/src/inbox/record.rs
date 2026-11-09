//! An event of the gateway's inbox: what the gateway seals of its audit
//! record, the row it is kept as, and the record read back from it.
//!
//! The sealed entry is the envelope the bus would carry of the record, its
//! subject included, and beside it what the trail keeps that the envelope
//! leaves out: the target, the address and the client. Who acted through
//! whom is not kept: the gateway records only what callers do in their
//! own name, so an event recorded through an impersonation is refused.

use ianua_domain::domains::audit::builder::ActedThrough;
use ianua_domain::domains::audit::record::{AuditRecord, AuditScope, AuditTarget};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::chain::EventOrigin;
use ianua_domain::types::{
    ActorRef, AuditRecordId, EventType, Fact, IpAddress, OrganizationId, TenantId, UserAgent,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::bus::{EventEnvelope, EventScope};
use crate::crypto::{EventSeal, raised_by_the_data_plane};
use crate::postgres::audit::payload::{opened, sealed};
use crate::postgres::foundation::stored::Stored;

const EVENT: Stored = Stored("gateway event");

/// What the gateway seals of one event.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Entry {
    /// The envelope the bus would carry of the event's record.
    event: EventEnvelope,
    /// The entity it affected, by id, or none.
    target_id: Option<String>,
    /// The address the request came from, when known.
    ip_address: Option<String>,
    /// The request's client, when known.
    user_agent: Option<String>,
}

/// One event as its row is written: its entry sealed for its subject.
pub(super) struct Sealed {
    pub(super) id: Uuid,
    pub(super) tenant_id: Uuid,
    pub(super) event_type: String,
    pub(super) subject: String,
    pub(super) payload: String,
    pub(super) seal: String,
    pub(super) occurred_at: OffsetDateTime,
}

/// One event of the inbox as it is read back.
pub(super) struct PendingRecord {
    pub(super) id: Uuid,
    pub(super) tenant_id: Uuid,
    pub(super) event_type: String,
    pub(super) subject: String,
    pub(super) payload: String,
    pub(super) seal: String,
}

/// An event of the inbox, checked and read back: its record, and where it
/// came from.
pub(super) struct Opened {
    pub(super) record: AuditRecord,
    pub(super) origin: EventOrigin,
}

/// Why an event of the inbox is dropped, never appended.
#[derive(Debug, thiserror::Error)]
pub(super) enum Dropped {
    /// Its seal is not the gateway's on what it says, or what it says is
    /// not what its row says.
    #[error("its seal does not hold")]
    Unsealed,
    /// It is not one of the events the gateway raises.
    #[error("it is not an event the gateway raises")]
    NotTheGateways,
    /// It does not read as an event this release knows.
    #[error("it does not read")]
    Unreadable(#[source] DomainError),
}

impl Entry {
    /// The row `record`, raised from `origin`, is written as: its entry,
    /// sealed with `seal` on its subject.
    ///
    /// # Errors
    ///
    /// - `DomainError::Forbidden` when the record is not of an event the
    ///   gateway raises, not a tenant's, or made through an impersonation.
    /// - `DomainError::Infrastructure` when it cannot be written out.
    pub(super) fn sealed_row(
        record: &AuditRecord,
        origin: EventOrigin,
        seal: &EventSeal,
    ) -> Result<Sealed, DomainError> {
        if !raised_by_the_data_plane(record.event_type) {
            return Err(DomainError::forbidden(message!(
                "infra-the-gateway-records-only-the-events",
                "the gateway records only the events the data plane raises"
            )));
        }
        let Some(tenant) = record.scope.tenant_id() else {
            return Err(DomainError::forbidden(message!(
                "infra-the-gateway-records-only-a-tenant",
                "the gateway records only a tenant's events"
            )));
        };
        if record.acted_through != ActedThrough::Directly {
            return Err(DomainError::forbidden(message!(
                "infra-the-gateway-records-only-what-a",
                "the gateway records only what a caller does in its own name"
            )));
        }
        let entry = Self::of(record, *tenant, origin)?;
        let payload = serde_json::to_string(&entry).map_err(DomainError::infra)?;
        let subject = entry.event.subject();
        Ok(Sealed {
            id: entry.event.id,
            tenant_id: *tenant.as_uuid(),
            event_type: entry.event.event_type,
            seal: seal.seal(&subject, payload.as_bytes()),
            subject,
            payload,
            occurred_at: entry.event.occurred_at,
        })
    }

    /// The entry of `tenant`'s `record`, raised from `origin`.
    fn of(
        record: &AuditRecord,
        tenant: TenantId,
        origin: EventOrigin,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            event: EventEnvelope {
                id: *record.id.as_uuid(),
                scope: EventScope::Tenant(*tenant.as_uuid()),
                organization_id: record.scope.organization_id().map(|id| *id.as_uuid()),
                event_type: record.event_type.as_str().to_owned(),
                actor: record.actor.audit_label(),
                payload: sealed(&record.payload)?,
                occurred_at: record.occurred_at,
                chain_depth: EventEnvelope::chain_depth_of(origin),
            },
            target_id: record.target.id().map(str::to_owned),
            ip_address: record.ip_address.known().map(|ip| ip.as_str().to_owned()),
            user_agent: record
                .user_agent
                .known()
                .map(|agent| agent.as_str().to_owned()),
        })
    }

    /// The record the entry holds, for `tenant`, every value read back
    /// through its rules.
    fn into_record(self, tenant: TenantId) -> Result<AuditRecord, DomainError> {
        let event_type = EventType::parse(&self.event.event_type)
            .ok_or_else(|| DomainError::corrupt_row(EVENT.0, "an unknown event type"))?;
        Ok(AuditRecord {
            id: AuditRecordId::from_uuid(self.event.id),
            scope: AuditScope::Tenant {
                organization: Fact::from_option(
                    self.event.organization_id.map(OrganizationId::from_uuid),
                ),
                tenant,
            },
            actor: ActorRef::from_recorded_label(&self.event.actor)?,
            event_type,
            target: self
                .target_id
                .map_or(AuditTarget::Untargeted, AuditTarget::Entity),
            ip_address: Fact::from_option(
                self.ip_address
                    .map(|ip| EVENT.value("ip address", IpAddress::new(ip)))
                    .transpose()?,
            ),
            user_agent: Fact::from_option(
                self.user_agent
                    .map(|agent| EVENT.value("user agent", UserAgent::new(agent)))
                    .transpose()?,
            ),
            payload: opened(self.event.payload)?,
            acted_through: ActedThrough::Directly,
            occurred_at: self.event.occurred_at,
        })
    }
}

impl PendingRecord {
    /// The event the row holds, once the gateway's `seal` holds for it, it
    /// is an event the gateway raises, and what it says is what its row
    /// says: its subject, its tenant and its type.
    ///
    /// # Errors
    ///
    /// [`Dropped`] naming why it is not appended.
    pub(super) fn opened(self, seal: &EventSeal) -> Result<Opened, Dropped> {
        if !seal.holds(&self.subject, self.payload.as_bytes(), &self.seal) {
            return Err(Dropped::Unsealed);
        }
        let entry: Entry = serde_json::from_str(&self.payload)
            .map_err(|error| Dropped::Unreadable(DomainError::infra(error)))?;
        let said_by_the_row = entry.event.subject() == self.subject
            && entry.event.scope == EventScope::Tenant(self.tenant_id)
            && entry.event.event_type == self.event_type;
        if !said_by_the_row {
            return Err(Dropped::Unsealed);
        }
        let raised_by_the_gateway =
            EventType::parse(&self.event_type).is_some_and(raised_by_the_data_plane);
        if !raised_by_the_gateway {
            return Err(Dropped::NotTheGateways);
        }
        let origin = entry.event.origin().map_err(Dropped::Unreadable)?;
        let record = entry
            .into_record(TenantId::from_uuid(self.tenant_id))
            .map_err(Dropped::Unreadable)?;
        Ok(Opened { record, origin })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::builder::{AuditContext, build_audit_record};
    use ianua_domain::domains::proxy::events::HoneypotHit;
    use ianua_domain::shared::events::data::{EventData, FieldValue};
    use ianua_domain::shared::events::event::DomainEvent;
    use ianua_domain::test_support::events::sample_tenant_event;
    use ianua_domain::types::{CorrelationId, OperatorId, UntrustedText, UserId};

    use super::*;
    use crate::crypto::keys::tests::test_root;

    fn gateway() -> EventSeal {
        EventSeal::data_plane(&test_root())
    }

    fn honeypot_event(tenant: TenantId) -> DomainEvent {
        HoneypotHit::observed(
            tenant,
            IpAddress::new("203.0.113.9").unwrap(),
            UntrustedText::record("/wp-admin"),
            CorrelationId::new(),
        )
    }

    fn honeypot_hit(tenant: TenantId) -> AuditRecord {
        build_audit_record(&honeypot_event(tenant), &AuditContext::system())
    }

    /// `record`'s row sealed with `seal`, as the drain reads it back.
    fn pending(record: &AuditRecord, seal: &EventSeal) -> PendingRecord {
        let sealed = Entry::sealed_row(record, EventOrigin::Outside, seal).unwrap();
        PendingRecord {
            id: sealed.id,
            tenant_id: sealed.tenant_id,
            event_type: sealed.event_type,
            subject: sealed.subject,
            payload: sealed.payload,
            seal: sealed.seal,
        }
    }

    /// An entry sealed by the gateway reads back as the record it was made
    /// from.
    #[test]
    fn a_sealed_entry_reads_back_as_its_record() {
        let tenant = TenantId::new();
        let record = honeypot_hit(tenant);

        let opened = pending(&record, &gateway()).opened(&gateway()).unwrap();

        assert_eq!(opened.record.id, record.id);
        assert_eq!(opened.record.event_type, record.event_type);
        assert_eq!(opened.record.scope.tenant_id(), Some(&tenant));
        assert_eq!(sorted(&opened.record.payload), sorted(&record.payload));
        assert_eq!(opened.origin, EventOrigin::Outside);
    }

    /// `data`'s fields by key: the stored payload keeps them by name, not
    /// in their order.
    fn sorted(data: &EventData) -> Vec<(String, FieldValue)> {
        let mut fields = data.fields().to_vec();
        fields.sort_by(|left, right| left.0.cmp(&right.0));
        fields
    }

    /// Sealing an event outside the data plane's permitted types is forbidden.
    #[test]
    fn an_event_the_gateway_does_not_raise_is_refused() {
        let record = build_audit_record(
            &sample_tenant_event(TenantId::new()),
            &AuditContext::system(),
        );

        let refused = Entry::sealed_row(&record, EventOrigin::Outside, &gateway());

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Changing a sealed payload or its row's tenant makes the row fail seal
    /// verification.
    #[test]
    fn a_changed_row_is_dropped() {
        let record = honeypot_hit(TenantId::new());
        let mut changed = pending(&record, &gateway());
        changed.payload = changed.payload.replace("wp-admin", "wp-login");
        let mut moved = pending(&record, &gateway());
        moved.tenant_id = *TenantId::new().as_uuid();

        assert!(matches!(changed.opened(&gateway()), Err(Dropped::Unsealed)));
        assert!(matches!(moved.opened(&gateway()), Err(Dropped::Unsealed)));
    }

    /// An event recorded through impersonation cannot be sealed for the gateway
    /// inbox.
    #[test]
    fn an_event_recorded_through_an_impersonation_is_refused() {
        let context = AuditContext::system().impersonating(OperatorId::new(), UserId::new());
        let record = build_audit_record(&honeypot_event(TenantId::new()), &context);

        let refused = Entry::sealed_row(&record, EventOrigin::Outside, &gateway());

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// A valid gateway seal does not admit an event type the gateway cannot raise.
    #[test]
    fn a_sealed_row_of_another_type_is_dropped() {
        let tenant = TenantId::new();
        let record = build_audit_record(&sample_tenant_event(tenant), &AuditContext::system());
        let entry = Entry::of(&record, tenant, EventOrigin::Outside).unwrap();
        let payload = serde_json::to_string(&entry).unwrap();
        let subject = entry.event.subject();
        let row = PendingRecord {
            id: entry.event.id,
            tenant_id: *tenant.as_uuid(),
            event_type: entry.event.event_type,
            seal: gateway().seal(&subject, payload.as_bytes()),
            subject,
            payload,
        };

        assert!(matches!(
            row.opened(&gateway()),
            Err(Dropped::NotTheGateways)
        ));
    }

    /// A row sealed with the control-plane key fails gateway seal verification.
    #[test]
    fn a_row_under_another_seal_is_dropped() {
        let record = honeypot_hit(TenantId::new());
        let control_plane = EventSeal::control_plane(&test_root());

        let opened = pending(&record, &control_plane).opened(&gateway());

        assert!(matches!(opened, Err(Dropped::Unsealed)));
    }
}
