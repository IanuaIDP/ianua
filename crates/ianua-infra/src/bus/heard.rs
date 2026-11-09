//! An event a consumer was handed, read back into the event it records,
//! for the worker's planners.
//!
//! Nothing is read before the seal holds, and the envelope must name the
//! very subject the seal covers, so a seal the data plane may make for
//! its own few events never vouches for another. A tenant's event is then
//! read back whole from the trail by its record's id, the trail being the
//! record and the envelope only its pointer, and must be the event the
//! subject names. An organization's or the platform's is read from the
//! envelope, which carries all of it but the request's address, client
//! and target, as nothing acting on those events reads them.
//!
//! The envelope carries how deep in a workflow chain the work that raised
//! the event was, under the seal, so a workflow the event starts continues
//! the chain and is refused past its limit as it would be in one process.

use std::sync::Arc;

use ianua_app::ports::shared::{PublishedEvent, RecordedEvents};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::audit::builder::{ActedThrough, read_back};
use ianua_domain::domains::audit::record::{AuditRecord, AuditScope, AuditTarget};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::chain::EventOrigin;
use ianua_domain::types::{ActorRef, AuditRecordId, EventType, Fact, OrganizationId, TenantId};

use crate::bus::envelope::{EventEnvelope, EventScope};
use crate::bus::stream::HeardEvent;
use crate::crypto::EventCheck;
use crate::postgres::audit::payload::opened;

/// Why an event handed to a consumer was not read back.
#[derive(Debug, thiserror::Error)]
pub enum Unheard {
    /// Its seal does not hold for its subject, or its envelope names
    /// another: no part of the platform that may raise it sent it.
    #[error("the event's seal does not hold")]
    Unsealed,
    /// It does not read as an event this release knows.
    #[error("the event does not read")]
    Unreadable(#[source] DomainError),
    /// Its record could not be read now; it may be read later.
    #[error("the event's record could not be read")]
    Unread(#[source] DomainError),
}

/// Reads the events handed to the worker's consumers back into the events
/// they record.
pub struct HeardEvents {
    check: EventCheck,
    records: Arc<dyn RecordedEvents>,
}

impl std::fmt::Debug for HeardEvents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeardEvents").finish_non_exhaustive()
    }
}

impl HeardEvents {
    /// A reader checking each event with `check` and reading a tenant's
    /// back from `records`.
    #[must_use]
    pub fn new(check: EventCheck, records: Arc<dyn RecordedEvents>) -> Self {
        Self { check, records }
    }

    /// The event `heard` carries, or `None` when its record is gone, as
    /// after its retention ended.
    ///
    /// # Errors
    ///
    /// [`Unheard::Unsealed`] when its seal does not hold for what it says,
    /// [`Unheard::Unreadable`] when it does not read, and
    /// [`Unheard::Unread`] when its record cannot be read now.
    pub async fn published(&self, heard: &HeardEvent) -> Result<Option<PublishedEvent>, Unheard> {
        let envelope = self.opened(heard)?;
        let event_type = EventType::parse(&envelope.event_type).ok_or_else(|| {
            Unheard::Unreadable(DomainError::corrupt_row(EVENT, "an unknown event type"))
        })?;
        let origin = envelope.origin().map_err(Unheard::Unreadable)?;
        let record = match envelope.scope {
            EventScope::Tenant(tenant) => {
                let Some(record) = self.trail(TenantId::from_uuid(tenant), &envelope).await? else {
                    return Ok(None);
                };
                record
            }
            EventScope::Organization(_) | EventScope::Platform => {
                carried(envelope, event_type).map_err(Unheard::Unreadable)?
            }
        };
        if record.event_type != event_type {
            return Err(Unheard::Unsealed);
        }
        Ok(Some(published(&record, origin)))
    }

    /// The envelope `heard` carries, once its seal holds for its subject and
    /// the envelope names that subject.
    fn opened(&self, heard: &HeardEvent) -> Result<EventEnvelope, Unheard> {
        let Some(seal) = heard.seal.as_deref() else {
            return Err(Unheard::Unsealed);
        };
        if !self.check.holds(&heard.subject, &heard.payload, seal) {
            return Err(Unheard::Unsealed);
        }
        let envelope: EventEnvelope = serde_json::from_slice(&heard.payload)
            .map_err(|error| Unheard::Unreadable(DomainError::infra(error)))?;
        if envelope.subject() != heard.subject {
            return Err(Unheard::Unsealed);
        }
        Ok(envelope)
    }

    /// `tenant`'s record of `envelope`, read back from the trail.
    async fn trail(
        &self,
        tenant: TenantId,
        envelope: &EventEnvelope,
    ) -> Result<Option<AuditRecord>, Unheard> {
        self.records
            .find(
                &ScopedTenant::for_background(tenant),
                &AuditRecordId::from_uuid(envelope.id),
            )
            .await
            .map_err(Unheard::Unread)
    }
}

/// What the envelope of an event is called when it does not read.
const EVENT: &str = "published event";

/// The record of an organization's or the platform's event, as its
/// envelope carries it.
fn carried(envelope: EventEnvelope, event_type: EventType) -> Result<AuditRecord, DomainError> {
    let scope = match envelope.scope {
        EventScope::Organization(organization) => {
            AuditScope::Organization(OrganizationId::from_uuid(organization))
        }
        EventScope::Platform | EventScope::Tenant(_) => AuditScope::Platform,
    };
    Ok(AuditRecord {
        id: AuditRecordId::from_uuid(envelope.id),
        scope,
        actor: ActorRef::from_recorded_label(&envelope.actor)?,
        event_type,
        target: AuditTarget::Untargeted,
        ip_address: Fact::Unknown,
        user_agent: Fact::Unknown,
        payload: opened(envelope.payload)?,
        acted_through: ActedThrough::Directly,
        occurred_at: envelope.occurred_at,
    })
}

/// `record`'s event, raised from `origin`, read back with its context, for
/// a planner.
fn published(record: &AuditRecord, origin: EventOrigin) -> PublishedEvent {
    let read = read_back(record, origin);
    PublishedEvent {
        id: record.id,
        event: read.event,
        context: read.context,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ianua_app::ports::TenantScoped;
    use ianua_domain::domains::audit::builder::{AuditContext, build_audit_record};
    use ianua_domain::shared::events::chain::ChainDepth;
    use ianua_domain::shared::events::data::{EventData, FieldValue};
    use ianua_domain::test_support::events::{sample_organization_event, sample_tenant_event};
    use time::OffsetDateTime;

    use super::*;
    use crate::crypto::EventSeal;
    use crate::crypto::keys::tests::test_root;
    use crate::postgres::audit::payload::sealed;

    /// A trail kept in memory, by record id.
    #[derive(Default)]
    struct Trail(Mutex<HashMap<AuditRecordId, AuditRecord>>);

    impl TenantScoped for Trail {}

    #[async_trait]
    impl RecordedEvents for Trail {
        async fn find(
            &self,
            _tenant_id: &ScopedTenant,
            id: &AuditRecordId,
        ) -> Result<Option<AuditRecord>, DomainError> {
            let kept = self
                .0
                .lock()
                .map_err(|_| DomainError::infra_msg("poisoned"))?;
            Ok(kept.get(id).cloned())
        }
    }

    struct Fixture {
        heard: HeardEvents,
        trail: Arc<Trail>,
    }

    fn control_plane() -> EventSeal {
        EventSeal::control_plane(&test_root())
    }

    fn data_plane() -> EventSeal {
        EventSeal::data_plane(&test_root())
    }

    fn fixture() -> Fixture {
        let trail = Arc::new(Trail::default());
        Fixture {
            heard: HeardEvents::new(
                EventCheck::new(control_plane(), data_plane()),
                Arc::clone(&trail) as Arc<dyn RecordedEvents>,
            ),
            trail,
        }
    }

    fn envelope_of(record: &AuditRecord) -> EventEnvelope {
        let scope = match record.scope {
            AuditScope::Tenant { tenant, .. } => EventScope::Tenant(*tenant.as_uuid()),
            AuditScope::Organization(organization) => {
                EventScope::Organization(*organization.as_uuid())
            }
            AuditScope::Platform => EventScope::Platform,
        };
        EventEnvelope {
            id: *record.id.as_uuid(),
            scope,
            organization_id: record.scope.organization_id().map(|id| *id.as_uuid()),
            event_type: record.event_type.to_string(),
            actor: record.actor.audit_label(),
            payload: sealed(&record.payload).unwrap(),
            occurred_at: record.occurred_at,
            chain_depth: 0,
        }
    }

    fn sealed_by(seal: &EventSeal, envelope: &EventEnvelope) -> HeardEvent {
        let payload = serde_json::to_vec(envelope).unwrap();
        let subject = envelope.subject();
        HeardEvent {
            seal: Some(seal.seal(&subject, &payload)),
            subject,
            payload,
        }
    }

    fn tenant_record() -> AuditRecord {
        let tenant = TenantId::new();
        build_audit_record(&sample_tenant_event(tenant), &AuditContext::system())
    }

    /// A tenant's event is read back whole from the trail, under its
    /// record's id.
    #[tokio::test]
    async fn a_tenants_event_is_read_back_from_the_trail() {
        let fx = fixture();
        let record = tenant_record();
        fx.trail.0.lock().unwrap().insert(record.id, record.clone());

        let read = fx
            .heard
            .published(&sealed_by(&control_plane(), &envelope_of(&record)))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(read.id, record.id);
        assert_eq!(read.event.event_type(), record.event_type);
        assert_eq!(read.event.tenant_id(), record.scope.tenant_id());
    }

    /// A tenant's event whose record is gone, as after its retention, is
    /// nothing to act on.
    #[tokio::test]
    async fn an_event_whose_record_is_gone_reads_as_none() {
        let fx = fixture();
        let record = tenant_record();

        let read = fx
            .heard
            .published(&sealed_by(&control_plane(), &envelope_of(&record)))
            .await
            .unwrap();

        assert!(read.is_none());
    }

    /// An organization's event is read from its envelope.
    #[tokio::test]
    async fn an_organizations_event_is_read_from_its_envelope() {
        let fx = fixture();
        let organization = OrganizationId::new();
        let record = build_audit_record(
            &sample_organization_event(organization, OffsetDateTime::now_utc()),
            &AuditContext::system(),
        );

        let read = fx
            .heard
            .published(&sealed_by(&control_plane(), &envelope_of(&record)))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(read.event.organization_id(), Some(&organization));
        assert_eq!(sorted(&read.event.payload()), sorted(&record.payload));
    }

    /// `data`'s fields by key: an envelope keeps them, not their order.
    fn sorted(data: &EventData) -> Vec<(String, FieldValue)> {
        let mut fields = data.fields().to_vec();
        fields.sort_by(|left, right| left.0.cmp(&right.0));
        fields
    }

    /// Both a forged seal and a missing seal prevent an event from being read.
    #[tokio::test]
    async fn an_event_without_a_seal_that_holds_is_refused() {
        let fx = fixture();
        let record = tenant_record();
        fx.trail.0.lock().unwrap().insert(record.id, record.clone());
        let mut heard = sealed_by(&control_plane(), &envelope_of(&record));
        heard.seal = Some("forged".to_owned());
        let mut unsealed = heard.clone();
        unsealed.seal = None;

        assert!(matches!(
            fx.heard.published(&heard).await,
            Err(Unheard::Unsealed)
        ));
        assert!(matches!(
            fx.heard.published(&unsealed).await,
            Err(Unheard::Unsealed)
        ));
    }

    /// A data-plane seal on a honeypot subject cannot authorize an envelope
    /// naming a different event.
    #[tokio::test]
    async fn a_data_plane_seal_never_vouches_for_another_event() {
        let fx = fixture();
        let record = tenant_record();
        fx.trail.0.lock().unwrap().insert(record.id, record.clone());
        let envelope = envelope_of(&record);
        let payload = serde_json::to_vec(&envelope).unwrap();
        let tenant = record.scope.tenant_id().unwrap().as_uuid().simple();
        let subject = format!("tenant.{tenant}.proxy.honeypot_hit");
        let forged = HeardEvent {
            seal: Some(data_plane().seal(&subject, &payload)),
            subject,
            payload,
        };

        assert!(matches!(
            fx.heard.published(&forged).await,
            Err(Unheard::Unsealed)
        ));
    }

    /// An event a workflow execution's work raised two deep reads back as
    /// raised there, so a workflow it starts continues the chain.
    #[tokio::test]
    async fn an_event_keeps_the_depth_it_was_raised_at() {
        let fx = fixture();
        let record = tenant_record();
        fx.trail.0.lock().unwrap().insert(record.id, record.clone());
        let envelope = EventEnvelope {
            chain_depth: 2,
            ..envelope_of(&record)
        };

        let read = fx
            .heard
            .published(&sealed_by(&control_plane(), &envelope))
            .await
            .unwrap()
            .unwrap();

        let depth = ChainDepth::from_stored(2).unwrap();
        assert_eq!(read.event.origin(), EventOrigin::Execution(depth));
    }

    /// Resetting a sealed event's chain depth invalidates its seal and prevents reading it.
    #[tokio::test]
    async fn a_depth_changed_on_the_way_breaks_the_seal() {
        let fx = fixture();
        let record = tenant_record();
        fx.trail.0.lock().unwrap().insert(record.id, record.clone());
        let deep = EventEnvelope {
            chain_depth: 3,
            ..envelope_of(&record)
        };
        let mut heard = sealed_by(&control_plane(), &deep);
        heard.payload = serde_json::to_vec(&envelope_of(&record)).unwrap();

        assert!(matches!(
            fx.heard.published(&heard).await,
            Err(Unheard::Unsealed)
        ));
    }

    /// Even a correctly sealed event is unreadable when its chain depth exceeds the limit.
    #[tokio::test]
    async fn a_depth_past_the_chains_limit_does_not_read() {
        let fx = fixture();
        let record = tenant_record();
        fx.trail.0.lock().unwrap().insert(record.id, record.clone());
        let envelope = EventEnvelope {
            chain_depth: u8::MAX,
            ..envelope_of(&record)
        };

        assert!(matches!(
            fx.heard
                .published(&sealed_by(&control_plane(), &envelope))
                .await,
            Err(Unheard::Unreadable(_))
        ));
    }
}
