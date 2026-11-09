//! The outbox and its relay: every audit record the trail keeps is queued
//! beside it, in the same transaction, and published on the message bus
//! once the change commits.
//!
//! The relay takes the oldest queued records of each database, locked so
//! two relays never take the same ones, publishes each under its record's
//! id, so the bus keeps one copy of a record published twice, and removes
//! those the bus took. It stops at the first the bus refuses; that one and
//! the rest wait for the next pass. A bus that is down delays events, it
//! never loses one. Each event goes out under its publisher's seal on its
//! subject and payload, which a consumer checks before it acts on it. The
//! subject is the envelope's, and the bus server puts it under the
//! deployment's namespace.

mod record;

use std::num::NonZeroU32;
use std::sync::Arc;

use futures_util::future::try_join_all;
use ianua_domain::shared::errors::DomainError;
use uuid::Uuid;

use self::record::{PlatformPending, TenantPending};
use crate::bus::{Bus, EventEnvelope, SealedEvent};
use crate::crypto::EventSeal;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The relay of queued records to the message bus.
pub struct OutboxRelay {
    databases: Arc<Databases>,
    bus: Arc<dyn Bus>,
    seal: EventSeal,
}

impl std::fmt::Debug for OutboxRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxRelay").finish_non_exhaustive()
    }
}

impl OutboxRelay {
    /// A relay of the outboxes in `databases` to `bus`, sealing each event
    /// with `seal`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, bus: Arc<dyn Bus>, seal: EventSeal) -> Self {
        Self {
            databases,
            bus,
            seal,
        }
    }

    /// Publishes `envelopes` in order, each sealed, and answers the ids the
    /// bus took, up to the first it refused.
    async fn published(&self, envelopes: Vec<EventEnvelope>) -> Vec<Uuid> {
        let mut taken = Vec::with_capacity(envelopes.len());
        for envelope in envelopes {
            let Ok(payload) = serde_json::to_vec(&envelope) else {
                tracing::warn!(event = %envelope.id, "an event could not be written for the bus");
                break;
            };
            let subject = envelope.subject();
            let event = SealedEvent {
                subject: &subject,
                id: &envelope.id.to_string(),
                payload: &payload,
                seal: &self.seal.seal(&subject, &payload),
            };
            if let Err(error) = self.bus.publish(&event).await {
                tracing::warn!(%error, event = %envelope.id, "the bus did not take an event; it waits for the next pass");
                break;
            }
            taken.push(envelope.id);
        }
        taken
    }

    /// Publishes at most `batch` queued records of each place records are
    /// kept, and answers how many went out.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when an outbox cannot be read.
    /// A record the bus did not take is not an error: it waits.
    pub async fn pass(&self, batch: NonZeroU32) -> Result<u64, DomainError> {
        let limit = i64::from(batch.get());
        let apart = self
            .databases
            .with_own_database()
            .into_iter()
            .map(|tenant| self.tenants(RowScope::Tenant(tenant), limit));
        let (platform, shared, apart) = futures_util::try_join!(
            self.platform(limit),
            self.tenants(RowScope::Platform, limit),
            try_join_all(apart),
        )?;
        Ok(apart
            .into_iter()
            .fold(platform.saturating_add(shared), u64::saturating_add))
    }

    /// Relays the tenants' queued records kept where `scope` reads.
    async fn tenants(&self, scope: RowScope, limit: i64) -> Result<u64, DomainError> {
        scoped(&self.databases, scope, async |connection| {
            let pending =
                sqlx::query_file_as!(TenantPending, "queries/event_outbox/pending.sql", limit)
                    .fetch_all(&mut *connection)
                    .await?;
            let tenants: Vec<Uuid> = pending.iter().map(|record| record.tenant_id).collect();
            let taken = self
                .published(
                    pending
                        .into_iter()
                        .map(TenantPending::into_envelope)
                        .collect(),
                )
                .await;
            sqlx::query_file!("queries/event_outbox/remove.sql", &tenants, &taken)
                .execute(connection)
                .await?;
            Ok(u64::try_from(taken.len()).unwrap_or(u64::MAX))
        })
        .await
    }

    /// Relays the queued organization and platform records.
    async fn platform(&self, limit: i64) -> Result<u64, DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let pending = sqlx::query_file_as!(
                PlatformPending,
                "queries/platform_event_outbox/pending.sql",
                limit
            )
            .fetch_all(&mut *connection)
            .await?;
            let taken = self
                .published(
                    pending
                        .into_iter()
                        .map(PlatformPending::into_envelope)
                        .collect(),
                )
                .await;
            sqlx::query_file!("queries/platform_event_outbox/remove.sql", &taken)
                .execute(connection)
                .await?;
            Ok(u64::try_from(taken.len()).unwrap_or(u64::MAX))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)]

    use ianua_app::ports::shared::EventDispatcher;
    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::shared::events::chain::{ChainDepth, EventOrigin, MAX_CHAIN_DEPTH};
    use ianua_domain::test_support::events::sample_organization_event;
    use ianua_domain::types::{OrganizationId, TenantId};

    use super::*;
    use crate::bus::{EventScope, HeardEvent, HeardEvents, MemoryBus, Published, RefusingBus};
    use crate::crypto::EventCheck;
    use crate::crypto::keys::tests::test_root;
    use crate::postgres::audit::PgEventDispatcher;
    use crate::postgres::shared::PgRecordedEvents;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::{
        chain_heads, failed_sign_in, saved_organization, saved_tenant_of,
    };

    fn most(limit: u32) -> NonZeroU32 {
        NonZeroU32::new(limit).unwrap()
    }

    fn control_plane() -> EventSeal {
        EventSeal::control_plane(&test_root())
    }

    fn relay(db: &TestDb, bus: Arc<dyn Bus>) -> OutboxRelay {
        OutboxRelay::new(Arc::clone(&db.databases), bus, control_plane())
    }

    /// Events a tenant and an organization dispatched go out on the bus
    /// once, under their records' ids and subjects, and leave the outbox.
    #[tokio::test]
    async fn dispatched_events_go_out_once() {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        PgEventDispatcher::new(Arc::clone(&db.databases), chain_heads())
            .dispatch(
                &[
                    failed_sign_in(*tenant, 1),
                    sample_organization_event(organization, at(2)),
                ],
                &AuditContext::system(),
            )
            .await
            .unwrap();
        let bus = Arc::new(MemoryBus::new(100));
        let relay = relay(&db, bus.clone());

        let first = relay.pass(most(10)).await.unwrap();
        let again = relay.pass(most(10)).await.unwrap();

        let published = bus.published();
        assert_eq!((first, again), (2, 0));
        assert_scopes(&published, *tenant, organization);
    }

    /// Confirms the published envelopes retain both ownership scopes and scoped subjects.
    fn assert_scopes(published: &[Published], tenant: TenantId, organization: OrganizationId) {
        let envelopes: Vec<EventEnvelope> = published
            .iter()
            .map(|event| serde_json::from_slice(&event.payload).unwrap())
            .collect();
        assert!(
            envelopes
                .iter()
                .any(|envelope| envelope.scope == EventScope::Tenant(*tenant.as_uuid()))
        );
        assert!(envelopes.iter().any(|envelope| envelope.scope == EventScope::Organization(*organization.as_uuid())));
        assert!(published.iter().all(|event| {
            event.subject.starts_with("tenant.") || event.subject.starts_with("org.")
        }));
    }

    /// Every event goes out sealed by the control plane, so the worker
    /// acts on it; one changed on the way is not vouched for.
    #[tokio::test]
    async fn every_event_goes_out_sealed() {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        PgEventDispatcher::new(Arc::clone(&db.databases), chain_heads())
            .dispatch(&[failed_sign_in(*tenant, 1)], &AuditContext::system())
            .await
            .unwrap();
        let bus = Arc::new(MemoryBus::new(100));
        relay(&db, bus.clone()).pass(most(10)).await.unwrap();
        let check = EventCheck::new(control_plane(), EventSeal::data_plane(&test_root()));

        let event = bus.published().remove(0);

        assert!(check.holds(&event.subject, &event.payload, &event.seal));
        assert!(!check.holds(&event.subject, b"{}", &event.seal));
    }

    /// No more than the batch goes out in one pass; the rest go in the
    /// next.
    #[tokio::test]
    async fn a_pass_takes_no_more_than_its_batch() {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        let events: Vec<_> = (1..=3)
            .map(|seconds| failed_sign_in(*tenant, seconds))
            .collect();
        PgEventDispatcher::new(Arc::clone(&db.databases), chain_heads())
            .dispatch(&events, &AuditContext::system())
            .await
            .unwrap();
        let relay = relay(&db, Arc::new(MemoryBus::new(100)));

        let first = relay.pass(most(2)).await.unwrap();
        let second = relay.pass(most(2)).await.unwrap();

        assert_eq!((first, second), (2, 1));
    }

    /// A refusing bus leaves the event queued, and a later pass with a working
    /// bus publishes it.
    #[tokio::test]
    async fn events_wait_while_the_bus_is_down() {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        PgEventDispatcher::new(Arc::clone(&db.databases), chain_heads())
            .dispatch(&[failed_sign_in(*tenant, 1)], &AuditContext::system())
            .await
            .unwrap();

        let down = relay(&db, Arc::new(RefusingBus))
            .pass(most(10))
            .await
            .unwrap();
        let back = relay(&db, Arc::new(MemoryBus::new(100)))
            .pass(most(10))
            .await
            .unwrap();

        assert_eq!((down, back), (0, 1));
    }

    /// An event raised at the maximum workflow depth retains its execution
    /// origin and depth across the bus; that depth cannot be incremented.
    #[tokio::test]
    async fn a_workflow_raised_event_keeps_its_depth_across_the_bus() {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        let deepest = ChainDepth::from_stored(MAX_CHAIN_DEPTH).unwrap();
        PgEventDispatcher::new(Arc::clone(&db.databases), chain_heads())
            .dispatch(
                &[failed_sign_in(*tenant, 1).from_execution(deepest)],
                &AuditContext::system(),
            )
            .await
            .unwrap();
        let bus = Arc::new(MemoryBus::new(100));
        relay(&db, bus.clone()).pass(most(10)).await.unwrap();
        let published = bus.published().remove(0);
        let heard = HeardEvents::new(
            EventCheck::new(control_plane(), EventSeal::data_plane(&test_root())),
            Arc::new(PgRecordedEvents::new(Arc::clone(&db.databases))),
        );

        let read = heard
            .published(&HeardEvent {
                subject: published.subject,
                payload: published.payload,
                seal: Some(published.seal),
            })
            .await
            .unwrap()
            .unwrap();

        assert_eq!(read.event.origin(), EventOrigin::Execution(deepest));
        assert!(deepest.next().is_err());
    }
}
