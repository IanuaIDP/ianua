//! The gateway's dispatcher: the events its use cases send, sealed by the
//! gateway and kept in its inbox, in the running unit of work.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::ports::shared::EventDispatcher;
use ianua_domain::domains::audit::builder::{AuditContext, build_audit_record};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::TenantId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::EventSeal;
use crate::inbox::record::{Entry, Sealed};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The gateway's `EventDispatcher`: each event sealed with the data
/// plane's seal and kept in its tenant's inbox, never on the trail.
pub struct InboxEventDispatcher {
    databases: Arc<Databases>,
    seal: EventSeal,
}

impl std::fmt::Debug for InboxEventDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboxEventDispatcher")
            .finish_non_exhaustive()
    }
}

impl InboxEventDispatcher {
    /// A dispatcher keeping events in the inboxes of `databases`, which the
    /// gateway's role reaches, sealing each with `seal`, the data plane's.
    #[must_use]
    pub fn new(databases: Arc<Databases>, seal: EventSeal) -> Self {
        Self { databases, seal }
    }

    /// Keeps `tenant`'s sealed `rows` in its inbox, in one statement.
    async fn keep(&self, tenant: TenantId, rows: Vec<Sealed>) -> Result<(), DomainError> {
        let columns = Columns::of(rows);
        scoped(
            &self.databases,
            RowScope::Tenant(tenant),
            async |connection| {
                sqlx::query_file!(
                    "queries/gateway_events/add.sql",
                    tenant.as_uuid(),
                    &columns.ids,
                    &columns.event_types,
                    &columns.subjects,
                    &columns.payloads,
                    &columns.seals,
                    &columns.occurred_at as &[OffsetDateTime],
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

#[async_trait]
impl EventDispatcher for InboxEventDispatcher {
    /// Seals each event and keeps it in its tenant's inbox. Nothing is
    /// written unless every event is one the gateway raises.
    ///
    /// # Errors
    ///
    /// - `DomainError::Forbidden` when an event is not one the data plane
    ///   raises, not a tenant's, or recorded through an impersonation.
    /// - `DomainError::Infrastructure` when an event cannot be written.
    async fn dispatch(
        &self,
        events: &[DomainEvent],
        ctx: &AuditContext,
    ) -> Result<(), DomainError> {
        let mut tenants: HashMap<TenantId, Vec<Sealed>> = HashMap::new();
        for event in events {
            let record = build_audit_record(event, ctx);
            let sealed = Entry::sealed_row(&record, event.origin(), &self.seal)?;
            tenants
                .entry(TenantId::from_uuid(sealed.tenant_id))
                .or_default()
                .push(sealed);
        }
        try_join_all(
            tenants
                .into_iter()
                .map(|(tenant, rows)| self.keep(tenant, rows)),
        )
        .await?;
        Ok(())
    }
}

/// Many sealed rows' columns, one list per column, as one statement writes
/// them.
#[derive(Default)]
struct Columns {
    ids: Vec<Uuid>,
    event_types: Vec<String>,
    subjects: Vec<String>,
    payloads: Vec<String>,
    seals: Vec<String>,
    occurred_at: Vec<OffsetDateTime>,
}

impl Columns {
    fn of(rows: Vec<Sealed>) -> Self {
        let mut columns = Self::default();
        for row in rows {
            columns.ids.push(row.id);
            columns.event_types.push(row.event_type);
            columns.subjects.push(row.subject);
            columns.payloads.push(row.payload);
            columns.seals.push(row.seal);
            columns.occurred_at.push(row.occurred_at);
        }
        columns
    }
}
