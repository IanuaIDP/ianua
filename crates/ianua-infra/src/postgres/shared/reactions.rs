//! The events of each tenant the platform's monitors acted on, under
//! row-level security, so an event the bus hands out twice is acted on
//! once.
//!
//! A note is one insert that does nothing for an event its monitor noted
//! before, made in the running unit of work, so it is kept exactly when
//! what the monitor changed is; of two workers racing one event, exactly
//! one is told it was the first. The tenant's notes from before the bus
//! could last hand their events out are forgotten as the next is made.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::shared::{EventReactions, Noted, ReactionNote};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::errors::DomainError;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The longest a note may take before it is given up.
const NOTE_AT_MOST: Duration = Duration::from_secs(5);

/// The Postgres notes of the events the monitors acted on.
pub struct PgEventReactions {
    databases: Arc<Databases>,
}

impl TenantScoped for PgEventReactions {}

impl PgEventReactions {
    /// Notes kept in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The note `note` makes, without its time limit.
    async fn noted(
        &self,
        tenant_id: &ScopedTenant,
        note: &ReactionNote,
    ) -> Result<Noted, DomainError> {
        let made = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/event_reactions/forget.sql",
                    tenant_id.as_uuid(),
                    note.forget_before
                )
                .execute(&mut *connection)
                .await?;
                sqlx::query_file_scalar!(
                    "queries/event_reactions/note.sql",
                    tenant_id.as_uuid(),
                    note.reaction.as_str(),
                    note.record.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        Ok(made.map_or(Noted::Before, |_| Noted::First))
    }
}

#[async_trait]
impl EventReactions for PgEventReactions {
    async fn note(
        &self,
        tenant_id: &ScopedTenant,
        note: &ReactionNote,
    ) -> Result<Noted, DomainError> {
        tokio::time::timeout(NOTE_AT_MOST, self.noted(tenant_id, note))
            .await
            .map_err(DomainError::infra)?
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::shared::EventReaction;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{AuditRecordId, TenantId};

    use super::*;
    use crate::test_support::TestDb;

    /// A fresh database, the notes on it, and one tenant.
    async fn fixture() -> (TestDb, PgEventReactions, ScopedTenant) {
        let db = TestDb::fresh().await;
        let reactions = PgEventReactions::new(Arc::clone(&db.databases));
        (db, reactions, ScopedTenant::for_background(TenantId::new()))
    }

    fn note(reaction: EventReaction, record: AuditRecordId) -> ReactionNote {
        ReactionNote {
            reaction,
            record,
            forget_before: clock::now() - time::Duration::days(8),
        }
    }

    /// The first time a monitor acts on an event, the note is made.
    #[tokio::test]
    async fn the_first_note_of_an_event_is_made() {
        let (_db, reactions, tenant) = fixture().await;

        let noted = reactions
            .note(&tenant, &note(EventReaction::Drift, AuditRecordId::new()))
            .await
            .unwrap();

        assert_eq!(noted, Noted::First);
    }

    /// Repeating the same monitor's event note reports that it was
    /// recorded already.
    #[tokio::test]
    async fn an_event_noted_again_was_noted_before() {
        let (_db, reactions, tenant) = fixture().await;
        let event = note(EventReaction::Drift, AuditRecordId::new());
        reactions.note(&tenant, &event).await.unwrap();

        let again = reactions.note(&tenant, &event).await.unwrap();

        assert_eq!(again, Noted::Before);
    }

    /// Two monitors acting on one event each make their own note.
    #[tokio::test]
    async fn each_monitor_notes_the_event_for_itself() {
        let (_db, reactions, tenant) = fixture().await;
        let record = AuditRecordId::new();
        reactions
            .note(&tenant, &note(EventReaction::Drift, record))
            .await
            .unwrap();

        let other = reactions
            .note(&tenant, &note(EventReaction::Convergence, record))
            .await
            .unwrap();

        assert_eq!(other, Noted::First);
    }

    /// Concurrent notes for the same event and reaction grant exactly
    /// one caller the first-note result.
    #[tokio::test]
    async fn two_racing_notes_let_exactly_one_act() {
        let (_db, reactions, tenant) = fixture().await;
        let event = note(EventReaction::EgressDenial, AuditRecordId::new());

        let (one, two) = tokio::join!(
            reactions.note(&tenant, &event),
            reactions.note(&tenant, &event)
        );

        assert!((one.unwrap() == Noted::First) ^ (two.unwrap() == Noted::First));
    }
}
