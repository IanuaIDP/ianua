//! The review assignments people make between a tenant's agents, each row
//! under row-level security.
//!
//! An assignment links its two agents, so one naming an agent the tenant
//! does not have is refused, and deleting either agent takes it along.
//! Once made, only its end changes.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::ReviewAssignmentStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::oversight::review::ReviewAssignment;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, ReviewAssignmentId};

use self::record::{ReviewColumns, ReviewRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres review assignment store.
pub struct PgReviewAssignmentStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgReviewAssignmentStore {}

impl PgReviewAssignmentStore {
    /// A store keeping review assignments in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The assignments `records` hold, each rebuilt through the domain's
/// checks.
fn rebuilt_all(
    records: Vec<ReviewRecord>,
) -> Result<Vec<ReviewAssignment<ResolvedTenant>>, DomainError> {
    records.into_iter().map(ReviewRecord::into_review).collect()
}

#[async_trait]
impl ReviewAssignmentStore for PgReviewAssignmentStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        assignment: &ReviewAssignment<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ReviewColumns::of(assignment);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/agent_review_assignments/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.reviewer_id,
                    columns.reviewed_id,
                    columns.assigned_by_kind,
                    columns.assigned_by_id,
                    columns.assigned_at,
                    columns.ended_at,
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ReviewAssignmentId,
    ) -> Result<Option<ReviewAssignment<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ReviewRecord,
                    "queries/agent_review_assignments/by_ids.sql",
                    tenant_id.as_uuid(),
                    &ids[..]
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        Ok(rebuilt_all(records)?.into_iter().next())
    }

    async fn list_for_agent(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
    ) -> Result<Vec<ReviewAssignment<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ReviewRecord,
                    "queries/agent_review_assignments/of_agent.sql",
                    tenant_id.as_uuid(),
                    agent.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt_all(records)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::oversight::review::ReviewAssignmentRow;
    use ianua_domain::types::{Ending, TenantId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::run::{another_agent, review_row};
    use crate::test_support::rows::at;

    struct Fixture {
        db: TestDb,
        store: PgReviewAssignmentStore,
        tenant: ScopedTenant,
        reviewer: AgentId,
        reviewed: AgentId,
    }

    /// A fresh database, the store on it, and two agents of one tenant,
    /// one to review the other.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let reviewer = another_agent(&db.databases, &tenant).await;
        let reviewed = another_agent(&db.databases, &tenant).await;
        Fixture {
            store: PgReviewAssignmentStore::new(Arc::clone(&db.databases)),
            tenant,
            reviewer,
            reviewed,
            db,
        }
    }

    fn review(row: &ReviewAssignmentRow) -> ReviewAssignment<ResolvedTenant> {
        ReviewAssignment::reconstitute(*row).unwrap()
    }

    impl Fixture {
        async fn saved(&self, row: &ReviewAssignmentRow) -> ReviewAssignment<ResolvedTenant> {
            let assignment = review(row);
            self.store.save(&self.tenant, &assignment).await.unwrap();
            assignment
        }

        async fn found(&self, id: &ReviewAssignmentId) -> Option<ReviewAssignment<ResolvedTenant>> {
            self.store.find_by_id(&self.tenant, id).await.unwrap()
        }

        async fn of(&self, agent: &AgentId) -> Vec<ReviewAssignmentId> {
            let listed = self.store.list_for_agent(&self.tenant, agent).await;
            listed.unwrap().iter().map(|review| *review.id()).collect()
        }
    }

    /// Ann's assignment of one agent to review the other is found again as
    /// she made it.
    #[tokio::test]
    async fn a_saved_assignment_is_found_as_it_was_made() {
        let fx = fixture().await;
        let saved = fx.saved(&review_row(fx.reviewer, fx.reviewed)).await;

        let found = fx.found(saved.id()).await.unwrap();

        assert_eq!(found.reviewer(), &fx.reviewer);
        assert_eq!(found.reviewed(), &fx.reviewed);
        assert_eq!(found.assigned_by(), saved.assigned_by());
        assert_eq!(found.assigned_at(), at(0));
        assert!(found.is_active());
    }

    /// An id the tenant has no assignment for finds nothing, rather than
    /// failing.
    #[tokio::test]
    async fn an_unknown_assignment_is_not_found() {
        let fx = fixture().await;

        assert!(fx.found(&ReviewAssignmentId::new()).await.is_none());
    }

    /// Ann ends the review: saving it again keeps its end, and it no longer
    /// stands.
    #[tokio::test]
    async fn an_ended_assignment_keeps_its_end() {
        let fx = fixture().await;
        let saved = fx.saved(&review_row(fx.reviewer, fx.reviewed)).await;
        fx.saved(&ReviewAssignmentRow {
            id: *saved.id(),
            ending: Ending::Ended { at: at(7) },
            ..review_row(fx.reviewer, fx.reviewed)
        })
        .await;

        let found = fx.found(saved.id()).await.unwrap();

        assert_eq!(found.ended_at(), Some(at(7)));
        assert!(!found.is_active());
    }

    /// The assignments an agent is part of, as reviewer or reviewed, are
    /// listed newest first, ended ones included, and those it is no part
    /// of are left out.
    #[tokio::test]
    async fn an_agents_assignments_are_listed_newest_first() {
        let fx = fixture().await;
        let third = another_agent(&fx.db.databases, &fx.tenant).await;
        let reviewing = fx.saved(&review_row(fx.reviewer, fx.reviewed)).await;
        let reviewed = fx
            .saved(&ReviewAssignmentRow {
                assigned_at: at(4),
                ending: Ending::Ended { at: at(6) },
                ..review_row(third, fx.reviewer)
            })
            .await;
        let elsewhere = fx.saved(&review_row(third, fx.reviewed)).await;

        assert_eq!(fx.of(&fx.reviewer).await, [*reviewed.id(), *reviewing.id()]);
        assert!(!fx.of(&fx.reviewer).await.contains(elsewhere.id()));
    }

    /// Saving a review assignment for an unknown agent returns an
    /// infrastructure error.
    #[tokio::test]
    async fn an_assignment_of_an_unknown_agent_is_refused() {
        let fx = fixture().await;
        let stray = review(&review_row(fx.reviewer, AgentId::new()));

        let saved = fx.store.save(&fx.tenant, &stray).await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
    }

    /// Another tenant sees none of Acme's assignments, by id or for its
    /// agents.
    #[tokio::test]
    async fn another_tenants_assignments_are_invisible() {
        let fx = fixture().await;
        let saved = fx.saved(&review_row(fx.reviewer, fx.reviewed)).await;
        let other = ScopedTenant::for_background(TenantId::new());

        let by_id = fx.store.find_by_id(&other, saved.id()).await.unwrap();
        let listed = fx.store.list_for_agent(&other, &fx.reviewer).await;

        assert!(by_id.is_none());
        assert!(listed.unwrap().is_empty());
    }

    /// A dedicated tenant's review assignment is found directly in its
    /// database.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_keeps_its_assignments_there() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        let reviewer = another_agent(&fx.db.databases, &apart).await;
        let reviewed = another_agent(&fx.db.databases, &apart).await;
        let saved = review(&review_row(reviewer, reviewed));

        fx.store.save(&apart, &saved).await.unwrap();

        let in_own = PgReviewAssignmentStore::new(Arc::clone(&own.databases));
        let found = in_own.find_by_id(&apart, saved.id()).await.unwrap();
        assert!(found.is_some());
    }

    /// A stored review assignment naming an agent as its assigner is rejected
    /// as corrupt.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_assignment_is_refused() {
        let fx = fixture().await;
        let saved = fx.saved(&review_row(fx.reviewer, fx.reviewed)).await;
        fx.db
            .tamper(
                "ALTER TABLE agent_review_assignments \
                 DROP CONSTRAINT agent_review_assignments_assigner_known; \
                 UPDATE agent_review_assignments SET assigned_by_kind = 'agent'",
            )
            .await;

        let read = fx.store.find_by_id(&fx.tenant, saved.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
