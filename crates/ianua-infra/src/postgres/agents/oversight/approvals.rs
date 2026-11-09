//! The requests for a person to approve one action an agent wants to take,
//! each row under row-level security.
//!
//! A request is one row, and the people behind the delegation its action
//! uses are rows of their own, written once with it, in the order it names
//! them. Every read of a request goes through one mapping, its people read
//! for all the requests at once. Spending an approval is one statement
//! that writes without loading the request, so two calls racing for one
//! approval cannot both spend it. A save over a request decided or spent
//! since it was read is refused as a conflict, so a late approval never
//! undoes a denial or makes a spent approval whole again.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::ApprovalStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::oversight::approval::{ApprovalAction, ApprovalRequest};
use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, ApprovalId, DelegationId, PrincipalRef, TenantId};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{ApprovalColumns, ApprovalRecord, DelegatorRecord, delegators_by_request};
use crate::postgres::authorization::principals::kind_word;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;

/// The Postgres approval request store.
pub struct PgApprovalStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgApprovalStore {}

impl PgApprovalStore {
    /// A store keeping approval requests in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The requests of `tenant` that `rows` reads, each with the people
    /// behind its delegation.
    async fn read(
        &self,
        tenant: &ScopedTenant,
        rows: impl AsyncFnOnce(&mut PgConnection) -> Result<Vec<ApprovalRecord>, sqlx::Error>,
    ) -> Result<Vec<ApprovalRequest<ResolvedTenant>>, DomainError> {
        let read = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                let records = rows(&mut *connection).await?;
                with_delegators(connection, tenant, records).await
            },
        )
        .await?;
        read.into_iter()
            .map(|(record, delegators)| record.into_approval(delegators))
            .collect()
    }

    /// A count of `tenant`'s requests that `count` reads.
    async fn counted(
        &self,
        tenant: &ScopedTenant,
        count: impl AsyncFnOnce(&mut PgConnection) -> Result<i64, sqlx::Error>,
    ) -> Result<u32, DomainError> {
        let counted = scoped(&self.databases, RowScope::from(tenant), count).await?;
        Ok(u32::try_from(counted).unwrap_or(u32::MAX))
    }
}

/// `records`, each beside the people behind its delegation, read in one
/// query.
async fn with_delegators(
    connection: &mut PgConnection,
    tenant: &TenantId,
    records: Vec<ApprovalRecord>,
) -> Result<Vec<(ApprovalRecord, Vec<DelegatorRecord>)>, sqlx::Error> {
    let ids: Vec<Uuid> = records.iter().map(|record| record.id).collect();
    let delegators = sqlx::query_file_as!(
        DelegatorRecord,
        "queries/agent_approval_delegators/of_approvals.sql",
        tenant.as_uuid(),
        &ids
    )
    .fetch_all(connection)
    .await?;
    let mut by_request = delegators_by_request(delegators);
    Ok(records
        .into_iter()
        .map(|record| {
            let theirs = by_request.remove(&record.id).unwrap_or_default();
            (record, theirs)
        })
        .collect())
}

/// Writes `approval` as it is now, added or over what is stored, and says
/// whether it was written: one decided or spent since it was read is left
/// as it stands.
/// The checked statement keeps all approval columns in one write with explicit binds.
#[allow(clippy::too_many_lines)]
async fn write_approval(
    connection: &mut PgConnection,
    tenant: &TenantId,
    approval: &ApprovalColumns<'_>,
) -> Result<bool, sqlx::Error> {
    let (requester, run, owner) = (&approval.requested_by, &approval.run, &approval.owner);
    let (first, decider) = (&approval.first_by, &approval.decided_by);
    sqlx::query_file!(
        "queries/agent_approvals/save.sql",
        approval.id,
        tenant.as_uuid(),
        approval.agent_id,
        approval.delegation_id,
        requester.kind,
        requester.id,
        requester.person,
        run.run_id,
        run.pending_tool,
        run.pending_arguments,
        run.pending_at_step,
        run.exposure,
        run.chain_depth,
        owner.kind,
        owner.id,
        owner.person,
        approval.action_class,
        approval.action,
        approval.status,
        first.kind,
        first.id,
        first.person,
        approval.first_at,
        decider.kind,
        decider.id,
        decider.person,
        approval.decided_at,
        approval.created_at,
        approval.expires_at,
        approval.updated_at,
    )
    .execute(connection)
    .await
    .map(|done| done.rows_affected() > 0)
}

/// Writes the people behind `approval`'s delegation, in one statement.
async fn write_delegators(
    connection: &mut PgConnection,
    tenant: &TenantId,
    approval: &ApprovalColumns<'_>,
) -> Result<(), sqlx::Error> {
    let delegators = &approval.delegators;
    if delegators.places.is_empty() {
        return Ok(());
    }
    sqlx::query_file!(
        "queries/agent_approval_delegators/save.sql",
        tenant.as_uuid(),
        approval.id,
        &delegators.places,
        &delegators.kinds,
        &delegators.ids,
        &delegators.persons
    )
    .execute(connection)
    .await
    .map(|_| ())
}

#[async_trait]
impl ApprovalStore for PgApprovalStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ApprovalId,
    ) -> Result<Option<ApprovalRequest<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let found = self
            .read(tenant_id, async |connection| {
                sqlx::query_file_as!(
                    ApprovalRecord,
                    "queries/agent_approvals/by_ids.sql",
                    tenant_id.as_uuid(),
                    &ids[..]
                )
                .fetch_all(connection)
                .await
            })
            .await?;
        Ok(found.into_iter().next())
    }

    async fn list_for_agent(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
        status: Option<ApprovalStatus>,
    ) -> Result<Vec<ApprovalRequest<ResolvedTenant>>, DomainError> {
        let status = status.map(ApprovalStatus::word);
        let now = clock::now();
        self.read(tenant_id, async |connection| {
            sqlx::query_file_as!(
                ApprovalRecord,
                "queries/agent_approvals/of_agent.sql",
                tenant_id.as_uuid(),
                agent.as_uuid(),
                status,
                now
            )
            .fetch_all(connection)
            .await
        })
        .await
    }

    async fn list_in_tenant(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<ApprovalStatus>,
    ) -> Result<Vec<ApprovalRequest<ResolvedTenant>>, DomainError> {
        let status = status.map(ApprovalStatus::word);
        let now = clock::now();
        self.read(tenant_id, async |connection| {
            sqlx::query_file_as!(
                ApprovalRecord,
                "queries/agent_approvals/of_tenant.sql",
                tenant_id.as_uuid(),
                status,
                now
            )
            .fetch_all(connection)
            .await
        })
        .await
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        approval: &ApprovalRequest<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ApprovalColumns::of(approval)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                if !write_approval(&mut *connection, tenant_id, &columns).await? {
                    return Ok(false);
                }
                write_delegators(connection, tenant_id, &columns).await?;
                Ok(true)
            },
        )
        .await?;
        if written {
            return Ok(());
        }
        Err(DomainError::conflict(message!(
            "infra-the-approval-request-was-decided-or",
            "the approval request was decided or spent since it was read"
        )))
    }

    async fn find_pending_for_action(
        &self,
        tenant_id: &ScopedTenant,
        delegation: &DelegationId,
        action: &ApprovalAction,
        now: OffsetDateTime,
    ) -> Result<Option<ApprovalRequest<ResolvedTenant>>, DomainError> {
        let found = self
            .read(tenant_id, async |connection| {
                sqlx::query_file_as!(
                    ApprovalRecord,
                    "queries/agent_approvals/pending_for_action.sql",
                    tenant_id.as_uuid(),
                    delegation.as_uuid(),
                    action.as_str(),
                    now
                )
                .fetch_all(connection)
                .await
            })
            .await?;
        Ok(found.into_iter().next())
    }

    async fn consume_for_action(
        &self,
        tenant_id: &ScopedTenant,
        delegation: &DelegationId,
        action: &ApprovalAction,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let spent = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/agent_approvals/consume_for_action.sql",
                    tenant_id.as_uuid(),
                    delegation.as_uuid(),
                    action.as_str(),
                    now
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        Ok(spent.is_some())
    }

    async fn count_pending_for_delegation(
        &self,
        tenant_id: &ScopedTenant,
        delegation: &DelegationId,
        now: OffsetDateTime,
    ) -> Result<u32, DomainError> {
        self.counted(tenant_id, async |connection| {
            sqlx::query_file_scalar!(
                "queries/agent_approvals/pending_count.sql",
                tenant_id.as_uuid(),
                delegation.as_uuid(),
                now
            )
            .fetch_one(connection)
            .await
        })
        .await
    }

    async fn count_signed_by(
        &self,
        tenant_id: &ScopedTenant,
        approver: &PrincipalRef,
        since: OffsetDateTime,
    ) -> Result<u32, DomainError> {
        self.counted(tenant_id, async |connection| {
            sqlx::query_file_scalar!(
                "queries/agent_approvals/signed_count.sql",
                tenant_id.as_uuid(),
                kind_word(approver),
                approver.id(),
                since
            )
            .fetch_one(connection)
            .await
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::execution::run::AgentRun;
    use ianua_domain::domains::agents::oversight::approval::{
        Approval, ApprovalOrigin, ApprovalRequestRow, ApprovalState, FirstOfTwo, StoredDecision,
    };
    use ianua_domain::shared::model::aggregate::Aggregate as _;
    use ianua_domain::types::{Human, UserId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::run::{
        another_agent, delegated_approval_row, opened_approval_row, run_approval_row, run_row,
        saved_run,
    };
    use crate::test_support::rows::agents::saved_delegation;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::human;

    struct Fixture {
        db: TestDb,
        store: PgApprovalStore,
        tenant: ScopedTenant,
        agent: AgentId,
        owner: Human,
    }

    /// A fresh database, the store on it, and one agent of one tenant whose
    /// actions wait for approval.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let agent = another_agent(&db.databases, &tenant).await;
        Fixture {
            store: PgApprovalStore::new(Arc::clone(&db.databases)),
            tenant,
            agent,
            owner: human(UserId::new(), "owner@acme.example"),
            db,
        }
    }

    fn request(row: ApprovalRequestRow) -> ApprovalRequest<ResolvedTenant> {
        ApprovalRequest::reconstitute(row).unwrap()
    }

    fn bob() -> Human {
        human(UserId::new(), "bob@acme.example")
    }

    /// `row`, decided by `by` at `seconds` after the fixed moment as
    /// `status` says.
    fn decided(
        row: ApprovalRequestRow,
        status: ApprovalStatus,
        by: &Human,
        seconds: i64,
    ) -> ApprovalRequestRow {
        let decision = StoredDecision::Decided {
            by: by.clone(),
            at: at(seconds),
        };
        ApprovalRequestRow {
            state: ApprovalState::from_stored(status, None, decision).unwrap(),
            updated_at: at(seconds),
            ..row
        }
    }

    impl Fixture {
        async fn delegation(&self) -> DelegationId {
            saved_delegation(&self.db.databases, &self.tenant, self.agent).await
        }

        fn opened(&self) -> ApprovalRequestRow {
            opened_approval_row(self.agent, self.owner.clone())
        }

        fn delegated(&self, delegation: DelegationId) -> ApprovalRequestRow {
            delegated_approval_row(self.agent, self.owner.clone(), delegation)
        }

        async fn saved(&self, row: ApprovalRequestRow) -> ApprovalRequest<ResolvedTenant> {
            let approval = request(row);
            self.store.save(&self.tenant, &approval).await.unwrap();
            approval
        }

        async fn found(&self, id: &ApprovalId) -> Option<ApprovalRequest<ResolvedTenant>> {
            self.store.find_by_id(&self.tenant, id).await.unwrap()
        }

        async fn of_agent(&self, status: Option<ApprovalStatus>) -> Vec<ApprovalId> {
            let listed = self.store.list_for_agent(&self.tenant, &self.agent, status);
            ids(&listed.await.unwrap())
        }

        async fn in_tenant(
            &self,
            tenant: &ScopedTenant,
            status: Option<ApprovalStatus>,
        ) -> Vec<ApprovalId> {
            ids(&self.store.list_in_tenant(tenant, status).await.unwrap())
        }

        async fn spend(&self, delegation: &DelegationId, action: &ApprovalAction) -> bool {
            let spent = self
                .store
                .consume_for_action(&self.tenant, delegation, action, at(10));
            spent.await.unwrap()
        }
    }

    fn ids(requests: &[ApprovalRequest<ResolvedTenant>]) -> Vec<ApprovalId> {
        requests.iter().map(|request| *request.id()).collect()
    }

    /// Cid's request, opened by hand for the agent, is found again as he
    /// opened it, with the agent's owner and no delegators.
    #[tokio::test]
    async fn an_opened_request_is_found_as_it_was_opened() {
        let fx = fixture().await;
        let saved = fx.saved(fx.opened()).await;

        let found = fx.found(saved.id()).await.unwrap();

        assert_eq!(found.origin(), saved.origin());
        assert_eq!(found.parties(), saved.parties());
        assert_eq!(found.action(), saved.action());
        assert_eq!(found.action_class(), saved.action_class());
        assert_eq!(found.state(), saved.state());
        assert_eq!(found.expires_at(), at(600));
    }

    /// A request under a delegation is found with the people behind it, in
    /// the order it names them.
    #[tokio::test]
    async fn a_delegated_request_is_found_with_its_delegators() {
        let fx = fixture().await;
        let saved = fx.saved(fx.delegated(fx.delegation().await)).await;

        let found = fx.found(saved.id()).await.unwrap();

        assert_eq!(found.delegation_id(), saved.delegation_id());
        assert_eq!(found.parties().delegators(), saved.parties().delegators());
    }

    /// A request a run raised is found with the run, the call it paused on
    /// and who started it.
    #[tokio::test]
    async fn a_request_a_run_raised_is_found_with_its_run() {
        let fx = fixture().await;
        let run = saved_run(&fx.db.databases, &fx.tenant).await;
        let saved = fx.saved(run_approval_row(&run, fx.owner.clone())).await;

        let found = fx.found(saved.id()).await.unwrap();

        assert_eq!(found.run_id(), Some(run.id()));
        assert_eq!(found.pending_call(), saved.pending_call());
        assert!(matches!(found.origin(), ApprovalOrigin::Run(_)));
        assert_eq!(found.origin(), saved.origin());
    }

    /// Saving an approval request for an unstored run returns an
    /// infrastructure error and leaves the request absent.
    #[tokio::test]
    async fn a_request_of_an_unknown_run_is_refused() {
        let fx = fixture().await;
        let never_saved = AgentRun::reconstitute(run_row(fx.agent)).unwrap();
        let approval = request(run_approval_row(&never_saved, fx.owner.clone()));

        let saved = fx.store.save(&fx.tenant, &approval).await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
        assert!(fx.found(approval.id()).await.is_none());
    }

    /// An id the tenant has no request for finds nothing, rather than
    /// failing.
    #[tokio::test]
    async fn an_unknown_request_is_not_found() {
        let fx = fixture().await;

        assert!(fx.found(&ApprovalId::new()).await.is_none());
    }

    /// Bob denies the request: saving it again keeps the denial with Bob
    /// as the person who made it, not only his account.
    #[tokio::test]
    async fn a_denial_keeps_the_person_who_made_it() {
        let fx = fixture().await;
        let saved = fx.saved(fx.opened()).await;
        let bob = bob();
        fx.saved(ApprovalRequestRow {
            id: *saved.id(),
            ..decided(fx.opened(), ApprovalStatus::Denied, &bob, 5)
        })
        .await;

        let found = fx.found(saved.id()).await.unwrap();

        assert_eq!(found.status(), ApprovalStatus::Denied);
        let decision = found.state().decision().unwrap();
        assert_eq!(decision.decider(), &bob);
        assert_eq!(decision.at(), at(5));
    }

    /// Bob gives the first of two approvals: it is kept with him and the
    /// time, and the request still waits.
    #[tokio::test]
    async fn a_first_approval_is_kept_while_the_request_waits() {
        let fx = fixture().await;
        let bob = bob();
        let first = Approval {
            by: bob.clone(),
            at: at(3),
        };
        let saved = fx
            .saved(ApprovalRequestRow {
                state: ApprovalState::Pending(FirstOfTwo::Given(first)),
                updated_at: at(3),
                ..fx.opened()
            })
            .await;

        let found = fx.found(saved.id()).await.unwrap();

        assert!(found.is_pending());
        assert_eq!(found.first_approval().map(|first| &first.by), Some(&bob));
    }

    /// An agent's requests are listed newest first, narrowed to one status
    /// when one is asked for, and leave out another agent's.
    #[tokio::test]
    async fn an_agents_requests_are_listed_newest_first_by_status() {
        let fx = fixture().await;
        let older = fx.saved(fx.opened()).await;
        let newer = fx
            .saved(ApprovalRequestRow {
                created_at: at(2),
                ..decided(fx.opened(), ApprovalStatus::Denied, &bob(), 4)
            })
            .await;
        let other = another_agent(&fx.db.databases, &fx.tenant).await;
        let theirs = fx.saved(opened_approval_row(other, fx.owner.clone())).await;

        let every = fx.of_agent(None).await;
        let pending = fx.of_agent(Some(ApprovalStatus::Pending)).await;
        let tenant = fx
            .in_tenant(&fx.tenant, Some(ApprovalStatus::Pending))
            .await;

        assert_eq!(every, [*newer.id(), *older.id()]);
        assert_eq!(pending, [*older.id()]);
        assert_eq!(tenant.len(), 2);
        assert!(tenant.contains(theirs.id()));
    }

    /// One second after expiry, both agent and tenant listings exclude the
    /// request from pending results and include it in expired results.
    #[tokio::test]
    async fn a_request_past_its_time_is_listed_as_expired() {
        let fx = fixture().await;
        let lapsed = fx.saved(fx.opened()).await;
        let _late = clock::freeze(lapsed.expires_at() + time::Duration::seconds(1));

        let pending = fx.of_agent(Some(ApprovalStatus::Pending)).await;
        let expired = fx.of_agent(Some(ApprovalStatus::Expired)).await;
        let tenant_pending = fx
            .in_tenant(&fx.tenant, Some(ApprovalStatus::Pending))
            .await;
        let tenant_expired = fx
            .in_tenant(&fx.tenant, Some(ApprovalStatus::Expired))
            .await;

        assert!(pending.is_empty());
        assert_eq!(expired, [*lapsed.id()]);
        assert!(tenant_pending.is_empty());
        assert_eq!(tenant_expired, [*lapsed.id()]);
    }

    /// The pending request for exactly one action under one delegation is
    /// found while it is open, and not once it has closed, for another
    /// action or under another delegation.
    #[tokio::test]
    async fn the_pending_request_for_an_action_is_found_while_open() {
        let fx = fixture().await;
        let delegation = fx.delegation().await;
        let saved = fx.saved(fx.delegated(delegation)).await;
        let other_action = ApprovalAction::new("GET /orders/2").unwrap();
        let store = &fx.store;
        let tenant = &fx.tenant;

        let open = store.find_pending_for_action(tenant, &delegation, saved.action(), at(10));
        let closed = store.find_pending_for_action(tenant, &delegation, saved.action(), at(600));
        let other = store.find_pending_for_action(tenant, &delegation, &other_action, at(10));
        let elsewhere = fx.delegation().await;
        let apart = store.find_pending_for_action(tenant, &elsewhere, saved.action(), at(10));

        assert_eq!(
            open.await.unwrap().map(|found| *found.id()),
            Some(*saved.id())
        );
        assert!(closed.await.unwrap().is_none());
        assert!(other.await.unwrap().is_none());
        assert!(apart.await.unwrap().is_none());
    }

    /// An approval can be consumed once and then reads as consumed with the
    /// consumption time. A pending request cannot be consumed.
    #[tokio::test]
    async fn an_approval_is_spent_once() {
        let fx = fixture().await;
        let delegation = fx.delegation().await;
        let approved = fx
            .saved(decided(
                fx.delegated(delegation),
                ApprovalStatus::Approved,
                &bob(),
                5,
            ))
            .await;
        let waiting = fx.delegation().await;
        let pending = fx.saved(fx.delegated(waiting)).await;

        let first = fx.spend(&delegation, approved.action()).await;
        let second = fx.spend(&delegation, approved.action()).await;
        let unapproved = fx.spend(&waiting, pending.action()).await;

        assert!(first);
        assert!(!second);
        assert!(!unapproved);
        let spent = fx.found(approved.id()).await.unwrap();
        assert_eq!(spent.status(), ApprovalStatus::Consumed);
        assert_eq!(spent.updated_at(), at(10));
    }

    /// Saving an approved copy after consumption returns a conflict. The
    /// request remains consumed and cannot be consumed again.
    #[tokio::test]
    async fn a_spent_approval_is_not_made_whole_by_an_old_copy() {
        let fx = fixture().await;
        let delegation = fx.delegation().await;
        let approved = fx
            .saved(decided(
                fx.delegated(delegation),
                ApprovalStatus::Approved,
                &bob(),
                5,
            ))
            .await;
        assert!(fx.spend(&delegation, approved.action()).await);

        let resaved = fx.store.save(&fx.tenant, &approved).await;

        assert!(matches!(resaved, Err(DomainError::Conflict(_))));
        assert!(!fx.spend(&delegation, approved.action()).await);
        let found = fx.found(approved.id()).await.unwrap();
        assert_eq!(found.status(), ApprovalStatus::Consumed);
    }

    /// Saving Bob's approval after Cid's denial returns a conflict and
    /// preserves the denied status with Cid as decider.
    #[tokio::test]
    async fn an_approval_from_an_old_copy_does_not_undo_a_denial() {
        let fx = fixture().await;
        let saved = fx.saved(fx.opened()).await;
        let cid = human(UserId::new(), "cid@acme.example");
        fx.saved(ApprovalRequestRow {
            id: *saved.id(),
            ..decided(fx.opened(), ApprovalStatus::Denied, &cid, 5)
        })
        .await;
        let approved = request(ApprovalRequestRow {
            id: *saved.id(),
            ..decided(fx.opened(), ApprovalStatus::Approved, &bob(), 6)
        });

        let late = fx.store.save(&fx.tenant, &approved).await;

        assert!(matches!(late, Err(DomainError::Conflict(_))));
        let found = fx.found(saved.id()).await.unwrap();
        assert_eq!(found.status(), ApprovalStatus::Denied);
        assert_eq!(found.state().decision().unwrap().decider(), &cid);
    }

    /// The same decision saved twice, as a retry does, is kept once and
    /// not refused.
    #[tokio::test]
    async fn the_same_decision_saved_again_is_kept() {
        let fx = fixture().await;
        let bob = bob();
        let denied = fx
            .saved(decided(fx.opened(), ApprovalStatus::Denied, &bob, 5))
            .await;

        let again = fx.store.save(&fx.tenant, &denied).await;

        assert!(again.is_ok());
        assert_eq!(
            fx.found(denied.id()).await.unwrap().status(),
            ApprovalStatus::Denied
        );
    }

    /// The requests waiting under a delegation are counted while open, and
    /// a decided or closed one is not.
    #[tokio::test]
    async fn the_open_requests_of_a_delegation_are_counted() {
        let fx = fixture().await;
        let delegation = fx.delegation().await;
        fx.saved(fx.delegated(delegation)).await;
        fx.saved(fx.delegated(delegation)).await;
        fx.saved(decided(
            fx.delegated(delegation),
            ApprovalStatus::Denied,
            &bob(),
            5,
        ))
        .await;
        let store = &fx.store;

        let open = store.count_pending_for_delegation(&fx.tenant, &delegation, at(10));
        let closed = store.count_pending_for_delegation(&fx.tenant, &delegation, at(600));

        assert_eq!(open.await.unwrap(), 2);
        assert_eq!(closed.await.unwrap(), 0);
    }

    /// Bob's grants and first signatures since a time are counted, and his
    /// denials and those before it are not.
    #[tokio::test]
    async fn the_approvals_a_person_signed_are_counted() {
        let fx = fixture().await;
        let bob = bob();
        fx.saved(decided(fx.opened(), ApprovalStatus::Approved, &bob, 5))
            .await;
        fx.saved(decided(fx.opened(), ApprovalStatus::Approved, &bob, 1))
            .await;
        fx.saved(decided(fx.opened(), ApprovalStatus::Denied, &bob, 5))
            .await;
        fx.saved(ApprovalRequestRow {
            state: ApprovalState::Pending(FirstOfTwo::Given(Approval {
                by: bob.clone(),
                at: at(6),
            })),
            updated_at: at(6),
            ..fx.opened()
        })
        .await;

        let signed = fx
            .store
            .count_signed_by(&fx.tenant, &bob.principal(), at(2))
            .await
            .unwrap();

        assert_eq!(signed, 2);
    }

    /// Another tenant sees none of Acme's requests, and cannot spend or
    /// count them.
    #[tokio::test]
    async fn another_tenants_requests_are_invisible() {
        let fx = fixture().await;
        let delegation = fx.delegation().await;
        let saved = fx
            .saved(decided(
                fx.delegated(delegation),
                ApprovalStatus::Approved,
                &bob(),
                5,
            ))
            .await;
        let other = ScopedTenant::for_background(TenantId::new());
        let store = &fx.store;

        let by_id = store.find_by_id(&other, saved.id()).await.unwrap();
        let spent = store.consume_for_action(&other, &delegation, saved.action(), at(10));

        assert!(by_id.is_none());
        assert!(!spent.await.unwrap());
        assert!(fx.in_tenant(&other, None).await.is_empty());
        assert!(fx.spend(&delegation, saved.action()).await);
    }

    /// A dedicated tenant's approval request reads back directly from its
    /// database with its parties unchanged.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_keeps_its_requests_there() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        let agent = another_agent(&fx.db.databases, &apart).await;
        let delegation = saved_delegation(&fx.db.databases, &apart, agent).await;
        let row = delegated_approval_row(agent, fx.owner.clone(), delegation);
        let saved = request(row);

        fx.store.save(&apart, &saved).await.unwrap();

        let in_own = PgApprovalStore::new(Arc::clone(&own.databases));
        let found = in_own
            .find_by_id(&apart, saved.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.parties(), saved.parties());
    }

    /// A stored approval request with an invalid owner address is rejected
    /// as corrupt.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_request_is_refused() {
        let fx = fixture().await;
        let saved = fx.saved(fx.opened()).await;
        fx.db
            .tamper("UPDATE agent_approvals SET owner_person = 'nobody'")
            .await;

        let read = fx.store.find_by_id(&fx.tenant, saved.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
