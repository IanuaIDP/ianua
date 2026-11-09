//! The orders people give to stop a tenant's runs, each row under
//! row-level security.
//!
//! An order is kept beside the run it stops, in the run's tenant, until
//! the worker driving the run has applied it and the run has ended. One
//! order is kept per run: a later one takes the place of the earlier. An
//! order for a run the tenant does not keep is refused, so a stop that
//! names nothing is never answered as done.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::RunCancellation;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::execution::run::CancelOrder;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::AgentRunId;

use self::record::{OrderColumns, OrderRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres run kill switch.
pub struct PgRunCancellation {
    databases: Arc<Databases>,
}

impl TenantScoped for PgRunCancellation {}

impl PgRunCancellation {
    /// A kill switch keeping its orders in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Removes the order for `run_id` of `tenant`.
    async fn forget(&self, tenant: &ScopedTenant, run_id: &AgentRunId) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                sqlx::query_file!(
                    "queries/agent_run_cancellations/delete.sql",
                    tenant.as_uuid(),
                    run_id.as_uuid()
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
impl RunCancellation for PgRunCancellation {
    async fn request_cancel(
        &self,
        tenant_id: &ScopedTenant,
        order: &CancelOrder,
    ) -> Result<(), DomainError> {
        let columns = OrderColumns::of(order);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/agent_run_cancellations/save.sql",
                    tenant_id.as_uuid(),
                    columns.run_id,
                    columns.by.kind,
                    columns.by.id,
                    columns.by.person,
                    columns.at,
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn order_for(
        &self,
        tenant_id: &ScopedTenant,
        run_id: &AgentRunId,
    ) -> Result<Option<CancelOrder>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    OrderRecord,
                    "queries/agent_run_cancellations/of_run.sql",
                    tenant_id.as_uuid(),
                    run_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(OrderRecord::into_order).transpose()
    }

    async fn clear(&self, tenant_id: &ScopedTenant, run_id: &AgentRunId) {
        if let Err(error) = self.forget(tenant_id, run_id).await {
            tracing::warn!(
                %error,
                run = %run_id.as_uuid(),
                "the order to stop an ended run was not forgotten"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::execution::run::CancelOrderRow;
    use ianua_domain::types::{Human, TenantId, UserId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::run::saved_run;
    use crate::test_support::rows::authorization::human;
    use crate::test_support::rows::identity::from_now;

    struct Fixture {
        db: TestDb,
        switch: PgRunCancellation,
        tenant: ScopedTenant,
        run: AgentRunId,
    }

    /// A fresh database, the kill switch on it, and one run of one tenant
    /// to stop.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let run = *saved_run(&db.databases, &tenant).await.id();
        Fixture {
            switch: PgRunCancellation::new(Arc::clone(&db.databases)),
            tenant,
            run,
            db,
        }
    }

    fn ann() -> Human {
        human(UserId::new(), "ann@acme.example")
    }

    fn order(run: AgentRunId, by: Human, seconds_ago: i64) -> CancelOrder {
        CancelOrder::reconstitute(CancelOrderRow {
            run_id: run,
            by,
            at: from_now(seconds_ago.saturating_neg()),
        })
        .unwrap()
    }

    impl Fixture {
        async fn held(&self) -> Option<CancelOrder> {
            self.switch
                .order_for(&self.tenant, &self.run)
                .await
                .unwrap()
        }
    }

    /// Ann presses stop: the worker finds her order, with who gave it and
    /// when, as she gave it.
    #[tokio::test]
    async fn a_stored_order_is_found_by_its_run() {
        let fx = fixture().await;
        let given = order(fx.run, ann(), 5);

        fx.switch.request_cancel(&fx.tenant, &given).await.unwrap();

        assert_eq!(fx.held().await, Some(given));
    }

    /// A run nobody asked to stop holds no order, rather than failing.
    #[tokio::test]
    async fn a_run_without_an_order_holds_none() {
        let fx = fixture().await;

        assert!(fx.held().await.is_none());
    }

    /// Ann presses stop, then Bob does: Bob's order takes the place of
    /// Ann's, and the run holds one order.
    #[tokio::test]
    async fn a_later_order_takes_the_place_of_the_earlier() {
        let fx = fixture().await;
        let bob = human(UserId::new(), "bob@acme.example");
        let later = order(fx.run, bob, 1);

        fx.switch
            .request_cancel(&fx.tenant, &order(fx.run, ann(), 9))
            .await
            .unwrap();
        fx.switch.request_cancel(&fx.tenant, &later).await.unwrap();

        assert_eq!(fx.held().await, Some(later));
    }

    /// Once the run has ended, its order is forgotten, and forgetting one
    /// again changes nothing.
    #[tokio::test]
    async fn a_cleared_order_is_gone() {
        let fx = fixture().await;
        let given = order(fx.run, ann(), 5);
        fx.switch.request_cancel(&fx.tenant, &given).await.unwrap();

        fx.switch.clear(&fx.tenant, &fx.run).await;
        fx.switch.clear(&fx.tenant, &fx.run).await;

        assert!(fx.held().await.is_none());
    }

    /// Saving a cancellation order for an unknown run returns an
    /// infrastructure error.
    #[tokio::test]
    async fn an_order_for_an_unknown_run_is_refused() {
        let fx = fixture().await;
        let stray = order(AgentRunId::new(), ann(), 5);

        let given = fx.switch.request_cancel(&fx.tenant, &stray).await;

        assert!(matches!(given, Err(DomainError::Infrastructure(_))));
    }

    /// Mallory's tenant cannot read or save an order for Acme's run. Clearing
    /// it through her tenant leaves Acme's original order intact.
    #[tokio::test]
    async fn another_tenant_neither_reads_nor_gives_an_order() {
        let fx = fixture().await;
        let mallory = ScopedTenant::for_background(TenantId::new());
        let given = order(fx.run, ann(), 5);
        fx.switch.request_cancel(&fx.tenant, &given).await.unwrap();

        let read = fx.switch.order_for(&mallory, &fx.run).await.unwrap();
        let theirs = fx.switch.request_cancel(&mallory, &given).await;
        fx.switch.clear(&mallory, &fx.run).await;

        assert!(read.is_none());
        assert!(matches!(theirs, Err(DomainError::Infrastructure(_))));
        assert_eq!(fx.held().await, Some(given));
    }

    /// A dedicated tenant's cancellation order reads back unchanged directly
    /// from its database.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_keeps_its_orders_there() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        let run = *saved_run(&fx.db.databases, &apart).await.id();
        let given = order(run, ann(), 5);

        fx.switch.request_cancel(&apart, &given).await.unwrap();

        let in_own = PgRunCancellation::new(Arc::clone(&own.databases));
        let held = in_own.order_for(&apart, &run).await.unwrap();
        assert_eq!(held, Some(given));
    }

    /// A stored cancellation order with an invalid person address is rejected
    /// as corrupt.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_order_is_refused() {
        let fx = fixture().await;
        let given = order(fx.run, ann(), 5);
        fx.switch.request_cancel(&fx.tenant, &given).await.unwrap();
        fx.db
            .tamper("UPDATE agent_run_cancellations SET ordered_by_person = 'nobody'")
            .await;

        let read = fx.switch.order_for(&fx.tenant, &fx.run).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
