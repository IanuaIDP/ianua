//! Organizations' subscriptions, kept in the platform database, one per
//! organization.
//!
//! The organization's id is the row's key, so a second subscription for
//! one organization cannot be kept: saving again replaces the one it has.
//! The two sweeps read their rows through an index holding only the
//! subscriptions in the state they look for.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::organization::OrgSubscriptionStore;
use ianua_domain::domains::organization::billing::subscription::OrgSubscription;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OrganizationId;
use time::OffsetDateTime;

use self::record::{SubscriptionColumns, SubscriptionRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of organizations' subscriptions.
pub struct PgOrgSubscriptionStore {
    databases: Arc<Databases>,
}

impl PgOrgSubscriptionStore {
    /// A store keeping subscriptions in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

fn rebuilt(records: Vec<SubscriptionRecord>) -> Result<Vec<OrgSubscription>, DomainError> {
    records
        .into_iter()
        .map(SubscriptionRecord::into_subscription)
        .collect()
}

#[async_trait]
impl OrgSubscriptionStore for PgOrgSubscriptionStore {
    async fn find_by_organization(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Option<OrgSubscription>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                SubscriptionRecord,
                "queries/org_subscriptions/of_organization.sql",
                organization_id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record
            .map(SubscriptionRecord::into_subscription)
            .transpose()
    }

    async fn list_trials_ended(
        &self,
        by: OffsetDateTime,
    ) -> Result<Vec<OrgSubscription>, DomainError> {
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                SubscriptionRecord,
                "queries/org_subscriptions/trials_ended.sql",
                by
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        rebuilt(records)
    }

    async fn list_past_due(&self) -> Result<Vec<OrgSubscription>, DomainError> {
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(SubscriptionRecord, "queries/org_subscriptions/past_due.sql")
                .fetch_all(connection)
                .await
        })
        .await?;
        rebuilt(records)
    }

    async fn save(&self, subscription: &OrgSubscription) -> Result<(), DomainError> {
        let columns = SubscriptionColumns::of(subscription);
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_subscriptions/save.sql",
                columns.organization_id,
                columns.plan,
                columns.cycle,
                columns.state,
                columns.trial_ends_at,
                columns.past_due_since,
                columns.payment_reference,
                columns.trial,
                columns.created_at,
                columns.updated_at,
            )
            .execute(connection)
            .await?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::organization::OrganizationStore;
    use ianua_domain::domains::organization::billing::payment::{
        BillingCycle, PaymentMethod, PaymentReference, SubscriptionState, TrialUse,
    };
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
    use ianua_domain::domains::organization::billing::subscription::OrgSubscriptionRow;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::shared::config::DomainLimits;

    use super::*;
    use crate::postgres::organization::PgOrganizationStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::{organization_row, subscription_row};

    /// A fresh database, and the store on it.
    async fn fixture() -> (TestDb, PgOrgSubscriptionStore) {
        let db = TestDb::fresh().await;
        let store = PgOrgSubscriptionStore::new(Arc::clone(&db.databases));
        (db, store)
    }

    /// Saves an organization under `slug` through its store.
    async fn an_organization(db: &TestDb, slug: &str) -> OrganizationId {
        let organization = Organization::reconstitute(organization_row(slug, slug)).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&organization)
            .await
            .unwrap();
        *organization.id()
    }

    fn subscription(row: OrgSubscriptionRow) -> OrgSubscription {
        OrgSubscription::reconstitute(row).unwrap()
    }

    fn trialing(organization: OrganizationId, ends_at: OffsetDateTime) -> OrgSubscription {
        subscription(OrgSubscriptionRow {
            plan: OrganizationPlan::Starter,
            state: SubscriptionState::Trialing { ends_at },
            trial: TrialUse::Used,
            ..subscription_row(organization)
        })
    }

    fn past_due_row(organization: OrganizationId, since: OffsetDateTime) -> OrgSubscriptionRow {
        OrgSubscriptionRow {
            plan: OrganizationPlan::Starter,
            state: SubscriptionState::PastDue { since },
            trial: TrialUse::Used,
            ..subscription_row(organization)
        }
    }

    fn past_due(organization: OrganizationId, since: OffsetDateTime) -> OrgSubscription {
        subscription(past_due_row(organization, since))
    }

    fn organizations(subscriptions: &[OrgSubscription]) -> Vec<OrganizationId> {
        subscriptions
            .iter()
            .map(|subscription| *subscription.organization_id())
            .collect()
    }

    /// Acme's subscription, paying annually by card, is found again as it
    /// was saved.
    #[tokio::test]
    async fn a_saved_subscription_is_found_by_its_organization() {
        let (db, store) = fixture().await;
        let acme = an_organization(&db, "acme").await;
        let paying = subscription(OrgSubscriptionRow {
            plan: OrganizationPlan::Business,
            cycle: BillingCycle::Annual,
            payment: PaymentMethod::OnFile(PaymentReference::new("pm_1NvXyz").unwrap()),
            trial: TrialUse::Used,
            ..subscription_row(acme)
        });

        store.save(&paying).await.unwrap();

        let found = store.find_by_organization(&acme).await.unwrap().unwrap();
        assert_eq!(found.organization_id(), &acme);
        assert_eq!(found.plan(), OrganizationPlan::Business);
        assert_eq!(found.cycle(), BillingCycle::Annual);
        assert_eq!(found.state(), SubscriptionState::Active);
        assert_eq!(found.payment(), paying.payment());
        assert_eq!(found.trial(), TrialUse::Used);
        assert_eq!(found.created_at(), at(0));
    }

    /// An organization that never subscribed finds nothing, rather than
    /// failing.
    #[tokio::test]
    async fn an_organization_without_a_subscription_finds_none() {
        let (db, store) = fixture().await;
        let acme = an_organization(&db, "acme").await;

        let found = store.find_by_organization(&acme).await.unwrap();

        assert!(found.is_none());
    }

    /// Saving a past-due subscription over Acme's trial preserves its
    /// creation time, updates its state and update time, and lists Acme once.
    #[tokio::test]
    async fn saving_again_replaces_the_one_subscription() {
        let (db, store) = fixture().await;
        let acme = an_organization(&db, "acme").await;
        store.save(&trialing(acme, at(100))).await.unwrap();
        let owing = subscription(OrgSubscriptionRow {
            created_at: at(50),
            updated_at: at(200),
            ..past_due_row(acme, at(100))
        });

        store.save(&owing).await.unwrap();

        let found = store.find_by_organization(&acme).await.unwrap().unwrap();
        assert_eq!(found.state(), SubscriptionState::PastDue { since: at(100) });
        assert_eq!(found.created_at(), at(0));
        assert_eq!(found.updated_at(), at(200));
        assert_eq!(organizations(&store.list_past_due().await.unwrap()), [acme]);
    }

    /// The sweep finds the trials that ended by the time it runs, the
    /// longest ended first, and leaves running trials and paid-up
    /// subscriptions.
    #[tokio::test]
    async fn the_trials_ended_by_a_time_are_found_longest_ended_first() {
        let (db, store) = fixture().await;
        let (later, earlier, running, paid) = (
            an_organization(&db, "later").await,
            an_organization(&db, "earlier").await,
            an_organization(&db, "running").await,
            an_organization(&db, "paid").await,
        );
        for held in [
            trialing(later, at(100)),
            trialing(earlier, at(50)),
            trialing(running, at(101)),
            subscription(subscription_row(paid)),
        ] {
            store.save(&held).await.unwrap();
        }

        let ended = store.list_trials_ended(at(100)).await.unwrap();

        assert_eq!(organizations(&ended), [earlier, later]);
    }

    /// The overdue sweep finds every subscription a payment is owed on, the
    /// longest owed first, and none that is paid up or trialing.
    #[tokio::test]
    async fn the_subscriptions_owing_a_payment_are_found_longest_owed_first() {
        let (db, store) = fixture().await;
        let (recent, oldest, trial, paid) = (
            an_organization(&db, "recent").await,
            an_organization(&db, "oldest").await,
            an_organization(&db, "trial").await,
            an_organization(&db, "paid").await,
        );
        for held in [
            past_due(recent, at(90)),
            past_due(oldest, at(10)),
            trialing(trial, at(5)),
            subscription(subscription_row(paid)),
        ] {
            store.save(&held).await.unwrap();
        }

        let owing = store.list_past_due().await.unwrap();

        assert_eq!(organizations(&owing), [oldest, recent]);
    }

    /// Reading a trial whose stored plan was changed to one without trials
    /// returns an infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_subscription_is_refused() {
        let (db, store) = fixture().await;
        let acme = an_organization(&db, "acme").await;
        store.save(&trialing(acme, at(100))).await.unwrap();
        db.tamper("UPDATE org_subscriptions SET plan = 'free'")
            .await;

        let read = store.find_by_organization(&acme).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Reading a subscription whose stored payment reference is malformed
    /// returns an infrastructure error.
    #[tokio::test]
    async fn a_payment_reference_that_breaks_its_rules_is_refused() {
        let (db, store) = fixture().await;
        let acme = an_organization(&db, "acme").await;
        store
            .save(&subscription(subscription_row(acme)))
            .await
            .unwrap();
        db.tamper("UPDATE org_subscriptions SET payment_reference = 'not a reference'")
            .await;

        let read = store.find_by_organization(&acme).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
