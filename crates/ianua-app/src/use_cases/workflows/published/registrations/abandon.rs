//! The background sweep that gives up on registrations still waiting long
//! after their publish should have finished.
//!
//! A registration is kept as waiting before its service is called. If the
//! process doing the publish dies there, nothing else would ever finish or
//! forget it. It was never in service, so it is forgotten with no record:
//! a record would claim a registration that never was. Each round handles
//! a bounded page and every row it handles leaves, so the sweep ends.

use std::sync::Arc;

use ianua_domain::shared::clock;
use time::Duration;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::{ServiceSubscriptionStore, SubscriptionAt, SubscriptionDirectory};
use crate::services::sweep_round::SweepRound;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// How long a registration may wait before it is given up on: far longer
/// than any publish holds a call to a service open.
const WAITS_AT_MOST: Duration = Duration::hours(1);

/// How many registrations one round gives up on at most; the next round
/// handles the rest.
const MOST_PER_ROUND: u32 = 200;

/// The ports [`AbandonUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AbandonPorts {
    /// Lists the registrations left waiting, across every tenant.
    pub directory: Arc<dyn SubscriptionDirectory>,
    /// Forgets them.
    pub subscriptions: Arc<dyn ServiceSubscriptionStore>,
}

/// Gives up on registrations left waiting.
///
/// It runs as a periodic job of the platform, with nobody asking.
pub struct AbandonUseCase {
    ports: AbandonPorts,
}

impl AbandonUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AbandonPorts) -> Self {
        Self { ports }
    }

    /// `round` with the registration at `at` forgotten, or counted as
    /// failed and found again next round.
    async fn round_with(&self, round: SweepRound, at: &SubscriptionAt) -> SweepRound {
        let tenant = ScopedTenant::for_background(at.tenant_id);
        let forgotten = self
            .ports
            .subscriptions
            .forget_waiting(&tenant, &at.subscription_id)
            .await;
        match forgotten {
            Ok(()) => round.with_changed(),
            Err(_) => round.with_failed(),
        }
    }
}

impl Command for AbandonUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<SweepRound, AppError>;

    /// Forgets each registration waiting for more than an hour.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when those left waiting cannot be listed.
    async fn execute(
        &self,
        _caller: &(),
        _auditor: &RequestAuditor,
        _input: (),
    ) -> Result<SweepRound, AppError> {
        let before = clock::now() - WAITS_AT_MOST;
        let stale = self
            .ports
            .directory
            .stale_waiting(before, MOST_PER_ROUND)
            .await
            .or_internal()?;
        let mut round = SweepRound::default();
        for at in &stale {
            round = self.round_with(round, at).await;
        }
        Ok(round)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::account::AccountSharing;
    use ianua_domain::domains::workflows::data::FieldName;
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
    use ianua_domain::domains::workflows::triggers::subscription::{
        Lapse, RemoteRegistration, ServiceSubscription,
    };
    use ianua_domain::domains::workflows::triggers::{
        EventFilter, FilterValue, ServiceTrigger, Trigger,
    };
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock::freeze;
    use ianua_domain::types::{IntegrationAccountId, ServiceSubscriptionId};

    use super::*;
    use crate::ports::workflows::Routing;
    use crate::services::registrations::subscription_secret_place;
    use crate::test_support::agents::caller_person;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::workflows::{
        FakeServiceSubscriptionStore, SHEETS, draft_on, published_by, sheets_account, tidy_step,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn waiting_registration(account: IntegrationAccountId) -> ServiceSubscription<ResolvedTenant> {
        let trigger = ServiceTrigger::from_stored(
            IntegrationKey::new(SHEETS).unwrap(),
            ServiceEventKey::new("row-added").unwrap(),
            account,
            vec![EventFilter::new(
                FieldName::new("sheet").unwrap(),
                FilterValue::new("finance").unwrap(),
            )],
        )
        .unwrap();
        let workflow = published_by(
            &caller_person(),
            draft_on(
                &caller_person(),
                vec![tidy_step("tidy")],
                Vec::new(),
                Trigger::Service(trigger),
            ),
        );
        let id = ServiceSubscriptionId::new();
        let sealed = FakeEncryptor::sealed_for(
            "signing words",
            &subscription_secret_place(&test_ctx().tenant(), &id),
        );
        ServiceSubscription::open(&workflow, id, sealed).unwrap()
    }

    /// One sweep over `store`.
    fn swept(store: &Arc<FakeServiceSubscriptionStore>) -> (SweepRound, Vec<String>) {
        let use_case = AbandonUseCase::new(AbandonPorts {
            directory: store.clone(),
            subscriptions: store.clone(),
        });
        let sink = Arc::new(FakeEventDispatcher::new());
        let round = block_on(use_case.execute(&(), &test_auditor(sink.clone()), ())).unwrap();
        let records = sink.records.lock().unwrap().clone();
        (round, records)
    }

    /// The worker publishing Ann's workflow died mid-call, leaving its
    /// registration waiting. Two hours on it is forgotten, with no record
    /// of a registration that never was, and a second sweep has nothing
    /// left to do.
    #[test]
    fn a_registration_left_waiting_is_forgotten_once_and_silently() {
        let account = sheets_account(&caller_person(), AccountSharing::OwnerOnly);
        let store = Arc::new(FakeServiceSubscriptionStore::empty());
        let frozen = freeze(clock::now() - Duration::hours(2));
        let waiting = waiting_registration(*account.id());
        block_on(store.insert(&test_ctx().tenant(), &waiting, &Routing::OwnAddress)).unwrap();
        drop(frozen);

        let (first, records) = swept(&store);
        let (second, _) = swept(&store);

        assert_eq!(first.changed(), 1);
        assert_eq!(second.changed(), 0);
        assert!(records.is_empty());
        assert!(store.all(test_ctx().tenant_id()).is_empty());
    }

    /// A publish a moment ago may still be waiting on its service. Its
    /// registration is left alone.
    #[test]
    fn a_registration_waiting_a_moment_is_left_alone() {
        let account = sheets_account(&caller_person(), AccountSharing::OwnerOnly);
        let store = Arc::new(FakeServiceSubscriptionStore::empty());
        let waiting = waiting_registration(*account.id());
        block_on(store.insert(&test_ctx().tenant(), &waiting, &Routing::OwnAddress)).unwrap();

        let (round, _) = swept(&store);

        assert_eq!(round.changed(), 0);
        assert_eq!(store.all(test_ctx().tenant_id()).len(), 1);
    }

    /// A live registration is never given up on, however old.
    #[test]
    fn a_live_registration_is_never_given_up_on() {
        let account = sheets_account(&caller_person(), AccountSharing::OwnerOnly);
        let store = Arc::new(FakeServiceSubscriptionStore::empty());
        let frozen = freeze(clock::now() - Duration::hours(2));
        let mut live = waiting_registration(*account.id());
        live.register(RemoteRegistration::new("hook-1").unwrap(), Lapse::Never)
            .unwrap();
        block_on(store.insert(&test_ctx().tenant(), &live, &Routing::OwnAddress)).unwrap();
        drop(frozen);

        let (round, _) = swept(&store);

        assert_eq!(round.changed(), 0);
        assert_eq!(store.all(test_ctx().tenant_id()).len(), 1);
    }
}
