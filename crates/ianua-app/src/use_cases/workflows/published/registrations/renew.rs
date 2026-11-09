//! The background sweep that renews workflows' registrations at services
//! before they lapse, as Google's watch channels and Jira's webhooks do.
//!
//! A registration the service will not renew, or whose account is gone,
//! lapses out loud: colleagues hear that the workflow stopped hearing its
//! events, and whoever publishes it again registers it afresh. A service
//! that cannot be reached is asked again next round, until the
//! registration's time runs out; then it lapses too.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::workflows::triggers::subscription::{
    ServiceSubscription, SubscriptionStatus,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, TenantId};
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{SubscriptionAt, SubscriptionDirectory};
use crate::services::kept_together::kept_together;
use crate::services::registrations::{
    RegistrationPorts, current_credential, keep_renewal, keys_of, lent_account,
};
use crate::services::renewal_sweep::{
    ACCOUNT_GONE, RenewalSweep, Renewed, after_answer, lapse, run_round,
};
use crate::services::sweep_round::SweepRound;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`RenewUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RenewPorts {
    /// Lists the registrations about to lapse, across every tenant.
    pub directory: Arc<dyn SubscriptionDirectory>,
    /// Renews them at their services.
    pub registrations: RegistrationPorts,
    /// Keeps each renewal or lapse and its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Renews every registration about to lapse.
///
/// It runs as a periodic job of the platform, with nobody asking.
pub struct RenewUseCase {
    ports: RenewPorts,
}

impl RenewUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RenewPorts) -> Self {
        Self { ports }
    }

    /// The registration at `at`, if it is still kept and live.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when it cannot be read.
    async fn live(
        &self,
        tenant: &ScopedTenant,
        at: &SubscriptionAt,
    ) -> Result<Option<ServiceSubscription<ResolvedTenant>>, AppError> {
        let found = self
            .ports
            .registrations
            .subscriptions
            .find_by_id(tenant, &at.subscription_id)
            .await
            .or_internal()?;
        Ok(found.filter(|kept| kept.status() == SubscriptionStatus::Live))
    }
}

#[async_trait]
impl RenewalSweep for RenewUseCase {
    type At = SubscriptionAt;
    type Held = ServiceSubscription<ResolvedTenant>;

    async fn due(
        &self,
        before: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<SubscriptionAt>, DomainError> {
        self.ports.directory.due(before, limit).await
    }

    fn tenant_of(at: &SubscriptionAt) -> TenantId {
        at.tenant_id
    }

    async fn renew_or_lapse(
        &self,
        auditor: &RequestAuditor,
        tenant: &ScopedTenant,
        at: &SubscriptionAt,
    ) -> Result<Renewed<Self::Held>, AppError> {
        let ports = &self.ports.registrations;
        let Some(mut subscription) = self.live(tenant, at).await? else {
            return Ok(Renewed::Skipped);
        };
        let mut account = match lent_account(ports, tenant, subscription.account()).await {
            Ok(account) => account,
            Err(AppError::Domain(_)) => {
                lapse(&mut subscription, ACCOUNT_GONE)?;
                return Ok(Renewed::Changed(Box::new(subscription)));
            }
            Err(other) => return Err(other),
        };
        let mut keys = keys_of(tenant, &account, &subscription);
        keys.credential = match current_credential(ports, auditor, tenant, &account).await {
            Ok(credential) => credential,
            Err(unsent) => return after_answer(subscription, Err(unsent)),
        };
        let answer = ports.registrar.renew(tenant, &subscription, &keys).await;
        keep_renewal(ports, auditor, tenant, &mut account, answer.renewal).await?;
        after_answer(subscription, answer.result)
    }

    async fn keep(
        &self,
        auditor: &RequestAuditor,
        tenant: &ScopedTenant,
        subscription: &mut ServiceSubscription<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let kept = async {
            self.ports
                .registrations
                .subscriptions
                .save(tenant, subscription)
                .await
                .or_internal()?;
            auditor
                .dispatch_by(&ActorRef::System, subscription.take_events(tenant))
                .await
                .or_internal()
        };
        kept_together(self.ports.unit_of_work.as_ref(), kept).await
    }
}

impl Command for RenewUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<SweepRound, AppError>;

    /// Renews each registration lapsing within a day, or lapses it out loud
    /// when it cannot be renewed, recording `workflows.subscription_lapsed`.
    /// Each renewal or lapse and its record are kept together: one that
    /// cannot be kept is counted as failed and found again next round.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the registrations due cannot be listed.
    async fn execute(
        &self,
        _caller: &(),
        auditor: &RequestAuditor,
        _input: (),
    ) -> Result<SweepRound, AppError> {
        run_round(self, auditor).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::account::AccountSharing;
    use ianua_domain::domains::workflows::data::FieldName;
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
    use ianua_domain::domains::workflows::triggers::subscription::{
        Lapse, Registration, RemoteRegistration,
    };
    use ianua_domain::domains::workflows::triggers::{
        EventFilter, FilterValue, ServiceTrigger, Trigger,
    };
    use ianua_domain::shared::clock;
    use ianua_domain::shared::model::aggregate::Aggregate;
    use ianua_domain::types::{IntegrationAccountId, ServiceSubscriptionId};
    use time::Duration;

    use super::*;
    use crate::ports::workflows::{RegistrationFailure, Routing, ServiceSubscriptionStore};
    use crate::test_support::agents::caller_person;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::workflows::{
        FakeIntegrationAccountStore, FakeServiceRegistrar, FakeServiceSubscriptionStore, SHEETS,
        accounts_now_of, draft_on, published_by, sheets_account, tidy_step,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Watches new finance rows through the selected integration account.
    fn finance_rows(account: IntegrationAccountId) -> ServiceTrigger {
        ServiceTrigger::from_stored(
            IntegrationKey::new(SHEETS).unwrap(),
            ServiceEventKey::new("row-added").unwrap(),
            account,
            vec![EventFilter::new(
                FieldName::new("sheet").unwrap(),
                FilterValue::new("finance").unwrap(),
            )],
        )
        .unwrap()
    }

    /// A live registration for a watching workflow through `account`,
    /// lapsing an hour from now, kept in a fresh store.
    fn lapsing_soon(
        account: IntegrationAccountId,
    ) -> (Arc<FakeServiceSubscriptionStore>, ServiceSubscriptionId) {
        let workflow = published_by(
            &caller_person(),
            draft_on(
                &caller_person(),
                vec![tidy_step("tidy")],
                Vec::new(),
                Trigger::Service(finance_rows(account)),
            ),
        );
        let id = ServiceSubscriptionId::new();
        let sealed = FakeEncryptor::sealed_for(
            "signing words",
            &crate::services::registrations::subscription_secret_place(&test_ctx().tenant(), &id),
        );
        let mut subscription = ServiceSubscription::open(&workflow, id, sealed).unwrap();
        subscription
            .register(
                RemoteRegistration::new("channel-1").unwrap(),
                Lapse::At(clock::now() + Duration::hours(1)),
            )
            .unwrap();
        let store = Arc::new(FakeServiceSubscriptionStore::empty());
        block_on(store.insert(&test_ctx().tenant(), &subscription, &Routing::OwnAddress)).unwrap();
        (store, id)
    }

    /// One sweep through `registrar`, the account kept or gone.
    fn swept(
        registrar: FakeServiceRegistrar,
        account_kept: bool,
    ) -> (
        SweepRound,
        ServiceSubscription<ResolvedTenant>,
        Vec<String>,
        Vec<&'static str>,
    ) {
        let account = sheets_account(&caller_person(), AccountSharing::OwnerOnly);
        let (store, id) = lapsing_soon(*account.id());
        let accounts = match account_kept {
            true => FakeIntegrationAccountStore::holding(&account),
            false => FakeIntegrationAccountStore::empty(),
        };
        let registrar = Arc::new(registrar);
        let connects = [SystemPermission::Workflows(WorkflowAction::ConnectAccounts)];
        let use_case = RenewUseCase::new(RenewPorts {
            directory: store.clone(),
            registrations: RegistrationPorts {
                accounts: Arc::new(accounts),
                accounts_now: Arc::new(accounts_now_of(&[(&caller_person(), &connects)])),
                subscriptions: store.clone(),
                registrar: registrar.clone(),
                ..RegistrationPorts::fakes()
            },
            ..RenewPorts::fakes()
        });
        let sink = Arc::new(FakeEventDispatcher::new());
        let round = block_on(use_case.execute(&(), &test_auditor(sink.clone()), ())).unwrap();
        let kept = block_on(store.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap();
        let records = sink.records.lock().unwrap().clone();
        (round, kept, records, registrar.asked())
    }

    /// Ann's watch channel lapses within the hour. The sweep renews it: the
    /// service names the new channel and a new time, kept quietly, since
    /// nothing changed for anyone.
    #[test]
    fn a_registration_about_to_lapse_is_renewed() {
        let later = clock::now() + Duration::days(7);

        let (round, kept, records, asked) = swept(
            FakeServiceRegistrar::taking("channel-2", Lapse::At(later)),
            true,
        );

        assert_eq!(round.changed(), 1);
        assert_eq!(asked, ["renew"]);
        assert_eq!(kept.status(), SubscriptionStatus::Live);
        assert!(matches!(
            kept.registration(),
            Registration::Taken { remote, .. } if remote.as_str() == "channel-2"
        ));
        assert!(records.is_empty());
        assert!(Aggregate::updated_at(&kept) >= Aggregate::created_at(&kept));
    }

    /// A refused renewal and a missing integration account each lapse the
    /// subscription, count as a change and record its lapse.
    #[test]
    fn a_registration_that_cannot_be_renewed_lapses_out_loud() {
        let refused = swept(
            FakeServiceRegistrar::failing(RegistrationFailure::Refused(
                "access revoked".to_owned(),
            )),
            true,
        );
        let orphaned = swept(
            FakeServiceRegistrar::taking("channel-2", Lapse::Never),
            false,
        );

        for (round, kept, records, _) in [refused, orphaned] {
            assert_eq!(round.changed(), 1);
            assert_eq!(kept.status(), SubscriptionStatus::Lapsed);
            assert_eq!(records, ["workflows.subscription_lapsed"]);
        }
    }

    /// The service cannot be reached and the watch still has time left. It
    /// is left live for the next round, counted as not done.
    #[test]
    fn an_unreachable_service_is_asked_again_next_round() {
        let (round, kept, records, _) = swept(
            FakeServiceRegistrar::failing(RegistrationFailure::Unreachable),
            true,
        );

        assert_eq!(round.failed(), 1);
        assert_eq!(kept.status(), SubscriptionStatus::Live);
        assert!(records.is_empty());
    }
}
