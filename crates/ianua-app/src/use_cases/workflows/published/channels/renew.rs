//! The background sweep that renews accounts' channels before they lapse,
//! as a Gmail watch must be within the week.
//!
//! A channel the service will not renew, or whose account is gone, lapses
//! out loud: colleagues hear that the account's workflows stopped hearing
//! their events, and publishing one again registers the channel afresh. A
//! service that cannot be reached is asked again next round, until the
//! channel's time runs out; then it lapses too, so the sweep ends.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::workflows::triggers::channel::AccountChannel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, TenantId};
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::{ChannelAt, ChannelDirectory};
use crate::services::account_channels::channel_keys;
use crate::services::kept_together::kept_together;
use crate::services::registrations::{RegistrationPorts, keep_renewal, lent_account};
use crate::services::renewal_sweep::{
    ACCOUNT_GONE, RenewalSweep, Renewed, after_answer, lapse, run_round,
};
use crate::services::sweep_round::SweepRound;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`RenewUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RenewPorts {
    /// Lists the channels about to lapse, across every tenant.
    pub directory: Arc<dyn ChannelDirectory>,
    /// Renews them at their services.
    pub registrations: RegistrationPorts,
}

/// Renews every channel about to lapse.
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

    /// The channel at `at`, if it is still kept and live.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when it cannot be read.
    async fn live(
        &self,
        tenant: &ScopedTenant,
        at: &ChannelAt,
    ) -> Result<Option<AccountChannel<ResolvedTenant>>, AppError> {
        let found = self
            .ports
            .registrations
            .channels
            .find_by_id(tenant, &at.channel_id)
            .await
            .or_internal()?;
        Ok(found.filter(AccountChannel::is_live))
    }
}

#[async_trait]
impl RenewalSweep for RenewUseCase {
    type At = ChannelAt;
    type Held = AccountChannel<ResolvedTenant>;

    async fn due(&self, before: OffsetDateTime, limit: u32) -> Result<Vec<ChannelAt>, DomainError> {
        self.ports.directory.due(before, limit).await
    }

    fn tenant_of(at: &ChannelAt) -> TenantId {
        at.tenant_id
    }

    async fn renew_or_lapse(
        &self,
        auditor: &RequestAuditor,
        tenant: &ScopedTenant,
        at: &ChannelAt,
    ) -> Result<Renewed<Self::Held>, AppError> {
        let ports = &self.ports.registrations;
        let Some(mut channel) = self.live(tenant, at).await? else {
            return Ok(Renewed::Skipped);
        };
        let mut account = match lent_account(ports, tenant, channel.account()).await {
            Ok(account) => account,
            Err(AppError::Domain(_)) => {
                lapse(&mut channel, ACCOUNT_GONE)?;
                return Ok(Renewed::Changed(Box::new(channel)));
            }
            Err(other) => return Err(other),
        };
        let keys = match channel_keys(ports, auditor, tenant, &account, &channel).await {
            Ok(keys) => keys,
            Err(unsent) => return after_answer(channel, Err(unsent)),
        };
        let answer = ports.registrar.renew_channel(tenant, &channel, &keys).await;
        keep_renewal(ports, auditor, tenant, &mut account, answer.renewal).await?;
        after_answer(channel, answer.result)
    }

    async fn keep(
        &self,
        auditor: &RequestAuditor,
        tenant: &ScopedTenant,
        channel: &mut AccountChannel<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let ports = &self.ports.registrations;
        let kept = async {
            ports.channels.save(tenant, channel).await.or_internal()?;
            auditor
                .dispatch_by(&ActorRef::System, channel.take_events(tenant))
                .await
                .or_internal()
        };
        kept_together(ports.unit_of_work.as_ref(), kept).await
    }
}

impl Command for RenewUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<SweepRound, AppError>;

    /// Renews each channel lapsing within a day, or lapses it out loud when
    /// it cannot be renewed, recording `workflows.channel_lapsed`. Each
    /// renewal or lapse and its record are kept together: one that cannot
    /// be kept is counted as failed and found again next round.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the channels due cannot be listed.
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
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_domain::domains::workflows::triggers::channel::{
        ChannelCursor, ChannelSetup, ChannelStatus, HistoryPlace, OpenChannel,
    };
    use ianua_domain::domains::workflows::triggers::subscription::{Lapse, RemoteRegistration};
    use ianua_domain::shared::clock;
    use ianua_domain::types::{AccountChannelId, IntegrationAccountId};
    use time::Duration;

    use super::*;
    use crate::ports::workflows::{AccountChannelStore as _, RegistrationFailure};
    use crate::services::account_channels::channel_secret_place;
    use crate::test_support::agents::caller_person;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::workflows::{
        FakeAccountChannelStore, FakeIntegrationAccountStore, FakeServiceRegistrar, SHEETS,
        accounts_now_of, sheets_account,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A live channel of `account`, lapsing at `lapses`, kept in a fresh
    /// store.
    fn lapsing(
        account: IntegrationAccountId,
        lapses: OffsetDateTime,
    ) -> (Arc<FakeAccountChannelStore>, AccountChannelId) {
        let id = AccountChannelId::new();
        let tenant = test_ctx().tenant();
        let mut channel = AccountChannel::open(OpenChannel {
            id,
            account,
            integration: IntegrationKey::new(SHEETS).unwrap(),
            secret: FakeEncryptor::sealed_for("own words", &channel_secret_place(&tenant, &id)),
            setup: ChannelSetup::Registered,
        })
        .unwrap();
        channel
            .register(
                RemoteRegistration::new("watch-1").unwrap(),
                Lapse::At(lapses),
                HistoryPlace::At(ChannelCursor::new("100").unwrap()),
            )
            .unwrap();
        let _ = channel.take_events(&tenant);
        let store = Arc::new(FakeAccountChannelStore::empty());
        block_on(store.insert_if_absent(&tenant, &channel)).unwrap();
        (store, id)
    }

    /// One sweep through `registrar`, the account kept or gone.
    fn swept(
        registrar: FakeServiceRegistrar,
        lapses: OffsetDateTime,
        account_kept: bool,
    ) -> (SweepRound, AccountChannel<ResolvedTenant>, Vec<String>) {
        let account = sheets_account(&caller_person(), AccountSharing::OwnerOnly);
        let (store, id) = lapsing(*account.id(), lapses);
        let accounts = match account_kept {
            true => FakeIntegrationAccountStore::holding(&account),
            false => FakeIntegrationAccountStore::empty(),
        };
        let connects = [SystemPermission::Workflows(WorkflowAction::ConnectAccounts)];
        let use_case = RenewUseCase::new(RenewPorts {
            directory: store.clone(),
            registrations: RegistrationPorts {
                accounts: Arc::new(accounts),
                accounts_now: Arc::new(accounts_now_of(&[(&caller_person(), &connects)])),
                channels: store.clone(),
                registrar: Arc::new(registrar),
                ..RegistrationPorts::fakes()
            },
        });
        let sink = Arc::new(FakeEventDispatcher::new());
        let round = block_on(use_case.execute(&(), &test_auditor(sink.clone()), ())).unwrap();
        let kept = block_on(store.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap();
        let records = sink.records.lock().unwrap().clone();
        (round, kept, records)
    }

    fn soon() -> OffsetDateTime {
        clock::now() + Duration::hours(1)
    }

    /// Ann's mailbox watch ends within the hour. The sweep renews it for
    /// another week, and keeps its place in the mailbox's history.
    #[test]
    fn a_channel_about_to_lapse_is_renewed_and_keeps_its_cursor() {
        let later = clock::now() + Duration::days(7);

        let (round, kept, records) = swept(
            FakeServiceRegistrar::taking("watch-2", Lapse::At(later)),
            soon(),
            true,
        );

        assert_eq!(round.changed(), 1);
        assert_eq!(kept.status(), ChannelStatus::Live);
        assert_eq!(kept.history().cursor().unwrap().as_str(), "100");
        assert!(records.is_empty());
    }

    /// A refused renewal and a gone account each lapse the channel out
    /// loud.
    #[test]
    fn a_channel_that_cannot_be_renewed_lapses_out_loud() {
        let refused = swept(
            FakeServiceRegistrar::failing(RegistrationFailure::Refused("revoked".to_owned())),
            soon(),
            true,
        );
        let orphaned = swept(
            FakeServiceRegistrar::taking("watch-2", Lapse::Never),
            soon(),
            false,
        );

        for (round, kept, records) in [refused, orphaned] {
            assert_eq!(round.changed(), 1);
            assert_eq!(kept.status(), ChannelStatus::Lapsed);
            assert_eq!(records, ["workflows.channel_lapsed"]);
        }
    }

    /// The service is down and the watch has time left: it is asked again
    /// next round. Once its time ran out the channel lapses, so the sweep
    /// does not try for ever.
    #[test]
    fn an_unreachable_service_is_asked_again_until_time_runs_out() {
        let unreachable = || FakeServiceRegistrar::failing(RegistrationFailure::Unreachable);

        let (waited, still, _) = swept(unreachable(), soon(), true);
        let (gave_up, lapsed, records) =
            swept(unreachable(), clock::now() - Duration::minutes(1), true);

        assert_eq!(waited.failed(), 1);
        assert_eq!(still.status(), ChannelStatus::Live);
        assert_eq!(gave_up.changed(), 1);
        assert_eq!(lapsed.status(), ChannelStatus::Lapsed);
        assert_eq!(records, ["workflows.channel_lapsed"]);
    }
}
