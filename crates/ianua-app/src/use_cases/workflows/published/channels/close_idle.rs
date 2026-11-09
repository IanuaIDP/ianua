//! The background sweep that takes an account's channel off its service
//! once no workflow waits on it.
//!
//! Removing a version does not close the channel it used: another workflow
//! may share it, or the version's replacement may be about to. The sweep
//! closes one that has had no workflow for an hour instead, so a publish
//! under way, which marks the channel as just used, never loses it. Only a
//! channel the platform registered is closed; one a person
//! set up by hand stays, so publishing again does not ask them to redo it.
//!
//! A service that cannot be reached is asked again next round, for at most
//! a week. After that the channel is forgotten anyway, so the sweep ends;
//! anything the service still sends is refused as unknown.

use std::sync::Arc;

use ianua_domain::domains::workflows::triggers::channel::AccountChannel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::ActorRef;
use time::Duration;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::{ChannelAt, ChannelDirectory, RegistrationFailure};
use crate::services::account_channels::channel_keys;
use crate::services::kept_together::kept_together;
use crate::services::registrations::{RegistrationPorts, keep_renewal};
use crate::services::sweep_round::SweepRound;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// How long a channel has had no workflow before it is closed.
const IDLE_FOR: Duration = Duration::hours(1);

/// How long an idle channel's service may stay out of reach before the
/// channel is forgotten anyway.
const GIVE_UP_AFTER: Duration = Duration::days(7);

/// How many channels one round closes at most; the next round closes the
/// rest.
const MOST_PER_ROUND: u32 = 200;

/// The ports [`CloseIdleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CloseIdlePorts {
    /// Lists the channels no workflow waits on, across every tenant.
    pub directory: Arc<dyn ChannelDirectory>,
    /// Takes them off their services.
    pub registrations: RegistrationPorts,
}

/// Closes channels no workflow waits on.
///
/// It runs as a periodic job of the platform, with nobody asking.
pub struct CloseIdleUseCase {
    ports: CloseIdlePorts,
}

impl CloseIdleUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CloseIdlePorts) -> Self {
        Self { ports }
    }

    /// Whether `channel` may be forgotten: its service took it off, or is
    /// no longer worth waiting for.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when its account cannot be read, or a renewed
    /// credential cannot be kept.
    async fn taken_off(
        &self,
        auditor: &RequestAuditor,
        tenant: &ScopedTenant,
        channel: &AccountChannel<ResolvedTenant>,
    ) -> Result<bool, AppError> {
        let ports = &self.ports.registrations;
        let found = ports
            .accounts
            .find_by_id(tenant, &channel.account())
            .await
            .or_internal()?;
        let Some(mut account) = found else {
            return Ok(true);
        };
        let keys = match channel_keys(ports, auditor, tenant, &account, channel).await {
            Ok(keys) => keys,
            Err(unsent) => return Ok(may_forget(channel, &Err(unsent))),
        };
        let answer = ports.registrar.close_channel(tenant, channel, &keys).await;
        keep_renewal(ports, auditor, tenant, &mut account, answer.renewal).await?;
        Ok(may_forget(channel, &answer.result))
    }

    /// Records `channel` closed and forgets it, together.
    async fn forget(
        &self,
        auditor: &RequestAuditor,
        tenant: &ScopedTenant,
        channel: &mut AccountChannel<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let ports = &self.ports.registrations;
        channel.close();
        let id = *channel.id();
        let kept = async {
            ports.channels.remove(tenant, &id).await.or_internal()?;
            auditor
                .dispatch_by(&ActorRef::System, channel.take_events(tenant))
                .await
                .or_internal()
        };
        kept_together(ports.unit_of_work.as_ref(), kept).await
    }

    /// Closes the channel at `at`, if it can be now.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when a store fails.
    async fn closed(&self, auditor: &RequestAuditor, at: &ChannelAt) -> Result<Closed, AppError> {
        let tenant = ScopedTenant::for_background(at.tenant_id);
        let found = self
            .ports
            .registrations
            .channels
            .find_by_id(&tenant, &at.channel_id)
            .await
            .or_internal()?;
        let Some(mut channel) = found else {
            return Ok(Closed::Gone);
        };
        if !self.taken_off(auditor, &tenant, &channel).await? {
            return Ok(Closed::Later);
        }
        self.forget(auditor, &tenant, &mut channel).await?;
        Ok(Closed::Done)
    }
}

/// What closing one channel came to.
enum Closed {
    /// It was taken off and forgotten.
    Done,
    /// Its service could not be reached; next round.
    Later,
    /// Something else already forgot it.
    Gone,
}

impl Command for CloseIdleUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<SweepRound, AppError>;

    /// Takes each registered channel idle for an hour off its service and
    /// forgets it, recording `workflows.channel_closed`.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the idle channels cannot be listed.
    async fn execute(
        &self,
        _caller: &(),
        auditor: &RequestAuditor,
        _input: (),
    ) -> Result<SweepRound, AppError> {
        let before = clock::now() - IDLE_FOR;
        let idle = self
            .ports
            .directory
            .idle(before, MOST_PER_ROUND)
            .await
            .or_internal()?;
        let mut round = SweepRound::default();
        for at in &idle {
            round = match self.closed(auditor, at).await {
                Ok(Closed::Done) => round.with_changed(),
                Ok(Closed::Gone) => round,
                Ok(Closed::Later) | Err(_) => round.with_failed(),
            };
        }
        Ok(round)
    }
}

/// Whether `channel` may be forgotten after `answer`: unless the service
/// was out of reach, and has not been for long enough to stop asking.
fn may_forget(
    channel: &AccountChannel<ResolvedTenant>,
    answer: &Result<(), RegistrationFailure>,
) -> bool {
    let waited_long_enough = clock::between(channel.updated_at(), clock::now()) > GIVE_UP_AFTER;
    !matches!(answer, Err(RegistrationFailure::Unreachable)) || waited_long_enough
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::account::AccountSharing;
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_domain::domains::workflows::triggers::channel::{
        ChannelSetup, HistoryPlace, OpenChannel,
    };
    use ianua_domain::domains::workflows::triggers::subscription::{Lapse, RemoteRegistration};
    use ianua_domain::shared::clock::freeze;
    use ianua_domain::types::{AccountChannelId, IntegrationAccountId};

    use super::*;
    use crate::ports::workflows::AccountChannelStore as _;
    use crate::services::account_channels::channel_secret_place;
    use crate::test_support::agents::caller_person;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::workflows::{
        FakeAccountChannelStore, FakeIntegrationAccountStore, FakeServiceRegistrar, SHEETS,
        sheets_account,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A live registered channel of `account`, unchanged since `age` ago,
    /// which no workflow waits on.
    fn idle_since(account: IntegrationAccountId, age: Duration) -> Arc<FakeAccountChannelStore> {
        let frozen = freeze(clock::now() - age);
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
                RemoteRegistration::new("bot-hook").unwrap(),
                Lapse::Never,
                HistoryPlace::Unknown,
            )
            .unwrap();
        let _ = channel.take_events(&tenant);
        let store = Arc::new(FakeAccountChannelStore::empty());
        block_on(store.insert_if_absent(&tenant, &channel)).unwrap();
        drop(frozen);
        store
    }

    /// One sweep over a channel `age` old through `registrar`.
    fn swept(
        registrar: FakeServiceRegistrar,
        age: Duration,
    ) -> (SweepRound, usize, Vec<String>, Vec<&'static str>) {
        let account = sheets_account(&caller_person(), AccountSharing::OwnerOnly);
        let store = idle_since(*account.id(), age);
        let registrar = Arc::new(registrar);
        let use_case = CloseIdleUseCase::new(CloseIdlePorts {
            directory: store.clone(),
            registrations: RegistrationPorts {
                accounts: Arc::new(FakeIntegrationAccountStore::holding(&account)),
                channels: store.clone(),
                registrar: registrar.clone(),
                ..RegistrationPorts::fakes()
            },
        });
        let sink = Arc::new(FakeEventDispatcher::new());
        let round = block_on(use_case.execute(&(), &test_auditor(sink.clone()), ())).unwrap();
        let records = sink.records.lock().unwrap().clone();
        (round, store.count(), records, registrar.asked())
    }

    /// The last workflow on Ann's bot left service hours ago. The webhook
    /// comes off Telegram, the channel is forgotten and that is recorded.
    #[test]
    fn a_channel_no_workflow_waits_on_is_closed() {
        let (round, left, records, asked) = swept(
            FakeServiceRegistrar::taking("bot-hook", Lapse::Never),
            Duration::hours(2),
        );

        assert_eq!(round.changed(), 1);
        assert_eq!(left, 0);
        assert_eq!(records, ["workflows.channel_closed"]);
        assert_eq!(asked, ["close_channel"]);
    }

    /// Telegram is down, so the channel stays for the next round.
    #[test]
    fn an_unreachable_service_is_asked_again() {
        let (round, left, records, _) = swept(
            FakeServiceRegistrar::failing(RegistrationFailure::Unreachable),
            Duration::hours(2),
        );

        assert_eq!(round.failed(), 1);
        assert_eq!(left, 1);
        assert!(records.is_empty());
    }

    /// A service out of reach for over a week is not waited for any
    /// longer, so the sweep ends.
    #[test]
    fn a_service_out_of_reach_for_a_week_is_given_up_on() {
        let (round, left, records, _) = swept(
            FakeServiceRegistrar::failing(RegistrationFailure::Unreachable),
            Duration::days(8),
        );

        assert_eq!(round.changed(), 1);
        assert_eq!(left, 0);
        assert_eq!(records, ["workflows.channel_closed"]);
    }

    /// A channel that was in use a moment ago is left alone, so a version
    /// and its replacement can share it.
    #[test]
    fn a_channel_idle_for_a_moment_is_left_alone() {
        let (round, left, _, asked) = swept(
            FakeServiceRegistrar::taking("bot-hook", Lapse::Never),
            Duration::minutes(5),
        );

        assert_eq!(round.changed(), 0);
        assert_eq!(left, 1);
        assert!(asked.is_empty());
    }
}
