//! Set channel key: an account's owner pastes in the key the service signs
//! its deliveries with, such as HubSpot's app secret or the shared secret
//! set in a Salesforce callout. The channel goes live with it.

use std::sync::Arc;

use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::triggers::channel::ChannelKey;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::IntegrationAccountId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::workflows::{AccountChannelStore, IntegrationAccountStore, ServiceChannelSetup};
use crate::services::account_channels::channel_secret_place;
use crate::services::sealing::sealed_text;
use crate::use_case::Command;
use crate::use_cases::workflows::accounts::channels::lookup::existing_channel;
use crate::use_cases::workflows::accounts::channels::show::ChannelView;
use crate::use_cases::workflows::lookup::owned_account;

/// Which account's channel takes a key, and the key.
pub struct SetKeyRequest {
    /// The account whose channel takes it.
    pub account_id: IntegrationAccountId,
    /// The key, in the clear. It is sealed before it is kept.
    pub key: ChannelKey,
}

/// The ports [`SetKeyUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SetKeyPorts {
    /// Keeps the accounts.
    pub accounts: Arc<dyn IntegrationAccountStore>,
    /// Keeps the channels.
    pub channels: Arc<dyn AccountChannelStore>,
    /// Gives a channel its address.
    pub channel_setup: Arc<dyn ServiceChannelSetup>,
    /// Seals the key.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Takes the key an account's channel is proven with.
pub struct SetKeyUseCase {
    ports: SetKeyPorts,
}

impl SetKeyUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SetKeyPorts) -> Self {
        Self { ports }
    }
}

impl Command for SetKeyUseCase {
    type Caller = CallerContext;
    type Input = SetKeyRequest;
    type Output = Result<ChannelView, AppError>;

    /// Seals `request.key`, keeps it on the account's channel and puts the
    /// channel live, recording `workflows.channel_ready`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller.
    /// - `AppError::NotFound` for no such account, one the caller neither
    ///   owns nor may connect, or no channel yet.
    /// - `AppError::Forbidden` when the caller is not the owner.
    /// - `AppError::Conflict` when this service's channel takes no key.
    /// - `AppError::Internal` on sealing, storage or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: SetKeyRequest,
    ) -> Result<ChannelView, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        let tenant = ctx.tenant();
        let account = owned_account(
            self.ports.accounts.as_ref(),
            &tenant,
            &request.account_id,
            &control,
        )
        .await?;
        let mut channel =
            existing_channel(self.ports.channels.as_ref(), &tenant, &request.account_id).await?;
        let place = channel_secret_place(&tenant, channel.id());
        let encryptor = self.ports.encryptor.as_ref();
        let sealed = sealed_text(encryptor, request.key.as_str(), &place).await?;
        channel
            .paste_key(sealed, &account, &control)
            .map_err(AppError::from_domain)?;
        self.ports
            .channels
            .save(&tenant, &channel)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), channel.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(ChannelView::of(&channel, self.ports.channel_setup.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::account::{AccountSharing, IntegrationAccount};
    use ianua_domain::domains::workflows::triggers::channel::{
        AccountChannel, ChannelSetup, ChannelStatus, OpenChannel,
    };
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::AccountChannelId;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::agents::caller_person;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::workflows::{
        FakeAccountChannelStore, FakeIntegrationAccountStore, person, sheets_account,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const MAY_CONNECT: [SystemPermission; 1] =
        [SystemPermission::Workflows(WorkflowAction::ConnectAccounts)];

    fn channel_store(account: &IntegrationAccount<ResolvedTenant>) -> Arc<FakeAccountChannelStore> {
        let id = AccountChannelId::new();
        let tenant = test_ctx().tenant();
        let channel = AccountChannel::open(OpenChannel {
            id,
            account: *account.id(),
            integration: account.integration().clone(),
            secret: FakeEncryptor::sealed_for("own words", &channel_secret_place(&tenant, &id)),
            setup: ChannelSetup::PastedKey,
        })
        .unwrap();
        let store = Arc::new(FakeAccountChannelStore::empty());
        block_on(store.insert_if_absent(&tenant, &channel)).unwrap();
        store
    }

    fn pasted(
        account: &IntegrationAccount<ResolvedTenant>,
        store: Arc<FakeAccountChannelStore>,
        sink: Arc<FakeEventDispatcher>,
    ) -> Result<ChannelView, AppError> {
        let use_case = SetKeyUseCase::new(SetKeyPorts {
            accounts: Arc::new(FakeIntegrationAccountStore::holding(account)),
            channels: store,
            encryptor: Arc::new(FakeEncryptor),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&MAY_CONNECT)),
            ..SetKeyPorts::fakes()
        });
        block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(sink),
            SetKeyRequest {
                account_id: *account.id(),
                key: ChannelKey::new("hubspot app secret words").unwrap(),
            },
        ))
    }

    /// Ann pastes HubSpot's app secret. It is kept sealed for this channel,
    /// the channel goes live, and that is on the record.
    #[test]
    fn the_owner_pastes_a_key_and_the_channel_goes_live() {
        let account = sheets_account(&caller_person(), AccountSharing::OwnerOnly);
        let store = channel_store(&account);
        let sink = Arc::new(FakeEventDispatcher::new());

        let view = pasted(&account, store.clone(), sink.clone()).unwrap();

        let tenant = test_ctx().tenant();
        let kept = block_on(store.of_account(&tenant, account.id()))
            .unwrap()
            .unwrap();
        assert_eq!(view.status, ChannelStatus::Live);
        assert_eq!(
            kept.secret(),
            &FakeEncryptor::sealed_for(
                "hubspot app secret words",
                &channel_secret_place(&tenant, kept.id())
            )
        );
        assert_eq!(*sink.records.lock().unwrap(), ["workflows.channel_ready"]);
    }

    /// Stops: Sam may connect accounts but this is Ann's account. A key he
    /// pastes would let him forge the events that start her workflows, so
    /// it is refused and nothing is recorded.
    #[test]
    fn another_person_may_not_paste_a_key() {
        let ann = person("ann-the-owner@corp.test");
        let account = sheets_account(&ann, AccountSharing::Tenant);
        let store = channel_store(&account);
        let sink = Arc::new(FakeEventDispatcher::new());

        let refused = pasted(&account, store.clone(), sink.clone());

        let kept = block_on(store.of_account(&test_ctx().tenant(), account.id()))
            .unwrap()
            .unwrap();
        assert!(matches!(refused, Err(AppError::Forbidden(_))));
        assert!(!kept.is_live());
        assert!(sink.records.lock().unwrap().is_empty());
    }
}
