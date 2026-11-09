//! Show channel: the address to give a service for an account's events,
//! and what the channel still waits for. Nothing secret is in it.

use std::sync::Arc;

use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::triggers::channel::{
    AccountChannel, ChannelSetup, ChannelStatus,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::IntegrationAccountId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::workflows::{AccountChannelStore, IntegrationAccountStore, ServiceChannelSetup};
use crate::use_case::Query;
use crate::use_cases::workflows::accounts::channels::lookup::existing_channel;
use crate::use_cases::workflows::lookup::owned_account;

/// An account's channel, as a person setting it up sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelView {
    /// The address to give the service.
    pub address: String,
    /// How it gets to ready.
    pub setup: ChannelSetup,
    /// Where it is.
    pub status: ChannelStatus,
}

impl ChannelView {
    /// `channel` as a person sees it, at the address `setup` gives it.
    pub(super) fn of(
        channel: &AccountChannel<ResolvedTenant>,
        setup: &dyn ServiceChannelSetup,
    ) -> Self {
        Self {
            address: setup.channel_address(channel.id()),
            setup: channel.setup(),
            status: channel.status(),
        }
    }
}

/// The ports [`ShowUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ShowPorts {
    /// Keeps the accounts.
    pub accounts: Arc<dyn IntegrationAccountStore>,
    /// Keeps the channels.
    pub channels: Arc<dyn AccountChannelStore>,
    /// Gives a channel its address.
    pub channel_setup: Arc<dyn ServiceChannelSetup>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Shows an account's channel.
pub struct ShowUseCase {
    ports: ShowPorts,
}

impl ShowUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ShowPorts) -> Self {
        Self { ports }
    }
}

impl Query for ShowUseCase {
    type Caller = CallerContext;
    type Input = IntegrationAccountId;
    type Output = Result<ChannelView, AppError>;

    /// The channel of the account `account_id`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller.
    /// - `AppError::NotFound` for no such account, one the caller neither
    ///   owns nor may connect, or an account with no channel yet.
    /// - `AppError::Internal` when a store fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        account_id: IntegrationAccountId,
    ) -> Result<ChannelView, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        let tenant = ctx.tenant();
        owned_account(self.ports.accounts.as_ref(), &tenant, &account_id, &control).await?;
        let channel = existing_channel(self.ports.channels.as_ref(), &tenant, &account_id).await?;
        Ok(ChannelView::of(&channel, self.ports.channel_setup.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::account::{AccountSharing, IntegrationAccount};
    use ianua_domain::domains::workflows::triggers::channel::OpenChannel;
    use ianua_domain::types::AccountChannelId;

    use super::*;
    use crate::services::account_channels::channel_secret_place;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::agents::caller_person;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::workflows::{
        FakeAccountChannelStore, FakeIntegrationAccountStore, sheets_account,
    };
    use crate::test_support::{block_on, test_ctx};

    const MAY_CONNECT: [SystemPermission; 1] =
        [SystemPermission::Workflows(WorkflowAction::ConnectAccounts)];

    fn waiting_channel(
        account: &IntegrationAccount<ResolvedTenant>,
    ) -> Arc<FakeAccountChannelStore> {
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

    /// Ann opens her HubSpot account's channel to copy its address into
    /// HubSpot's settings, and sees that it waits for her key.
    #[test]
    fn the_owner_sees_the_address_and_what_it_waits_for() {
        let account = sheets_account(&caller_person(), AccountSharing::OwnerOnly);
        let use_case = ShowUseCase::new(ShowPorts {
            accounts: Arc::new(FakeIntegrationAccountStore::holding(&account)),
            channels: waiting_channel(&account),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&MAY_CONNECT)),
            ..ShowPorts::fakes()
        });

        let view = block_on(use_case.execute(&test_ctx(), *account.id())).unwrap();

        assert_eq!(view.status, ChannelStatus::AwaitingKey);
        assert!(view.address.starts_with("https://"));
    }

    /// An account no workflow has used for events has no channel to show.
    #[test]
    fn an_account_with_no_channel_is_not_found() {
        let account = sheets_account(&caller_person(), AccountSharing::OwnerOnly);
        let use_case = ShowUseCase::new(ShowPorts {
            accounts: Arc::new(FakeIntegrationAccountStore::holding(&account)),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&MAY_CONNECT)),
            ..ShowPorts::fakes()
        });

        let shown = block_on(use_case.execute(&test_ctx(), *account.id()));

        assert!(matches!(shown, Err(AppError::NotFound(_))));
    }
}
