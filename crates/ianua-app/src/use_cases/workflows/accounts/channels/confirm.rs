//! Confirm channel: an account's owner says they pasted the service's token
//! back at the service, so its events can be taken. Until then the channel
//! reads nothing, so a token posted by anyone who learned the address
//! starts no workflow.

use std::sync::Arc;

use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::IntegrationAccountId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::{AccountChannelStore, IntegrationAccountStore, ServiceChannelSetup};
use crate::use_case::Command;
use crate::use_cases::workflows::accounts::channels::lookup::existing_channel;
use crate::use_cases::workflows::accounts::channels::show::ChannelView;
use crate::use_cases::workflows::lookup::owned_account;

/// The ports [`ConfirmUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ConfirmPorts {
    /// Keeps the accounts.
    pub accounts: Arc<dyn IntegrationAccountStore>,
    /// Keeps the channels.
    pub channels: Arc<dyn AccountChannelStore>,
    /// Gives a channel its address.
    pub channel_setup: Arc<dyn ServiceChannelSetup>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Puts live a channel whose token its owner pasted back.
pub struct ConfirmUseCase {
    ports: ConfirmPorts,
}

impl ConfirmUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ConfirmPorts) -> Self {
        Self { ports }
    }
}

impl Command for ConfirmUseCase {
    type Caller = CallerContext;
    type Input = IntegrationAccountId;
    type Output = Result<ChannelView, AppError>;

    /// Puts the account's channel live, recording
    /// `workflows.channel_ready`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller.
    /// - `AppError::NotFound` for no such account, one the caller neither
    ///   owns nor may connect, or no channel yet.
    /// - `AppError::Forbidden` when the caller is not the owner.
    /// - `AppError::Domain` when no token is waiting.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        account_id: IntegrationAccountId,
    ) -> Result<ChannelView, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        let tenant = ctx.tenant();
        let account =
            owned_account(self.ports.accounts.as_ref(), &tenant, &account_id, &control).await?;
        let mut channel =
            existing_channel(self.ports.channels.as_ref(), &tenant, &account_id).await?;
        channel
            .confirm(&account, &control)
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
    use crate::services::account_channels::channel_secret_place;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::agents::caller_person;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::workflows::{
        FakeAccountChannelStore, FakeIntegrationAccountStore, sheets_account,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const MAY_CONNECT: [SystemPermission; 1] =
        [SystemPermission::Workflows(WorkflowAction::ConnectAccounts)];

    fn confirmed(
        account: &IntegrationAccount<ResolvedTenant>,
        token_arrived: bool,
    ) -> Result<ChannelView, AppError> {
        let id = AccountChannelId::new();
        let tenant = test_ctx().tenant();
        let place = channel_secret_place(&tenant, &id);
        let mut channel: AccountChannel<ResolvedTenant> = AccountChannel::open(OpenChannel {
            id,
            account: *account.id(),
            integration: account.integration().clone(),
            secret: FakeEncryptor::sealed_for("own words", &place),
            setup: ChannelSetup::TokenFromService,
        })
        .unwrap();
        if token_arrived {
            channel
                .receive_token(FakeEncryptor::sealed_for("the notion token", &place))
                .unwrap();
        }
        let store = Arc::new(FakeAccountChannelStore::empty());
        block_on(store.insert_if_absent(&tenant, &channel)).unwrap();
        let use_case = ConfirmUseCase::new(ConfirmPorts {
            accounts: Arc::new(FakeIntegrationAccountStore::holding(account)),
            channels: store,
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&MAY_CONNECT)),
            ..ConfirmPorts::fakes()
        });
        let sink = Arc::new(FakeEventDispatcher::new());
        block_on(use_case.execute(&test_ctx(), &test_auditor(sink), *account.id()))
    }

    /// Ann pasted Notion's token back. The channel goes live.
    #[test]
    fn the_owner_confirms_and_the_channel_goes_live() {
        let account = sheets_account(&caller_person(), AccountSharing::OwnerOnly);

        let view = confirmed(&account, true).unwrap();

        assert_eq!(view.status, ChannelStatus::Live);
    }

    /// With no token from the service there is nothing to confirm.
    #[test]
    fn nothing_to_confirm_is_refused() {
        let account = sheets_account(&caller_person(), AccountSharing::OwnerOnly);

        let refused = confirmed(&account, false);

        assert!(matches!(refused, Err(AppError::Domain(_))));
    }
}
