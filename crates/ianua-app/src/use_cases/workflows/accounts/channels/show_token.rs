//! Show channel token: the token a service sent an account's channel,
//! given to the account's owner to paste back at the service, as Notion
//! asks. Reading it is on the record.

use std::sync::Arc;

use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::IntegrationAccountId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::workflows::{AccountChannelStore, IntegrationAccountStore};
use crate::services::account_channels::channel_secret_place;
use crate::services::sealing::opened_text;
use crate::use_case::Command;
use crate::use_cases::workflows::accounts::channels::lookup::existing_channel;
use crate::use_cases::workflows::lookup::owned_account;

/// The ports [`ShowTokenUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ShowTokenPorts {
    /// Keeps the accounts.
    pub accounts: Arc<dyn IntegrationAccountStore>,
    /// Keeps the channels.
    pub channels: Arc<dyn AccountChannelStore>,
    /// Opens the token.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Gives an account's owner the token its channel waits on.
pub struct ShowTokenUseCase {
    ports: ShowTokenPorts,
}

impl ShowTokenUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ShowTokenPorts) -> Self {
        Self { ports }
    }
}

impl Command for ShowTokenUseCase {
    type Caller = CallerContext;
    type Input = IntegrationAccountId;
    type Output = Result<Secret, AppError>;

    /// The token waiting on the account's channel, recording
    /// `workflows.channel_token_shown`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller.
    /// - `AppError::NotFound` for no such account, one the caller neither
    ///   owns nor may connect, or no channel yet.
    /// - `AppError::Forbidden` when the caller is not the owner.
    /// - `AppError::Conflict` when no token is waiting.
    /// - `AppError::Internal` when it does not open, or cannot be recorded.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        account_id: IntegrationAccountId,
    ) -> Result<Secret, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        let tenant = ctx.tenant();
        let account =
            owned_account(self.ports.accounts.as_ref(), &tenant, &account_id, &control).await?;
        let mut channel =
            existing_channel(self.ports.channels.as_ref(), &tenant, &account_id).await?;
        let sealed = channel
            .show_token(&account, &control)
            .map_err(AppError::from_domain)?;
        let token = opened_text(
            self.ports.encryptor.as_ref(),
            &sealed,
            &channel_secret_place(&tenant, channel.id()),
        )
        .await
        .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), channel.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::account::{AccountSharing, IntegrationAccount};
    use ianua_domain::domains::workflows::triggers::channel::{
        AccountChannel, ChannelSetup, OpenChannel,
    };
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::AccountChannelId;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::agents::caller_person;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::workflows::{
        FakeAccountChannelStore, FakeIntegrationAccountStore, sheets_account,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const MAY_CONNECT: [SystemPermission; 1] =
        [SystemPermission::Workflows(WorkflowAction::ConnectAccounts)];

    fn shown(
        account: &IntegrationAccount<ResolvedTenant>,
        token: Option<&str>,
        sink: Arc<FakeEventDispatcher>,
    ) -> Result<Secret, AppError> {
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
        if let Some(token) = token {
            channel
                .receive_token(FakeEncryptor::sealed_for(token, &place))
                .unwrap();
        }
        let store = Arc::new(FakeAccountChannelStore::empty());
        block_on(store.insert_if_absent(&tenant, &channel)).unwrap();
        let use_case = ShowTokenUseCase::new(ShowTokenPorts {
            accounts: Arc::new(FakeIntegrationAccountStore::holding(account)),
            channels: store,
            encryptor: Arc::new(FakeEncryptor),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&MAY_CONNECT)),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(sink), *account.id()))
    }

    /// Notion sent its token. Ann reads it to paste it back, and her
    /// reading it is recorded.
    #[test]
    fn the_owner_reads_the_token_on_the_record() {
        let account = sheets_account(&caller_person(), AccountSharing::OwnerOnly);
        let sink = Arc::new(FakeEventDispatcher::new());

        let token = shown(&account, Some("the notion token"), sink.clone()).unwrap();

        assert_eq!(token.expose(), "the notion token");
        assert_eq!(
            *sink.records.lock().unwrap(),
            ["workflows.channel_token_shown"]
        );
    }

    /// Before Notion has sent anything there is nothing to read.
    #[test]
    fn no_token_yet_is_refused() {
        let account = sheets_account(&caller_person(), AccountSharing::OwnerOnly);
        let sink = Arc::new(FakeEventDispatcher::new());

        let shown = shown(&account, None, sink.clone());

        assert!(matches!(shown, Err(AppError::Conflict(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }
}
