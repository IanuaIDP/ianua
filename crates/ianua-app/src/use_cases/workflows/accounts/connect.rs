//! Connect account: a person connects an account at an integration, for
//! workflow actions to act through.
//!
//! The account is owned by whoever connects it, and only someone who may
//! connect accounts does. The credential is sealed before it is kept, so
//! the app never stores it in the clear.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::account::{
    AccountSharing, ConnectAccountParams, IntegrationAccount, OperationScope,
};
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{IntegrationAccountId, Label, SealedSecret};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use crate::ports::workflows::{AccountVerifier, IntegrationAccountStore, IntegrationCatalog};
use crate::services::sealing::sealed_text;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// An account to connect, as the person connecting it describes it.
pub struct ConnectRequest {
    /// The provider adapter that understands this account's credential.
    pub integration: IntegrationKey,
    /// Its name for people.
    pub name: Label,
    /// The credential, in the clear. It is sealed before it is kept.
    pub credential: Secret,
    /// Who may have workflows act through it.
    pub sharing: AccountSharing,
    /// Which operations it may be used for.
    pub scope: OperationScope,
}

/// The ports [`ConnectUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ConnectPorts {
    /// Keeps the accounts.
    pub accounts: Arc<dyn IntegrationAccountStore>,
    /// Says which integrations are installed.
    pub catalog: Arc<dyn IntegrationCatalog>,
    /// Asks the integration whether the credential works.
    pub verifier: Arc<dyn AccountVerifier>,
    /// Seals the credential.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Connects integration accounts.
pub struct ConnectUseCase {
    ports: ConnectPorts,
}

impl ConnectUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ConnectPorts) -> Self {
        Self { ports }
    }

    /// `request`, once its integration is installed and its service took
    /// the credential, holding the credential to keep: its own, or what
    /// asking replaced it with.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the integration offers nothing.
    /// - `AppError::Domain` when the service refused the credential.
    /// - `AppError::Upstream` when the service could not be asked.
    /// - `AppError::Internal` when the catalog cannot be read.
    async fn vouched(&self, request: ConnectRequest) -> Result<ConnectRequest, AppError> {
        ensure_installed(self.ports.catalog.as_ref(), &request.integration).await?;
        let verifier = self.ports.verifier.as_ref();
        let credential =
            ensure_credential_works(verifier, &request.integration, &request.credential).await?;
        Ok(ConnectRequest {
            credential,
            ..request
        })
    }

    /// What connecting the account `request` describes in `tenant` asks
    /// for, under a fresh id, its credential sealed for that account.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the credential cannot be sealed.
    async fn params(
        &self,
        tenant: &ScopedTenant,
        request: ConnectRequest,
    ) -> Result<ConnectAccountParams, AppError> {
        let id = IntegrationAccountId::new();
        let place = integration_credential_place(tenant, &id);
        let credential = sealed(self.ports.encryptor.as_ref(), &request.credential, &place).await?;
        Ok(ConnectAccountParams {
            id,
            integration: request.integration,
            name: request.name,
            credential,
            sharing: request.sharing,
            scope: request.scope,
        })
    }
}

impl Command for ConnectUseCase {
    type Caller = CallerContext;
    type Input = ConnectRequest;
    type Output = Result<IntegrationAccount<ResolvedTenant>, AppError>;

    /// Connects an account owned by the person `ctx` names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without account-connection rights; `NotFound` for a missing integration.
    /// - `AppError::Domain` for a refused credential; `Upstream` for an unreachable service, keeping nothing so a retry can succeed.
    /// - `AppError::Internal` on catalog, sealing, persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ConnectRequest,
    ) -> Result<IntegrationAccount<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::ConnectAccounts)
            .map_err(AppError::from_domain)?;
        let request = self.vouched(request).await?;
        let params = self.params(&ctx.tenant(), request).await?;
        let mut account =
            IntegrationAccount::connect(params, &control).map_err(AppError::from_domain)?;
        self.ports
            .accounts
            .save(&ctx.tenant(), &account)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), account.take_events(&ctx.tenant()))
            .await
            .or_internal()?;
        Ok(account)
    }
}

/// Refuses an integration the catalog offers nothing for.
async fn ensure_installed(
    catalog: &dyn IntegrationCatalog,
    integration: &IntegrationKey,
) -> Result<(), AppError> {
    let offered = catalog.offered(integration).await.or_internal()?;
    if offered.is_empty() {
        return Err(AppError::NotFound(message!(
            "workflows-integration",
            "integration"
        )));
    }
    Ok(())
}

/// The credential to keep, once `integration`'s service took `credential`
/// or the integration has no service of its own to ask: `credential`
/// itself, or what asking replaced it with, for a service whose grants
/// rotate. A service that could not be asked refuses it too, so an account
/// is never kept on a credential nobody vouched for when it could have been
/// checked.
///
/// # Errors
///
/// - `AppError::Domain` when the service refused it.
/// - `AppError::Upstream` when the service could not be asked.
pub(crate) async fn ensure_credential_works(
    verifier: &dyn AccountVerifier,
    integration: &IntegrationKey,
    credential: &Secret,
) -> Result<Secret, AppError> {
    let checked = verifier.check(integration, credential).await;
    match checked.verdict {
        AccountCheck::Accepted | AccountCheck::NotCheckable => {
            Ok(checked.replaced_by.unwrap_or_else(|| credential.clone()))
        }
        AccountCheck::Refused(why) => Err(AppError::Domain(DomainError::invalid(message!(
            "workflows-the-service-refused-the-credential",
            format!("{integration} refused the credential: {why}")
        )))),
        AccountCheck::Unreachable => Err(AppError::Upstream(Box::new(DomainError::infra_msg(
            format!("{integration} could not be asked whether the credential works"),
        )))),
    }
}

/// Where `tenant`'s account `account` keeps its credential.
pub(crate) fn integration_credential_place(
    tenant: &ScopedTenant,
    account: &IntegrationAccountId,
) -> SealedFor {
    SealedFor::new(
        SealOwner::from(tenant),
        SealedField::IntegrationCredential,
        account,
    )
}

/// `credential` sealed for keeping at `place`.
///
/// # Errors
///
/// - `AppError::Internal` when it cannot be sealed.
pub(crate) async fn sealed(
    encryptor: &dyn SecretEncryptor,
    credential: &Secret,
    place: &SealedFor,
) -> Result<SealedSecret, AppError> {
    sealed_text(encryptor, credential.expose(), place).await
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::types::{ActionClass, UntrustedText};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::workflows::{
        FakeAccountVerifier, FakeIntegrationAccountStore, FakeIntegrationCatalog, SHEETS,
        account_credential_place, append_row,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const TOKEN: &str = "sheets-api-token";

    /// The store a connect writes to, and what it recorded.
    struct Written {
        accounts: Arc<FakeIntegrationAccountStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Written {
        fn new() -> Self {
            Self {
                accounts: Arc::new(FakeIntegrationAccountStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self, authorities: FakeTenantAuthorities) -> ConnectPorts {
            self.checked_by(
                authorities,
                Arc::new(FakeAccountVerifier::answering(AccountCheck::Accepted)),
            )
        }

        fn checked_by(
            &self,
            authorities: FakeTenantAuthorities,
            verifier: Arc<FakeAccountVerifier>,
        ) -> ConnectPorts {
            ConnectPorts {
                accounts: self.accounts.clone(),
                catalog: Arc::new(FakeIntegrationCatalog::offering(vec![append_row(
                    ActionClass::Write,
                )])),
                verifier,
                encryptor: Arc::new(FakeEncryptor),
                tenant_authorities: Arc::new(authorities),
            }
        }

        fn connect(
            &self,
            ports: ConnectPorts,
            integration: &str,
        ) -> Result<IntegrationAccount<ResolvedTenant>, AppError> {
            let use_case = ConnectUseCase::new(ports);
            block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                request(integration),
            ))
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    fn request(integration: &str) -> ConnectRequest {
        ConnectRequest {
            integration: IntegrationKey::new(integration).unwrap(),
            name: Label::new("name", "Finance sheets").unwrap(),
            credential: Secret::new(TOKEN),
            sharing: AccountSharing::OwnerOnly,
            scope: OperationScope::All,
        }
    }

    fn connector() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(
            WorkflowAction::ConnectAccounts,
        )])
    }

    /// Ann, who may connect accounts, connects her finance sheets. The
    /// account is kept, owned by her, and its connection is recorded.
    #[test]
    fn the_person_connecting_owns_the_account_and_it_is_recorded() {
        let written = Written::new();

        let account = written.connect(written.ports(connector()), SHEETS).unwrap();

        let kept = written.accounts.stored(account.id()).unwrap();
        assert!(kept.owner().is_same_account_as(&caller_person()));
        assert_eq!(written.records(), ["workflows.account_connected"]);
    }

    /// Ann hands over her API token. What is kept is the token sealed, never
    /// the token as she typed it.
    #[test]
    fn the_credential_is_kept_sealed() {
        let written = Written::new();

        let account = written.connect(written.ports(connector()), SHEETS).unwrap();

        let kept = written.accounts.stored(account.id()).unwrap();
        assert_eq!(
            kept.credential(),
            &FakeEncryptor::sealed_for(TOKEN, &account_credential_place(account.id()))
        );
    }

    /// The service is asked once about a revoked token and refuses it. The
    /// connection fails without saving an account or recording an audit event.
    #[test]
    fn a_credential_the_service_refuses_is_not_kept() {
        let written = Written::new();
        let refusing = Arc::new(FakeAccountVerifier::answering(AccountCheck::Refused(
            UntrustedText::record("the token was revoked"),
        )));

        let result = written.connect(written.checked_by(connector(), refusing.clone()), SHEETS);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(written.accounts.count(), 0);
        assert!(written.records().is_empty());
        assert_eq!(refusing.asked().len(), 1);
    }

    /// An unreachable credential verifier makes connection fail with an upstream
    /// error and leaves no account saved.
    #[test]
    fn a_credential_that_cannot_be_checked_now_is_not_kept() {
        let written = Written::new();
        let down = Arc::new(FakeAccountVerifier::answering(AccountCheck::Unreachable));

        let result = written.connect(written.checked_by(connector(), down), SHEETS);

        assert!(matches!(result, Err(AppError::Upstream(_))));
        assert_eq!(written.accounts.count(), 0);
    }

    /// An integration with no service of its own to ask keeps the account
    /// unchecked.
    #[test]
    fn a_credential_with_nothing_to_ask_is_kept() {
        let written = Written::new();
        let unchecked = Arc::new(FakeAccountVerifier::answering(AccountCheck::NotCheckable));

        let result = written.connect(written.checked_by(connector(), unchecked), SHEETS);

        assert!(result.is_ok());
        assert_eq!(written.accounts.count(), 1);
    }

    /// A workflow viewer cannot connect an account; the verifier receives no
    /// request to check the supplied token.
    #[test]
    fn a_refused_caller_never_reaches_the_service() {
        let written = Written::new();
        let sam =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);
        let verifier = Arc::new(FakeAccountVerifier::answering(AccountCheck::Accepted));

        let result = written.connect(written.checked_by(sam, verifier.clone()), SHEETS);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(verifier.asked().is_empty());
    }

    /// Ann connects an account at an integration nobody installed. It is
    /// refused as not found, and nothing is kept.
    #[test]
    fn an_integration_that_is_not_installed_is_not_found() {
        let written = Written::new();

        let result = written.connect(written.ports(connector()), "unknown-crm");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(written.accounts.count(), 0);
    }

    /// A workflow viewer's connection request is forbidden, leaving no account
    /// saved and no audit event recorded.
    #[test]
    fn a_caller_who_may_not_connect_accounts_is_refused() {
        let written = Written::new();
        let sam =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let result = written.connect(written.ports(sam), SHEETS);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(written.accounts.count(), 0);
        assert!(written.records().is_empty());
    }

    /// A workflow viewer receives forbidden even when the requested integration
    /// is not installed.
    #[test]
    fn a_refused_caller_learns_nothing_about_the_catalog() {
        let written = Written::new();
        let sam =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let result = written.connect(written.ports(sam), "unknown-crm");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot connect an account; none is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let written = Written::new();
        let mallory = FakeTenantAuthorities::refusing(Refusal::SignedOut);

        let result = written.connect(written.ports(mallory), SHEETS);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(written.accounts.count(), 0);
    }
}
