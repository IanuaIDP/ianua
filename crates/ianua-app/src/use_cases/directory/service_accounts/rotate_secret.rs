//! Rotate service account secret: replace the secret an application binds
//! with, as when Jira's configuration file leaked.

use std::sync::Arc;

use ianua_domain::domains::authentication::directory_service::control::DirectoryControlCheck as _;
use ianua_domain::domains::authentication::directory_service::scope::DirectoryAccess;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::DirectoryServiceAccountId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::directory::{DirectoryServiceAccountStore, ServiceAccountSecrets};
use crate::use_case::Command;
use crate::use_cases::directory::service_accounts::lookup::existing_service_account;

/// The ports [`RotateSecretUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RotateSecretPorts {
    /// Keeps the tenant's service accounts.
    pub accounts: Arc<dyn DirectoryServiceAccountStore>,
    /// Makes the new secret.
    pub secrets: Arc<dyn ServiceAccountSecrets>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Replaces a service account's secret.
pub struct RotateSecretUseCase {
    ports: RotateSecretPorts,
}

impl RotateSecretUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RotateSecretPorts) -> Self {
        Self { ports }
    }
}

impl Command for RotateSecretUseCase {
    type Caller = CallerContext;
    type Input = DirectoryServiceAccountId;
    type Output = Result<Secret, AppError>;

    /// Gives the account a new secret and records
    /// `authentication.directory_service_account_secret_rotated`. The new
    /// secret comes back once; every bind made with the old one stops
    /// counting at its next request.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not hand out the access the
    ///   account has.
    /// - `AppError::NotFound` if the account doesn't exist.
    /// - `AppError::Internal` on secret, audit or persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: DirectoryServiceAccountId,
    ) -> Result<Secret, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_may_grant(DirectoryAccess::ReadOnly)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let store = self.ports.accounts.as_ref();
        let mut account = existing_service_account(store, &tenant, &id).await?;
        let (secret, secret_hash) = self.ports.secrets.generate().await.or_internal()?;
        account
            .rotate_secret(secret_hash, &authority)
            .map_err(AppError::from_domain)?;

        store.save(&tenant, &account).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), account.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::directory_service::account::ServiceAccountStatus;
    use ianua_domain::domains::authorization::permission::{AuthConfigAction, SystemPermission};
    use ianua_domain::types::TokenHash;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::directory_service::{
        FakeServiceAccountStore, JIRA_SECRET, service_secret_hash, test_service_account,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn seeded(
        access: DirectoryAccess,
    ) -> (Arc<FakeServiceAccountStore>, DirectoryServiceAccountId) {
        let id = DirectoryServiceAccountId::new();
        let account = test_service_account(id, access, ServiceAccountStatus::Active);
        let store = FakeServiceAccountStore::holding(&test_ctx().tenant(), [account]);
        (Arc::new(store), id)
    }

    fn rotate(
        store: Arc<FakeServiceAccountStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        id: DirectoryServiceAccountId,
    ) -> Result<Secret, AppError> {
        let use_case = RotateSecretUseCase::new(RotateSecretPorts {
            accounts: store,
            tenant_authorities: Arc::new(authorities),
            ..RotateSecretPorts::fakes()
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), id))
    }

    fn kept_hash(store: &FakeServiceAccountStore, id: &DirectoryServiceAccountId) -> TokenHash {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
            .secret_hash()
            .clone()
    }

    /// Jira's configuration leaked. Ann rotates its secret: the new one is
    /// shown once, only its hash is kept, and the rotation is recorded.
    #[test]
    fn a_new_secret_is_shown_once_and_kept_hashed() {
        let (store, id) = seeded(DirectoryAccess::ReadOnly);
        let audit = Arc::new(FakeEventDispatcher::new());

        let secret = rotate(
            store.clone(),
            FakeTenantAuthorities::holding_everything(),
            &audit,
            id,
        )
        .unwrap();

        assert_eq!(kept_hash(&store, &id), service_secret_hash(secret.expose()));
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["authentication.directory_service_account_secret_rotated"]
        );
    }

    /// Ann names an account Acme does not have. It is not found.
    #[test]
    fn an_unknown_account_is_not_found() {
        let (store, _) = seeded(DirectoryAccess::ReadOnly);
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = rotate(
            store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            DirectoryServiceAccountId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller with the right over sign-in settings alone cannot rotate
    /// an account's secret; its hash stays unchanged and no rotation is
    /// audited.
    #[test]
    fn rotating_a_secret_needs_the_right_over_users() {
        let (store, id) = seeded(DirectoryAccess::ReadOnly);
        let audit = Arc::new(FakeEventDispatcher::new());
        let settings_only = [SystemPermission::AuthConfig(AuthConfigAction::Update)];

        let result = rotate(
            store.clone(),
            FakeTenantAuthorities::holding(&settings_only),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(kept_hash(&store, &id), service_secret_hash(JIRA_SECRET));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot request a new service-account secret.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded(DirectoryAccess::ReadOnly);
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = rotate(
            store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
