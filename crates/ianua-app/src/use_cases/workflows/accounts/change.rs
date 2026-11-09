//! Change account: a person changes an integration account.
//!
//! What widens what an account lets others do (enabling it, a new
//! credential, sharing it, widening its operations) is its owner's alone.
//! What narrows it (disabling it, keeping it to its owner) and renaming it
//! may also be done by anyone who may connect accounts, so a leaked
//! credential is switched off without waiting for its owner. The domain
//! decides which is which.

use std::sync::Arc;

use ianua_domain::domains::workflows::account::{IntegrationAccount, OperationScope};
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{IntegrationAccountId, Label};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{SealedFor, SecretEncryptor};
use crate::ports::workflows::{AccountVerifier, IntegrationAccountStore};
use crate::use_case::Command;
use crate::use_cases::workflows::accounts::connect::{
    ensure_credential_works, integration_credential_place, sealed,
};
use crate::use_cases::workflows::lookup::owned_account;

/// One change to an integration account.
pub enum AccountChange {
    /// Lets it be used again.
    Enable,
    /// Stops it being used.
    Disable,
    /// Replaces its credential with this one, in the clear. It is sealed
    /// before it is kept.
    ReplaceCredential(Secret),
    /// Lets workflows run for anyone in the tenant act through it.
    ShareWithTenant,
    /// Keeps it to its owner's workflows.
    KeepToOwner,
    /// Changes which operations it may be used for.
    LimitTo(OperationScope),
    /// Changes the label people use to recognize this connected account.
    Rename(Label),
}

/// Which account to change, and how.
pub struct ChangeRequest {
    /// The connected credential whose settings will change.
    pub account_id: IntegrationAccountId,
    /// The requested mutation to the account's access or presentation.
    pub change: AccountChange,
}

/// The ports [`ChangeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangePorts {
    /// Keeps the accounts.
    pub accounts: Arc<dyn IntegrationAccountStore>,
    /// Seals a replacement credential.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Asks the integration whether a replacement credential works.
    pub verifier: Arc<dyn AccountVerifier>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes integration accounts.
pub struct ChangeUseCase {
    ports: ChangePorts,
}

impl ChangeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangePorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeUseCase {
    type Caller = CallerContext;
    type Input = ChangeRequest;
    type Output = Result<IntegrationAccount<ResolvedTenant>, AppError>;

    /// Makes `request.change` to the account for the person `ctx` names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing account or one the caller neither owns nor may connect, hiding existence.
    /// - `AppError::Forbidden` for an owner-only change by another caller; `Domain` for an unchanged status or refused replacement credential.
    /// - `AppError::Upstream` when credential verification cannot reach the service; the existing credential remains.
    /// - `AppError::Internal` on sealing, persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeRequest,
    ) -> Result<IntegrationAccount<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        let mut account = owned_account(
            self.ports.accounts.as_ref(),
            &ctx.tenant(),
            &request.account_id,
            &control,
        )
        .await?;
        let sealing = CredentialSealing {
            encryptor: self.ports.encryptor.as_ref(),
            verifier: self.ports.verifier.as_ref(),
            place: integration_credential_place(&ctx.tenant(), account.id()),
        };
        apply_change(&sealing, &control, &mut account, request.change).await?;
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

/// What a new credential is checked and sealed with, and the place it is
/// sealed for.
struct CredentialSealing<'a> {
    encryptor: &'a dyn SecretEncryptor,
    verifier: &'a dyn AccountVerifier,
    place: SealedFor,
}

/// Makes `change` to `account` as the person `control` names, a new
/// credential sealed through `sealing`.
async fn apply_change(
    sealing: &CredentialSealing<'_>,
    control: &WorkflowControl<'_>,
    account: &mut IntegrationAccount<ResolvedTenant>,
    change: AccountChange,
) -> Result<(), AppError> {
    let made = match change {
        AccountChange::Enable => account.enable(control),
        AccountChange::Disable => account.disable(control),
        AccountChange::ReplaceCredential(credential) => {
            return replace(sealing, control, account, &credential).await;
        }
        AccountChange::ShareWithTenant => account.share_with_tenant(control),
        AccountChange::KeepToOwner => account.keep_to_owner(control),
        AccountChange::LimitTo(scope) => account.limit_to(control, scope),
        AccountChange::Rename(name) => account.rename(control, name),
    };
    made.map_err(AppError::from_domain)
}

/// `account` given `credential`, sealed through `sealing`, once the domain
/// let the person `control` names replace it and the integration's service
/// took it. The owner is checked before the service is asked, so nobody
/// else tries tokens through an account; a refused credential leaves the
/// account unsaved. A service whose grants rotate replaces the credential
/// as it is asked, and the account keeps the replacement.
async fn replace(
    sealing: &CredentialSealing<'_>,
    control: &WorkflowControl<'_>,
    account: &mut IntegrationAccount<ResolvedTenant>,
    credential: &Secret,
) -> Result<(), AppError> {
    let sealed_credential = sealed(sealing.encryptor, credential, &sealing.place).await?;
    account
        .replace_credential(control, sealed_credential)
        .map_err(AppError::from_domain)?;
    let kept = ensure_credential_works(sealing.verifier, account.integration(), credential).await?;
    if kept.expose() != credential.expose() {
        account.renew_credential(sealed(sealing.encryptor, &kept, &sealing.place).await?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::account::{
        AccountSharing, AccountStatus, ScopedOperations,
    };
    use ianua_domain::domains::workflows::integration::OperationKey;
    use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
    use ianua_domain::types::UntrustedText;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::workflows::{
        APPEND_ROW, FakeAccountVerifier, FakeIntegrationAccountStore, account_credential_place,
        person, sheets_account,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// An account kept in the store, and what changing it recorded.
    struct Kept {
        account: IntegrationAccount<ResolvedTenant>,
        accounts: Arc<FakeIntegrationAccountStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Kept {
        fn owned_by(owner: &ianua_domain::types::Human, sharing: AccountSharing) -> Self {
            let account = sheets_account(owner, sharing);
            Self {
                accounts: Arc::new(FakeIntegrationAccountStore::holding(&account)),
                account,
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn change(
            &self,
            authorities: FakeTenantAuthorities,
            change: AccountChange,
        ) -> Result<IntegrationAccount<ResolvedTenant>, AppError> {
            let accepting = Arc::new(FakeAccountVerifier::answering(AccountCheck::Accepted));
            self.change_checked_by(accepting, authorities, change)
        }

        fn change_checked_by(
            &self,
            verifier: Arc<FakeAccountVerifier>,
            authorities: FakeTenantAuthorities,
            change: AccountChange,
        ) -> Result<IntegrationAccount<ResolvedTenant>, AppError> {
            let use_case = ChangeUseCase::new(ChangePorts {
                accounts: self.accounts.clone(),
                encryptor: Arc::new(FakeEncryptor),
                verifier,
                tenant_authorities: Arc::new(authorities),
            });
            let request = ChangeRequest {
                account_id: *self.account.id(),
                change,
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), request))
        }

        fn stored(&self) -> IntegrationAccount<ResolvedTenant> {
            self.accounts.stored(self.account.id()).unwrap()
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    fn connector() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(
            WorkflowAction::ConnectAccounts,
        )])
    }

    fn only_append() -> OperationScope {
        OperationScope::Only(
            ScopedOperations::new(vec![OperationKey::new(APPEND_ROW).unwrap()]).unwrap(),
        )
    }

    /// Ann shares her own account with the tenant. It is kept shared, and
    /// the change is recorded.
    #[test]
    fn the_owner_shares_their_account_and_it_is_recorded() {
        let kept = Kept::owned_by(&caller_person(), AccountSharing::OwnerOnly);

        kept.change(connector(), AccountChange::ShareWithTenant)
            .unwrap();

        assert_eq!(kept.stored().sharing(), AccountSharing::Tenant);
        assert_eq!(kept.records(), ["workflows.account_changed"]);
    }

    /// Ann rotates her token. The new one is kept sealed.
    #[test]
    fn a_replaced_credential_is_kept_sealed() {
        let kept = Kept::owned_by(&caller_person(), AccountSharing::OwnerOnly);

        kept.change(
            connector(),
            AccountChange::ReplaceCredential(Secret::new("rotated-token")),
        )
        .unwrap();

        let stored = kept.stored();
        assert_eq!(
            stored.credential(),
            &FakeEncryptor::sealed_for("rotated-token", &account_credential_place(stored.id()))
        );
    }

    /// A replacement token refused by the service leaves the saved credential
    /// unchanged and records no audit event.
    #[test]
    fn a_replacement_the_service_refuses_leaves_the_old_credential() {
        let kept = Kept::owned_by(&caller_person(), AccountSharing::OwnerOnly);
        let before = kept.stored().credential().clone();
        let refusing = Arc::new(FakeAccountVerifier::answering(AccountCheck::Refused(
            UntrustedText::record("bad credentials"),
        )));

        let result = kept.change_checked_by(
            refusing,
            connector(),
            AccountChange::ReplaceCredential(Secret::new("mistyped-token")),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(kept.stored().credential(), &before);
        assert!(kept.records().is_empty());
    }

    /// Replacing another person's credential is forbidden even with account
    /// connection rights; the verifier receives no request.
    #[test]
    fn someone_not_the_owner_never_reaches_the_service() {
        let kept = Kept::owned_by(&person("bob@corp.test"), AccountSharing::OwnerOnly);
        let verifier = Arc::new(FakeAccountVerifier::answering(AccountCheck::Accepted));

        let result = kept.change_checked_by(
            verifier.clone(),
            connector(),
            AccountChange::ReplaceCredential(Secret::new("sams-token")),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(verifier.asked().is_empty());
    }

    /// Ann disables her account and enables it again. Each is kept and
    /// recorded under its own name.
    #[test]
    fn disabling_and_enabling_are_recorded_as_such() {
        let kept = Kept::owned_by(&caller_person(), AccountSharing::OwnerOnly);

        kept.change(connector(), AccountChange::Disable).unwrap();
        kept.change(connector(), AccountChange::Enable).unwrap();

        assert_eq!(kept.stored().status(), AccountStatus::Active);
        assert_eq!(
            kept.records(),
            ["workflows.account_disabled", "workflows.account_enabled"]
        );
    }

    /// Account connection rights do not permit sharing another person's account,
    /// setting its scope or replacing its credential. Each change is forbidden;
    /// sharing remains owner-only and no audit event is recorded.
    #[test]
    fn only_the_owner_widens_an_account() {
        let kept = Kept::owned_by(&person("bob@corp.test"), AccountSharing::OwnerOnly);

        let shared = kept.change(connector(), AccountChange::ShareWithTenant);
        let limited = kept.change(connector(), AccountChange::LimitTo(OperationScope::All));
        let replaced = kept.change(
            connector(),
            AccountChange::ReplaceCredential(Secret::new("sams-token")),
        );

        for result in [shared, limited, replaced] {
            assert!(matches!(result, Err(AppError::Forbidden(_))));
        }
        assert_eq!(kept.stored().sharing(), AccountSharing::OwnerOnly);
        assert!(kept.records().is_empty());
    }

    /// Bob's shared credential leaked. Cid, who may connect accounts but
    /// does not own it, disables it and keeps it to Bob, without waiting
    /// for him.
    #[test]
    fn someone_who_may_connect_accounts_narrows_anyones_account() {
        let kept = Kept::owned_by(&person("bob@corp.test"), AccountSharing::Tenant);

        kept.change(connector(), AccountChange::Disable).unwrap();
        kept.change(connector(), AccountChange::KeepToOwner)
            .unwrap();

        let stored = kept.stored();
        assert_eq!(stored.status(), AccountStatus::Disabled);
        assert_eq!(stored.sharing(), AccountSharing::OwnerOnly);
    }

    /// Ann limits her account to appending rows. It is kept limited.
    #[test]
    fn the_owner_limits_the_operations() {
        let kept = Kept::owned_by(&caller_person(), AccountSharing::OwnerOnly);

        kept.change(connector(), AccountChange::LimitTo(only_append()))
            .unwrap();

        assert_eq!(kept.stored().scope(), &only_append());
    }

    /// A workflow viewer cannot disable another person's account. It appears
    /// missing to the caller and remains active.
    #[test]
    fn a_caller_who_neither_owns_nor_may_connect_accounts_is_answered_as_for_a_missing_one() {
        let kept = Kept::owned_by(&person("bob@corp.test"), AccountSharing::Tenant);
        let sam =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let result = kept.change(sam, AccountChange::Disable);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(kept.stored().status(), AccountStatus::Active);
    }

    /// A signed-out session cannot disable its owner's integration account.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let kept = Kept::owned_by(&caller_person(), AccountSharing::OwnerOnly);

        let result = kept.change(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            AccountChange::Disable,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Ann changes an account the tenant does not have. It is not found.
    #[test]
    fn an_unknown_account_is_not_found() {
        let kept = Kept::owned_by(&caller_person(), AccountSharing::OwnerOnly);
        let use_case = ChangeUseCase::new(ChangePorts {
            accounts: kept.accounts.clone(),
            ..ChangePorts::fakes()
        });
        let request = ChangeRequest {
            account_id: IntegrationAccountId::new(),
            change: AccountChange::Disable,
        };

        let result =
            block_on(use_case.execute(&test_ctx(), &test_auditor(kept.sink.clone()), request));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
