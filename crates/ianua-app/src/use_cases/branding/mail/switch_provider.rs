//! Switch mail provider: send a tenant's own mail through an SMTP server
//! or a mail service of its own, or through the platform's mail again.
//!
//! The tenant's mail carries its password reset and sign-in links, so
//! moving it needs the branding right and the person proving who they are
//! again just now. A provider just named is unverified: mail keeps going
//! through the platform until a test send through it works.

use std::sync::Arc;

use ianua_domain::domains::branding::control::BrandingControl;
use ianua_domain::shared::events::raised::Raises as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::branding::TenantMailProviderStore;
use crate::ports::organization::{OrgUserStore, OrganizationStore};
use crate::services::authentication::fresh_proof::admin::{AdminProofSources, proved_admin};
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof};
use crate::use_case::Command;
use crate::use_cases::branding::lookup::current_mail_provider;
use crate::use_cases::branding::mail::provider::{NamedMailProvider, sealed_provider};

/// The provider to send through, with what the caller gave to prove who
/// they are.
pub struct SwitchMailProviderRequest {
    /// The provider, with its credentials as typed.
    pub provider: NamedMailProvider,
    /// What the caller typed again just now to prove who they are.
    pub proof: ReenteredProof,
}

/// The ports [`SwitchMailProviderUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SwitchMailProviderPorts {
    /// Where each tenant's mail provider is kept.
    pub provider_store: Arc<dyn TenantMailProviderStore>,
    /// Seals the provider's credentials before they are kept.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// What a caller holds in their tenant, and who is signed in.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Turns what the caller typed again into a fresh proof of them.
    pub fresh_proofs: Arc<dyn FreshProofs>,
    /// Organization members, for a member switching the provider.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Organizations, for a member switching the provider.
    pub organizations: Arc<dyn OrganizationStore>,
}

/// Names the provider the caller's tenant's mail goes out through.
pub struct SwitchMailProviderUseCase {
    ports: SwitchMailProviderPorts,
}

impl SwitchMailProviderUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: SwitchMailProviderPorts) -> Self {
        Self { ports }
    }
}

impl Command for SwitchMailProviderUseCase {
    type Caller = CallerContext;
    type Input = SwitchMailProviderRequest;
    type Output = Result<(), AppError>;

    /// Names the provider `request` gives for the tenant `ctx` acts in,
    /// unverified until a test send through it works, and records
    /// `branding.mail_provider_changed`, naming only the kinds.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change branding,
    ///   came with a key rather than a signed-in session, or what they typed
    ///   again does not prove who they are.
    /// - `AppError::StepUpRequired` when the caller has a second factor and
    ///   gave no code from it.
    /// - `AppError::AccountLocked` after too many wrong codes.
    /// - `AppError::Internal` on sealing, persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: SwitchMailProviderRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let sources = AdminProofSources {
            authorities: self.ports.tenant_authorities.as_ref(),
            proofs: self.ports.fresh_proofs.as_ref(),
            members: self.ports.org_users.as_ref(),
            organizations: self.ports.organizations.as_ref(),
        };
        let admin = proved_admin(sources, ctx, request.proof).await?;
        let tenant = ctx.tenant();
        let store = self.ports.provider_store.as_ref();
        let mut current = current_mail_provider(store, &tenant).await?;
        let provider =
            sealed_provider(self.ports.encryptor.as_ref(), &tenant, request.provider).await?;
        current
            .switch_to(provider, &BrandingControl::new(&authority), admin.fresh())
            .map_err(AppError::from_domain)?;
        store.save(&tenant, &current).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), current.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{BrandingAction, SystemPermission};
    use ianua_domain::domains::branding::mail_provider::{
        MailProvider, MailProviderKind, ProviderCheck,
    };
    use ianua_domain::shared::security::secret::Secret;

    use super::*;
    use crate::ports::branding::mail_credential_place;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{FakeEncryptor, right_password, wrong_password};
    use crate::test_support::branding::FakeTenantMailProviderStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Setup {
        uc: SwitchMailProviderUseCase,
        providers: Arc<FakeTenantMailProviderStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn over(authorities: FakeTenantAuthorities) -> Self {
            let providers = Arc::new(FakeTenantMailProviderStore::empty());
            Self {
                uc: SwitchMailProviderUseCase::new(SwitchMailProviderPorts {
                    provider_store: providers.clone(),
                    tenant_authorities: Arc::new(authorities),
                    ..SwitchMailProviderPorts::fakes()
                }),
                providers,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn switch(&self, proof: ReenteredProof) -> Result<(), AppError> {
            let request = SwitchMailProviderRequest {
                provider: NamedMailProvider::SendGrid {
                    api_key: Secret::new("SG.acme-key"),
                },
                proof,
            };
            block_on(
                self.uc
                    .execute(&test_ctx(), &test_auditor(self.audit.clone()), request),
            )
        }

        fn kind(&self) -> MailProviderKind {
            self.providers
                .stored(test_ctx().tenant_id())
                .map_or(MailProviderKind::Platform, |provider| {
                    provider.provider().kind()
                })
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann, who proved herself just now, sends Acme's mail through its
    /// SendGrid account. The key is kept sealed, the provider waits for a
    /// test send, and the switch is recorded.
    #[test]
    fn a_proved_admin_names_a_provider_with_its_key_sealed() {
        let setup = Setup::over(FakeTenantAuthorities::holding_everything());

        setup.switch(right_password()).unwrap();

        let stored = setup.providers.stored(test_ctx().tenant_id()).unwrap();
        assert_eq!(
            *stored.provider(),
            MailProvider::SendGrid {
                api_key: FakeEncryptor::sealed_for(
                    "SG.acme-key",
                    &mail_credential_place(Some(test_ctx().tenant_id()))
                )
            }
        );
        assert_eq!(stored.check(), ProviderCheck::Unverified);
        assert_eq!(*stored.delivers_through(), MailProvider::Platform);
        assert_eq!(setup.recorded(), vec!["branding.mail_provider_changed"]);
    }

    /// A wrong password cannot authorize switching mail providers; the
    /// platform provider remains selected and no change is recorded.
    #[test]
    fn a_wrong_password_is_refused() {
        let setup = Setup::over(FakeTenantAuthorities::holding_everything());

        let result = setup.switch(wrong_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.kind(), MailProviderKind::Platform);
        assert!(setup.recorded().is_empty());
    }

    /// The branding view right does not permit switching providers, and
    /// the platform provider remains selected.
    #[test]
    fn a_caller_who_may_only_view_branding_is_refused() {
        let setup = Setup::over(FakeTenantAuthorities::holding(&[
            SystemPermission::Branding(BrandingAction::View),
        ]));

        let result = setup.switch(right_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.kind(), MailProviderKind::Platform);
    }

    /// A signed-out session cannot switch mail providers, and no provider
    /// configuration is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::over(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = setup.switch(right_password());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(setup.providers.stored(test_ctx().tenant_id()).is_none());
    }
}
