//! Replace a tenant's authentication configuration.
//!
//! Everything about how a tenant's users sign in: which methods are allowed,
//! how strong a password has to be, whether MFA is demanded, how long sessions
//! last, when an account locks, and when a sign-in must clear more than a
//! password.
//!
//! Replaced whole rather than patched. A half-applied auth config is a tenant
//! in a state nobody chose, and its rules (an idle timeout inside its
//! session, at least one way in) only hold across the whole thing.

use std::sync::Arc;

use ianua_domain::domains::tenant::access::auth_config::TenantAuthConfig;
use ianua_domain::domains::tenant::access::sign_in_gate::SignInChange;
use ianua_domain::domains::tenant::control::{TenantArea, TenantControl};
use ianua_domain::shared::events::raised::RaisesComplete as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::TextMessaging;
use crate::ports::organization::{OrgUserStore, OrganizationStore};
use crate::ports::shared::MailSetup;
use crate::ports::tenant::TenantStore;
use crate::services::authentication::channels::Channels;
use crate::services::authentication::fresh_proof::admin::{AdminProofSources, proved_admin};
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof};
use crate::services::lookup::existing_tenant;
use crate::use_case::Command;

/// New sign-in settings, with what the caller gave to prove who they are.
pub struct UpdateAuthConfigRequest {
    /// The settings to put in force.
    pub config: TenantAuthConfig,
    /// What the caller typed again just now to prove who they are. A
    /// stolen session alone must not weaken how the tenant is protected.
    pub proof: ReenteredProof,
}

/// The ports [`UpdateAuthConfigUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdateAuthConfigPorts {
    /// Loads and saves the workspace's sign-in policy.
    pub tenant_store: Arc<dyn TenantStore>,
    /// What a caller holds in their tenant, and who is signed in.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Turns what the caller typed again into a fresh proof of them.
    pub fresh_proofs: Arc<dyn FreshProofs>,
    /// Organization members, for a member changing the settings.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Organizations, for a member changing the settings.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Whether codes can be texted here, before texted codes are offered.
    pub text_messaging: Arc<dyn TextMessaging>,
    /// Whether anything can be mailed here, before mailed codes or magic
    /// links are offered.
    pub mail: Arc<dyn MailSetup>,
}

/// Replaces the caller's tenant's sign-in settings.
pub struct UpdateAuthConfigUseCase {
    ports: UpdateAuthConfigPorts,
}

impl UpdateAuthConfigUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: UpdateAuthConfigPorts) -> Self {
        Self { ports }
    }

    /// Refuses `after` when it newly offers a factor or a way in this
    /// deployment cannot deliver: texted codes with nothing to text them,
    /// mailed codes or magic links with no mail server.
    fn ensure_deliverable(
        &self,
        before: &TenantAuthConfig,
        after: &TenantAuthConfig,
    ) -> Result<(), AppError> {
        let channels = Channels::of(&self.ports.text_messaging, &self.ports.mail);
        channels.ensure_newly_deliverable(before.into(), after.into())
    }
}

impl Command for UpdateAuthConfigUseCase {
    type Caller = CallerContext;
    type Input = UpdateAuthConfigRequest;
    type Output = Result<(), AppError>;

    /// Puts `req.config` in force for the tenant `ctx` acts in and records
    /// `tenant.auth_config_updated`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without sign-in-settings rights, through a key or for inadequate fresh proof.
    /// - `AppError::StepUpRequired` for a missing factor code; `AccountLocked` after too many wrong codes.
    /// - `AppError::Domain` for settings excluding the caller's sign-in, newly offered undeliverable text/mail factors or magic links, or a closed tenant.
    /// - `AppError::NotFound` for a missing tenant; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: UpdateAuthConfigRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        TenantControl::new(&authority)
            .ensure_may(&ctx.tenant_id(), TenantArea::SignIn)
            .map_err(AppError::from_domain)?;
        let sources = AdminProofSources {
            authorities: self.ports.tenant_authorities.as_ref(),
            proofs: self.ports.fresh_proofs.as_ref(),
            members: self.ports.org_users.as_ref(),
            organizations: self.ports.organizations.as_ref(),
        };
        let admin = proved_admin(sources, ctx, req.proof).await?;
        let tenant_id = ctx.tenant();
        let mut tenant = existing_tenant(self.ports.tenant_store.as_ref(), &tenant_id).await?;
        self.ensure_deliverable(tenant.auth_config(), &req.config)?;
        let change = SignInChange {
            config: req.config,
            saved_from: admin.saved_from(),
        };
        tenant
            .update_auth_config(TenantControl::new(&authority), admin.fresh(), change)
            .map_err(AppError::from_domain)?;
        self.ports.tenant_store.save(&tenant).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), tenant.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::mfa::enrollment::MfaMethod;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::types::OrgUserId;

    use super::*;
    use crate::context::{CallerIdentity, Credential};
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{FakeTextMessaging, right_password, wrong_password};
    use crate::test_support::operator::operator_without_grant;
    use crate::test_support::organization::{
        org_store_with, org_user_store_with, test_org, test_org_user,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{
        Fake, FakeEventDispatcher, FakeMailSetup, block_on, test_auditor, test_ctx, test_session_id,
    };

    struct Setup {
        uc: UpdateAuthConfigUseCase,
        tenants: Arc<FakeTenantStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(authorities: FakeTenantAuthorities) -> Self {
            let tenants = Arc::new(FakeTenantStore::holding(test_tenant_for_ctx()));
            Self {
                uc: UpdateAuthConfigUseCase::new(UpdateAuthConfigPorts {
                    tenant_store: tenants.clone(),
                    tenant_authorities: Arc::new(authorities),
                    ..UpdateAuthConfigPorts::fakes()
                }),
                tenants,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn new() -> Self {
            Self::with(FakeTenantAuthorities::holding_everything())
        }

        /// The tenant, its organization, and an owner of it calling with
        /// her organization session.
        fn with_member() -> (Self, CallerContext) {
            let tenants = Arc::new(FakeTenantStore::holding(test_tenant_for_ctx()));
            let organization_id = test_ctx().organization_id();
            let olivia = test_org_user(organization_id, "olivia@acme.test", OrgRole::Owner);
            let caller = member_caller(*olivia.id());
            let setup = Self {
                uc: UpdateAuthConfigUseCase::new(UpdateAuthConfigPorts {
                    tenant_store: tenants.clone(),
                    org_users: Arc::new(org_user_store_with([olivia])),
                    organizations: org_store_with([test_org(organization_id, "acme")]),
                    ..UpdateAuthConfigPorts::fakes()
                }),
                tenants,
                audit: Arc::new(FakeEventDispatcher::new()),
            };
            (setup, caller)
        }

        fn update_as(
            &self,
            ctx: &CallerContext,
            req: UpdateAuthConfigRequest,
        ) -> Result<(), AppError> {
            block_on(self.uc.execute(ctx, &test_auditor(self.audit.clone()), req))
        }

        fn update(&self, req: UpdateAuthConfigRequest) -> Result<(), AppError> {
            self.update_as(&test_ctx(), req)
        }

        fn stored(&self) -> TenantAuthConfig {
            block_on(self.tenants.find_by_id(&test_ctx().tenant_id()))
                .unwrap()
                .unwrap()
                .auth_config()
                .clone()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn member_caller(member: OrgUserId) -> CallerContext {
        CallerContext::new(
            CallerIdentity::OrgUser(member),
            Credential::OrgSession(test_session_id()),
            test_ctx().organization_id(),
            test_ctx().tenant_id(),
            test_ctx().plan_limits().clone(),
        )
        .unwrap()
    }

    fn config_allowing(methods: Vec<AuthMethod>) -> TenantAuthConfig {
        TenantAuthConfig::new(TenantAuthSettings {
            enabled_methods: methods,
            ..TenantAuthSettings::default()
        })
        .unwrap()
    }

    fn password_and_passkey() -> UpdateAuthConfigRequest {
        UpdateAuthConfigRequest {
            config: config_allowing(vec![AuthMethod::Password, AuthMethod::Passkey]),
            proof: right_password(),
        }
    }

    /// Ann, who typed her password again just now, allows passwords and
    /// passkeys. The settings are saved and the change recorded.
    #[test]
    fn a_saved_config_is_the_one_that_comes_back() {
        let setup = Setup::new();
        let request = password_and_passkey();
        let expected = request.config.clone();

        setup.update(request).unwrap();

        assert_eq!(setup.stored(), expected);
        assert_eq!(setup.recorded(), vec!["tenant.auth_config_updated"]);
    }

    /// A caller signed in with a password cannot allow only passkeys.
    /// The sign-in settings stay unchanged and no event is recorded.
    #[test]
    fn settings_that_shut_out_the_caller_are_refused_and_not_audited() {
        let setup = Setup::new();
        let before = setup.stored();
        let request = UpdateAuthConfigRequest {
            config: config_allowing(vec![AuthMethod::Passkey]),
            proof: right_password(),
        };

        let result = setup.update(request);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.recorded().is_empty());
        assert_eq!(setup.stored(), before);
    }

    /// A deployment without text messaging cannot newly offer texted codes.
    /// The sign-in settings stay unchanged and no event is recorded.
    #[test]
    fn newly_offering_texted_codes_where_nothing_texts_is_refused() {
        let tenants = Arc::new(FakeTenantStore::holding(test_tenant_for_ctx()));
        let setup = Setup {
            uc: UpdateAuthConfigUseCase::new(UpdateAuthConfigPorts {
                tenant_store: tenants.clone(),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
                text_messaging: FakeTextMessaging::not_set_up(),
                ..UpdateAuthConfigPorts::fakes()
            }),
            tenants,
            audit: Arc::new(FakeEventDispatcher::new()),
        };
        let before = setup.stored();
        let request = UpdateAuthConfigRequest {
            config: TenantAuthConfig::new(TenantAuthSettings {
                second_factors: vec![MfaMethod::Totp, MfaMethod::SmsCode],
                ..TenantAuthSettings::default()
            })
            .unwrap(),
            proof: right_password(),
        };

        let result = setup.update(request);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.recorded().is_empty());
        assert_eq!(setup.stored(), before);
    }

    /// The settings Acme's admin asks for, on a deployment whose mail is
    /// set up as `mail` says.
    fn update_with_mail(
        mail: Arc<dyn MailSetup>,
        settings: TenantAuthSettings,
    ) -> (Result<(), AppError>, Vec<String>) {
        let tenants = Arc::new(FakeTenantStore::holding(test_tenant_for_ctx()));
        let setup = Setup {
            uc: UpdateAuthConfigUseCase::new(UpdateAuthConfigPorts {
                tenant_store: tenants.clone(),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
                mail,
                ..UpdateAuthConfigPorts::fakes()
            }),
            tenants,
            audit: Arc::new(FakeEventDispatcher::new()),
        };
        let request = UpdateAuthConfigRequest {
            config: TenantAuthConfig::new(settings).unwrap(),
            proof: right_password(),
        };
        let result = setup.update(request);
        (result, setup.recorded())
    }

    fn mailed_codes() -> TenantAuthSettings {
        TenantAuthSettings {
            second_factors: vec![MfaMethod::Totp, MfaMethod::EmailCode],
            ..TenantAuthSettings::default()
        }
    }

    fn magic_links() -> TenantAuthSettings {
        TenantAuthSettings {
            enabled_methods: vec![AuthMethod::Password, AuthMethod::MagicLink],
            ..TenantAuthSettings::default()
        }
    }

    /// A deployment without mail cannot newly offer mailed second-factor
    /// codes. The change is refused and no event is recorded.
    #[test]
    fn newly_offering_mailed_codes_where_nothing_is_mailed_is_refused() {
        let (result, recorded) = update_with_mail(FakeMailSetup::not_set_up(), mailed_codes());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(recorded.is_empty());
    }

    /// A deployment without mail cannot enable magic-link sign-in.
    /// The change is refused and no event is recorded.
    #[test]
    fn newly_enabling_magic_links_where_nothing_is_mailed_is_refused() {
        let (result, recorded) = update_with_mail(FakeMailSetup::not_set_up(), magic_links());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(recorded.is_empty());
    }

    /// With a mail server set up, Ann may offer mailed codes and switch
    /// magic links on.
    #[test]
    fn mailed_codes_and_magic_links_are_allowed_where_mail_goes_out() {
        let (codes, _) = update_with_mail(Fake::fake(), mailed_codes());
        let (links, _) = update_with_mail(Fake::fake(), magic_links());

        assert!(codes.is_ok());
        assert!(links.is_ok());
    }

    /// A wrong password cannot authorize new sign-in settings. The stored
    /// settings stay unchanged and no event is recorded.
    #[test]
    fn a_wrong_password_is_refused() {
        let setup = Setup::new();
        let before = setup.stored();
        let request = UpdateAuthConfigRequest {
            proof: wrong_password(),
            ..password_and_passkey()
        };

        let result = setup.update(request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.stored(), before);
        assert!(setup.recorded().is_empty());
    }

    /// Olivia, an owner of the organization signed in on its plane, types
    /// her password again and allows passwords and passkeys. Her own
    /// sign-in is the organization's, so the settings cannot shut her out,
    /// and they are saved.
    #[test]
    fn a_member_who_proves_herself_changes_the_settings() {
        let (setup, olivia) = Setup::with_member();
        let request = UpdateAuthConfigRequest {
            config: config_allowing(vec![AuthMethod::Passkey]),
            proof: right_password(),
        };
        let expected = request.config.clone();

        setup.update_as(&olivia, request).unwrap();

        assert_eq!(setup.stored(), expected);
        assert_eq!(setup.recorded(), vec!["tenant.auth_config_updated"]);
    }

    /// An organization member supplying a wrong password cannot change tenant
    /// sign-in settings. The stored settings stay and no event is recorded.
    #[test]
    fn a_member_with_a_wrong_password_is_refused() {
        let (setup, olivia) = Setup::with_member();
        let before = setup.stored();
        let request = UpdateAuthConfigRequest {
            proof: wrong_password(),
            ..password_and_passkey()
        };

        let result = setup.update_as(&olivia, request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.stored(), before);
        assert!(setup.recorded().is_empty());
    }

    /// A tenant that does not exist is not found.
    #[test]
    fn updating_a_tenant_that_does_not_exist_is_not_found() {
        let uc = UpdateAuthConfigUseCase::new(UpdateAuthConfigPorts::fakes());

        let result = block_on(uc.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            password_and_passkey(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without sign-in-settings update rights cannot allow passwords
    /// and passkeys. The change is refused and no event is recorded.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let setup = Setup::with(FakeTenantAuthorities::holding(&[]));

        let result = setup.update(password_and_passkey());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A signed-out session cannot change the tenant's sign-in settings.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = setup.update(password_and_passkey());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot change the tenant's
    /// sign-in settings.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let setup = Setup::new();

        let result = setup.update_as(&operator_without_grant(), password_and_passkey());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
