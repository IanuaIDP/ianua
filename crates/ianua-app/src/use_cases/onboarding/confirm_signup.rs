//! Confirm signup: the sign-up link comes back, and the organization, its
//! first tenant and its owner are founded, the owner's address proven by
//! the link.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::organization::signup::ConfirmedSignup;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::PendingSignupStore;
use crate::use_case::Command;
use crate::use_cases::onboarding::founding::{
    Charter, Founded, Founder, FounderAddress, FoundingRequest, SELF_SERVICE_PLAN,
};

/// The ports [`ConfirmSignupUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ConfirmSignupPorts {
    /// Hands out the sign-up the link names, once.
    pub pending_signups: Arc<dyn PendingSignupStore>,
    /// Hashes the token the link carries.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Founds the organization a sign-up asked for, once its link comes back.
pub struct ConfirmSignupUseCase {
    founder: Founder,
    ports: ConfirmSignupPorts,
}

impl ConfirmSignupUseCase {
    /// A use case founding through `founder` and working through `ports`.
    #[must_use]
    pub fn new(founder: Founder, ports: ConfirmSignupPorts) -> Self {
        Self { founder, ports }
    }

    /// The sign-up the link carrying `token` names, confirmed now.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when no sign-up waits for the link: it was
    ///   used already, or never sent.
    /// - `AppError::LinkExpired` when the link ran out.
    /// - `AppError::Internal` on lookup failure.
    async fn confirmed(&self, token: &Secret) -> Result<ConfirmedSignup, AppError> {
        let hash = self.ports.token_generator.hash_raw(token.expose());
        let pending = self
            .ports
            .pending_signups
            .take(&hash)
            .await
            .or_internal()?
            .ok_or_else(|| {
                AppError::NotFound(message!(
                    "onboarding-this-sign-up-link-is-not",
                    "this sign-up link is not valid"
                ))
            })?;
        pending.confirm(clock::now()).ok_or_else(|| {
            AppError::LinkExpired(message!(
                "onboarding-this-sign-up-link-has-run",
                "this sign-up link has run out"
            ))
        })
    }
}

impl Command for ConfirmSignupUseCase {
    type Caller = ();
    type Input = Secret;
    type Output = Result<Founded, AppError>;

    /// Founds the requested organization using a one-use mailbox proof; its owner can sign in.
    /// Records `organization.created`, `tenant.provisioned`, `organization.tenant_created`,
    /// `organization.subscription_started` and `organization.org_user_created`.
    /// The tenant starts in `Provisioning`; `tenant.provisioned` starts its setup.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when no sign-up waits for the link.
    /// - `AppError::LinkExpired` when the link ran out.
    /// - `AppError::Conflict` if the requested company name is now taken.
    /// - `AppError::Domain` if a name breaks the rules.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        token: Secret,
    ) -> Result<Founded, AppError> {
        let confirmed = self.confirmed(&token).await?;
        self.founder.found(auditor, &founding(confirmed)).await
    }
}

/// What founding a confirmed sign-up takes.
fn founding(confirmed: ConfirmedSignup) -> FoundingRequest {
    let details = confirmed.details;
    FoundingRequest {
        company_name: details.company_name.as_str().to_owned(),
        tenant_name: details.tenant_name.as_str().to_owned(),
        admin_address: FounderAddress::Proven(confirmed.email),
        admin_display_name: details.admin_display_name,
        admin_password: details.password_hash,
        timezone: Some(details.timezone),
        locale: Some(details.locale),
        charter: Charter::Hosted(SELF_SERVICE_PLAN),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::signup::{PendingSignup, SignupDetails};
    use ianua_domain::domains::tenant::compliance_limits::ComplianceLimits;
    use ianua_domain::domains::tenant::status::TenantStatus;
    use ianua_domain::test_support::fakes::FakeHasher;
    use ianua_domain::types::{
        DisplayName, Email, Label, Lifetime, Locale, OrganizationId, PasswordHash, Timezone,
    };

    use super::*;
    use crate::ports::organization::{OrgUserStore, OrganizationStore};
    use crate::ports::tenant::TenantStore;
    use crate::test_support::authentication::hashing_with;
    use crate::test_support::organization::{
        FakeOrgSubscriptionStore, FakeOrgUserStore, FakeOrganizationStore, FakePendingSignupStore,
        test_org,
    };
    use crate::test_support::tenant::{FakeTenantStore, cfg, test_tenant_in};
    use crate::test_support::{FakeEventDispatcher, ReadBeforeWrite, block_on, test_auditor};
    use crate::use_cases::onboarding::founding::FoundingPorts;

    /// The raw token Alice's link carries.
    const TOKEN: &str = "alice-link";

    /// What Alice asked for when she signed Acme up.
    fn details() -> SignupDetails {
        SignupDetails {
            company_name: Label::new("company_name", "Acme Corp").unwrap(),
            tenant_name: Label::new("tenant_name", "Production").unwrap(),
            admin_display_name: DisplayName::new("Alice", &cfg().display_name).unwrap(),
            password_hash: PasswordHash::from_stored("argon2-hash".to_owned()),
            timezone: Timezone::new("UTC").unwrap(),
            locale: Locale::new("en-US").unwrap(),
        }
    }

    /// The stores a confirmation founds into, with Alice's sign-up waiting.
    struct Setup {
        use_case: ConfirmSignupUseCase,
        pending: Arc<FakePendingSignupStore>,
        orgs: Arc<FakeOrganizationStore>,
        subscriptions: Arc<FakeOrgSubscriptionStore>,
        tenants: Arc<FakeTenantStore>,
        owners: Arc<FakeOrgUserStore>,
        events: Arc<FakeEventDispatcher>,
    }

    /// The organization and tenant stores a confirmation founds into.
    struct Stores {
        /// The organization store the founder reads and writes through.
        org_port: Arc<dyn OrganizationStore>,
        /// The organizations as they are now.
        orgs: Arc<FakeOrganizationStore>,
        /// The tenants as they are now.
        tenants: Arc<FakeTenantStore>,
    }

    impl Stores {
        /// Starts with no organization or tenant records.
        fn empty() -> Self {
            let orgs = Arc::new(FakeOrganizationStore::empty());
            Self {
                org_port: orgs.clone(),
                orgs,
                tenants: Arc::new(FakeTenantStore::empty()),
            }
        }

        /// Connects founding to these records and the subscription and owner stores.
        fn founder(
            &self,
            subscriptions: &Arc<FakeOrgSubscriptionStore>,
            owners: &Arc<FakeOrgUserStore>,
        ) -> Founder {
            Founder::new(
                hashing_with(Arc::new(FakeHasher)),
                cfg(),
                ComplianceLimits::default(),
                FoundingPorts {
                    org_store: self.org_port.clone(),
                    subscriptions: subscriptions.clone(),
                    tenant_store: self.tenants.clone(),
                    org_user_store: owners.clone(),
                    ..FoundingPorts::fakes()
                },
            )
        }
    }

    impl Setup {
        /// Alice's sign-up waiting, with nothing else founded yet.
        fn waiting() -> Self {
            Self::waiting_over(Stores::empty())
        }

        /// Alice's sign-up waiting, founding into `stores`.
        fn waiting_over(stores: Stores) -> Self {
            let ports = ConfirmSignupPorts::fakes();
            let hash = ports.token_generator.hash_raw(TOKEN);
            let signup = PendingSignup::request(
                Email::new("admin@acme.com").unwrap(),
                details(),
                hash,
                Lifetime::seconds(86_400).unwrap(),
            )
            .unwrap();
            let pending = Arc::new(FakePendingSignupStore::holding(signup));
            let subscriptions = Arc::new(FakeOrgSubscriptionStore::empty());
            let owners = Arc::new(FakeOrgUserStore::empty());
            let founder = stores.founder(&subscriptions, &owners);
            Self {
                use_case: ConfirmSignupUseCase::new(
                    founder,
                    ConfirmSignupPorts {
                        pending_signups: pending.clone(),
                        ..ports
                    },
                ),
                pending,
                orgs: stores.orgs,
                subscriptions,
                tenants: stores.tenants,
                owners,
                events: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// Follows the link carrying `token`.
        fn confirm(&self, token: &str) -> Result<Founded, AppError> {
            block_on(self.use_case.execute(
                &(),
                &test_auditor(self.events.clone()),
                Secret::new(token),
            ))
        }
    }

    /// Alice follows her link. Acme, its first tenant and Alice as its
    /// owner are founded, her address proven by the link, and the founding
    /// is recorded.
    #[test]
    fn the_link_founds_the_organization_with_a_proven_owner() {
        let setup = Setup::waiting();

        let founded = setup.confirm(TOKEN).unwrap();

        assert_eq!(founded.org_slug, "acme-corp");
        assert_eq!(founded.tenant_slug, "production");
        let owner = block_on(setup.owners.find_by_id(&founded.admin_user_id))
            .unwrap()
            .unwrap();
        assert!(owner.email_verified());
        assert_eq!(
            setup.events.records.lock().unwrap().as_slice(),
            [
                "organization.created",
                "tenant.provisioned",
                "organization.tenant_created",
                "organization.subscription_started",
                "organization.org_user_created",
                "organization.org_user_email_verified",
            ]
        );
    }

    /// The first tenant waits in provisioning for the workflow that
    /// activates it, and the organization lands on the free plan, its
    /// subscription started there.
    #[test]
    fn the_founded_organization_starts_free_and_provisioning() {
        let setup = Setup::waiting();

        let founded = setup.confirm(TOKEN).unwrap();

        let org = block_on(setup.orgs.find_by_id(&founded.organization_id))
            .unwrap()
            .unwrap();
        assert_eq!(org.plan(), SELF_SERVICE_PLAN);
        let subscription = setup
            .subscriptions
            .stored(&founded.organization_id)
            .unwrap();
        assert_eq!(subscription.plan(), SELF_SERVICE_PLAN);
        let tenant = &setup.tenants.tenants.lock().unwrap()[0];
        assert_eq!(*tenant.id(), founded.tenant_id);
        assert_eq!(tenant.status(), TenantStatus::Provisioning);
    }

    /// After a signup link founds its organization, using it again answers
    /// not found and leaves exactly one organization.
    #[test]
    fn a_link_works_once() {
        let setup = Setup::waiting();
        setup.confirm(TOKEN).unwrap();

        let again = setup.confirm(TOKEN);

        assert!(matches!(again, Err(AppError::NotFound(_))));
        assert_eq!(setup.orgs.count(), 1);
    }

    /// Globex signed up first and named its first tenant "Production".
    /// Alice names Acme's the same: slugs are unique only within an
    /// organization, so Acme's `production` is founded beside Globex's.
    #[test]
    fn a_second_company_founds_its_own_production_tenant() {
        let stores = Stores::empty();
        let globex = test_tenant_in(OrganizationId::new(), "production", "globex.test");
        block_on(stores.tenants.save(&globex)).unwrap();
        let setup = Setup::waiting_over(stores);

        let founded = setup.confirm(TOKEN).unwrap();

        assert_eq!(founded.tenant_slug, "production");
        assert_eq!(setup.tenants.count(), 2);
        assert_eq!(setup.orgs.count(), 1);
    }

    /// If the company name is claimed after the initial read, confirmation
    /// reports that name conflict, retains one organization and records no
    /// founding events.
    #[test]
    fn a_company_name_claimed_meanwhile_is_a_conflict() {
        let live = Arc::new(FakeOrganizationStore::empty());
        let bobs = test_org(OrganizationId::new(), "acme-corp");
        block_on(live.save(&bobs)).unwrap();
        let racing = ReadBeforeWrite::new(FakeOrganizationStore::empty(), live.clone());
        let setup = Setup::waiting_over(Stores {
            org_port: Arc::new(racing),
            orgs: live,
            tenants: Arc::new(FakeTenantStore::empty()),
        });

        let result = setup.confirm(TOKEN);

        let Err(AppError::Conflict(message)) = result else {
            panic!("a company name claimed meanwhile is a conflict");
        };
        assert_eq!(message, "company name already taken");
        assert_eq!(setup.orgs.count(), 1);
        assert!(setup.events.records.lock().unwrap().is_empty());
    }

    /// A guessed signup token answers not found, creates no organization
    /// and leaves the legitimate pending signup available.
    #[test]
    fn a_guessed_link_founds_nothing() {
        let setup = Setup::waiting();

        let result = setup.confirm("guess");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.orgs.count(), 0);
        assert_eq!(setup.pending.count(), 1);
    }
}
