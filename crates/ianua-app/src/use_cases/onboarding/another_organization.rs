//! A signed-in member founding another organization under their own
//! address.
//!
//! An address is unique within an organization, not across the platform,
//! so one person may own several. The new organization is founded as a
//! public sign-up founds one, on the same plan, with its first tenant and
//! the member as its first owner: a new account of theirs, in the new
//! organization alone, with a password of its own. Their sign-in vouches
//! for the address, which was proven when it was verified, so the new
//! account starts verified and no link is mailed.

use std::sync::Arc;

use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Locale, Timezone};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::onboarding::SelfServiceFounding;
use crate::use_cases::onboarding::founding::{
    Charter, Founded, FounderAddress, FoundingRequest, SELF_SERVICE_PLAN,
};

/// The organization to found. It holds the new account's password, so it
/// has no `Debug`.
pub struct AnotherOrganizationRequest {
    /// Company name (used to derive org slug and display name).
    pub company_name: String,
    /// Tenant name (used to derive tenant slug and display name).
    pub tenant_name: String,
    /// The password of the member's account in the new organization.
    pub password: Secret,
    /// Timezone for the tenant (defaults to UTC).
    pub timezone: Option<Timezone>,
    /// Locale for the tenant (defaults to en-US).
    pub locale: Option<Locale>,
}

/// The ports [`FoundAnotherOrganizationUseCase`] needs beside its founder.
#[derive(ianua_macros::Fakes)]
pub struct AnotherOrganizationPorts {
    /// Who acts on an organization, to know the member founding.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Founds another organization for a signed-in member.
pub struct FoundAnotherOrganizationUseCase {
    founding: SelfServiceFounding,
    ports: AnotherOrganizationPorts,
}

impl FoundAnotherOrganizationUseCase {
    /// A use case founding through `founding` and working through `ports`.
    #[must_use]
    pub fn new(founding: SelfServiceFounding, ports: AnotherOrganizationPorts) -> Self {
        Self { founding, ports }
    }

    /// What founding takes for the member `caller` signs in as: their
    /// address, vouched for by their own sign-in, and their name.
    async fn founding(
        &self,
        caller: &OrgCaller,
        request: AnotherOrganizationRequest,
    ) -> Result<FoundingRequest, AppError> {
        let (_, actor) = self.ports.org_actors.actor(caller).await?;
        let holder = actor.signed_in()?;
        let member = actor.member();
        let address = member
            .vouched_address(&holder)
            .map_err(AppError::from_domain)?;
        Ok(FoundingRequest {
            company_name: request.company_name,
            tenant_name: request.tenant_name,
            admin_address: FounderAddress::Proven(address),
            admin_display_name: member.display_name().clone(),
            admin_password: self
                .founding
                .founder
                .checked_password(request.password.expose())
                .await?,
            timezone: request.timezone,
            locale: request.locale,
            charter: Charter::Hosted(SELF_SERVICE_PLAN),
        })
    }
}

impl Command for FoundAnotherOrganizationUseCase {
    type Caller = OrgCaller;
    type Input = AnotherOrganizationRequest;
    type Output = Result<Founded, AppError>;

    /// Founds another organization on the sign-up plan with the caller's verified
    /// address as owner, leaving their existing account and organization unchanged.
    /// Records `organization.created`, `tenant.provisioned`, `organization.tenant_created`,
    /// `organization.subscription_started`, `organization.org_user_created` and `organization.org_user_email_verified`.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` for closed enrollment or an unverified address.
    /// - `AppError::Unauthenticated` for a key caller or invalid session.
    /// - `AppError::Conflict` if the company name is taken.
    /// - `AppError::Domain` for invalid names/passwords or a breached/uncheckable password.
    /// - `AppError::Internal` on persistence, hashing or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: AnotherOrganizationRequest,
    ) -> Result<Founded, AppError> {
        self.founding.enrollment.ensure_open()?;
        let founding = self.founding(caller, request).await?;
        self.founding.founder.found(auditor, &founding).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::breach::BreachStatus;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::tenant::compliance_limits::ComplianceLimits;
    use ianua_domain::test_support::fakes::FakeHasher;

    use super::*;
    use crate::ports::authentication::CredentialBreachChecker;
    use crate::ports::organization::OrgUserStore;
    use crate::test_support::acting::FakeOrgActors;
    use crate::test_support::authentication::{FakeBreachChecker, hashing_with};
    use crate::test_support::organization::{FakeOrgUserStore, FakeOrganizationStore};
    use crate::test_support::tenant::cfg;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};
    use crate::use_cases::onboarding::Enrollment;
    use crate::use_cases::onboarding::founding::{Founder, FoundingPorts};

    struct Setup {
        uc: FoundAnotherOrganizationUseCase,
        members: Arc<FakeOrgUserStore>,
        orgs: Arc<FakeOrganizationStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn setup(enrollment: Enrollment, actors: FakeOrgActors) -> Setup {
        setup_checking(enrollment, actors, Arc::new(FakeBreachChecker::default()))
    }

    /// A founding as [`setup`] makes it, looking the new owner's password
    /// up in `breaches`.
    fn setup_checking(
        enrollment: Enrollment,
        actors: FakeOrgActors,
        breaches: Arc<dyn CredentialBreachChecker>,
    ) -> Setup {
        let members = Arc::new(FakeOrgUserStore::empty());
        let orgs = Arc::new(FakeOrganizationStore::empty());
        let founder = Founder::new(
            hashing_with(Arc::new(FakeHasher)),
            cfg(),
            ComplianceLimits::default(),
            FoundingPorts {
                org_store: orgs.clone(),
                org_user_store: members.clone(),
                breach_checker: breaches,
                ..FoundingPorts::fakes()
            },
        );
        let ports = AnotherOrganizationPorts {
            org_actors: Arc::new(actors),
        };
        Setup {
            uc: FoundAnotherOrganizationUseCase::new(
                SelfServiceFounding {
                    founder,
                    enrollment,
                },
                ports,
            ),
            members,
            orgs,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn globex() -> AnotherOrganizationRequest {
        AnotherOrganizationRequest {
            company_name: "Globex".to_owned(),
            tenant_name: "Production".to_owned(),
            password: Secret::new("SecureP@ssw0rd!"),
            timezone: None,
            locale: None,
        }
    }

    impl Setup {
        fn found(&self) -> Result<Founded, AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                globex(),
            ))
        }
    }

    /// Alice, a member of Acme, founds Globex while signed in. She owns it
    /// under the same address, verified at once, on the plan a sign-up
    /// gets, and the founding is recorded.
    #[test]
    fn a_member_founds_another_organization_under_her_address() {
        let setup = setup(Enrollment::Open, FakeOrgActors::in_role(OrgRole::Member));

        let founded = setup.found().unwrap();

        let owner = block_on(setup.members.find_by_id(&founded.admin_user_id))
            .unwrap()
            .unwrap();
        assert_eq!(owner.role(), OrgRole::Owner);
        assert!(owner.email_verified());
        assert_eq!(founded.org_slug, "globex");
        assert_eq!(setup.orgs.count(), 1);
        assert!(
            setup
                .audit
                .records
                .lock()
                .unwrap()
                .contains(&"organization.created".to_owned())
        );
    }

    /// An organization key cannot replace a member's sign-in when founding
    /// another organization, and no organization is stored.
    #[test]
    fn a_key_founds_nothing() {
        let actors = FakeOrgActors::through_key(OrgRole::Owner, Vec::new());
        let setup = setup(Enrollment::Open, actors);

        let result = setup.found();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(setup.orgs.count(), 0);
    }

    /// Closed enrollment refuses a signed-in member's attempt to found
    /// another organization, leaving the organization store empty.
    #[test]
    fn a_closed_installation_founds_nothing() {
        let setup = setup(Enrollment::Closed, FakeOrgActors::in_role(OrgRole::Owner));

        let result = setup.found();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.orgs.count(), 0);
    }

    /// A breached password for the new owner is refused, and neither an
    /// organization nor a member is stored.
    #[test]
    fn a_breached_password_founds_nothing() {
        let breaches = Arc::new(FakeBreachChecker {
            status: BreachStatus::Breached(3),
        });
        let setup = setup_checking(
            Enrollment::Open,
            FakeOrgActors::in_role(OrgRole::Member),
            breaches,
        );

        let result = setup.found();

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(setup.orgs.count(), 0);
        assert_eq!(setup.members.count(), 0);
    }
}
