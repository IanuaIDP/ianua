//! Install: a self-hosted installation creating its one organization.

use ianua_domain::types::{DisplayName, Email, PasswordHash};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest, SortOrder};
use crate::use_case::Command;
use crate::use_cases::onboarding::founding::{
    Charter, Founded, Founder, FounderAddress, FoundingRequest,
};

/// The organization an installation is configured to have.
///
/// No `Debug`: it carries the owner's password. No primary domain: the
/// first tenant proves a domain after it exists, then makes it primary.
pub struct InstallRequest {
    /// Organization name (used to derive its slug and display name).
    pub organization_name: String,
    /// First tenant's name (used to derive its slug and display name).
    pub tenant_name: String,
    /// The owner's email address.
    pub owner_email: Email,
    /// The owner's full name, shown in the dashboard.
    pub owner_display_name: DisplayName,
    /// The owner's first password.
    pub owner_password: String,
}

impl InstallRequest {
    /// What founding the installation's organization takes, with the
    /// owner's password already checked and hashed as `password`.
    fn founding(self, password: PasswordHash) -> FoundingRequest {
        FoundingRequest {
            company_name: self.organization_name,
            tenant_name: self.tenant_name,
            admin_address: FounderAddress::Unproven(self.owner_email),
            admin_display_name: self.owner_display_name,
            admin_password: password,
            timezone: None,
            locale: None,
            charter: Charter::Installation,
        }
    }
}

/// What installing did.
pub enum Installation {
    /// The organization was created just now.
    Created(Founded),
    /// An organization already existed, so nothing was touched.
    AlreadyInstalled,
}

/// Creates the installation's organization, once.
pub struct InstallUseCase {
    founder: Founder,
}

impl InstallUseCase {
    /// A use case founding through `founder`.
    #[must_use]
    pub fn new(founder: Founder) -> Self {
        Self { founder }
    }

    async fn is_installed(&self) -> Result<bool, AppError> {
        let first = self
            .founder
            .org_store()
            .list_all(
                None,
                &SortOrder::default(),
                &PageRequest::first(Limit::internal(1)),
            )
            .await
            .or_internal()?;
        Ok(!first.is_empty())
    }
}

impl Command for InstallUseCase {
    type Caller = ();
    type Input = InstallRequest;
    type Output = Result<Installation, AppError>;

    /// Founds the configured organization unless one already exists, and
    /// records `organization.created`, `tenant.provisioned`,
    /// `organization.tenant_created`, `organization.subscription_started`
    /// and `organization.org_user_created` when it does.
    ///
    /// The installer runs it, before anyone can sign in, so it takes no
    /// caller. Once any organization exists the configuration is not read
    /// again, so changing the owner's address or password in it afterwards
    /// changes nothing; those are changed in the product, where they are
    /// audited. The organization lands on the self-hosted plan. The owner's
    /// address starts unverified, as every new account's does, and the
    /// founding hands back a one-time setup token, good for a day, that
    /// confirms it without a mail server. The server prints it once.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the configured names or password are invalid,
    ///   or the password appears in known breaches or could not be looked
    ///   up.
    /// - `AppError::Conflict` if a second process founded it first.
    /// - `AppError::Internal` on persistence, hashing or audit failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        request: InstallRequest,
    ) -> Result<Installation, AppError> {
        if self.is_installed().await? {
            return Ok(Installation::AlreadyInstalled);
        }
        let password = self
            .founder
            .checked_password(&request.owner_password)
            .await?;
        let founding = request.founding(password);
        let founded = self.founder.found(auditor, &founding).await?;
        Ok(Installation::Created(founded))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::authentication::credentials::breach::BreachStatus;
    use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
    use ianua_domain::domains::identity::tokens::installation_setup::InstallationSetup;
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
    use ianua_domain::domains::tenant::compliance_limits::ComplianceLimits;
    use ianua_domain::domains::tenant::status::TenantStatus;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::test_support::fakes::{FakeHasher, FakeRefreshTokenGenerator};
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::ports::authentication::CredentialBreachChecker;
    use crate::ports::organization::{OrgTokenStore, OrgUserStore, OrganizationStore};
    use crate::test_support::authentication::{FakeBreachChecker, hashing_with};
    use crate::test_support::organization::{
        FakeOrgTokenStore, FakeOrgUserStore, FakeOrganizationStore, org_store_with, test_org,
    };
    use crate::test_support::tenant::{FakeTenantStore, cfg};
    use crate::test_support::{FakeEventDispatcher, ReadBeforeWrite, block_on, test_auditor};
    use crate::use_cases::onboarding::founding::{FoundingPorts, SetupToken};
    use crate::use_cases::organization::invitations::{
        ConfirmInstallerPorts, ConfirmInstallerUseCase,
    };

    struct Setup {
        uc: InstallUseCase,
        orgs: Arc<FakeOrganizationStore>,
        tenants: Arc<FakeTenantStore>,
        owners: Arc<FakeOrgUserStore>,
        setup_tokens: Arc<FakeOrgTokenStore<InstallationSetup>>,
        events: Arc<FakeEventDispatcher>,
    }

    fn setup_with(orgs: Arc<FakeOrganizationStore>) -> Setup {
        setup_over(orgs.clone(), orgs)
    }

    /// An install reading and writing organizations through `org_port`,
    /// over `orgs` as they are now.
    fn setup_over(org_port: Arc<dyn OrganizationStore>, orgs: Arc<FakeOrganizationStore>) -> Setup {
        setup_checking(org_port, orgs, Arc::new(FakeBreachChecker::default()))
    }

    /// An install as [`setup_over`] makes it, looking the owner's password
    /// up in `breaches`.
    fn setup_checking(
        org_port: Arc<dyn OrganizationStore>,
        orgs: Arc<FakeOrganizationStore>,
        breaches: Arc<dyn CredentialBreachChecker>,
    ) -> Setup {
        let tenants = Arc::new(FakeTenantStore::empty());
        let owners = Arc::new(FakeOrgUserStore::empty());
        let setup_tokens = Arc::new(FakeOrgTokenStore::empty());
        let founder = Founder::new(
            hashing_with(Arc::new(FakeHasher)),
            cfg(),
            ComplianceLimits::default(),
            FoundingPorts {
                org_store: org_port,
                tenant_store: tenants.clone(),
                org_user_store: owners.clone(),
                setup_token_store: setup_tokens.clone(),
                breach_checker: breaches,
                ..FoundingPorts::fakes()
            },
        );
        Setup {
            uc: InstallUseCase::new(founder),
            orgs,
            tenants,
            owners,
            setup_tokens,
            events: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn setup() -> Setup {
        setup_with(Arc::new(FakeOrganizationStore::empty()))
    }

    fn request() -> InstallRequest {
        InstallRequest {
            organization_name: "Acme Corp".to_owned(),
            tenant_name: "Main".to_owned(),
            owner_email: Email::new("owner@acme.com").unwrap(),
            owner_display_name: DisplayName::new("Olive Owner", &cfg().display_name).unwrap(),
            owner_password: "SecureP@ssw0rd!".to_owned(),
        }
    }

    fn install_with(s: &Setup, req: InstallRequest) -> Result<Installation, AppError> {
        block_on(s.uc.execute(&(), &test_auditor(s.events.clone()), req))
    }

    fn install(s: &Setup) -> Result<Installation, AppError> {
        install_with(s, request())
    }

    fn issued(token: SetupToken) -> Option<Secret> {
        match token {
            SetupToken::Issued(raw) => Some(raw),
            SetupToken::NotIssued => None,
        }
    }

    fn created(installation: Installation) -> Option<Founded> {
        match installation {
            Installation::Created(founded) => Some(founded),
            Installation::AlreadyInstalled => None,
        }
    }

    /// Olive starts her installation for the first time. Its organization,
    /// first tenant and Olive as owner are made.
    #[test]
    fn a_fresh_installation_founds_its_organization() {
        let s = setup();

        let founded = created(install(&s).unwrap()).unwrap();

        assert_eq!(founded.org_slug, "acme-corp");
        assert_eq!(founded.tenant_slug, "main");
        assert_eq!(s.orgs.count(), 1);
        assert_eq!(s.tenants.count(), 1);
        assert_eq!(s.owners.count(), 1);
    }

    /// Olive's install hands back a setup token for her, and keeps it, so
    /// she can confirm her address without a mail server.
    #[test]
    fn a_fresh_installation_issues_a_setup_token_for_its_owner() {
        let s = setup();

        let founded = created(install(&s).unwrap()).unwrap();

        let raw = issued(founded.setup_token).unwrap();
        assert_eq!(s.setup_tokens.count(), 1);
        let hash = FakeRefreshTokenGenerator::new().hash_raw(raw.expose());
        let stored = block_on(s.setup_tokens.find_by_hash(&hash))
            .unwrap()
            .unwrap();
        assert_eq!(stored.org_user_id(), &founded.admin_user_id);
    }

    /// The setup token Olive's install printed confirms her address, once.
    #[test]
    fn the_setup_token_confirms_the_owner_once() {
        let s = setup();
        let founded = created(install(&s).unwrap()).unwrap();
        let admin = founded.admin_user_id;
        let raw = issued(founded.setup_token).unwrap();
        let confirm = ConfirmInstallerUseCase::new(ConfirmInstallerPorts {
            org_user_store: s.owners.clone(),
            setup_token_store: s.setup_tokens.clone(),
            ..ConfirmInstallerPorts::fakes()
        });
        let auditor = test_auditor(s.events.clone());

        let first = block_on(confirm.execute(&(), &auditor, raw.expose().to_owned()));
        let again = block_on(confirm.execute(&(), &auditor, raw.expose().to_owned()));

        assert_eq!(first.unwrap(), admin);
        assert!(matches!(again, Err(AppError::NotFound(_))));
        let owner = block_on(s.owners.find_by_id(&admin)).unwrap().unwrap();
        assert!(owner.email_verified());
    }

    /// The installation's organization is on the self-hosted plan.
    #[test]
    fn the_organization_lands_on_the_self_hosted_plan() {
        let s = setup();

        let founded = created(install(&s).unwrap()).unwrap();

        let organization = block_on(s.orgs.find_by_id(&founded.organization_id))
            .unwrap()
            .unwrap();
        assert_eq!(organization.plan(), OrganizationPlan::SelfHosted);
    }

    /// The first tenant waits in provisioning, and its making is recorded.
    #[test]
    fn the_first_tenant_starts_provisioning() {
        let s = setup();

        install(&s).unwrap();

        assert_eq!(
            s.tenants.tenants.lock().unwrap()[0].status(),
            TenantStatus::Provisioning
        );
        assert!(
            s.events
                .records
                .lock()
                .unwrap()
                .contains(&"tenant.provisioned".to_owned())
        );
    }

    /// The installation starts again. Nothing is made twice and nothing
    /// more is recorded.
    #[test]
    fn running_it_again_changes_nothing() {
        let s = setup();
        install(&s).unwrap();
        let events_after_first = s.events.records.lock().unwrap().len();

        let second = install(&s).unwrap();

        assert!(matches!(second, Installation::AlreadyInstalled));
        assert_eq!(s.orgs.count(), 1);
        assert_eq!(s.owners.count(), 1);
        assert_eq!(s.events.records.lock().unwrap().len(), events_after_first);
    }

    /// Any organization already there, whatever its name, means the
    /// installation is done.
    #[test]
    fn an_existing_organization_of_any_name_counts_as_installed() {
        let s = setup_with(org_store_with([test_org(OrganizationId::new(), "other")]));

        let result = install(&s).unwrap();

        assert!(matches!(result, Installation::AlreadyInstalled));
        assert_eq!(s.orgs.count(), 1);
        assert_eq!(s.owners.count(), 0);
    }

    /// When another installer saves the organization after the initial
    /// read, founding returns a conflict, retaining one organization and
    /// creating no tenant or owner.
    #[test]
    fn a_second_process_founding_first_is_a_conflict() {
        let live = Arc::new(FakeOrganizationStore::empty());
        block_on(live.save(&test_org(OrganizationId::new(), "acme-corp"))).unwrap();
        let racing = ReadBeforeWrite::new(FakeOrganizationStore::empty(), live.clone());
        let s = setup_over(Arc::new(racing), live);

        let result = install(&s);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(s.orgs.count(), 1);
        assert_eq!(s.tenants.count(), 0);
        assert_eq!(s.owners.count(), 0);
    }

    /// A configured password too weak for the organization's rules is
    /// refused and nothing is made.
    #[test]
    fn a_weak_configured_password_is_refused() {
        let s = setup();
        let req = InstallRequest {
            owner_password: "short".to_owned(),
            ..request()
        };

        let result = install_with(&s, req);

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
        assert_eq!(s.orgs.count(), 0);
    }

    /// A breached owner password is refused during installation, leaving
    /// both the organization and owner stores empty.
    #[test]
    fn a_breached_configured_password_is_refused() {
        let orgs = Arc::new(FakeOrganizationStore::empty());
        let breaches = Arc::new(FakeBreachChecker {
            status: BreachStatus::Breached(7),
        });
        let s = setup_checking(orgs.clone(), orgs, breaches);

        let result = install(&s);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(s.orgs.count(), 0);
        assert_eq!(s.owners.count(), 0);
    }
}
