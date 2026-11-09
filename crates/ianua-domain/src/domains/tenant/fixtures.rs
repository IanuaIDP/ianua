//! Tenants, people and proofs the tenant context's tests share.

use crate::domains::authentication::sessions::session::Session;
use crate::domains::authorization::permission::SystemPermission;
use crate::domains::identity::account::control::RecentProof;
use crate::domains::identity::sealed::Sealed;
use crate::domains::tenant::compliance_limits::ComplianceLimits;
use crate::domains::tenant::control::{LifecycleStep, OrgSteward, TenantControl, principal_of};
use crate::domains::tenant::custom_domains::owned_domain::OwnedDomain;
use crate::domains::tenant::custom_domains::registered_domain::{
    DomainConnection, DomainVerificationToken, NewDomain, RegisteredDomain,
};
use crate::domains::tenant::hosts::PlatformLabel;
use crate::domains::tenant::lifecycle::{EarlyDeletion, ProvisionTenantParams, Tenant};
use crate::domains::tenant::provisioning::infrastructure::{DeploymentRegion, TenantResidency};
use crate::isolation::scope::ResolvedTenant;
use crate::shared::config::DomainLimits;
use crate::test_support::authority::assumed_authority;
use crate::types::{
    ActedBy, DisplayName, DomainName, Email, Human, HumanAccount, Locale, OrganizationId,
    PersonKey, PrincipalId, TenantId, TenantSlug, Text, Timezone, UserId,
};

/// Every right a tenant admin may hold over the tenant itself.
pub(crate) const ADMIN: &[SystemPermission] = &[
    SystemPermission::ManageTenantSettings,
    SystemPermission::ManageAuthConfig,
    SystemPermission::ManageMtls,
    SystemPermission::ManageCompliance,
    SystemPermission::ManageDomains,
];

/// The parameters of Acme's tenant, placed in Frankfurt.
pub(crate) fn acme_params() -> ProvisionTenantParams {
    let limits = DomainLimits::default();
    ProvisionTenantParams {
        id: TenantId::new(),
        platform_label: PlatformLabel::new(
            TenantId::new().as_uuid().simple().to_string()[16..].to_owned(),
        )
        .unwrap(),
        organization_id: OrganizationId::new(),
        slug: TenantSlug::new("acme", &limits.slug).unwrap(),
        display_name: DisplayName::new("Acme Corp", &limits.display_name).unwrap(),
        contact_email: Email::new("admin@acme.com").unwrap(),
        timezone: Timezone::new("UTC").unwrap(),
        locale: Locale::new("en-US").unwrap(),
        residency: TenantResidency::shared_on_platform(DeploymentRegion::EuCentral1),
    }
}

/// Acme's tenant, just provisioned by the platform under the default
/// limits.
pub(crate) fn provisioned() -> Tenant {
    Tenant::provision(
        acme_params(),
        &ComplianceLimits::default(),
        ActedBy::Platform,
    )
    .unwrap()
}

/// Acme's tenant once the platform finished provisioning it.
pub(crate) fn active() -> Tenant {
    let mut tenant = provisioned();
    tenant.activate(ActedBy::Platform).unwrap();
    tenant
}

/// `tenant` archived and deleted by the platform, without waiting out the
/// grace.
pub(crate) fn deleted(mut tenant: Tenant) -> Tenant {
    tenant.archive(ActedBy::Platform).unwrap();
    let reason = EarlyDeletion::Abuse(Text::new("note", "phishing pages").unwrap());
    tenant.delete_early(ActedBy::Platform, reason).unwrap();
    tenant
}

/// Proof that `tenant` registered and verified `name`.
pub(crate) fn proved_domain(tenant: &Tenant, name: &str) -> OwnedDomain {
    let scope = ResolvedTenant::new(*tenant.id(), tenant.slug().clone());
    let admin = person("admin@acme.test");
    let mut registered = RegisteredDomain::<ResolvedTenant>::register(
        NewDomain {
            domain: DomainName::new(name).unwrap(),
            connection: DomainConnection::SelfManaged,
            dns_challenge_token: DomainVerificationToken::new("challenge").unwrap(),
        },
        &scope,
        holding(&admin, tenant, ADMIN),
    )
    .unwrap();
    registered.mark_verified().unwrap();
    registered.owned_by(&scope).unwrap()
}

/// A person signed in to a tenant account under `address`.
pub(crate) fn person(address: &str) -> Human {
    Human::new(
        HumanAccount::User(UserId::new()),
        PersonKey::new(address).unwrap(),
    )
}

/// The tenant user `session` belongs to, under `address`.
pub(crate) fn holder_of(session: &Session<ResolvedTenant>, address: &str) -> Human {
    Human::new(
        HumanAccount::User(*session.user_id()),
        PersonKey::new(address).unwrap(),
    )
}

/// `by`, holding `system` in `tenant`.
pub(crate) fn holding<'a>(
    by: &'a Human,
    tenant: &Tenant,
    system: &'a [SystemPermission],
) -> TenantControl<'a> {
    TenantControl::new(assumed_authority(by, *tenant.id(), system, &[]))
}

/// Proof that the holder of one account proved who they are just now.
pub(crate) struct ProvedJustNow(PrincipalId);

impl ProvedJustNow {
    /// The proof `person` gives by signing in again.
    pub(crate) fn by(person: &Human) -> Self {
        Self(principal_of(person.account()))
    }
}

impl Sealed for ProvedJustNow {}

impl RecentProof for ProvedJustNow {
    fn proves_recently(&self, account: &PrincipalId) -> bool {
        *account == self.0
    }
}

/// A member of one organization who may take only some steps.
pub(crate) struct Member {
    organization: OrganizationId,
    steps: Vec<LifecycleStep>,
}

impl Member {
    /// A member of the organization that owns `tenant`, holding the rights
    /// for `steps`.
    pub(crate) fn of(tenant: &Tenant, steps: &[LifecycleStep]) -> Self {
        Self::of_organization(*tenant.organization_id(), steps)
    }

    /// A member of `organization`, holding the rights for `steps`.
    pub(crate) fn of_organization(organization: OrganizationId, steps: &[LifecycleStep]) -> Self {
        Self {
            organization,
            steps: steps.to_vec(),
        }
    }

    /// A member of some other organization, holding every right there.
    pub(crate) fn elsewhere() -> Self {
        Self {
            organization: OrganizationId::new(),
            steps: vec![
                LifecycleStep::Provision,
                LifecycleStep::Suspend,
                LifecycleStep::Reactivate,
                LifecycleStep::Archive,
                LifecycleStep::Restore,
                LifecycleStep::Delete,
            ],
        }
    }
}

impl Sealed for Member {}

impl OrgSteward for Member {
    fn may_take(&self, organization: &OrganizationId, step: LifecycleStep) -> bool {
        self.organization == *organization && self.steps.contains(&step)
    }
}
