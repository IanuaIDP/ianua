//! Who may change a tenant: its own admins for its settings, and its
//! organization or the platform for its life.

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::permission::{
    AuthConfigAction, ComplianceAction, DomainAction, MtlsAction, SystemPermission,
    TenantSettingsAction,
};
use crate::domains::identity::account::control::RecentProof;
use crate::domains::identity::sealed::Sealed;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{ActedBy, Human, HumanAccount, OrganizationId, PrincipalId, TenantId};

/// The part of a tenant a change touches. Each part needs its own right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantArea {
    /// The name, contact address, timezone, locale and primary domain.
    Profile,
    /// How the tenant's users sign in.
    SignIn,
    /// Which certificate authorities may sign client certificates.
    Mtls,
    /// Data residency, audit retention and operator impersonation.
    Compliance,
    /// The tenant's own domains.
    Domains,
    /// Claims on new domains for the tenant. Adding one is its own right,
    /// apart from changing the ones it holds.
    DomainClaims,
    /// Removing one of the tenant's domains. Its mail and sign-in pages stop
    /// working on that name, so it is its own right, apart from changing it.
    DomainRemoval,
    /// Streams that send the tenant's audit records to a SIEM. They carry
    /// every record out of the platform, so they need the compliance right.
    AuditStreaming,
}

impl TenantArea {
    /// The right a change to this part needs.
    fn needs(self) -> SystemPermission {
        match self {
            Self::Profile => SystemPermission::TenantSettings(TenantSettingsAction::Update),
            Self::SignIn => SystemPermission::AuthConfig(AuthConfigAction::Update),
            Self::Mtls => SystemPermission::Mtls(MtlsAction::Update),
            Self::Compliance | Self::AuditStreaming => {
                SystemPermission::Compliance(ComplianceAction::Update)
            }
            Self::Domains => SystemPermission::Domains(DomainAction::Update),
            Self::DomainClaims => SystemPermission::Domains(DomainAction::Create),
            Self::DomainRemoval => SystemPermission::Domains(DomainAction::Delete),
        }
    }
}

/// A person changing a tenant, with what they hold in it.
///
/// What a person holds comes from their roles in one tenant. So the check
/// names that tenant, and passes for no other. Sam is an admin in his own
/// tenant. Without this, what he holds there would change Ann's tenant too.
#[derive(Debug, Clone, Copy)]
pub struct TenantControl<'a> {
    authority: &'a TenantAuthority,
}

impl<'a> TenantControl<'a> {
    /// The person `authority` names, acting with what it says they hold.
    #[must_use]
    pub fn new(authority: &'a TenantAuthority) -> Self {
        Self { authority }
    }

    /// The person acting.
    #[must_use]
    pub fn by(&self) -> &'a Human {
        self.authority.who()
    }

    /// Refuses a change to `area` of `tenant` unless the person may use the
    /// right for it there now, through their roles or an active break-glass
    /// grant.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when what they hold was worked out for
    ///   another tenant.
    /// - [`DomainError::Forbidden`] when they do not hold the right.
    pub fn ensure_may(&self, tenant: &TenantId, area: TenantArea) -> Result<(), DomainError> {
        self.authority.ensure_within(tenant)?;
        self.authority.ensure_holds(area.needs())
    }

    /// Refuses unless the person proved who they are again just now.
    ///
    /// Someone who steals a session holds it until it ends. A change that
    /// weakens how the tenant is protected must not be made with it alone.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `proof` is not a fresh proof of the
    ///   person acting.
    pub fn ensure_proved_recently(&self, proof: &impl RecentProof) -> Result<(), DomainError> {
        if proof.proves_recently(&principal_of(self.by().account())) {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "branding-this-change-needs-the-person-to",
            "this change needs the person to prove who they are again"
        )))
    }
}

/// The principal an account stands for.
pub(crate) fn principal_of(account: HumanAccount) -> PrincipalId {
    match account {
        HumanAccount::User(id) => id.into(),
        HumanAccount::OrgUser(id) => id.into(),
    }
}

/// A step in a tenant's life that a member of its organization may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleStep {
    /// Make a new tenant for the organization.
    Provision,
    /// Freeze the tenant.
    Suspend,
    /// Bring a suspended tenant back.
    Reactivate,
    /// Close the tenant and start the wait before it may be deleted.
    Archive,
    /// Bring an archived tenant back before it is deleted.
    Restore,
    /// Wipe an archived tenant for good.
    Delete,
}

/// Whether a member of an organization may take a step in the life of one
/// of its tenants.
///
/// Members hold rights of the organization's own, which the organization
/// context knows. It answers with its member's authority. Tenant sits below
/// organization, so it names only this rule. The trait is sealed, so no
/// caller outside the crate can answer with a yes that never checked.
pub trait OrgSteward: Sealed {
    /// Whether the member belongs to `organization` and holds the right for
    /// `step` there.
    fn may_take(&self, organization: &OrganizationId, step: LifecycleStep) -> bool;
}

/// Who moves a tenant through its life: a member of its organization, or
/// the platform.
pub type Steward<'a> = ActedBy<&'a dyn OrgSteward>;

/// Refuses `step` on a tenant owned by `organization`, unless the platform
/// takes it or a member who holds the right for it.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when the member is of another organization
///   or does not hold the right.
pub(crate) fn ensure_may_take(
    by: Steward<'_>,
    organization: &OrganizationId,
    step: LifecycleStep,
) -> Result<(), DomainError> {
    let ActedBy::By(member) = by else {
        return Ok(());
    };
    if member.may_take(organization, step) {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "tenant-only-a-member-of-the-tenant",
        "only a member of the tenant's organization who holds the right may do this"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::tenant::fixtures::{Member, ProvedJustNow, active, holding, person};

    /// The settings view right cannot authorize sign-in changes, while
    /// the authentication-config update right passes that check.
    #[test]
    fn a_change_needs_the_right_for_its_area() {
        let sam = person("sam@acme.test");
        let acme = active();
        let view = [SystemPermission::TenantSettings(TenantSettingsAction::View)];
        let sign_in = [SystemPermission::AuthConfig(AuthConfigAction::Update)];

        let refused = holding(&sam, &acme, &view).ensure_may(acme.id(), TenantArea::SignIn);
        let allowed = holding(&sam, &acme, &sign_in).ensure_may(acme.id(), TenantArea::SignIn);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(allowed.is_ok());
    }

    /// Settings-management authority resolved in one tenant cannot authorize
    /// profile changes in another tenant.
    #[test]
    fn what_someone_holds_in_one_tenant_changes_no_other() {
        let sam = person("sam@acme.test");
        let his = active();
        let anns = active();
        let manage = [SystemPermission::ManageTenantSettings];

        let refused = holding(&sam, &his, &manage).ensure_may(anns.id(), TenantArea::Profile);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Ann's recent proof is rejected for Sam's authority, while Sam's own
    /// recent proof satisfies the same check.
    #[test]
    fn only_the_person_acting_can_prove_themselves_again() {
        let sam = person("sam@acme.test");
        let ann = person("ann@acme.test");
        let control = holding(&sam, &active(), &[]);

        assert!(matches!(
            control.ensure_proved_recently(&ProvedJustNow::by(&ann)),
            Err(DomainError::Forbidden(_))
        ));
        assert!(
            control
                .ensure_proved_recently(&ProvedJustNow::by(&sam))
                .is_ok()
        );
    }

    /// Deletion is refused to a member lacking its right and to a member
    /// of another organization. The member's permitted suspension and the
    /// platform's deletion both pass.
    #[test]
    fn a_step_needs_a_member_of_the_organization_with_the_right() {
        let acme = active();
        let organization = acme.organization_id();
        let bob = Member::of(&acme, &[LifecycleStep::Suspend]);
        let eve = Member::elsewhere();

        let bob_deletes = ensure_may_take(ActedBy::By(&bob), organization, LifecycleStep::Delete);
        let eve_deletes = ensure_may_take(ActedBy::By(&eve), organization, LifecycleStep::Delete);
        let bob_suspends = ensure_may_take(ActedBy::By(&bob), organization, LifecycleStep::Suspend);

        assert!(matches!(bob_deletes, Err(DomainError::Forbidden(_))));
        assert!(matches!(eve_deletes, Err(DomainError::Forbidden(_))));
        assert!(bob_suspends.is_ok());
        assert!(ensure_may_take(ActedBy::Platform, organization, LifecycleStep::Delete).is_ok());
    }
}
