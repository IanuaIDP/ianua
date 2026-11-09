//! Where a member's sign-in to the organization lands.
//!
//! Every active member signs in, whether or not they reach a tenant yet. A
//! session lands in the tenant the member named, or else the first active
//! tenant they reach, or the first of those when none is active. When they
//! reach no tenant, because their role reaches none or nobody granted them
//! one yet, the session works on the organization alone.
//!
//! Landing is a choice, not a check. [`OrgSession::create`] still decides
//! whether the member may work in the tenant chosen, so naming a tenant
//! the member does not reach is refused there.
//!
//! [`OrgSession::create`]: crate::domains::organization::access::session::OrgSession::create

use crate::domains::organization::access::session::SessionPlace;
use crate::domains::organization::members::membership::{OrgRole, TenantReach};
use crate::domains::tenant::lifecycle::Tenant;
use crate::domains::tenant::status::TenantStatus;
use crate::shared::errors::DomainError;
use crate::types::{TenantId, TenantSlug};

/// What a sign-in may land in: the organization's tenants, and the ones
/// the member was granted.
#[derive(Debug)]
pub struct LandingChoices<'a> {
    /// Every tenant of the organization.
    pub tenants: Vec<Tenant>,
    /// The tenants the member was granted. Only a plain member's are read:
    /// an owner or admin reaches every tenant, a billing contact or viewer
    /// none.
    pub granted: &'a [TenantId],
}

/// Which tenant a member asked to land in when signing in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskedTenant<'a> {
    /// The tenant with this slug.
    Named(&'a TenantSlug),
    /// None: the sign-in lands where the member's reach puts it.
    Unnamed,
}

/// Where a member's new session works.
#[derive(Debug)]
pub enum SignInLanding {
    /// In this tenant of the organization.
    Tenant(Box<Tenant>),
    /// On the organization alone: the member reaches no tenant.
    Organization,
}

impl SignInLanding {
    /// Where a sign-in of a member holding `role` lands, among `choices`.
    ///
    /// A billing contact or a viewer reaches no tenant, so their session
    /// works on the organization alone even when they name one. Anyone else
    /// lands in the tenant they `asked` for by name, or the first active
    /// tenant they reach, or the first they reach when none is active. A
    /// member who reaches no tenant yet lands on the organization alone.
    ///
    /// Sam accepted his invitation to Acme a minute ago, and nobody granted
    /// him a tenant yet. Without the organization as a place, he cannot sign
    /// in at all, not even to read who his colleagues are.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when `asked` names no tenant of the
    ///   organization.
    pub fn for_sign_in(
        role: OrgRole,
        asked: AskedTenant<'_>,
        choices: LandingChoices<'_>,
    ) -> Result<Self, DomainError> {
        if role.tenant_reach() == TenantReach::Nothing {
            return Ok(Self::Organization);
        }
        if let AskedTenant::Named(slug) = asked {
            return tenant_named(slug, choices.tenants);
        }
        let reached = reached_by(role, choices);
        Ok(preferred(reached).map_or(Self::Organization, |tenant| Self::Tenant(Box::new(tenant))))
    }

    /// Where the session opened here works.
    #[must_use]
    pub fn place(&self) -> SessionPlace {
        match self {
            Self::Tenant(tenant) => SessionPlace::Tenant(*tenant.id()),
            Self::Organization => SessionPlace::Organization,
        }
    }
}

/// The tenant of `tenants` with `slug`, or not found.
fn tenant_named(slug: &TenantSlug, tenants: Vec<Tenant>) -> Result<SignInLanding, DomainError> {
    tenants
        .into_iter()
        .find(|tenant| tenant.slug() == slug)
        .map(|tenant| SignInLanding::Tenant(Box::new(tenant)))
        .ok_or(DomainError::NotFound)
}

/// The tenants of `choices` a holder of `role` reaches: all of them for an
/// owner or admin, the granted ones for a plain member, none for a billing
/// contact or a viewer.
fn reached_by(role: OrgRole, choices: LandingChoices<'_>) -> Vec<Tenant> {
    let LandingChoices { tenants, granted } = choices;
    match role.tenant_reach() {
        TenantReach::Every => tenants,
        TenantReach::Granted => tenants
            .into_iter()
            .filter(|tenant| granted.contains(tenant.id()))
            .collect(),
        TenantReach::Nothing => Vec::new(),
    }
}

/// The first active tenant of `candidates`, or the first of all when none
/// is active.
fn preferred(mut candidates: Vec<Tenant>) -> Option<Tenant> {
    let index = candidates
        .iter()
        .position(|tenant| tenant.status() == TenantStatus::Active)
        .unwrap_or(0);
    (index < candidates.len()).then(|| candidates.swap_remove(index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::tenant::compliance_limits::ComplianceLimits;
    use crate::domains::tenant::fixtures::acme_params;
    use crate::domains::tenant::lifecycle::ProvisionTenantParams;
    use crate::shared::config::SlugLimits;
    use crate::types::ActedBy;

    fn slug(name: &str) -> TenantSlug {
        TenantSlug::new(name, &SlugLimits::default()).unwrap()
    }

    /// A tenant called `name`, just provisioned.
    fn provisioning(name: &str) -> Tenant {
        Tenant::provision(
            ProvisionTenantParams {
                id: TenantId::new(),
                slug: slug(name),
                ..acme_params()
            },
            &ComplianceLimits::default(),
            ActedBy::Platform,
        )
        .unwrap()
    }

    /// A tenant called `name`, provisioned and active.
    fn active(name: &str) -> Tenant {
        let mut tenant = provisioning(name);
        tenant.activate(ActedBy::Platform).unwrap();
        tenant
    }

    /// The slug of the tenant `landing` lands in, if any.
    fn landed_slug(landing: &SignInLanding) -> Option<&str> {
        match landing {
            SignInLanding::Tenant(tenant) => Some(tenant.slug().as_str()),
            SignInLanding::Organization => None,
        }
    }

    /// Sam, a plain member who just accepted his invitation, holds no grant
    /// yet. He signs in, and his session works on the organization alone.
    #[test]
    fn a_member_without_a_grant_lands_on_the_organization() {
        let choices = LandingChoices {
            tenants: vec![active("production"), active("staging")],
            granted: &[],
        };

        let landing =
            SignInLanding::for_sign_in(OrgRole::Member, AskedTenant::Unnamed, choices).unwrap();

        assert_eq!(landing.place(), SessionPlace::Organization);
    }

    /// Ann owns Acme, which has no tenant yet. She signs in to the
    /// organization alone.
    #[test]
    fn an_owner_of_an_organization_without_tenants_lands_on_it() {
        let choices = LandingChoices {
            tenants: Vec::new(),
            granted: &[],
        };

        let landing =
            SignInLanding::for_sign_in(OrgRole::Owner, AskedTenant::Unnamed, choices).unwrap();

        assert_eq!(landing.place(), SessionPlace::Organization);
    }

    /// Sam was granted staging since he last signed in. He signs in again
    /// and lands there, though production is listed first.
    #[test]
    fn a_member_lands_in_the_tenant_granted_to_him() {
        let staging = active("staging");
        let granted = [*staging.id()];
        let choices = LandingChoices {
            tenants: vec![active("production"), staging],
            granted: &granted,
        };

        let landing =
            SignInLanding::for_sign_in(OrgRole::Member, AskedTenant::Unnamed, choices).unwrap();

        assert_eq!(landed_slug(&landing), Some("staging"));
    }

    /// Ann owns Acme, whose first tenant is still being set up. She lands
    /// in the active one listed after it.
    #[test]
    fn an_active_tenant_is_preferred_to_one_listed_ahead_of_it() {
        let choices = LandingChoices {
            tenants: vec![provisioning("staging"), active("production")],
            granted: &[],
        };

        let landing =
            SignInLanding::for_sign_in(OrgRole::Owner, AskedTenant::Unnamed, choices).unwrap();

        assert_eq!(landed_slug(&landing), Some("production"));
    }

    /// Ann owns Acme, whose only tenant is still being set up. She lands in
    /// it rather than on the organization.
    #[test]
    fn without_an_active_tenant_the_first_reached_is_landed_in() {
        let choices = LandingChoices {
            tenants: vec![provisioning("staging")],
            granted: &[],
        };

        let landing =
            SignInLanding::for_sign_in(OrgRole::Owner, AskedTenant::Unnamed, choices).unwrap();

        assert_eq!(landed_slug(&landing), Some("staging"));
    }

    /// Ann names staging. Her session lands there, not in the first active
    /// tenant.
    #[test]
    fn a_named_tenant_is_landed_in() {
        let choices = LandingChoices {
            tenants: vec![active("production"), provisioning("staging")],
            granted: &[],
        };

        let landing = SignInLanding::for_sign_in(
            OrgRole::Owner,
            AskedTenant::Named(&slug("staging")),
            choices,
        )
        .unwrap();

        assert_eq!(landed_slug(&landing), Some("staging"));
    }

    /// Requesting an unknown organization tenant returns not found.
    #[test]
    fn a_tenant_the_organization_lacks_is_not_found() {
        let choices = LandingChoices {
            tenants: vec![active("production")],
            granted: &[],
        };

        let landing = SignInLanding::for_sign_in(
            OrgRole::Owner,
            AskedTenant::Named(&slug("nowhere")),
            choices,
        );

        assert!(matches!(landing, Err(DomainError::NotFound)));
    }

    /// Billing and viewer roles land on the organization even with a grant for the requested tenant.
    #[test]
    fn billing_and_viewer_land_on_the_organization_even_when_granted() {
        for role in [OrgRole::Billing, OrgRole::Viewer] {
            let production = active("production");
            let granted = [*production.id()];
            let choices = LandingChoices {
                tenants: vec![production],
                granted: &granted,
            };

            let landing =
                SignInLanding::for_sign_in(role, AskedTenant::Named(&slug("production")), choices)
                    .unwrap();

            assert_eq!(landing.place(), SessionPlace::Organization, "{role}");
        }
    }

    /// A grant outside the organization does not provide a tenant landing within it.
    #[test]
    fn a_grant_outside_the_organization_lands_nowhere_in_it() {
        let granted = [TenantId::new()];
        let choices = LandingChoices {
            tenants: vec![active("production")],
            granted: &granted,
        };

        let landing =
            SignInLanding::for_sign_in(OrgRole::Member, AskedTenant::Unnamed, choices).unwrap();

        assert_eq!(landing.place(), SessionPlace::Organization);
    }
}
