//! Where a member's sign-in lands: the tenant they named, or else the
//! first active tenant they may reach, or the organization alone when they
//! reach no tenant.
//!
//! The choice is the domain's ([`SignInLanding::for_sign_in`]); this step
//! reads the organization's tenants and the member's grants for it. The
//! domain still decides whether the member may work in the tenant chosen
//! when the session opens. A member who reaches no tenant, because their
//! role reaches none or nobody granted them one yet, signs in to the
//! organization alone and is told they have no tenant access.

use ianua_domain::domains::organization::access::landing::{
    AskedTenant, LandingChoices, SignInLanding,
};
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{TenantId, TenantSlug};

use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest, SortOrder};
use crate::ports::organization::OrgTenantGrantStore;
use crate::ports::tenant::TenantStore;

/// The most tenants a sign-in looks through.
const MAX_LANDING_TENANTS: u32 = 1000;

/// Where a member's new session works, as they are told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LandedTenant {
    /// The session works in this tenant.
    Tenant {
        /// The tenant.
        id: TenantId,
        /// The address label used to enter the selected workspace.
        slug: TenantSlug,
    },
    /// The member reaches no tenant, so the session works on the
    /// organization alone: a billing contact's or a viewer's, or a plain
    /// member's nobody granted a tenant yet.
    NoTenantAccess,
}

impl LandedTenant {
    /// The slug of the tenant the session works in, if it works in one.
    #[must_use]
    pub fn slug(&self) -> Option<&TenantSlug> {
        match self {
            Self::Tenant { slug, .. } => Some(slug),
            Self::NoTenantAccess => None,
        }
    }
}

impl From<&SignInLanding> for LandedTenant {
    fn from(landing: &SignInLanding) -> Self {
        match landing {
            SignInLanding::Tenant(tenant) => Self::Tenant {
                id: *tenant.id(),
                slug: tenant.slug().clone(),
            },
            SignInLanding::Organization => Self::NoTenantAccess,
        }
    }
}

/// Where the tenants a sign-in may land in are read from.
#[derive(Clone, Copy)]
pub(in crate::use_cases::organization) struct Landing<'a> {
    /// The organization's tenants.
    pub(in crate::use_cases::organization) tenants: &'a dyn TenantStore,
    /// The tenants a member was let into.
    pub(in crate::use_cases::organization) grants: &'a dyn OrgTenantGrantStore,
}

impl Landing<'_> {
    /// Where `member` of `organization` signs in to, as the domain chooses
    /// it among the organization's tenants and the member's grants.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when no tenant of the organization has the
    ///   slug named.
    /// - `AppError::Internal` on storage failure.
    pub(in crate::use_cases::organization) async fn place_for(
        &self,
        member: &OrgUser,
        organization: &Organization,
        named: Option<&TenantSlug>,
    ) -> Result<SignInLanding, AppError> {
        let tenants = self.organization_tenants(organization).await?;
        let granted = self
            .grants
            .list_tenant_ids(member.id())
            .await
            .or_internal()?;
        let choices = LandingChoices {
            tenants,
            granted: &granted,
        };
        let asked = named.map_or(AskedTenant::Unnamed, AskedTenant::Named);
        SignInLanding::for_sign_in(member.role(), asked, choices).map_err(landing_refused)
    }

    async fn organization_tenants(
        &self,
        organization: &Organization,
    ) -> Result<Vec<Tenant>, AppError> {
        let tenants = self
            .tenants
            .list_by_organization(
                organization.id(),
                None,
                &SortOrder::default(),
                &PageRequest::first(Limit::internal(MAX_LANDING_TENANTS)),
            )
            .await
            .or_internal()?
            .items;
        Ok(tenants)
    }
}

/// The answer to a landing the domain refused. A tenant named that the
/// organization lacks answers as bad credentials do, so a sign-in reveals
/// nothing about which tenants exist.
fn landing_refused(error: DomainError) -> AppError {
    match error {
        DomainError::NotFound => AppError::NotFound(message!(
            "authentication-invalid-credentials",
            "invalid credentials"
        )),
        other => AppError::from_domain(other),
    }
}
