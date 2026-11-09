//! The issuer a tenant's own tokens carry, worked out from its records.
//!
//! Every token the platform signs for a tenant names the same `iss`: the one
//! the tenant set, or the platform's issuer for it. App sessions, agents'
//! task tokens, security signals and OIDC tokens carry it, and a consumer
//! never trusts a token from it, since those tokens belong to the tenant's
//! people and agents.

use std::sync::Arc;

use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::tenant::access::auth_config::TokenIssuer;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::message;
use ianua_domain::types::{HttpsUrl, Issuer, TenantId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::organization::OrganizationStore;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;

/// Works out a tenant's own token issuer: the one it set, or the platform's
/// issuer for it.
#[derive(Clone)]
pub struct TenantIssuers {
    tenants: Arc<dyn TenantStore>,
    organizations: Arc<dyn OrganizationStore>,
    app_base_url: HttpsUrl,
}

impl TenantIssuers {
    /// Reads tenants from `tenants` and their organizations from
    /// `organizations`, under the platform address `app_base_url`.
    #[must_use]
    pub fn new(
        tenants: Arc<dyn TenantStore>,
        organizations: Arc<dyn OrganizationStore>,
        app_base_url: HttpsUrl,
    ) -> Self {
        Self {
            tenants,
            organizations,
            app_base_url,
        }
    }

    /// The issuer `tenant_id`'s own tokens carry now.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the tenant or its organization is not on
    ///   record.
    /// - `AppError::Internal` on storage failure.
    pub async fn of(&self, tenant_id: &TenantId) -> Result<Issuer, AppError> {
        let tenant = existing_tenant(self.tenants.as_ref(), tenant_id).await?;
        let organization = self
            .organizations
            .find_by_id(tenant.organization_id())
            .await
            .or_internal()?
            .or_not_found(message!(
                "authentication-organization-not-found",
                "organization not found"
            ))?;
        Ok(issuer_of(&self.app_base_url, &tenant, &organization))
    }
}

/// The issuer `tenant` of `organization` names on its tokens under the
/// platform address `app_base_url`: its own when it set one, the platform's
/// issuer for it otherwise.
pub(crate) fn issuer_of(
    app_base_url: &HttpsUrl,
    tenant: &Tenant,
    organization: &Organization,
) -> Issuer {
    match tenant.auth_config().jwt_issuer() {
        TokenIssuer::Custom(own) => Issuer::from(own),
        TokenIssuer::Platform => {
            Issuer::of_tenant(app_base_url, organization.slug(), tenant.slug())
        }
    }
}

/// The issuers of the tenant every test caller acts in, under the test
/// platform address.
#[cfg(any(test, feature = "test-support"))]
impl crate::test_support::Fake for TenantIssuers {
    fn fake() -> Self {
        let tenant = crate::test_support::tenant::test_tenant_for_ctx();
        let organization =
            crate::test_support::organization::test_org(*tenant.organization_id(), "acme");
        Self::new(
            Arc::new(crate::test_support::tenant::FakeTenantStore::holding(
                tenant,
            )),
            crate::test_support::organization::org_store_with([organization]),
            crate::test_support::Fake::fake(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::organization::FakeOrganizationStore;
    use crate::test_support::tenant::FakeTenantStore;
    use crate::test_support::{Fake, block_on, test_ctx};

    /// Acme's tenant names no issuer of its own, so its tokens carry the
    /// platform's issuer for it, under the platform's address.
    #[test]
    fn a_tenant_without_its_own_issuer_uses_the_platforms() {
        let issuers = TenantIssuers::fake();

        let issuer = block_on(issuers.of(&test_ctx().tenant_id())).unwrap();

        assert_eq!(
            issuer.as_str(),
            "https://app.test/api/v1/organizations/acme/tenants/acme"
        );
    }

    /// A tenant nobody registered has no issuer to compare with, so the
    /// question is answered as not found rather than with a guess.
    #[test]
    fn an_unknown_tenant_has_no_issuer() {
        let issuers = TenantIssuers::new(
            Arc::new(FakeTenantStore::empty()),
            Arc::new(FakeOrganizationStore::empty()),
            HttpsUrl::fake(),
        );

        let result = block_on(issuers.of(&test_ctx().tenant_id()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
