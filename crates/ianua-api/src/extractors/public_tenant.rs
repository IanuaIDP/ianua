//! The tenant a public protocol endpoint is addressed to.
//!
//! OAuth token and device endpoints, OIDC discovery, the JWKS document, the
//! SAML metadata documents and the SCIM service are called by programs, not
//! by a signed-in person: a relying party, a device, an identity provider, a
//! directory. They name their tenant in the path and prove themselves, when
//! they must, with a credential the use case checks. This extractor finds
//! the tenant the path names and hands the use case the app's
//! [`ScopedTenant`] for it.

use axum::extract::{FromRequestParts, RawPathParams};
use axum::http::request::Parts;
use ianua_app::auditor::RequestAuditor;
use ianua_app::error::AppError;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::audit::builder::AuditContext;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::config::SlugLimits;
use ianua_domain::types::{Fact, HttpsUrl, Issuer, TenantSlug};

use crate::error::ApiError;
use crate::extractors::callers::{RequestMeta, organization_named, tenant_named};
use crate::state::ApiState;

/// A tenant named by the path of a public endpoint, open to requests made
/// in its name.
pub(crate) struct PublicTenant {
    /// The tenant, scoped for the use case's store calls.
    pub tenant: ScopedTenant,
    /// The slug of the tenant's organization, as the path names it.
    pub org_slug: TenantSlug,
    /// The tenant's slug, as the path names it.
    pub tenant_slug: TenantSlug,
    /// Records what the request changes, for nobody identified yet, in the
    /// tenant and its organization.
    pub auditor: RequestAuditor,
}

impl PublicTenant {
    /// The tenant's issuer under `app_base_url`: the `iss` of the tokens it
    /// signs and the base of its OIDC and SAML endpoints.
    #[must_use]
    pub(crate) fn issuer(&self, app_base_url: &HttpsUrl) -> Issuer {
        Issuer::of_tenant(app_base_url, &self.org_slug, &self.tenant_slug)
    }
}

impl FromRequestParts<ApiState> for PublicTenant {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let (org_slug, tenant_slug) = path_slugs(parts, state).await?;
        let organization = organization_named(state, &org_slug).await?;
        let tenant = tenant_named(state, &tenant_slug, &organization).await?;
        let Ok(meta) = RequestMeta::from_request_parts(parts, state).await;
        let context = AuditContext::anonymous(*organization.id())
            .with_tenant(*tenant.id())
            .with_request(
                Fact::from_option(meta.ip_address),
                Fact::from_option(meta.user_agent),
            );
        Ok(Self {
            tenant: ScopedTenant::from(&ResolvedTenant::new(*tenant.id(), tenant.slug().clone())),
            org_slug,
            tenant_slug,
            auditor: RequestAuditor::new(state.event_dispatcher.clone(), context),
        })
    }
}

/// The organization and tenant slugs of `parts`' path. A slug that is not a
/// valid one names nothing, so it is not found.
async fn path_slugs(
    parts: &mut Parts,
    state: &ApiState,
) -> Result<(TenantSlug, TenantSlug), ApiError> {
    let params = RawPathParams::from_request_parts(parts, state)
        .await
        .map_err(|_| not_found())?;
    let limits = SlugLimits::default();
    let slug = |name: &str| {
        params
            .iter()
            .find(|(key, _)| *key == name)
            .and_then(|(_, value)| TenantSlug::new(value, &limits).ok())
            .ok_or_else(not_found)
    };
    Ok((slug("org_slug")?, slug("tenant_slug")?))
}

/// The plain `404` for a path that names no tenant.
fn not_found() -> ApiError {
    ApiError(AppError::NotFound(message!("api-not-found", "not found")))
}
