//! Where this platform's federation endpoints for one tenant live: its SAML
//! names and addresses as identity provider and as service provider, its
//! SCIM base path, and the dashboard pages a browser is sent on to.
//!
//! Every address is built from the deployment's own base URL and the
//! tenant's slugs, never from what a request says.

use ianua_app::error::AppError;
use ianua_app::ports::federation::ServiceProvider;
use ianua_app::use_cases::federation::connections::SpMetadataRequest;
use ianua_app::use_cases::federation::idp::GetMetadataRequest;
use ianua_app::use_cases::federation::logout::StartSingleRequest;
use ianua_domain::domains::federation::saml::logout::LogoutStatus;
use ianua_domain::types::{ConnectionId, HttpsUrl, SamlEntityId, TenantSlug};
use url::form_urlencoded::Serializer;

use crate::error::ApiError;

/// The federation addresses of the tenant a path names, under the
/// deployment's base URL.
pub(crate) struct FederationSite {
    base: String,
    org: TenantSlug,
    tenant: TenantSlug,
}

impl FederationSite {
    /// The addresses of `org`/`tenant` under `base`.
    #[must_use]
    pub(crate) fn new(base: &HttpsUrl, org: TenantSlug, tenant: TenantSlug) -> Self {
        Self {
            base: base.as_str().trim_end_matches('/').to_owned(),
            org,
            tenant,
        }
    }

    /// The tenant's API path, `/api/v1/organizations/{org}/tenants/{tenant}`.
    fn tenant_path(&self) -> String {
        format!(
            "/api/v1/organizations/{}/tenants/{}",
            self.org.as_str(),
            self.tenant.as_str()
        )
    }

    /// The API address `rest` names under the tenant.
    fn address(&self, rest: &str) -> Result<HttpsUrl, ApiError> {
        HttpsUrl::new(format!("{}{}{rest}", self.base, self.tenant_path()))
            .map_err(|refused| ApiError(AppError::internal(refused)))
    }

    /// The tenant as an identity provider: its issuer, the base of its
    /// endpoints.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the base URL makes no valid entity id,
    ///   which a valid deployment never does.
    pub(crate) fn idp_entity_id(&self) -> Result<SamlEntityId, ApiError> {
        SamlEntityId::new(format!("{}{}", self.base, self.tenant_path()))
            .map_err(|refused| ApiError(AppError::internal(refused)))
    }

    /// The tenant's identity provider metadata terms: its entity id and
    /// where sign-in and logout requests go.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the base URL makes no valid address.
    pub(crate) fn identity_provider(&self) -> Result<GetMetadataRequest, ApiError> {
        Ok(GetMetadataRequest {
            entity_id: self.idp_entity_id()?,
            sso_url: self.address("/saml/sso")?,
            slo_url: Some(self.address("/saml/slo")?),
        })
    }

    /// This platform as the tenant's identity providers know it: the
    /// deployment's base URL as entity id, the tenant's assertion consumer
    /// service as where answers are posted.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the base URL makes no valid entity id or
    ///   address.
    pub(crate) fn service_provider(&self) -> Result<ServiceProvider, ApiError> {
        Ok(ServiceProvider {
            entity_id: self.sp_entity_id()?,
            acs_url: self.address("/federation/saml/acs")?,
        })
    }

    /// This platform's entity id as a service provider.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the base URL makes no valid entity id.
    pub(crate) fn sp_entity_id(&self) -> Result<SamlEntityId, ApiError> {
        SamlEntityId::new(self.base.as_str())
            .map_err(|refused| ApiError(AppError::internal(refused)))
    }

    /// Where `connection`'s provider sends logout requests and answers.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the base URL makes no valid address.
    pub(crate) fn connection_slo_url(
        &self,
        connection: &ConnectionId,
    ) -> Result<HttpsUrl, ApiError> {
        self.address(&format!("/federation/connections/{connection}/saml/slo"))
    }

    /// What `connection`'s service provider metadata names: this platform,
    /// and where the provider sends logouts.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the base URL makes no valid entity id or
    ///   address.
    pub(crate) fn sp_metadata(
        &self,
        connection: ConnectionId,
    ) -> Result<SpMetadataRequest, ApiError> {
        Ok(SpMetadataRequest {
            service_provider: self.service_provider()?,
            slo_url: self.connection_slo_url(&connection)?,
            connection_id: connection,
        })
    }

    /// The logout of the caller's session at every peer it reached: the
    /// tenant as identity provider to its apps, this platform as service
    /// provider to the provider it signed in through.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the base URL makes no valid entity id.
    pub(crate) fn single_logout(&self) -> Result<StartSingleRequest, ApiError> {
        Ok(StartSingleRequest {
            idp_entity_id: self.idp_entity_id()?,
            sp_entity_id: self.sp_entity_id()?,
        })
    }

    /// The tenant's SCIM base path, as a directory is configured with it.
    #[must_use]
    pub(crate) fn scim_path(&self) -> String {
        format!(
            "/scim/v2/organizations/{}/tenants/{}",
            self.org.as_str(),
            self.tenant.as_str()
        )
    }

    /// The dashboard page answering `connection`'s provider's logout
    /// request, carrying `query`.
    #[must_use]
    pub(crate) fn connection_logout_page(&self, connection: &ConnectionId, query: &str) -> String {
        self.dashboard_page(
            &format!("/federation/connections/{connection}/saml/slo"),
            query,
        )
    }

    /// The dashboard's sign-in page, told how a logout went at the peer.
    #[must_use]
    pub(crate) fn logged_out_page(&self, status: LogoutStatus) -> String {
        let mut query = Serializer::new(String::new());
        query.append_pair("logout", status.as_str());
        self.dashboard_page("/login", &query.finish())
    }

    /// The tenant's dashboard page `page`, carrying `query`.
    #[must_use]
    pub(crate) fn dashboard_page(&self, page: &str, query: &str) -> String {
        format!(
            "{}/organizations/{}/tenants/{}{page}?{query}",
            self.base,
            self.org.as_str(),
            self.tenant.as_str()
        )
    }
}
