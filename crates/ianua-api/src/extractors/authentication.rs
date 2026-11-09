//! Who signs in, out or up, as the authentication use cases name them.
//!
//! Signing in runs before anyone is identified, so most of these endpoints
//! have no caller at all: only the tenant the path names, where the request
//! came from, and an auditor that records it. A sign-in still waiting for
//! its second factor is named by the bearer it was handed, the same token a
//! finished session signs requests with. These extractors build the app's
//! own caller types from those; whether a session finished signing in, and
//! what it may do, is the app's question.

use axum::extract::{FromRequestParts, RawPathParams};
use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::request::Parts;
use ianua_app::auditor::RequestAuditor;
use ianua_app::context::{CallerContext, CallerIdentity, Credential};
use ianua_app::email::LinkScope;
use ianua_app::error::AppError;
use ianua_app::ports::authentication::SEAL_HEADER;
use ianua_app::ports::federation::ServiceProvider;
use ianua_app::services::authentication::sign_in_gate::ClientOrigin;
use ianua_app::tenancy::ScopedTenant;
use ianua_app::use_cases::authentication::federation::SsoReturn;
use ianua_app::use_cases::authentication::mfa::{FactorSetter, PendingSignIn, SetupProof};
use ianua_app::use_cases::authentication::passkeys::registrant::{self, Registrant};
use ianua_app::use_cases::authentication::sessions::SigningOut;
use ianua_domain::domains::audit::builder::AuditContext;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::config::SlugLimits;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Fact, HttpsUrl, SamlEntityId, SessionId, TenantSlug, UserId};

use crate::error::ApiError;
use crate::extractors::callers::{RequestMeta, TenantCaller};
use crate::state::ApiState;

/// The cookie a browser keeps while it signs in at an identity provider.
pub(crate) const SSO_COOKIE: &str = "ianua_sso";

/// Someone signing in to the tenant the path names, before anyone is
/// identified.
///
/// An unknown organization or tenant is not found. Whether the tenant
/// takes sign-ins now is the app's to say.
pub(crate) struct SignInVisitor {
    /// The tenant the path names.
    pub tenant: ScopedTenant,
    /// Where an emailed link for this tenant lands.
    pub link_scope: LinkScope,
    /// Where the request came from, as a sign-in records it.
    pub origin: ClientOrigin,
    /// Records what the request changes, in the tenant's trail.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for SignInVisitor {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let (org_slug, tenant_slug) = path_slugs(parts, state).await?;
        let organization = state
            .org_store
            .find_by_slug(&org_slug)
            .await
            .map_err(AppError::internal)?
            .ok_or_else(not_found)?;
        let tenant = state
            .tenant_store
            .find_by_slug_in_org(&tenant_slug, organization.id())
            .await
            .map_err(AppError::internal)?
            .ok_or_else(not_found)?;
        let Ok(meta) = RequestMeta::from_request_parts(parts, state).await;
        let context = AuditContext::system()
            .with_organization(*organization.id())
            .with_tenant(*tenant.id())
            .with_request(
                Fact::from_option(meta.ip_address.clone()),
                Fact::from_option(meta.user_agent.clone()),
            );
        Ok(Self {
            tenant: ScopedTenant::from(&ResolvedTenant::new(*tenant.id(), tenant.slug().clone())),
            link_scope: LinkScope::tenant(organization.slug().clone(), tenant.slug().clone()),
            origin: meta.into(),
            auditor: RequestAuditor::new(state.event_dispatcher.clone(), context),
        })
    }
}

impl From<RequestMeta> for ClientOrigin {
    fn from(meta: RequestMeta) -> Self {
        Self {
            ip_address: Fact::from_option(meta.ip_address),
            user_agent: meta.user_agent,
        }
    }
}

/// A tenant user's own session, as the bearer names it, whether or not it
/// finished signing in.
///
/// The bearer is the session's refresh token. It shows a sign-in waiting
/// for its second factor as well as a finished session; which of the two
/// the request may use is the app's to decide.
pub(crate) struct SessionHolder {
    /// Who holds the session, and in which tenant.
    pub caller: CallerContext,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
    session_id: SessionId,
    user_id: UserId,
    refresh_token: Secret,
}

impl FromRequestParts<ApiState> for SessionHolder {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let refresh_token = bearer(&parts.headers).ok_or(ApiError(AppError::Unauthenticated))?;
        let TenantCaller {
            caller, auditor, ..
        } = TenantCaller::from_request_parts(parts, state).await?;
        let (CallerIdentity::TenantUser(user_id), Credential::TenantSession(session_id)) =
            (*caller.identity(), caller.credential().clone())
        else {
            return Err(not_a_session());
        };
        Ok(Self {
            caller,
            auditor,
            session_id,
            user_id,
            refresh_token,
        })
    }
}

impl SessionHolder {
    /// The tenant the session is in.
    #[must_use]
    pub(crate) fn tenant(&self) -> ScopedTenant {
        self.caller.tenant()
    }

    /// Whose session it is.
    #[must_use]
    pub(crate) fn user_id(&self) -> UserId {
        self.user_id
    }

    /// The bearer's own session, as the sign-in a second factor is given
    /// for.
    fn own_sign_in(&self) -> PendingSignIn {
        PendingSignIn {
            tenant: self.tenant(),
            session_id: self.session_id,
            user_id: self.user_id,
        }
    }

    /// Who sets up a factor with `proof`: the person signed in when they
    /// proved who they are again, the sign-in waiting for the factor when
    /// they did not.
    #[must_use]
    pub(crate) fn factor_setter(&self, proof: &SetupProof) -> FactorSetter {
        match proof {
            SetupProof::Reentered(_) => FactorSetter::SignedIn(Box::new(self.caller.clone())),
            SetupProof::OwedBySignIn => FactorSetter::SigningIn(self.own_sign_in()),
        }
    }

    /// Who confirms a factor: the sign-in `completing` names, which the
    /// code finishes, or the person signed in when the request names none.
    ///
    /// A waiting sign-in is shown by its own refresh token, so the one
    /// named must be the session the bearer is. Otherwise whoever holds
    /// another of the person's sessions, and learnt the id of a sign-in
    /// they never finished, could set up their own authenticator on it.
    ///
    /// # Errors
    ///
    /// `403` when the sign-in named is not the bearer's own session.
    pub(crate) fn confirming_setter(
        &self,
        completing: Option<SessionId>,
    ) -> Result<FactorSetter, ApiError> {
        let Some(named) = completing else {
            return Ok(FactorSetter::SignedIn(Box::new(self.caller.clone())));
        };
        if named != self.session_id {
            return Err(ApiError(AppError::Forbidden(message!(
                "api-the-sign-in-named-is-not",
                "the sign-in named is not the one this request comes from"
            ))));
        }
        Ok(FactorSetter::SigningIn(self.own_sign_in()))
    }

    /// The person signed in, adding a passkey.
    #[must_use]
    pub(crate) fn signed_in_registrant(&self) -> Registrant {
        Registrant::SignedIn(Box::new(self.caller.clone()))
    }

    /// The sign-in waiting for its second factor, adding a passkey as that
    /// factor.
    #[must_use]
    pub(crate) fn waiting_registrant(&self) -> Registrant {
        Registrant::SettingUpFactor(registrant::PendingSignIn {
            tenant: self.tenant(),
            refresh_token: self.refresh_token.clone(),
        })
    }

    /// Whoever holds the session's refresh token, ending it.
    #[must_use]
    pub(crate) fn signing_out(&self) -> SigningOut {
        SigningOut::ByToken {
            tenant: self.tenant(),
            refresh_token: self.refresh_token.clone(),
        }
    }
}

/// A browser on its way through single sign-on for the tenant the path
/// names: the visitor, the secret it keeps while it is at the identity
/// provider, and the addresses the provider sends it back to.
pub(crate) struct SsoBrowser {
    /// The tenant, the request's origin and its auditor.
    pub visitor: SignInVisitor,
    /// The secret the browser sent back, or empty when it has none, which
    /// matches no sign-in.
    pub binding: Secret,
    /// Where the identity provider and the browser are sent.
    pub way_back: SsoWayBack,
}

/// The addresses a single sign-on uses, built from the deployment's own
/// address and the tenant's slugs, never from the request.
pub(crate) struct SsoWayBack {
    /// Where an OIDC provider sends the browser back.
    pub oidc_callback: HttpsUrl,
    /// Who this deployment is to a SAML provider, and where it posts.
    pub service_provider: ServiceProvider,
    /// The tenant's pages on the dashboard.
    pub dashboard: String,
    /// The path the browser's secret is sent under: the callbacks only.
    pub cookie_path: String,
    /// How long the browser keeps its secret, in seconds.
    pub cookie_lifetime_secs: u32,
}

impl SsoWayBack {
    /// Where the identity provider sends the browser back to.
    #[must_use]
    pub(crate) fn returns_to(&self) -> SsoReturn {
        SsoReturn {
            oidc_callback: self.oidc_callback.clone(),
            service_provider: self.service_provider.clone(),
        }
    }
}

impl FromRequestParts<ApiState> for SsoBrowser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let (org_slug, tenant_slug) = path_slugs(parts, state).await?;
        let visitor = SignInVisitor::from_request_parts(parts, state).await?;
        let way_back = way_back(
            &state.authentication.app_base_url,
            (&org_slug, &tenant_slug),
            state.http.sso_cookie_lifetime_secs,
        )?;
        Ok(Self {
            visitor,
            binding: Secret::new(sso_binding(&parts.headers)),
            way_back,
        })
    }
}

/// A request the gateway relays over the sealed internal channel, an app
/// sign-in or a question about an agent approval: the seal it put on the
/// request, if the request carries a readable one, and an auditor that
/// knows nothing of the client yet.
///
/// Never refuses: a missing or unreadable seal is `None`, and checking it is
/// the use case's job, which answers an unsealed request as it answers a
/// forged one. A sign-in carries the client's address and user agent inside
/// the sealed body, and its use case adds them once it has opened it.
pub(crate) struct GatewayRelay {
    /// The gateway's seal over the body.
    pub seal: Option<String>,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for GatewayRelay {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self {
            seal: parts
                .headers
                .get(SEAL_HEADER)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
            auditor: RequestAuditor::system(state.event_dispatcher.clone()),
        })
    }
}

/// The organization and tenant slugs the path names. A slug that is not a
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

/// The single sign-on addresses of the tenant `slugs` name, under
/// `app_base_url`.
fn way_back(
    app_base_url: &HttpsUrl,
    (org, tenant): (&TenantSlug, &TenantSlug),
    cookie_lifetime_secs: u32,
) -> Result<SsoWayBack, ApiError> {
    let base = app_base_url.as_str().trim_end_matches('/');
    let federation = format!(
        "/api/v1/organizations/{}/tenants/{}/federation",
        org.as_str(),
        tenant.as_str()
    );
    let address =
        |path: &str| HttpsUrl::new(format!("{base}{federation}{path}")).map_err(AppError::internal);
    Ok(SsoWayBack {
        oidc_callback: address("/oidc/callback")?,
        service_provider: ServiceProvider {
            entity_id: SamlEntityId::new(base).map_err(AppError::internal)?,
            acs_url: address("/saml/acs")?,
        },
        dashboard: format!(
            "{base}/organizations/{}/tenants/{}",
            org.as_str(),
            tenant.as_str()
        ),
        cookie_path: federation,
        cookie_lifetime_secs,
    })
}

/// The single sign-on secret among the request's cookies, or empty.
fn sso_binding(headers: &HeaderMap) -> String {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|header| header.split(';'))
        .find_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            (name == SSO_COOKIE).then(|| value.to_owned())
        })
        .unwrap_or_default()
}

/// The bearer credential the request carries, if any.
fn bearer(headers: &HeaderMap) -> Option<Secret> {
    let header = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let token = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))?
        .trim();
    (!token.is_empty()).then(|| Secret::new(token))
}

/// A plain `404` that says nothing of what was missing.
fn not_found() -> ApiError {
    ApiError(AppError::NotFound(message!("api-not-found", "not found")))
}

/// A credential that is not a tenant user's session, where only one names
/// a sign-in.
fn not_a_session() -> ApiError {
    ApiError(AppError::Forbidden(message!(
        "api-only-a-signed-in-session-acts",
        "only a signed-in session acts here"
    )))
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    /// Request headers carrying the given `Cookie` header.
    fn with_cookie(cookie: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_static(cookie));
        headers
    }

    /// Ann's browser sends other cookies too, and her sign-in secret is
    /// still found among them.
    #[test]
    fn the_sso_secret_is_read_among_other_cookies() {
        let headers = with_cookie("theme=dark; ianua_sso=abc-123; x=1");

        assert_eq!(sso_binding(&headers), "abc-123");
    }

    /// A browser with no sign-in cookie, or only one with a similar name,
    /// holds no secret.
    #[test]
    fn a_browser_without_the_sso_cookie_holds_no_secret() {
        assert_eq!(sso_binding(&HeaderMap::new()), "");
        assert_eq!(sso_binding(&with_cookie("ianua_sso_other=abc")), "");
    }

    /// The callback, the SAML address, the dashboard and the cookie path all
    /// come from the deployment's address and the `acme`/`prod` slugs.
    #[test]
    fn the_way_back_is_built_from_the_deployment_address_and_the_slugs() {
        let limits = SlugLimits::default();
        let org = TenantSlug::new("acme", &limits).unwrap();
        let tenant = TenantSlug::new("prod", &limits).unwrap();
        let base = HttpsUrl::new("https://ianua.example.com/").unwrap();

        let Ok(way) = way_back(&base, (&org, &tenant), 600) else {
            panic!("the way back is built from a valid base address");
        };

        assert_eq!(
            way.oidc_callback.as_str(),
            "https://ianua.example.com/api/v1/organizations/acme/tenants/prod/federation/oidc/callback"
        );
        assert_eq!(
            way.service_provider.acs_url.as_str(),
            "https://ianua.example.com/api/v1/organizations/acme/tenants/prod/federation/saml/acs"
        );
        assert_eq!(
            way.dashboard,
            "https://ianua.example.com/organizations/acme/tenants/prod"
        );
        assert_eq!(
            way.cookie_path,
            "/api/v1/organizations/acme/tenants/prod/federation"
        );
    }

    /// A `Basic` credential is not read as a bearer one.
    #[test]
    fn only_a_bearer_credential_is_read() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic abc"));

        assert!(bearer(&headers).is_none());
    }
}
