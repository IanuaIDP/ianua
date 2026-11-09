//! The OIDC discovery document a tenant publishes, so relying parties can
//! configure themselves (OpenID Connect Discovery 1.0 3, RFC 8414 2), with
//! every endpoint and capability the tenant answers.

use ianua_app::ports::oauth::DPOP_SIGNING_ALGORITHMS;
use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
use ianua_domain::domains::oauth::clients::credential::TokenEndpointAuthMethod;
use ianua_domain::types::Issuer;
use serde::Serialize;

use crate::extractors::oauth::token::GRANT_TYPES;

/// The ways a client may prove itself here: every registered method but
/// `tls_client_auth`, since no TLS client certificate reaches the API.
const AUTH_METHODS: [TokenEndpointAuthMethod; 4] = [
    TokenEndpointAuthMethod::ClientSecretBasic,
    TokenEndpointAuthMethod::ClientSecretPost,
    TokenEndpointAuthMethod::PrivateKeyJwt,
    TokenEndpointAuthMethod::None,
];

/// The algorithms a tenant's keys sign with; a tenant moves between them
/// with an algorithm migration.
const SIGNING_ALGORITHMS: [&str; 3] = ["RS256", "ES256", "EdDSA"];

/// The tenant's protocol endpoints and capabilities, used by relying parties to configure
/// sign-in.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OidcDiscoveryDocument {
    /// The tenant's issuer identifier.
    pub issuer: String,
    /// URL of the authorization endpoint.
    pub authorization_endpoint: String,
    /// URL of the token endpoint.
    pub token_endpoint: String,
    /// URL of the JWKS document.
    pub jwks_uri: String,
    /// URL of the `userinfo` endpoint.
    pub userinfo_endpoint: String,
    /// URL of the pushed authorization request endpoint (RFC 9126).
    pub pushed_authorization_request_endpoint: String,
    /// URL of the device authorization endpoint (RFC 8628).
    pub device_authorization_endpoint: String,
    /// URL of the introspection endpoint (RFC 7662).
    pub introspection_endpoint: String,
    /// URL of the revocation endpoint (RFC 7009).
    pub revocation_endpoint: String,
    /// URL of the end session endpoint (RP-Initiated Logout).
    pub end_session_endpoint: String,
    /// URL of the dynamic client registration endpoint (RFC 7591); an app
    /// registers with an initial access token the tenant handed out.
    pub registration_endpoint: String,
    /// The authorization results a client may request; currently only `code`.
    pub response_types_supported: Vec<&'static str>,
    /// The ways an authorization result can return to the client: query or form post.
    pub response_modes_supported: Vec<&'static str>,
    /// The flows accepted by the token endpoint, using their protocol spellings.
    pub grant_types_supported: Vec<&'static str>,
    /// Supported subject identifier types.
    pub subject_types_supported: Vec<&'static str>,
    /// Supported ID token signing algorithms.
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    /// The permission and identity bundles advertised to relying parties.
    pub scopes_supported: Vec<&'static str>,
    /// The attributes an ID token or userinfo response may contain.
    pub claims_supported: Vec<&'static str>,
    /// Supported authentication context classes.
    pub acr_values_supported: Vec<&'static str>,
    /// The interactions a client may request, including silent sign-in and fresh consent.
    pub prompt_values_supported: Vec<&'static str>,
    /// Supported token endpoint client authentication methods.
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    /// Supported algorithms for a client's signed assertion.
    pub token_endpoint_auth_signing_alg_values_supported: Vec<&'static str>,
    /// Supported introspection endpoint client authentication methods.
    pub introspection_endpoint_auth_methods_supported: Vec<&'static str>,
    /// Supported revocation endpoint client authentication methods.
    pub revocation_endpoint_auth_methods_supported: Vec<&'static str>,
    /// Supported PKCE methods.
    pub code_challenge_methods_supported: Vec<&'static str>,
    /// The algorithms a `DPoP` proof may be signed with (RFC 9449 5.1).
    /// Certificate-bound tokens (`tls_client_certificate_bound_access_tokens`)
    /// are not offered: no TLS client certificate reaches the API.
    pub dpop_signing_alg_values_supported: Vec<&'static str>,
    /// Whether an authorization answer names its issuer (RFC 9207).
    pub authorization_response_iss_parameter_supported: bool,
    /// Whether a pushed request is required; it is not.
    pub require_pushed_authorization_requests: bool,
    /// Whether apps can be told of a sign-out over the back channel.
    pub backchannel_logout_supported: bool,
    /// Whether the back-channel logout token names the session.
    pub backchannel_logout_session_supported: bool,
    /// Whether apps can be told of a sign-out in the browser.
    pub frontchannel_logout_supported: bool,
    /// Whether the front-channel page is told the issuer and session.
    pub frontchannel_logout_session_supported: bool,
}

impl From<&Issuer> for OidcDiscoveryDocument {
    fn from(issuer: &Issuer) -> Self {
        let methods = AUTH_METHODS.iter().map(|method| method.as_str()).collect();
        Self::configured(issuer.as_str(), methods)
    }
}

impl OidcDiscoveryDocument {
    /// Keeps the flat discovery contract together after selecting offered authentication methods.
    #[allow(clippy::too_many_lines)]
    fn configured(base: &str, methods: Vec<&'static str>) -> Self {
        let at = |path: &str| format!("{base}{path}");
        Self {
            issuer: base.to_owned(),
            authorization_endpoint: at("/oauth/authorize"),
            token_endpoint: at("/oauth/token"),
            jwks_uri: at("/.well-known/jwks.json"),
            userinfo_endpoint: at("/oauth/userinfo"),
            pushed_authorization_request_endpoint: at("/oauth/par"),
            device_authorization_endpoint: at("/oauth/device/code"),
            introspection_endpoint: at("/oauth/introspect"),
            revocation_endpoint: at("/oauth/revoke"),
            end_session_endpoint: at("/oauth/logout"),
            registration_endpoint: at("/oauth/register"),
            response_types_supported: vec!["code"],
            response_modes_supported: vec!["query", "form_post"],
            grant_types_supported: GRANT_TYPES.to_vec(),
            subject_types_supported: vec!["public"],
            id_token_signing_alg_values_supported: SIGNING_ALGORITHMS.to_vec(),
            scopes_supported: vec!["openid", "email", "profile", "roles"],
            claims_supported: CLAIMS.to_vec(),
            acr_values_supported: AssuranceLevel::ALL.iter().map(|l| l.acr()).collect(),
            prompt_values_supported: vec!["none", "login", "consent", "select_account"],
            token_endpoint_auth_methods_supported: methods.clone(),
            token_endpoint_auth_signing_alg_values_supported: SIGNING_ALGORITHMS.to_vec(),
            introspection_endpoint_auth_methods_supported: methods.clone(),
            revocation_endpoint_auth_methods_supported: methods,
            code_challenge_methods_supported: vec!["S256"],
            dpop_signing_alg_values_supported: DPOP_SIGNING_ALGORITHMS.to_vec(),
            authorization_response_iss_parameter_supported: true,
            require_pushed_authorization_requests: false,
            backchannel_logout_supported: true,
            backchannel_logout_session_supported: true,
            frontchannel_logout_supported: true,
            frontchannel_logout_session_supported: true,
        }
    }
}

/// The claims an ID token or `userinfo` may carry.
const CLAIMS: [&str; 19] = [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "sid",
    "at_hash",
    "email",
    "email_verified",
    "name",
    "locale",
    "zoneinfo",
    "roles",
    "aal",
    "tenant_id",
];
