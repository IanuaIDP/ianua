//! Signing in through an OpenID Connect provider a tenant set up: the
//! redirect to it, the code it sends back, and the check that its issuer
//! publishes a discovery document.
//!
//! The provider's address is the tenant's choice, so every call to it goes
//! through the screened client: its issuer is refused when it names an
//! internal address, each name it resolves is screened again, nothing
//! follows a redirect, and every call is held to a timeout. The provider's
//! endpoints come from its discovery document, and any of them written as
//! an IP address, which no resolver would screen, is refused. Every answer
//! is read within a size limit, and an ID token is held to the platform's
//! own algorithms and times, never to what the provider lists.
//!
//! What a provider answers is its own text, so it reaches the operator's
//! log and never the person signing in or the administrator: they see a
//! fixed message. The log holds each cause's message alone, never an
//! answer the library kept whole, since a token answer it could not read
//! still holds the tokens.

mod party;
mod transport;

use std::time::Duration;

use async_trait::async_trait;
use der::Encode as _;
use ianua_app::ports::federation::{
    OidcAuthRedirect, OidcClientConfig, OidcCodeExchange, OidcValidator,
};
use ianua_domain::domains::federation::oidc::identity::{OidcIdentityClaims, OidcIdentityParams};
use ianua_domain::domains::federation::provider_values::ProviderValues;
use ianua_domain::message;
use ianua_domain::shared::errors::{DomainError, causes};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::{CertificatePem, ConnectionId, Email, FederatedSubject, HttpsUrl, Nonce};

use crate::crypto::certificates::pem::certificate_in;
use crate::http::calls::reachable;
use crate::http::client::{screened, screened_trusting};
use crate::http::sign_in::oidc::party::{
    ProviderIdentity, ProviderSettings, Redirect, RelyingParty,
};
use crate::http::sign_in::oidc::transport::Screened;

/// What the person signing in is told when the provider's answer does not
/// hold, whatever the provider said.
const EXCHANGE_REFUSED: &str = "the identity provider's answer could not be verified";

/// What an administrator is told when the issuer publishes no usable
/// discovery document.
const ISSUER_REFUSED: &str = "the issuer does not publish a usable OpenID Connect configuration at \
     /.well-known/openid-configuration; it must match the provider's issuer exactly, including \
     any trailing slash";

/// Signs people in through OpenID Connect providers, over the screened
/// client.
///
/// One relying party serves every connection, so a provider's discovery
/// document and keys are fetched once an hour, not on every sign-in.
pub struct HttpOidcValidator {
    party: RelyingParty,
    networks: UpstreamNetworks,
}

impl HttpOidcValidator {
    /// A validator whose calls to a provider give up after `timeout` and
    /// reach only public addresses and those in `networks`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(timeout: Duration, networks: UpstreamNetworks) -> Result<Self, DomainError> {
        let http = screened(timeout, networks.clone())?;
        Ok(Self::using(http, networks))
    }

    /// A validator trusting only the deployment's private certificate
    /// authority. Address screening, redirects and timeouts remain enforced.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` for an unreadable certificate
    /// or a client that cannot be built.
    pub fn trusting(
        timeout: Duration,
        networks: UpstreamNetworks,
        authority: &CertificatePem,
    ) -> Result<Self, DomainError> {
        let certificate = certificate_in(authority.as_str()).map_err(DomainError::infra)?;
        let der = certificate.to_der().map_err(DomainError::infra)?;
        let root = reqwest::Certificate::from_der(&der).map_err(DomainError::infra)?;
        let http = screened_trusting(timeout, networks.clone(), root)?;
        Ok(Self::using(http, networks))
    }

    /// Keeps the same screened transport for discovery and code exchange.
    fn using(http: reqwest::Client, networks: UpstreamNetworks) -> Self {
        Self {
            party: RelyingParty::new(Screened::new(http, networks.clone())),
            networks,
        }
    }

    /// Fetches and checks the discovery document of `issuer`.
    async fn verify_discovery(&self, issuer: &str) -> Result<(), DomainError> {
        reachable(issuer, &self.networks)?;
        self.party.discover(issuer).await.map_err(|error| {
            tracing::warn!(%issuer, error = %causes(&error), "an OpenID Connect issuer did not hold");
            DomainError::invalid(message!("infra-the-issuer-does-not-publish-a", ISSUER_REFUSED))
        })
    }

    /// The redirect to the provider `client` names.
    async fn redirect(&self, client: &ProviderSettings) -> Result<Redirect, DomainError> {
        reachable(&client.issuer, &self.networks)?;
        self.party
            .redirect(client)
            .await
            .map_err(DomainError::infra)
    }

    /// Who the provider `client` names says signed in, for `code`.
    async fn identity(
        &self,
        client: &ProviderSettings,
        code: Code<'_>,
    ) -> Result<ProviderIdentity, DomainError> {
        reachable(&client.issuer, &self.networks)?;
        self.party
            .exchange(client, code)
            .await
            .map_err(|error| {
                tracing::warn!(issuer = %client.issuer, error = %causes(&error), "an OpenID Connect code exchange failed");
                DomainError::invalid(message!("infra-the-identity-provider-s-answer-could", EXCHANGE_REFUSED))
            })
    }
}

/// The code a provider sent back, with what the sign-in began with, as
/// text. Holds secrets, so it has no `Debug`.
#[derive(Clone, Copy)]
struct Code<'a> {
    code: &'a str,
    nonce: &'a str,
    pkce_verifier: &'a str,
}

#[async_trait]
impl OidcValidator for HttpOidcValidator {
    async fn exchange_code(
        &self,
        config: &OidcClientConfig,
        exchange: &OidcCodeExchange<'_>,
        connection_id: &ConnectionId,
    ) -> Result<OidcIdentityClaims, DomainError> {
        let client = client_config(config, exchange.redirect_uri);
        let code = Code {
            code: exchange.code.expose(),
            nonce: exchange.nonce.as_str(),
            pkce_verifier: exchange.pkce_verifier.expose(),
        };
        let identity = self.identity(&client, code).await?;
        claims_of(identity, *connection_id)
    }

    async fn build_authorization_url(
        &self,
        config: &OidcClientConfig,
        redirect_uri: &HttpsUrl,
    ) -> Result<OidcAuthRedirect, DomainError> {
        let redirect = self.redirect(&client_config(config, redirect_uri)).await?;
        redirect_of(redirect)
    }

    async fn confirm_issuer(&self, issuer: &HttpsUrl) -> Result<(), DomainError> {
        self.verify_discovery(issuer.as_str()).await
    }
}

/// The provider `config` names, sending the person back to
/// `redirect_uri`.
///
/// The use case hands the credential over as an opened secret, separately
/// from the sealed configuration kept in storage.
fn client_config(config: &OidcClientConfig, redirect_uri: &HttpsUrl) -> ProviderSettings {
    ProviderSettings {
        issuer: config.issuer.as_str().to_owned(),
        client_id: config.client_id.as_str().to_owned(),
        client_secret: config.client_secret.expose().to_owned(),
        redirect_uri: redirect_uri.as_str().to_owned(),
        scopes: config
            .scopes
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect(),
    }
}

/// The redirect as the port hands it on. The URL is the provider's
/// authorization endpoint, so one that is not HTTPS is the provider's fault.
fn redirect_of(redirect: Redirect) -> Result<OidcAuthRedirect, DomainError> {
    Ok(OidcAuthRedirect {
        url: HttpsUrl::new(redirect.url).map_err(DomainError::infra)?,
        state: Secret::new(redirect.state),
        nonce: Nonce::new(redirect.nonce).map_err(DomainError::infra)?,
        pkce_verifier: Secret::new(redirect.pkce_verifier),
    })
}

/// The claims of `identity`, from the connection `connection_id`.
///
/// Every other claim holding text, such as `groups`, goes on to the
/// connection's mapping rules.
///
/// # Errors
///
/// Returns `DomainError::Validation` when the token names no email address,
/// or an email or subject that does not read as one.
fn claims_of(
    identity: ProviderIdentity,
    connection_id: ConnectionId,
) -> Result<OidcIdentityClaims, DomainError> {
    let Some(email) = identity.email else {
        return Err(DomainError::invalid(message!(
            "infra-the-identity-provider-named-no-email",
            "the identity provider named no email address"
        )));
    };
    Ok(OidcIdentityClaims::new(OidcIdentityParams {
        connection_id,
        sub: FederatedSubject::new(identity.sub)?,
        email: Email::new(email)?,
        email_verified: identity.email_verified,
        amr: identity.amr,
        name: identity.name,
        given_name: identity.given_name,
        family_name: identity.family_name,
        picture: identity.picture,
        locale: identity.locale,
        claims: ProviderValues::new(identity.others),
    }))
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::{Value, json};
    use sha2::Sha256;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::crypto::certificates::rsa_keys::RsaSigningKey;
    use crate::http::calls::tests::loopback;

    const NONCE: &str = "nonce-of-this-sign-in-0123456789";
    const CLIENT_ID: &str = "ianua-client";

    /// A provider standing in for a real one: its discovery document, its
    /// keys, and a token endpoint answering with `id_token`.
    struct Provider {
        server: MockServer,
        issuer: String,
    }

    impl Provider {
        async fn publishing(key: &RsaSigningKey, issuer_named: Option<&str>) -> Self {
            let server = MockServer::start().await;
            let issuer = server.uri().replace("127.0.0.1", "localhost");
            let named = issuer_named.map_or_else(|| issuer.clone(), str::to_owned);
            mount_json(
                &server,
                "/.well-known/openid-configuration",
                discovery(&issuer, &named),
            )
            .await;
            mount_json(&server, "/jwks", jwks(key)).await;
            Self { server, issuer }
        }

        async fn answering_with(&self, id_token: &str) {
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "access_token": "at",
                    "token_type": "Bearer",
                    "expires_in": 300,
                    "id_token": id_token,
                })))
                .mount(&self.server)
                .await;
        }

        fn client(&self) -> ProviderSettings {
            ProviderSettings {
                issuer: self.issuer.clone(),
                client_id: CLIENT_ID.to_owned(),
                client_secret: "client-secret".to_owned(),
                redirect_uri: "https://ianua.example/callback".to_owned(),
                scopes: vec!["openid".to_owned(), "email".to_owned()],
            }
        }
    }

    async fn mount_json(server: &MockServer, route: &str, body: Value) {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    fn discovery(at: &str, issuer: &str) -> Value {
        json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{at}/authorize"),
            "token_endpoint": format!("{at}/token"),
            "jwks_uri": format!("{at}/jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
        })
    }

    fn jwks(key: &RsaSigningKey) -> Value {
        let public = key.public_key();
        json!({"keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "k1",
            "n": URL_SAFE_NO_PAD.encode(public.modulus()),
            "e": URL_SAFE_NO_PAD.encode(public.exponent()),
        }]})
    }

    fn test_key() -> RsaSigningKey {
        let (key, _) = RsaSigningKey::generated().unwrap();
        key
    }

    /// An ID token for Ada from `issuer`, carrying `nonce`, signed with
    /// `key`.
    fn id_token(key: &RsaSigningKey, issuer: &str, nonce: &str) -> String {
        signed(key, &ada_claims(issuer, nonce))
    }

    /// Ada's claims from `issuer`, carrying `nonce`, issued now.
    fn ada_claims(issuer: &str, nonce: &str) -> Value {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        json!({
            "iss": issuer,
            "aud": CLIENT_ID,
            "sub": "ada-at-the-provider",
            "email": "ada@acme.com",
            "email_verified": true,
            "nonce": nonce,
            "iat": now,
            "exp": now + 300,
        })
    }

    /// `claims` as a token signed with `key` under RS256.
    fn signed(key: &RsaSigningKey, claims: &Value) -> String {
        let input = signing_input("RS256", claims);
        let signature = key.sign_sha256(input.as_bytes()).unwrap();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    /// The header and claims of a token signed under `alg`, as they are
    /// signed.
    fn signing_input(alg: &str, claims: &Value) -> String {
        let header = json!({"alg": alg, "kid": "k1", "typ": "JWT"});
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    }

    fn validator(networks: UpstreamNetworks) -> HttpOidcValidator {
        HttpOidcValidator::new(Duration::from_secs(5), networks).unwrap()
    }

    fn code(nonce: &str) -> Code<'_> {
        Code {
            code: "the-code",
            nonce,
            pkce_verifier: "the-verifier-of-this-sign-in",
        }
    }

    /// An issuer whose discovery document names it as the issuer is
    /// confirmed.
    #[tokio::test]
    async fn an_issuer_naming_itself_is_confirmed() {
        let provider = Provider::publishing(&test_key(), None).await;

        let result = validator(loopback())
            .verify_discovery(&provider.issuer)
            .await;

        assert!(result.is_ok());
    }

    /// Discovery naming a different issuer returns a validation error.
    #[tokio::test]
    async fn an_issuer_naming_another_is_refused() {
        let provider = Provider::publishing(&test_key(), Some("https://other.example")).await;

        let result = validator(loopback())
            .verify_discovery(&provider.issuer)
            .await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// An issuer resolving to disallowed loopback addresses returns a
    /// validation error without receiving a discovery request.
    #[tokio::test]
    async fn an_issuer_resolving_inside_the_deployment_is_refused() {
        let provider = Provider::publishing(&test_key(), None).await;

        let result = validator(UpstreamNetworks::public_only())
            .verify_discovery(&provider.issuer)
            .await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(
            provider
                .server
                .received_requests()
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// A literal metadata address fails issuer validation.
    #[tokio::test]
    async fn an_issuer_written_as_an_internal_address_is_refused() {
        let result = validator(UpstreamNetworks::public_only())
            .verify_discovery("http://169.254.169.254")
            .await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// The provider's code is swapped for a signed ID token, and Ada's
    /// subject and email come back as claims.
    #[tokio::test]
    async fn a_code_is_exchanged_for_the_claims_it_names() {
        let key = test_key();
        let provider = Provider::publishing(&key, None).await;
        provider
            .answering_with(&id_token(&key, &provider.issuer, NONCE))
            .await;

        let identity = validator(loopback())
            .identity(&provider.client(), code(NONCE))
            .await
            .unwrap();
        let claims = claims_of(identity, ConnectionId::new()).unwrap();

        assert_eq!(claims.sub().as_str(), "ada-at-the-provider");
        assert_eq!(claims.email().as_str(), "ada@acme.com");
    }

    /// An otherwise valid ID token carrying another sign-in's nonce returns
    /// a validation error.
    #[tokio::test]
    async fn a_token_with_another_nonce_is_refused() {
        let key = test_key();
        let provider = Provider::publishing(&key, None).await;
        provider
            .answering_with(&id_token(
                &key,
                &provider.issuer,
                "nonce-of-another-sign-in-0123",
            ))
            .await;

        let result = validator(loopback())
            .identity(&provider.client(), code(NONCE))
            .await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// An ID token signed by a key outside the provider's published set
    /// returns a validation error.
    #[tokio::test]
    async fn a_token_signed_by_another_key_is_refused() {
        let provider = Provider::publishing(&test_key(), None).await;
        provider
            .answering_with(&id_token(&test_key(), &provider.issuer, NONCE))
            .await;

        let result = validator(loopback())
            .identity(&provider.client(), code(NONCE))
            .await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// The groups the provider names reach the connection's mapping rules.
    #[tokio::test]
    async fn the_groups_a_provider_names_reach_the_claims() {
        let key = test_key();
        let provider = Provider::publishing(&key, None).await;
        let mut claims = ada_claims(&provider.issuer, NONCE);
        claims["groups"] = json!(["admins", "staff"]);
        provider.answering_with(&signed(&key, &claims)).await;

        let identity = validator(loopback())
            .identity(&provider.client(), code(NONCE))
            .await
            .unwrap();
        let claims = claims_of(identity, ConnectionId::new()).unwrap();

        assert_eq!(claims.claims().values("groups"), ["admins", "staff"]);
    }

    /// An HS256 ID token signed with the client secret returns a validation
    /// error even when discovery lists that algorithm.
    #[tokio::test]
    async fn a_token_signed_with_the_client_secret_is_refused() {
        let provider = Provider::publishing(&test_key(), None).await;
        let input = signing_input("HS256", &ada_claims(&provider.issuer, NONCE));
        let mut mac = <hmac::Hmac<Sha256> as hmac::Mac>::new_from_slice(b"client-secret").unwrap();
        hmac::Mac::update(&mut mac, input.as_bytes());
        let tag = hmac::Mac::finalize(mac).into_bytes();
        provider
            .answering_with(&format!("{input}.{}", URL_SAFE_NO_PAD.encode(tag)))
            .await;

        let result = validator(loopback())
            .identity(&provider.client(), code(NONCE))
            .await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// Whether the token `make` builds from Ada's claims, signed by the
    /// provider's own key, is refused.
    async fn refused(make: impl FnOnce(&RsaSigningKey, Value) -> String) -> bool {
        let key = test_key();
        let provider = Provider::publishing(&key, None).await;
        let token = make(&key, ada_claims(&provider.issuer, NONCE));
        provider.answering_with(&token).await;
        let result = validator(loopback())
            .identity(&provider.client(), code(NONCE))
            .await;
        matches!(result, Err(DomainError::Validation(_)))
    }

    /// An expired ID token fails validation despite a valid provider signature.
    #[tokio::test]
    async fn an_expired_token_is_refused() {
        let past = time::OffsetDateTime::now_utc().unix_timestamp() - 60;

        let refused = refused(|key, mut claims| {
            claims["exp"] = json!(past);
            signed(key, &claims)
        })
        .await;

        assert!(refused);
    }

    /// A signed ID token naming another client as its audience fails validation.
    #[tokio::test]
    async fn a_token_for_another_audience_is_refused() {
        let refused = refused(|key, mut claims| {
            claims["aud"] = json!("another-client");
            signed(key, &claims)
        })
        .await;

        assert!(refused);
    }

    /// A signed ID token naming another issuer fails validation.
    #[tokio::test]
    async fn a_token_from_another_issuer_is_refused() {
        let refused = refused(|key, mut claims| {
            claims["iss"] = json!("https://other.example");
            signed(key, &claims)
        })
        .await;

        assert!(refused);
    }

    /// A signed ID token without a nonce fails validation.
    #[tokio::test]
    async fn a_token_without_a_nonce_is_refused() {
        let refused = refused(|key, mut claims| {
            claims.as_object_mut().unwrap().remove("nonce");
            signed(key, &claims)
        })
        .await;

        assert!(refused);
    }

    /// An unsigned ID token declaring `alg: none` fails validation.
    #[tokio::test]
    async fn an_unsigned_token_is_refused() {
        let refused = refused(|_, claims| format!("{}.", signing_input("none", &claims))).await;

        assert!(refused);
    }

    /// Discovery pointing its key set at the literal metadata IP returns a
    /// validation error.
    #[tokio::test]
    async fn an_endpoint_written_as_an_ip_address_is_refused() {
        let server = MockServer::start().await;
        let issuer = server.uri().replace("127.0.0.1", "localhost");
        let mut document = discovery(&issuer, &issuer);
        document["jwks_uri"] = json!("http://169.254.169.254/keys");
        mount_json(&server, "/.well-known/openid-configuration", document).await;

        let result = validator(loopback()).verify_discovery(&issuer).await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A malformed token response produces an error cause naming the failed
    /// exchange and excluding both access and refresh token values.
    #[tokio::test]
    async fn an_unreadable_token_answer_is_logged_without_its_tokens() {
        let provider = Provider::publishing(&test_key(), None).await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "access-token-distinctive",
                "refresh_token": "refresh-token-distinctive",
                "token_type": "Bearer",
                "expires_in": {},
            })))
            .mount(&provider.server)
            .await;
        let code = code(NONCE);

        let error = validator(loopback())
            .party
            .exchange(&provider.client(), code)
            .await
            .err()
            .unwrap();

        let logged = causes(&error);
        assert!(logged.contains("token exchange failed"), "{logged}");
        assert!(!logged.contains("token-distinctive"), "{logged}");
    }

    /// A signed ID token issued an hour ago fails validation even while its
    /// expiry remains in the future.
    #[tokio::test]
    async fn a_token_issued_long_ago_is_refused() {
        let key = test_key();
        let provider = Provider::publishing(&key, None).await;
        let mut claims = ada_claims(&provider.issuer, NONCE);
        let hour_ago = time::OffsetDateTime::now_utc().unix_timestamp() - 3600;
        claims["iat"] = json!(hour_ago);
        provider.answering_with(&signed(&key, &claims)).await;

        let result = validator(loopback())
            .identity(&provider.client(), code(NONCE))
            .await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A provider identity without an email address fails claim conversion
    /// with a validation error.
    #[test]
    fn an_identity_without_an_email_is_refused() {
        let identity = ProviderIdentity {
            sub: "ada".to_owned(),
            email: None,
            email_verified: None,
            amr: Vec::new(),
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            locale: None,
            others: std::collections::HashMap::new(),
        };

        let result = claims_of(identity, ConnectionId::new());

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A plain-HTTP authorization address fails redirect conversion.
    #[test]
    fn a_redirect_to_plain_http_is_refused() {
        let redirect = Redirect {
            url: "http://idp.example/authorize".to_owned(),
            state: "state".to_owned(),
            nonce: NONCE.to_owned(),
            pkce_verifier: "verifier".to_owned(),
        };

        assert!(redirect_of(redirect).is_err());
    }
}
