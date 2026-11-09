//! The relying party: the redirect to a provider, the code it sends back
//! exchanged for an ID token, and that token checked.
//!
//! One relying party serves every connection. A provider's discovery
//! document and keys are fetched once an hour per issuer, and every call
//! goes through the screened client with its answer read within a limit.
//!
//! An ID token is held to what this platform allows, never to what the
//! provider's document lists: it is signed with an asymmetric key in one of
//! [`PINNED_ALGORITHMS`], never with the client secret and never unsigned;
//! its issuer, audience, expiry and nonce are checked, and it was issued
//! within [`ISSUED_WITHIN`] of now, give or take [`CLOCK_SKEW`].

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ianua_domain::shared::clock;
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey,
    CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata,
    CoreResponseType, CoreRevocableToken, CoreRevocationErrorResponse,
    CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
    AdditionalClaims, AuthenticationFlow, AuthorizationCode, Client, ClientId, ClientSecret,
    CsrfToken, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet, IdTokenClaims,
    IdTokenFields, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    StandardErrorResponse, StandardTokenResponse, TokenResponse, TokenUrl, UserInfoUrl,
};
use serde::{Deserialize, Serialize};

use crate::http::sign_in::oidc::Code;
use crate::http::sign_in::oidc::transport::Screened;

/// How long a provider's discovery document is kept per issuer.
const METADATA_TTL: Duration = Duration::from_secs(3600);

/// The most issuers whose documents are kept at once: far past the
/// providers a deployment's tenants really sign in through.
const MOST_ISSUERS: usize = 1024;

/// The algorithms an ID token may be signed with: asymmetric ones only, so
/// a token is never taken on the client secret the platform also holds.
const PINNED_ALGORITHMS: [CoreJwsSigningAlgorithm; 6] = [
    CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
    CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384,
    CoreJwsSigningAlgorithm::RsaSsaPssSha256,
    CoreJwsSigningAlgorithm::EcdsaP256Sha256,
    CoreJwsSigningAlgorithm::EcdsaP384Sha384,
    CoreJwsSigningAlgorithm::EdDsa,
];

/// How long before now an ID token may have been issued: it is exchanged
/// for at once, so an older one is a replay.
const ISSUED_WITHIN: i64 = 10 * 60;

/// How far a provider's clock may run ahead of ours.
const CLOCK_SKEW: i64 = 60;

/// Every claim of an ID token beyond the standard ones, such as `groups`,
/// as the provider sent it.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct OtherClaims {
    #[serde(flatten)]
    claims: HashMap<String, serde_json::Value>,
}

impl AdditionalClaims for OtherClaims {}

/// The ID token fields, with the other claims kept.
type TokenFields = IdTokenFields<
    OtherClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

/// A client of one provider, as discovery leaves it: its authorization
/// endpoint set, its token and user info endpoints as the document says.
type ProviderClient = Client<
    OtherClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    StandardTokenResponse<TokenFields, CoreTokenType>,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// Why a step with a provider failed, in the provider's own words, for the
/// operator's log only.
#[derive(Debug, thiserror::Error)]
pub(super) enum PartyError {
    /// The discovery document could not be fetched, read or trusted.
    #[error("discovery failed")]
    Discovery(#[source] Cause),
    /// The redirect to the provider could not be built.
    #[error("the redirect could not be built")]
    Redirect(#[source] Cause),
    /// The provider refused the code, or its answer could not be read.
    #[error("the token exchange failed")]
    Exchange(#[source] Cause),
    /// The ID token did not hold.
    #[error("the ID token does not hold")]
    Token(#[source] Cause),
}

/// What went wrong under a [`PartyError`], kept whole for the log.
type Cause = Box<dyn std::error::Error + Send + Sync>;

/// One provider as a connection names it.
#[derive(Clone)]
pub(super) struct ProviderSettings {
    /// The issuer, where its discovery document is read from.
    pub(super) issuer: String,
    /// The client id the provider gave the tenant.
    pub(super) client_id: String,
    /// The client secret, opened for this call.
    pub(super) client_secret: String,
    /// Where the provider sends the person back.
    pub(super) redirect_uri: String,
    /// The scopes asked for.
    pub(super) scopes: Vec<String>,
}

/// Shows no client secret.
impl std::fmt::Debug for ProviderSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderSettings")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .finish_non_exhaustive()
    }
}

/// Where to send the person, and what the sign-in must keep until the
/// provider sends them back.
pub(super) struct Redirect {
    /// The provider's authorization address.
    pub(super) url: String,
    /// The `state` the callback must carry.
    pub(super) state: String,
    /// The nonce the ID token must carry.
    pub(super) nonce: String,
    /// The PKCE verifier the code is exchanged with.
    pub(super) pkce_verifier: String,
}

/// Who a checked ID token says signed in.
pub(super) struct ProviderIdentity {
    /// The subject, unique at the provider.
    pub(super) sub: String,
    /// The email address.
    pub(super) email: Option<String>,
    /// Whether the provider verified it.
    pub(super) email_verified: Option<bool>,
    /// How the person signed in at the provider.
    pub(super) amr: Vec<String>,
    /// The full name.
    pub(super) name: Option<String>,
    /// Personal name from the checked provider claims, when supplied.
    pub(super) given_name: Option<String>,
    /// Surname from the checked provider claims, when supplied.
    pub(super) family_name: Option<String>,
    /// The picture's address.
    pub(super) picture: Option<String>,
    /// Language preference reported by the identity provider.
    pub(super) locale: Option<String>,
    /// Every other claim holding text or a list of text, such as `groups`,
    /// for the connection's mapping rules.
    pub(super) others: HashMap<String, Vec<String>>,
}

/// The relying party every connection signs in through.
pub(super) struct RelyingParty {
    transport: Screened,
    discovered: Mutex<HashMap<String, (CoreProviderMetadata, Instant)>>,
}

impl RelyingParty {
    /// A relying party calling providers through `transport`.
    pub(super) fn new(transport: Screened) -> Self {
        Self {
            transport,
            discovered: Mutex::new(HashMap::new()),
        }
    }

    /// Fetches and checks `issuer`'s discovery document, keeping it for
    /// the sign-ins that follow.
    ///
    /// # Errors
    ///
    /// [`PartyError::Discovery`] when the document cannot be fetched or
    /// read, names another issuer, or names an endpoint by IP address.
    pub(super) async fn discover(&self, issuer: &str) -> Result<(), PartyError> {
        self.metadata(issuer).await.map(|_| ())
    }

    /// The redirect to the provider `settings` names.
    ///
    /// # Errors
    ///
    /// [`PartyError::Discovery`] or [`PartyError::Redirect`] when it cannot
    /// be built.
    pub(super) async fn redirect(
        &self,
        settings: &ProviderSettings,
    ) -> Result<Redirect, PartyError> {
        let client = self.client(settings).await?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut asked = client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge);
        for scope in settings.scopes.iter().filter(|scope| *scope != "openid") {
            asked = asked.add_scope(Scope::new(scope.clone()));
        }
        let (url, state, nonce) = asked.url();
        Ok(Redirect {
            url: url.to_string(),
            state: state.secret().clone(),
            nonce: nonce.secret().clone(),
            pkce_verifier: verifier.secret().clone(),
        })
    }

    /// Exchanges `code` for an ID token, checks it and reads who signed in.
    ///
    /// # Errors
    ///
    /// - [`PartyError::Discovery`] when the provider cannot be discovered.
    /// - [`PartyError::Exchange`] when the provider refuses the code.
    /// - [`PartyError::Token`] when the ID token is missing or does not
    ///   hold.
    pub(super) async fn exchange(
        &self,
        settings: &ProviderSettings,
        code: Code<'_>,
    ) -> Result<ProviderIdentity, PartyError> {
        let client = self.client(settings).await?;
        let answer = client
            .exchange_code(AuthorizationCode::new(code.code.to_owned()))
            .map_err(|error| PartyError::Exchange(Box::new(error)))?
            .set_pkce_verifier(PkceCodeVerifier::new(code.pkce_verifier.to_owned()))
            .request_async(&self.transport)
            .await
            .map_err(|error| PartyError::Exchange(Box::new(error)))?;
        let token = answer
            .id_token()
            .ok_or_else(|| PartyError::Token("the answer holds no ID token".into()))?;
        let verifier = client
            .id_token_verifier()
            .set_allowed_algs(PINNED_ALGORITHMS)
            .set_issue_time_verifier_fn(|issued| ensure_recent_issue(issued.timestamp()));
        let claims = token
            .claims(&verifier, &Nonce::new(code.nonce.to_owned()))
            .map_err(|error| PartyError::Token(Box::new(error)))?;
        Ok(provider_identity(claims))
    }

    /// The client of the provider `settings` names, from its document.
    async fn client(&self, settings: &ProviderSettings) -> Result<ProviderClient, PartyError> {
        let metadata = self.metadata(&settings.issuer).await?;
        let redirect = RedirectUrl::new(settings.redirect_uri.clone())
            .map_err(|error| PartyError::Redirect(Box::new(error)))?;
        Ok(ProviderClient::from_provider_metadata(
            metadata,
            ClientId::new(settings.client_id.clone()),
            Some(ClientSecret::new(settings.client_secret.clone())),
        )
        .set_redirect_uri(redirect))
    }

    /// `issuer`'s discovery document, read again once it is older than
    /// [`METADATA_TTL`].
    async fn metadata(&self, issuer: &str) -> Result<CoreProviderMetadata, PartyError> {
        if let Some(kept) = self.kept(issuer) {
            return Ok(kept);
        }
        let url = IssuerUrl::new(issuer.to_owned())
            .map_err(|error| PartyError::Discovery(Box::new(error)))?;
        let metadata = CoreProviderMetadata::discover_async(url, &self.transport)
            .await
            .map_err(|error| PartyError::Discovery(Box::new(error)))?;
        ensure_named_endpoints(&metadata)?;
        self.keep(issuer.to_owned(), metadata.clone());
        Ok(metadata)
    }

    /// The document kept for `issuer`, while it is fresh.
    fn kept(&self, issuer: &str) -> Option<CoreProviderMetadata> {
        let discovered = self
            .discovered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (metadata, fetched_at) = discovered.get(issuer)?;
        (fetched_at.elapsed() < METADATA_TTL).then(|| metadata.clone())
    }

    /// Keeps `metadata` as `issuer`'s document, making room for it first.
    fn keep(&self, issuer: String, metadata: CoreProviderMetadata) {
        let mut discovered = self
            .discovered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        make_room(&mut discovered, &issuer, now);
        discovered.insert(issuer, (metadata, now));
    }
}

/// Copies the verified provider claims into the connection's identity representation.
fn provider_identity(claims: &IdTokenClaims<OtherClaims, CoreGenderClaim>) -> ProviderIdentity {
    ProviderIdentity {
        sub: claims.subject().to_string(),
        email: claims.email().map(|email| email.as_str().to_owned()),
        email_verified: claims.email_verified(),
        amr: claims
            .auth_method_refs()
            .map(|methods| methods.iter().map(|m| m.as_str().to_owned()).collect())
            .unwrap_or_default(),
        name: claims
            .name()
            .and_then(|n| n.get(None))
            .map(|n| n.as_str().to_owned()),
        given_name: claims
            .given_name()
            .and_then(|n| n.get(None))
            .map(|n| n.as_str().to_owned()),
        family_name: claims
            .family_name()
            .and_then(|n| n.get(None))
            .map(|n| n.as_str().to_owned()),
        picture: claims
            .picture()
            .and_then(|p| p.get(None))
            .map(|p| p.as_str().to_owned()),
        locale: claims.locale().map(ToString::to_string),
        others: texts_of(&claims.additional_claims().claims),
    }
}

/// Drops every document past [`METADATA_TTL`] at `now` from `kept`, then,
/// when another issuer still could not be kept within [`MOST_ISSUERS`], the
/// oldest one, so a stream of made-up issuers never grows the process.
fn make_room<T>(kept: &mut HashMap<String, (T, Instant)>, issuer: &str, now: Instant) {
    kept.retain(|_, (_, fetched_at)| now.saturating_duration_since(*fetched_at) < METADATA_TTL);
    if kept.len() < MOST_ISSUERS || kept.contains_key(issuer) {
        return;
    }
    let oldest = kept
        .iter()
        .min_by_key(|(_, (_, fetched_at))| *fetched_at)
        .map(|(name, _)| name.clone());
    if let Some(oldest) = oldest {
        kept.remove(&oldest);
    }
}

/// Whether a token issued at `issued`, in seconds since the epoch, was
/// issued within [`ISSUED_WITHIN`] before now, and not more than
/// [`CLOCK_SKEW`] ahead of it.
fn ensure_recent_issue(issued: i64) -> Result<(), String> {
    let now = clock::now().unix_timestamp();
    if issued > now.saturating_add(CLOCK_SKEW) {
        return Err("the ID token was issued in the future".to_owned());
    }
    if issued < now.saturating_sub(ISSUED_WITHIN) {
        return Err("the ID token was issued too long ago".to_owned());
    }
    Ok(())
}

/// The claims of `claims` that hold text or a list of text, each as its
/// values, in the order sent. Any other claim is left out.
fn texts_of(claims: &HashMap<String, serde_json::Value>) -> HashMap<String, Vec<String>> {
    claims
        .iter()
        .filter_map(|(name, value)| Some((name.clone(), texts(value)?)))
        .collect()
}

/// `value` as text values: one for a string, each string of a list of
/// strings, and none for anything else.
fn texts(value: &serde_json::Value) -> Option<Vec<String>> {
    match value {
        serde_json::Value::String(text) => Some(vec![text.clone()]),
        serde_json::Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect(),
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::Object(_) => None,
    }
}

/// Refuses a provider whose server-side endpoints are named by IP address.
///
/// The client screens the addresses names resolve to, but a URL naming an
/// IP address is never resolved, so it would reach whatever it names
/// unchecked. The discovery document is the provider's to write, so
/// without this a provider could point the key or token endpoint at an
/// internal service.
fn ensure_named_endpoints(metadata: &CoreProviderMetadata) -> Result<(), PartyError> {
    let fetched = [
        Some(metadata.jwks_uri().url()),
        metadata.token_endpoint().map(TokenUrl::url),
        metadata.userinfo_endpoint().map(UserInfoUrl::url),
    ];
    let Some(by_address) = fetched
        .into_iter()
        .flatten()
        .find(|url| !matches!(url.host(), Some(openidconnect::url::Host::Domain(_))))
    else {
        return Ok(());
    };
    Err(PartyError::Discovery(
        format!("endpoint {by_address} is not named by host name").into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A token issued just now, or a little ahead within the skew, holds.
    #[test]
    fn a_token_issued_just_now_holds() {
        let now = clock::now().unix_timestamp();

        assert!(ensure_recent_issue(now).is_ok());
        assert!(ensure_recent_issue(now + CLOCK_SKEW - 1).is_ok());
    }

    /// Issue times beyond the permitted future skew or maximum age fail
    /// the recency check.
    #[test]
    fn a_token_from_the_future_or_long_ago_is_refused() {
        let now = clock::now().unix_timestamp();

        assert!(ensure_recent_issue(now + CLOCK_SKEW + 60).is_err());
        assert!(ensure_recent_issue(now - ISSUED_WITHIN - 60).is_err());
    }

    /// Adding one issuer beyond the cache capacity leaves exactly the
    /// permitted number of documents and retains the newest issuer.
    #[test]
    fn the_documents_kept_stay_within_their_limit() {
        let mut kept: HashMap<String, ((), Instant)> = HashMap::new();
        let start = Instant::now();

        for n in 0..=MOST_ISSUERS {
            let issuer = format!("https://idp-{n}.example");
            let now = start + Duration::from_millis(u64::try_from(n).unwrap());
            make_room(&mut kept, &issuer, now);
            kept.insert(issuer, ((), now));
        }

        assert_eq!(kept.len(), MOST_ISSUERS);
        assert!(kept.contains_key(&format!("https://idp-{MOST_ISSUERS}.example")));
    }

    /// Making room for a new issuer removes the sole document when it
    /// reaches its expiry time.
    #[test]
    fn a_stale_document_is_dropped_when_another_is_kept() {
        let mut kept: HashMap<String, ((), Instant)> = HashMap::new();
        let fetched_at = Instant::now();
        kept.insert("https://stale.example".to_owned(), ((), fetched_at));

        make_room(
            &mut kept,
            "https://fresh.example",
            fetched_at + METADATA_TTL,
        );

        assert!(kept.is_empty());
    }

    /// The claims holding text or lists of text reach the mapping rules;
    /// others are left out.
    #[test]
    fn only_text_claims_are_kept() {
        let claims: HashMap<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({
                "groups": ["admins", "staff"],
                "department": "finance",
                "level": 3,
                "mixed": ["a", 1],
            }))
            .unwrap();

        let kept = texts_of(&claims);

        assert_eq!(kept["groups"], ["admins", "staff"]);
        assert_eq!(kept["department"], ["finance"]);
        assert!(!kept.contains_key("level"));
        assert!(!kept.contains_key("mixed"));
    }
}
