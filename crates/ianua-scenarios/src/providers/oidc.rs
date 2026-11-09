//! A bounded HTTPS OIDC provider: discovery, JWKS and a single-use code
//! exchange that checks client credentials, redirect URI and PKCE.

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey as _;
use rcgen::{CertificateParams, KeyPair};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tempfile::NamedTempFile;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;
use uuid::Uuid;

use crate::providers::parameter;
use crate::wire::Status;
use crate::wire::federation::{Begun, Callback, ProviderAnswer};
use crate::wire::organization::IdentityProviderConfig;

const CLIENT: &str = "ianua-scenarios";
const SECRET: &str = " Scenario provider client secret +%:&= ";

/// Which signed claim differs from the flow Ianua started.
#[derive(Clone, Copy)]
pub enum Claim {
    /// All claims match the authorization request.
    Correct,
    /// The issuer names a different provider.
    WrongIssuer,
    /// The token names another relying party.
    WrongAudience,
    /// The nonce names another authorization.
    WrongNonce,
    /// The proof expired before it was exchanged.
    Expired,
    /// The proof claims an issuance beyond allowed skew.
    FutureIssued,
    /// The proof claims an overly old issuance.
    OldIssued,
    /// The claims are signed with an unregistered key.
    WrongSignature,
    /// The proof selects no signature algorithm.
    Unsigned,
    /// The provider says it did not verify the address.
    UnverifiedEmail,
}

/// The provider's HTTPS listener and signing identity, stopped on drop.
pub struct Provider {
    shared: Arc<Shared>,
    key: SigningKey,
    authority: NamedTempFile,
    serving: JoinHandle<()>,
}

/// One pending authorization code, consumed by the token endpoint.
struct Grant {
    code: String,
    token: String,
    challenge: String,
    redirect: String,
}

/// The discovery identity and pending grant seen by the HTTPS listener.
/// Counting every exchange lets scenarios distinguish an early refusal
/// from fetching a token and rejecting its claims.
struct Shared {
    issuer: String,
    jwks: Value,
    grant: RwLock<Option<Grant>>,
    exchanges: AtomicUsize,
}

impl Provider {
    /// Starts a provider on a fresh loopback HTTPS address, with its own
    /// P-256 signing key and self-signed certificate. The temporary PEM file
    /// lets the stack trust this provider through its normal configuration.
    ///
    /// # Panics
    ///
    /// When the listener, signing key, TLS configuration or authority file
    /// cannot be created, so the scenario has no usable provider.
    /// This fixture requires a listening HTTPS identity before federation scenarios can run.
    #[allow(clippy::expect_used)]
    pub async fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("a provider port");
        let issuer = format!(
            "https://localhost:{}",
            listener.local_addr().expect("an address").port()
        );
        let key = KeyPair::generate().expect("a provider key");
        let certificate = CertificateParams::new(vec!["localhost".to_owned()])
            .expect("parameters")
            .self_signed(&key)
            .expect("a provider certificate");
        let signing = SigningKey::from_pkcs8_der(&key.serialize_der()).expect("P-256");
        let server = tls_config(&key, &certificate);
        let authority = NamedTempFile::new().expect("an authority file");
        std::fs::write(authority.path(), certificate.pem()).expect("write the authority");
        let shared = Arc::new(Shared::new(issuer, &signing));
        let serving = tokio::spawn(serve(
            listener,
            TlsAcceptor::from(Arc::new(server)),
            Arc::clone(&shared),
        ));
        Self {
            shared,
            key: signing,
            authority,
            serving,
        }
    }

    /// The settings Ann registers through the identity-provider API.
    /// The credential includes outer spaces and URL-sensitive punctuation;
    /// sign-in must preserve them through storage and HTTP Basic encoding.
    #[must_use]
    pub fn config(&self) -> IdentityProviderConfig {
        IdentityProviderConfig::Oidc {
            issuer: self.shared.issuer.clone(),
            client_id: CLIENT.to_owned(),
            encrypted_client_secret: SECRET.to_owned(),
            scopes: vec!["openid".to_owned(), "email".to_owned()],
        }
    }

    /// The PEM path supplied as `OIDC_PROVIDER_CA_FILE`. The provider owns
    /// the temporary file, so it remains available while the stack starts.
    ///
    /// # Panics
    ///
    /// When the temporary path cannot be represented as UTF-8 configuration.
    /// The fixture's trust file must have a path usable in the stack's text configuration.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn authority_file(&self) -> &str {
        self.authority.path().to_str().expect("a UTF-8 path")
    }

    /// Prepares one code exchange for Ianua's redirect and returns the
    /// callback its browser would submit. It retains the redirect and PKCE
    /// challenge for verification at the token endpoint. A changed claim
    /// is signed too, so refusal must check the claim, not just a signature.
    /// Calling this again replaces the fixture's single pending grant.
    ///
    /// # Panics
    ///
    /// When the redirect names another client, lacks a required parameter,
    /// uses a PKCE method other than S256, or the grant lock is poisoned.
    /// A poisoned grant lock means a previous fixture assertion failed and cannot be recovered here.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn callback(&self, begun: Begun, email: &str, claim: Claim) -> Callback {
        assert_eq!(parameter(&begun.redirect_url, "client_id"), CLIENT);
        assert_eq!(
            parameter(&begun.redirect_url, "code_challenge_method"),
            "S256"
        );
        let claims = self.claims(&begun, email, claim);
        let code = Uuid::new_v4().to_string();
        let grant = Grant {
            code: code.clone(),
            token: self.token(&claims, claim),
            challenge: parameter(&begun.redirect_url, "code_challenge"),
            redirect: parameter(&begun.redirect_url, "redirect_uri"),
        };
        *self.shared.grant.write().expect("the grant lock") = Some(grant);
        Callback {
            binding: begun.binding,
            answer: ProviderAnswer::Oidc {
                state: parameter(&begun.redirect_url, "state"),
                code,
            },
        }
    }

    /// Prepares the normal ID-token claims and changes only the requested refusal condition.
    fn claims(&self, begun: &Begun, email: &str, claim: Claim) -> Value {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut claims = json!({"iss": self.shared.issuer, "aud": CLIENT, "sub": "ann-at-provider",
            "email": email, "email_verified": true, "iat": now, "exp": now + 300,
            "nonce": parameter(&begun.redirect_url, "nonce")});
        match claim {
            Claim::Correct | Claim::WrongSignature | Claim::Unsigned => {}
            Claim::WrongIssuer => claims["iss"] = json!("https://other-provider.example"),
            Claim::WrongAudience => claims["aud"] = json!("another-client"),
            Claim::WrongNonce => claims["nonce"] = json!("another-authorization-request"),
            Claim::Expired => claims["exp"] = json!(now - 300),
            Claim::FutureIssued => claims["iat"] = json!(now + 300),
            Claim::OldIssued => claims["iat"] = json!(now - 900),
            Claim::UnverifiedEmail => claims["email_verified"] = json!(false),
        }
        claims
    }

    /// How many requests reached the token endpoint, including refused ones.
    #[must_use]
    pub fn exchanges(&self) -> usize {
        self.shared.exchanges.load(Ordering::SeqCst)
    }

    /// Makes the next exchange fail as an expired provider authorization code.
    /// A later authorization can replace it and proceed normally.
    ///
    /// # Panics
    ///
    /// When another fixture operation poisoned the pending-grant lock.
    /// Continuing after a poisoned fixture lock could conceal the earlier assertion failure.
    #[allow(clippy::expect_used)]
    pub fn discard_grant(&self) {
        self.shared.grant.write().expect("the grant lock").take();
    }

    /// Encodes the requested proof, changing only its signing authority or
    /// algorithm for signature scenarios. Normal claim variants retain ES256.
    /// The fixture signs a compact token with generated P-256 keys; failure invalidates its setup.
    #[allow(clippy::expect_used)]
    fn token(&self, claims: &Value, claim: Claim) -> String {
        if matches!(claim, Claim::Unsigned) {
            return format!(
                "{}.{}.",
                URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
                URL_SAFE_NO_PAD.encode(claims.to_string())
            );
        }
        let token = self.signed(claims);
        if !matches!(claim, Claim::WrongSignature) {
            return token;
        }
        let (input, _) = token.rsplit_once('.').expect("a compact token");
        let key = KeyPair::generate().expect("an untrusted key");
        let key = SigningKey::from_pkcs8_der(&key.serialize_der()).expect("P-256");
        let signature: Signature = key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    /// Cancels and joins the listener and its current connection, so the
    /// scenario finishes with no provider task still serving requests.
    ///
    /// # Panics
    ///
    /// When the listener already ended or panicked instead of being cancelled.
    /// Listener cancellation is an assertion: a task that ended another way must fail the scenario.
    #[allow(clippy::expect_used)]
    pub async fn stop(mut self) {
        self.serving.abort();
        let ended = (&mut self.serving)
            .await
            .expect_err("the provider ran until stopped");
        assert!(ended.is_cancelled());
    }

    /// A compact ES256 ID token whose key id matches the published JWKS.
    /// The supplied claims are signed unchanged, including a deliberately
    /// wrong issuer, audience or nonce used by a rejection scenario.
    fn signed(&self, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD
                .encode(json!({"alg": "ES256", "kid": "provider", "typ": "JWT"}).to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature: Signature = self.key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
}

impl Shared {
    /// Starts with this provider's discovery identity and no pending authorization grant.
    fn new(issuer: String, key: &SigningKey) -> Self {
        Self {
            issuer,
            jwks: jwks(key),
            grant: RwLock::new(None),
            exchanges: AtomicUsize::new(0),
        }
    }
}

/// Builds TLS from a provider's generated matching key and certificate.
/// This P-256 fixture identity supports the configured default TLS versions.
#[allow(clippy::expect_used)]
pub(crate) fn tls_config(key: &KeyPair, certificate: &rcgen::Certificate) -> ServerConfig {
    ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .expect("TLS configuration")
}

impl Drop for Provider {
    /// Cancels the listener when a failed assertion skips explicit cleanup.
    /// Successful scenarios use `stop` to wait for cancellation as well.
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// Publishes only the P-256 public coordinates, under the key id used in
/// the ID token header, so Ianua verifies the provider's real signature.
/// An uncompressed P-256 verifying point always has both affine coordinates.
#[allow(clippy::expect_used)]
fn jwks(key: &SigningKey) -> Value {
    let point = key.verifying_key().to_encoded_point(false);
    json!({"keys": [{"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": "provider",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("x")), "y": URL_SAFE_NO_PAD.encode(point.y().expect("y"))}]})
}

/// One connection at a time, with the TLS handshake and request bounded
/// together. Closing each response prevents an idle pooled socket blocking discovery.
/// Listener failure aborts the fixture task and is detected by explicit shutdown assertions.
#[allow(clippy::expect_used)]
async fn serve(listener: TcpListener, tls: TlsAcceptor, shared: Arc<Shared>) {
    loop {
        let (stream, _) = listener.accept().await.expect("a provider connection");
        let state = Arc::clone(&shared);
        let connection = async {
            let Ok(stream) = tls.accept(stream).await else {
                return;
            };
            let service = service_fn(move |request| respond(request, Arc::clone(&state)));
            let _ = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service)
                .await;
        };
        let _ = tokio::time::timeout(Duration::from_secs(10), connection).await;
    }
}

/// Serves discovery, public keys and code exchange over the same TLS
/// identity. Provider errors and unknown routes return HTTP `Status::BAD_REQUEST` JSON,
/// allowing Ianua's normal HTTP adapter to handle refusals.
async fn respond(
    request: Request<Incoming>,
    shared: Arc<Shared>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let body = match (request.method().as_str(), request.uri().path()) {
        ("GET", "/.well-known/openid-configuration") => discovery(&shared.issuer),
        ("GET", "/jwks") => shared.jwks.clone(),
        ("POST", "/token") => exchange(request, &shared).await,
        _ => json!({"error": "invalid_request"}),
    };
    let status = if body.get("error").is_some() {
        Status::BAD_REQUEST
    } else {
        Status::OK
    };
    let mut response = Response::new(Full::new(Bytes::from(body.to_string())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    Ok(response)
}

/// Advertises this provider's endpoints and ES256 signing support.
/// The authorization URL is carried in redirects; scenarios prepare the
/// callback directly rather than serving an interactive login page.
fn discovery(issuer: &str) -> Value {
    json!({"issuer": issuer, "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"), "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"], "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"]})
}

/// Releases the prepared ID token only for the exact client credential,
/// code, redirect URI, grant type and S256 verifier. The request body is
/// bounded to 16 KiB. A correctly authenticated request consumes the grant
/// before checking its form fields, so a refused exchange cannot retry it.
/// Every call is counted, including calls refused before consuming a grant.
/// An unreadable request or poisoned grant is a fixture failure, preserving its existing assertions.
#[allow(clippy::expect_used)]
async fn exchange(request: Request<Incoming>, shared: &Shared) -> Value {
    shared.exchanges.fetch_add(1, Ordering::SeqCst);
    if !authorized(request.headers()) {
        return json!({"error": "invalid_client"});
    }
    let body = Limited::new(request.into_body(), 16 * 1024)
        .collect()
        .await
        .expect("a bounded token request")
        .to_bytes();
    let fields: std::collections::HashMap<_, _> =
        url::form_urlencoded::parse(&body).into_owned().collect();
    let Some(grant) = shared.grant.write().expect("the grant lock").take() else {
        return json!({"error": "invalid_grant"});
    };
    let verifier = fields
        .get("code_verifier")
        .map(String::as_str)
        .unwrap_or_default();
    if fields.get("code") != Some(&grant.code)
        || fields.get("redirect_uri") != Some(&grant.redirect)
        || fields.get("grant_type").map(String::as_str) != Some("authorization_code")
        || URL_SAFE_NO_PAD.encode(Sha256::digest(verifier)) != grant.challenge
    {
        return json!({"error": "invalid_grant"});
    }
    json!({"access_token": Uuid::new_v4().to_string(), "token_type": "Bearer", "expires_in": 300, "id_token": grant.token})
}

/// Checks the exact client credential, including the fixture secret's outer spaces.
fn authorized(headers: &hyper::HeaderMap) -> bool {
    let encoded: String = url::form_urlencoded::byte_serialize(SECRET.as_bytes()).collect();
    let expected = format!("Basic {}", STANDARD.encode(format!("{CLIENT}:{encoded}")));
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        == Some(expected.as_str())
}
