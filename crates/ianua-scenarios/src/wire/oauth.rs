//! A tenant as an OAuth 2.0 and OpenID Connect provider for applications
//! of its own: registering a client, a person's consent, the token
//! endpoint's form, the tokens it issues, what the user info endpoint
//! says, the provider's published discovery and keys, and a machine
//! client's own tokens and what introspection says of them. Beside them,
//! a client registered with any proof and settings, the forms a client
//! proves itself in by secret, signed assertion or nothing, its secret
//! rotated, and the apps a person consented to.

use serde::{Deserialize, Serialize};
use url::form_urlencoded;

/// `POST …/oauth/clients`: a client registered with the tenant.
#[derive(Debug, Clone, Serialize)]
pub struct NewClient {
    /// The name people see on the consent page.
    pub name: String,
    /// Where codes may be sent.
    pub redirect_uris: Vec<String>,
    /// The grants it may use, such as `AuthorizationCode` and
    /// `RefreshToken`.
    pub grant_types: Vec<String>,
    /// The scopes it may ask for.
    pub scopes: Vec<String>,
    /// How it proves itself at the token endpoint: `none` for a public
    /// client, which holds no secret.
    pub token_endpoint_auth_method: String,
    /// Where a person may be sent after signing out through it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub post_logout_redirect_uris: Vec<String>,
}

/// `POST …/oauth/end-session`: the dashboard's sign-out page hands back
/// the app's sign-out request, with the person's session when the browser
/// holds one. Holds an ID token, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct EndSession {
    /// The ID token the app names the person with, if it does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_hint: Option<String>,
    /// The app asking.
    pub client_id: String,
    /// Where the app wants the person sent afterwards.
    pub post_logout_redirect_uri: String,
    /// What the app wants back.
    pub state: String,
    /// Whether the person confirmed they want to sign out.
    pub confirmed: bool,
}

/// What the sign-out step came to.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionEnded {
    /// `signed_out`, `confirm` or `not_signed_in`.
    pub outcome: String,
    /// Where the person goes afterwards, with the app's `state`.
    pub redirect_to: Option<String>,
}

/// Registration handles for administration and OAuth protocol requests.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientRegistered {
    /// Its id in the tenant.
    pub id: String,
    /// The `client_id` it names itself by at the provider.
    pub client_id: String,
}

/// `POST …/oauth/authorize`: the authorization request as the browser
/// brought it, with the person's consent given.
#[derive(Debug, Clone, Serialize)]
pub struct Consent {
    /// The client asking.
    pub client_id: String,
    /// Where the code goes: one of the client's registered addresses.
    pub redirect_uri: String,
    /// `code`.
    pub response_type: String,
    /// The scopes asked for, separated by spaces.
    pub scope: String,
    /// The client's own state, handed back with the code.
    pub state: String,
    /// The client's nonce, bound into the ID token.
    pub nonce: String,
    /// The PKCE challenge the code is bound to.
    pub code_challenge: String,
    /// `S256`.
    pub code_challenge_method: String,
    /// `given`.
    pub consent: String,
}

/// What the authorization answered. Holds the code, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct Authorized {
    /// `issued` when a code was.
    pub outcome: String,
    /// The code, when one was issued.
    #[serde(default)]
    pub code: Option<String>,
    /// The client's address the browser is sent to, carrying the code and
    /// the state.
    #[serde(default)]
    pub redirect_to: Option<String>,
    /// Whether this request gave the client new consent, once a code was
    /// issued.
    #[serde(default)]
    pub consent_granted: Option<bool>,
    /// The scopes the consent page asks the person about, when the
    /// outcome is `consent`.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// The error the client is told, when the outcome is `refused`.
    #[serde(default)]
    pub error: Option<String>,
}

/// `POST …/oauth/token`, as a form: the grant a client redeems. Holds a
/// code or a refresh token, so it has no `Debug`.
#[derive(Clone)]
pub enum TokenRequest {
    /// A code from an authorization, with the PKCE verifier it was bound
    /// to.
    AuthorizationCode {
        /// The client redeeming it.
        client_id: String,
        /// Single-use authorization issued after the user's consent.
        code: String,
        /// The address the code was sent to.
        redirect_uri: String,
        /// The verifier whose challenge the authorization carried.
        code_verifier: String,
    },
    /// A refresh token traded for fresh tokens.
    RefreshToken {
        /// The client the token was issued to.
        client_id: String,
        /// Existing credential exchanged for a fresh token pair.
        refresh_token: String,
    },
}

impl TokenRequest {
    /// The grant as the form the token endpoint reads.
    #[must_use]
    pub fn form(&self) -> String {
        let fields: Vec<(&str, &str)> = match self {
            Self::AuthorizationCode {
                client_id,
                code,
                redirect_uri,
                code_verifier,
            } => vec![
                ("grant_type", "authorization_code"),
                ("client_id", client_id),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("code_verifier", code_verifier),
            ],
            Self::RefreshToken {
                client_id,
                refresh_token,
            } => vec![
                ("grant_type", "refresh_token"),
                ("client_id", client_id),
                ("refresh_token", refresh_token),
            ],
        };
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish()
    }
}

/// The tokens a grant issued. Holds them, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct Tokens {
    /// Bearer credential used to call resources allowed by the grant.
    pub access_token: String,
    /// The refresh token, when the grant hands one out.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// The signed OIDC ID token, when `openid` was asked for.
    #[serde(default)]
    pub id_token: Option<String>,
    /// How the access token is presented: `Bearer`, or `DPoP` for one
    /// bound to a key.
    #[serde(default)]
    pub token_type: Option<String>,
    /// The scopes the access token carries, separated by spaces.
    #[serde(default)]
    pub scope: Option<String>,
    /// The kind of token a token exchange issued.
    #[serde(default)]
    pub issued_token_type: Option<String>,
}

/// `POST …/oauth/revoke`, as a form: a token the client gives up. Holds
/// the token, so it has no `Debug`.
#[derive(Clone)]
pub struct Revocation {
    /// The client the token was issued to.
    pub client_id: String,
    /// Issued credential the client asks the provider to invalidate.
    pub token: String,
}

impl Revocation {
    /// The revocation as the form the endpoint reads.
    #[must_use]
    pub fn form(&self) -> String {
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("client_id", self.client_id.as_str()),
                ("token", self.token.as_str()),
            ])
            .finish()
    }
}

/// What `GET …/oauth/userinfo` says of the person an access token stands
/// for.
#[derive(Debug, Clone, Deserialize)]
pub struct UserInfo {
    /// Their id, as in their ID token.
    pub sub: String,
    /// Their address, with the `email` scope.
    #[serde(default)]
    pub email: Option<String>,
}

/// The provider's discovery document, from
/// `GET …/.well-known/openid-configuration`.
#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    /// The issuer every ID token names.
    pub issuer: String,
    /// Where the signing keys are published.
    pub jwks_uri: String,
    /// Where a browser asks for a code.
    pub authorization_endpoint: String,
    /// Where grants are redeemed, and the address a client assertion or a
    /// `DPoP` proof made for a token request names.
    pub token_endpoint: String,
    /// Where an access token is traded for what it says of its person.
    pub userinfo_endpoint: String,
    /// Where a confidential client asks what a token says of itself.
    pub introspection_endpoint: String,
    /// Where a client gives a token up.
    pub revocation_endpoint: String,
    /// Where an app sends a browser to sign out.
    pub end_session_endpoint: String,
    /// Where a device asks for its codes.
    pub device_authorization_endpoint: String,
    /// What an authorization may answer with.
    pub response_types_supported: Vec<String>,
    /// The grants the token endpoint answers.
    pub grant_types_supported: Vec<String>,
    /// The PKCE methods a code may be bound with.
    pub code_challenge_methods_supported: Vec<String>,
    /// The algorithms ID tokens may be signed with.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// The ways a client may prove itself at the token endpoint.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// The algorithms a client's signed assertion may use.
    pub token_endpoint_auth_signing_alg_values_supported: Vec<String>,
    /// The algorithms a `DPoP` proof may be signed with.
    pub dpop_signing_alg_values_supported: Vec<String>,
    /// Whether an authorization answer names its issuer.
    pub authorization_response_iss_parameter_supported: bool,
}

/// The provider's published signing keys.
#[derive(Debug, Clone, Deserialize)]
pub struct Keys {
    /// Public verification material advertised by the provider's JWKS endpoint.
    pub keys: Vec<Key>,
}

/// One published signing key: its public parts only.
#[derive(Debug, Clone, Deserialize)]
pub struct Key {
    /// Its id, which a token's header names.
    pub kid: String,
    /// Its type, such as `RSA`.
    pub kty: String,
    /// The RSA modulus, base64url.
    pub n: String,
    /// The RSA exponent, base64url.
    pub e: String,
}

/// `POST …/oauth/clients`: a machine client, such as a service of the
/// company's own, that gets tokens for itself with its secret.
#[derive(Debug, Clone, Serialize)]
pub struct NewMachineClient {
    /// The name the tenant's administrators see.
    pub name: String,
    /// `ClientCredentials`.
    pub grant_types: Vec<String>,
    /// The scopes its tokens carry.
    pub scopes: Vec<String>,
    /// `client_secret_post`: it sends its secret in the form.
    pub token_endpoint_auth_method: String,
    /// The form and lifetimes of its tokens.
    pub settings: MachineClientSettings,
}

/// What a machine client is set up with beyond its grants.
#[derive(Debug, Clone, Serialize)]
pub struct MachineClientSettings {
    /// `jwt`, so its access tokens are signed with the tenant's key, or
    /// `opaque`.
    pub access_token_format: String,
    /// How long its tokens last.
    pub token_lifetimes: OwnTokenLifetimes,
}

/// A client's own token lifetimes, each in seconds.
#[derive(Debug, Clone, Serialize)]
pub struct OwnTokenLifetimes {
    /// `own`.
    pub kind: String,
    /// How long an access token lasts.
    pub access_token_seconds: i64,
    /// How long an ID token lasts.
    pub id_token_seconds: i64,
    /// How long a refresh token lasts unless used.
    pub refresh_idle_seconds: i64,
    /// How long a refresh token family lasts from its first token.
    pub refresh_family_seconds: i64,
}

/// A confidential client just registered, with the secret shown once.
/// Holds it, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct ConfidentialClientRegistered {
    /// Its id in the tenant.
    pub id: String,
    /// The `client_id` it names itself by at the provider.
    pub client_id: String,
    /// The secret it proves itself with.
    pub client_secret: String,
}

/// `POST …/oauth/token`, as a form: a machine client asking for a token
/// for itself with its secret. Holds the secret, so it has no `Debug`.
#[derive(Clone)]
pub struct ClientCredentialsGrant {
    /// The client asking.
    pub client_id: String,
    /// Its secret, sent in the form.
    pub client_secret: String,
}

impl ClientCredentialsGrant {
    /// The grant as the form the token endpoint reads, asking for every
    /// scope the client was registered with.
    #[must_use]
    pub fn form(&self) -> String {
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
            ])
            .finish()
    }
}

/// `POST …/oauth/introspect`, as a form: a confidential client asking
/// what an access token says about itself. Holds the token and the
/// secret, so it has no `Debug`.
#[derive(Clone)]
pub struct Introspection {
    /// The client asking, which proves itself with its secret.
    pub client_id: String,
    /// Its secret, sent in the form.
    pub client_secret: String,
    /// The access token asked about.
    pub token: String,
}

impl Introspection {
    /// The question as the form the endpoint reads.
    #[must_use]
    pub fn form(&self) -> String {
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("token", self.token.as_str()),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
            ])
            .finish()
    }
}

/// What an access token says about itself. One that does not work says
/// only that.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenFacts {
    /// Whether the token works now.
    pub active: bool,
    /// The client holding it, for a token that works.
    #[serde(default)]
    pub client_id: Option<String>,
    /// When it expires, in seconds since the epoch, for a token that
    /// works.
    #[serde(default)]
    pub exp: Option<i64>,
    /// The scopes it carries, separated by spaces, for a token that works.
    #[serde(default)]
    pub scope: Option<String>,
    /// Whom it acts for: a person's id, or the holding client's own
    /// `client_id` for a machine.
    #[serde(default)]
    pub sub: Option<String>,
    /// The `client_id` of the client it is meant for.
    #[serde(default)]
    pub aud: Option<String>,
    /// The issuer that made it.
    #[serde(default)]
    pub iss: Option<String>,
    /// How it is presented: `Bearer` or `DPoP`.
    #[serde(default)]
    pub token_type: Option<String>,
    /// What it is bound to, for a bound token.
    #[serde(default)]
    pub cnf: Option<Confirmation>,
}

/// What a token is bound to (`cnf`).
#[derive(Debug, Clone, Deserialize)]
pub struct Confirmation {
    /// The thumbprint of the `DPoP` key it is bound to.
    #[serde(default)]
    pub jkt: Option<String>,
}

/// `POST …/oauth/device/code`, as a form: a device that cannot show a
/// browser asks for the codes a person approves it with.
#[derive(Debug, Clone)]
pub struct DeviceAsk {
    /// The device's client, a public one proving only its id.
    pub client_id: String,
    /// The scopes it asks for, separated by spaces.
    pub scope: String,
}

impl DeviceAsk {
    /// The request as the form the endpoint reads.
    #[must_use]
    pub fn form(&self) -> String {
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("client_id", self.client_id.as_str()),
                ("scope", self.scope.as_str()),
            ])
            .finish()
    }
}

/// The codes a device was given: one it polls with and keeps to itself,
/// one it shows the person. Holds the device code, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct DeviceCodes {
    /// The code the device polls the token endpoint with.
    pub device_code: String,
    /// The short code the device shows, for the person to type.
    pub user_code: String,
    /// The page the person visits to type it.
    pub verification_uri: String,
    /// The same page with the code filled in.
    pub verification_uri_complete: String,
    /// How many seconds the device waits between polls.
    pub interval: u16,
}

/// `POST …/oauth/device/approve` or `…/deny`: the code the device shows,
/// as the person typed it.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceAnswer {
    /// What the person typed from the device.
    pub user_code: String,
}

/// `POST …/oauth/token`, as a form: a device polling for the tokens a
/// person approved. Holds the device code, so it has no `Debug`.
#[derive(Clone)]
pub struct DevicePoll {
    /// The device's client.
    pub client_id: String,
    /// The code it was given.
    pub device_code: String,
}

impl DevicePoll {
    /// The poll as the form the token endpoint reads.
    #[must_use]
    pub fn form(&self) -> String {
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", self.client_id.as_str()),
                ("device_code", self.device_code.as_str()),
            ])
            .finish()
    }
}

/// `POST …/oauth/clients`: a client registered with the proof and the
/// settings it is given, for every kind a scenario needs beyond the
/// public app and the machine client above.
#[derive(Debug, Clone, Serialize)]
pub struct NewConfiguredClient {
    /// The name people see on the consent page.
    pub name: String,
    /// Where codes may be sent.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<String>,
    /// The grants it may use, such as `ClientCredentials` or
    /// `TokenExchange`.
    pub grant_types: Vec<String>,
    /// The scopes it may ask for.
    pub scopes: Vec<String>,
    /// `none`, `client_secret_post` or `private_key_jwt`.
    pub token_endpoint_auth_method: String,
    /// The public keys it signs its assertions with, for
    /// `private_key_jwt`, as a JWK Set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>,
    /// What it is set up with beyond the above.
    pub settings: ClientSettings,
}

/// A client's settings; a setting left out takes the platform's default.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ClientSettings {
    /// `jwt` or `opaque`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_format: Option<String>,
    /// `bearer`, or `dpop` for tokens always bound to a key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_constraint: Option<String>,
    /// How long its tokens last.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_lifetimes: Option<OwnTokenLifetimes>,
}

/// A client just registered, with its secret when it was given one.
/// Holds it, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct RegisteredClient {
    /// Its id in the tenant, by which it is rotated, revoked or its
    /// consent withdrawn.
    pub id: String,
    /// The `client_id` it names itself by at the provider.
    pub client_id: String,
    /// The secret, shown once, for a client that proves itself with one.
    #[serde(default)]
    pub client_secret: Option<String>,
}

/// How a client proves itself in a form. Holds a secret or a signed
/// assertion, so it has no `Debug`.
#[derive(Clone)]
pub enum ClientProof {
    /// Its secret, in the form (`client_secret_post`).
    Secret {
        /// The client it names.
        client_id: String,
        /// The secret it was shown.
        client_secret: String,
    },
    /// A JWT it signed with its own key (`private_key_jwt`).
    Assertion {
        /// The client it names.
        client_id: String,
        /// The signed JWT.
        assertion: String,
    },
    /// Nothing but its id, as a public client proves itself.
    Nothing {
        /// The client it names.
        client_id: String,
    },
}

impl ClientProof {
    /// The form fields the proof is sent in.
    fn fields(&self) -> Vec<(&'static str, &str)> {
        match self {
            Self::Secret {
                client_id,
                client_secret,
            } => vec![
                ("client_id", client_id.as_str()),
                ("client_secret", client_secret.as_str()),
            ],
            Self::Assertion {
                client_id,
                assertion,
            } => vec![
                ("client_id", client_id.as_str()),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", assertion.as_str()),
            ],
            Self::Nothing { client_id } => vec![("client_id", client_id.as_str())],
        }
    }
}

/// A grant a client redeems at the token endpoint while proving itself.
/// Holds tokens, so it has no `Debug`.
#[derive(Clone)]
pub enum ProvenGrant {
    /// Tokens for the client itself, for `scope` or every scope it was
    /// given.
    ClientCredentials {
        /// The scopes asked for, separated by spaces.
        scope: Option<String>,
    },
    /// The access token `subject_token` traded for one meant for the
    /// client `audience` names.
    Exchange {
        /// The access token traded.
        subject_token: String,
        /// The `client_id` of the client the new token is for.
        audience: String,
        /// The scopes asked for, separated by spaces, or the subject
        /// token's.
        scope: Option<String>,
    },
}

impl ProvenGrant {
    /// The form fields the grant is sent in.
    fn fields(&self) -> Vec<(&'static str, &str)> {
        match self {
            Self::ClientCredentials { scope } => {
                let mut fields = vec![("grant_type", "client_credentials")];
                fields.extend(scope.as_deref().map(|scope| ("scope", scope)));
                fields
            }
            Self::Exchange {
                subject_token,
                audience,
                scope,
            } => {
                let mut fields = vec![
                    (
                        "grant_type",
                        "urn:ietf:params:oauth:grant-type:token-exchange",
                    ),
                    ("subject_token", subject_token.as_str()),
                    (
                        "subject_token_type",
                        "urn:ietf:params:oauth:token-type:access_token",
                    ),
                    ("audience", audience.as_str()),
                ];
                fields.extend(scope.as_deref().map(|scope| ("scope", scope)));
                fields
            }
        }
    }
}

/// `POST …/oauth/token`, as a form: a grant and the client's proof.
#[derive(Clone)]
pub struct ProvenTokenRequest {
    /// How the client proves itself.
    pub proof: ClientProof,
    /// What it redeems.
    pub grant: ProvenGrant,
}

impl ProvenTokenRequest {
    /// The request as the form the token endpoint reads.
    #[must_use]
    pub fn form(&self) -> String {
        let mut fields = self.grant.fields();
        fields.extend(self.proof.fields());
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish()
    }
}

/// `POST …/oauth/introspect` or `…/oauth/revoke`, as a form: a token and
/// the proof of the client asking about it or giving it up. Holds both,
/// so it has no `Debug`.
#[derive(Clone)]
pub struct ProvenQuestion {
    /// How the client proves itself.
    pub proof: ClientProof,
    /// The token asked about.
    pub token: String,
}

impl ProvenQuestion {
    /// The question as the form the endpoint reads.
    #[must_use]
    pub fn form(&self) -> String {
        let mut fields = vec![("token", self.token.as_str())];
        fields.extend(self.proof.fields());
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish()
    }
}

/// `POST …/oauth/clients/{id}/rotate-secret`: how long the old secret
/// keeps working beside the new one.
#[derive(Debug, Clone, Serialize)]
pub struct RotateSecret {
    /// The overlap in seconds; `0` ends the old secret at once.
    pub overlap_seconds: u32,
}

/// A client's new secret, shown once. Holds it, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct RotatedSecret {
    /// The new secret.
    pub client_secret: String,
}

/// `GET …/oauth/my-apps`: one app the signed-in person consented to.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizedApp {
    /// The client's id in the tenant, by which the consent is withdrawn.
    pub id: String,
    /// The `client_id` it names itself by.
    pub client_id: String,
    /// The name people see.
    pub name: String,
    /// The scopes the person gave it.
    pub scopes: Vec<String>,
}
