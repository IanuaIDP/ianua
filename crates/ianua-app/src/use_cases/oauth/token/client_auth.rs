//! A client proving itself where tokens are handed out or checked: the
//! token, pushed request, device, revocation and introspection endpoints.
//!
//! The client is found by the `client_id` it names, the `cli_...` value it
//! was issued, and only the way it registered counts (RFC 6749 2.3, RFC
//! 7523, RFC 8705). Mallory learns the id of an app that signs its requests
//! with a key; if a secret also worked for it, she would only have to guess
//! one.

use std::sync::Arc;

use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::domains::oauth::clients::credential::{
    CertificateSubject, ClientCredential, ClientKeys, TokenEndpointAuthMethod,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ClientId, Issuer};

use crate::error::{AppError, OrInternal};
use crate::input::validate_secret;
use crate::ports::oauth::{
    AssertionReplayGuard, ClientAssertionVerifier, ClientSecretVerifier, OAuthClientStore,
};
use crate::tenancy::ScopedTenant;
use crate::use_cases::oauth::token::refusal::TokenError;

/// How a request proves its client, as the API read it off the request.
pub enum ClientProof {
    /// A secret in the `Authorization: Basic` header
    /// (`client_secret_basic`).
    BasicSecret {
        /// The client it names.
        client_id: ClientId,
        /// The credential extracted from HTTP Basic authentication.
        secret: Secret,
    },
    /// A secret in the form body (`client_secret_post`).
    PostedSecret {
        /// The client it names.
        client_id: ClientId,
        /// The credential supplied in the token request's form body.
        secret: Secret,
    },
    /// A JWT the client signed with its own key (`private_key_jwt`).
    SignedAssertion {
        /// The client the request names: its `client_id`, or the
        /// assertion's `sub` read unverified to find its keys. The verified
        /// assertion must name the same one.
        client_id: ClientId,
        /// The signed JWT whose signature and claims must be verified.
        assertion: Secret,
    },
    /// The TLS client certificate the connection was made with
    /// (`tls_client_auth`), its key proved by the handshake.
    Certificate {
        /// The client it names.
        client_id: ClientId,
        /// The certificate's subject distinguished name.
        subject: CertificateSubject,
    },
    /// Nothing, for a public client (`none`).
    Nothing {
        /// The client it names.
        client_id: ClientId,
    },
}

impl ClientProof {
    /// The client the request names.
    #[must_use]
    pub fn client_id(&self) -> &ClientId {
        match self {
            Self::BasicSecret { client_id, .. }
            | Self::PostedSecret { client_id, .. }
            | Self::SignedAssertion { client_id, .. }
            | Self::Certificate { client_id, .. }
            | Self::Nothing { client_id } => client_id,
        }
    }

    /// The way it proves the client.
    #[must_use]
    pub fn method(&self) -> TokenEndpointAuthMethod {
        match self {
            Self::BasicSecret { .. } => TokenEndpointAuthMethod::ClientSecretBasic,
            Self::PostedSecret { .. } => TokenEndpointAuthMethod::ClientSecretPost,
            Self::SignedAssertion { .. } => TokenEndpointAuthMethod::PrivateKeyJwt,
            Self::Certificate { .. } => TokenEndpointAuthMethod::TlsClientAuth,
            Self::Nothing { .. } => TokenEndpointAuthMethod::None,
        }
    }
}

/// The ports a client proving itself needs.
#[derive(ianua_macros::Fakes)]
pub struct ClientAuthPorts {
    /// Where clients are kept.
    pub client_store: Arc<dyn OAuthClientStore>,
    /// Checks a presented secret against a kept hash.
    pub secret_verifier: Arc<dyn ClientSecretVerifier>,
    /// Checks a signed client assertion.
    pub assertion_verifier: Arc<dyn ClientAssertionVerifier>,
    /// Remembers the assertions already used.
    pub replay_guard: Arc<dyn AssertionReplayGuard>,
}

/// Who is asking where the client proves itself: the tenant the request's
/// address names, and its issuer, which a signed assertion is addressed to.
#[derive(Clone, Copy)]
pub(crate) struct Asking<'a> {
    /// The scope selected by the token endpoint's address.
    pub(crate) tenant: &'a ScopedTenant,
    /// The expected audience of a client's signed proof.
    pub(crate) issuer: &'a Issuer,
}

/// The active client `proof` names, once it proved itself the way it
/// registered.
///
/// # Errors
///
/// - `TokenError::Refused` with `invalid_client` when the client is
///   unknown, revoked, registered another way, or its proof does not hold.
///   Which of those is never said.
/// - `TokenError::Failed` when a lookup or check fails.
pub(crate) async fn authenticated_client(
    ports: &ClientAuthPorts,
    asking: Asking<'_>,
    proof: &ClientProof,
) -> Result<OAuthClient<ResolvedTenant>, TokenError> {
    let client = ports
        .client_store
        .find_by_client_id_value(asking.tenant, proof.client_id())
        .await
        .or_internal()?
        .filter(OAuthClient::is_active)
        .filter(|client| client.credential().accepts_method(proof.method()))
        .ok_or_else(TokenError::invalid_client)?;
    ensure_proved(ports, asking, &client, proof).await?;
    Ok(client)
}

/// Refuses `proof` unless it holds for `client`.
async fn ensure_proved(
    ports: &ClientAuthPorts,
    asking: Asking<'_>,
    client: &OAuthClient<ResolvedTenant>,
    proof: &ClientProof,
) -> Result<(), TokenError> {
    let proved = match (proof, client.credential()) {
        (
            ClientProof::BasicSecret { secret, .. } | ClientProof::PostedSecret { secret, .. },
            credential,
        ) => secret_holds(ports, credential, secret).await?,
        (ClientProof::SignedAssertion { assertion, .. }, ClientCredential::PrivateKeyJwt(keys)) => {
            let signed = Signed { keys, assertion };
            assertion_holds(ports, asking, client, signed).await?
        }
        (ClientProof::Certificate { subject, .. }, ClientCredential::TlsClientAuth(registered)) => {
            subject == registered
        }
        (ClientProof::Nothing { .. }, ClientCredential::Public) => true,
        _ => false,
    };
    proved.then_some(()).ok_or_else(TokenError::invalid_client)
}

/// Whether `secret` is one `credential` accepts now: the current one, or
/// the one before it while its overlap lasts.
async fn secret_holds(
    ports: &ClientAuthPorts,
    credential: &ClientCredential,
    secret: &Secret,
) -> Result<bool, TokenError> {
    if validate_secret("client_secret", secret.expose()).is_err() {
        return Ok(false);
    }
    for hash in credential.secrets_accepted_at(clock::now()) {
        if ports
            .secret_verifier
            .verify(secret, hash)
            .await
            .or_internal()?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// An assertion and the keys it must be signed with.
#[derive(Clone, Copy)]
struct Signed<'a> {
    keys: &'a ClientKeys,
    assertion: &'a Secret,
}

/// Whether `signed` was signed by `client`'s key, for this tenant's issuer,
/// and is used here for the first time.
async fn assertion_holds(
    ports: &ClientAuthPorts,
    asking: Asking<'_>,
    client: &OAuthClient<ResolvedTenant>,
    signed: Signed<'_>,
) -> Result<bool, TokenError> {
    let checked = ports
        .assertion_verifier
        .verify(signed.assertion, signed.keys, asking.issuer)
        .await;
    let verified = match checked {
        Ok(verified) => verified,
        Err(DomainError::Unauthorized(_)) => return Ok(false),
        Err(failure) => return Err(AppError::from_domain(failure).into()),
    };
    if verified.client != *client.client_id_value() {
        return Ok(false);
    }
    let first = ports
        .replay_guard
        .first_use(
            asking.tenant,
            client.id(),
            &verified.jti,
            verified.expires_at,
        )
        .await
        .or_internal()?;
    Ok(first)
}
