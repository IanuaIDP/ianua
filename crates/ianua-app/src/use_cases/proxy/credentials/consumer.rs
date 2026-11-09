//! A consumer's credential: its API key, its client certificate, or a token
//! it signed with its own keys.
//!
//! A request never names the consumer it acts as. The credential finds the
//! consumer, the consumer's own sign-in check turns it into proof, and the
//! request is counted against its quota. A consumer's token is checked
//! against the keys that consumer publishes, never the tenant's: the
//! tenant's tokens belong to people.

use std::sync::Arc;

use ianua_domain::domains::consumers::authority::ConsumerAuthority;
use ianua_domain::domains::consumers::consumer::Consumer;
use ianua_domain::domains::consumers::credential::ConsumerCredentialKind;
use ianua_domain::domains::proxy::access::question::DpopBinding;
use ianua_domain::domains::proxy::request::context::{Caller, ConsumerCredential};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Audience, CertificateFingerprint, Expiry, HttpsUrl, PrincipalRef};

use crate::acting::ConsumerAuthorities;
use crate::context::{ConsumerCaller, PresentedCredential};
use crate::error::AppError;
use crate::ports::authentication::{
    ClaimedToken, ConsumerKeyDigests, ConsumerToken, ConsumerTokenVerifier, ExpectedToken,
    PresentedKey,
};
use crate::ports::consumers::ConsumerStore;
use crate::tenancy::ScopedTenant;
use crate::use_cases::proxy::credentials::checking::Checking;
use crate::use_cases::proxy::credentials::held::{claims_of, held_by};
use crate::use_cases::proxy::credentials::outcome::{Identification, Refusal, proven, read};

/// The ports signing a consumer in by the credential it presents.
#[derive(ianua_macros::Fakes)]
pub struct ConsumerPorts {
    /// Reads a presented API key into its prefix and digest.
    pub keys: Arc<dyn ConsumerKeyDigests>,
    /// Checks a consumer's token against the keys it publishes.
    pub verifier: Arc<dyn ConsumerTokenVerifier>,
    /// The tenant's consumers, found by the issuer and subject they sign
    /// tokens as.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// Signs a consumer in by its credential, and counts the request
    /// against its quota.
    pub authorities: Arc<dyn ConsumerAuthorities>,
}

/// The consumer an API key belongs to.
///
/// # Errors
///
/// - [`Refusal::Invalid`] when the key has no consumer key's shape.
/// - The cases [`consumer_signed_in`] lists.
pub(crate) async fn by_key(
    ports: &ConsumerPorts,
    checking: &Checking<'_>,
    key: &Secret,
) -> Result<Identification, Refusal> {
    let presented = ports.keys.presented(key).ok_or(Refusal::Invalid)?;
    by_digest(ports, checking, presented).await
}

/// The consumer an API key, already read into its prefix and digest,
/// belongs to.
///
/// # Errors
///
/// - The cases [`consumer_signed_in`] lists.
pub(crate) async fn by_digest(
    ports: &ConsumerPorts,
    checking: &Checking<'_>,
    key: PresentedKey,
) -> Result<Identification, Refusal> {
    let credential = PresentedCredential::Key {
        prefix: key.prefix,
        digest: key.digest,
    };
    proven_consumer(ports, checking, credential, ConsumerCredential::ApiKey).await
}

/// The consumer `credential`, a key or certificate presented as `kind`,
/// signs in, proven until that credential stops working.
///
/// # Errors
///
/// - The cases [`consumer_signed_in`] lists.
async fn proven_consumer(
    ports: &ConsumerPorts,
    checking: &Checking<'_>,
    credential: PresentedCredential,
    kind: ConsumerCredential,
) -> Result<Identification, Refusal> {
    let signed_in = consumer_signed_in(ports, checking, credential).await?;
    let principal = PrincipalRef::Consumer(*signed_in.id());
    let held = held_by(checking.records, checking.tenant, principal).await?;
    let claims = claims_of(&held);
    let caller = Caller::Consumer {
        consumer_id: *signed_in.id(),
        credential: kind,
    };
    Ok(proven(
        caller,
        signed_in.until(),
        held,
        claims,
        DpopBinding::Unbound,
    ))
}

/// The consumer the client certificate the handshake verified belongs to.
///
/// # Errors
///
/// - The cases [`consumer_signed_in`] lists.
pub(crate) async fn by_certificate(
    ports: &ConsumerPorts,
    checking: &Checking<'_>,
    fingerprint: &CertificateFingerprint,
) -> Result<Identification, Refusal> {
    let credential = PresentedCredential::Certificate(*fingerprint);
    proven_consumer(ports, checking, credential, ConsumerCredential::Certificate).await
}

/// A token signed by someone other than the tenant, as it was presented.
pub(crate) struct ForeignToken<'a> {
    /// The raw credential whose external signature and claims must be checked.
    pub token: &'a Secret,
    /// The issuer and subject it claims, not yet checked.
    pub claimed: ClaimedToken,
    /// The audience the route's service pins.
    pub audience: &'a Audience,
}

/// The consumer a token it signed names, once the keys it publishes check
/// it for the route's audience.
///
/// # Errors
///
/// - [`Refusal::UnknownSubject`] when no consumer of the tenant signs
///   tokens as the issuer and subject it claims.
/// - The verifier's refusals, as [`Refusal`] maps them.
/// - [`Refusal::Invalid`] when what checked out is not what it claimed.
/// - The cases [`consumer_signed_in`] lists.
pub(crate) async fn by_token(
    ports: &ConsumerPorts,
    checking: &Checking<'_>,
    foreign: ForeignToken<'_>,
) -> Result<Identification, Refusal> {
    let claimed = &foreign.claimed;
    let keys_at = published_keys(ports, checking.tenant, claimed).await?;
    let expected = ExpectedToken {
        issuer: &claimed.issuer,
        audience: foreign.audience,
    };
    let reading = ports
        .verifier
        .verify(foreign.token, &keys_at, expected)
        .await
        .map_err(Refusal::unavailable)?;
    let verified = read(reading)?;
    ensure_as_claimed(&verified, claimed)?;
    let credential = PresentedCredential::Token {
        issuer: verified.issuer,
        subject: verified.subject,
    };
    let signed_in = consumer_signed_in(ports, checking, credential).await?;
    let principal = PrincipalRef::Consumer(*signed_in.id());
    let held = held_by(checking.records, checking.tenant, principal).await?;
    let mut claims = claims_of(&held);
    claims.scopes = verified.scopes;
    let caller = Caller::Consumer {
        consumer_id: *signed_in.id(),
        credential: ConsumerCredential::Token,
    };
    let expiry = signed_in.until().earliest(Expiry::At(verified.expires_at));
    Ok(proven(caller, expiry, held, claims, DpopBinding::Unbound))
}

/// Refuses a token that checked out as another issuer's or subject's than
/// it claimed when its keys were chosen.
///
/// # Errors
///
/// - [`Refusal::Invalid`] when either differs.
fn ensure_as_claimed(verified: &ConsumerToken, claimed: &ClaimedToken) -> Result<(), Refusal> {
    if verified.issuer != claimed.issuer || verified.subject != claimed.subject {
        return Err(Refusal::Invalid);
    }
    Ok(())
}

/// The consumer `credential` signs in to the tenant `checking` targets,
/// with the request counted against its quota as `checking` says.
///
/// # Errors
///
/// - [`Refusal::UnknownSubject`] when no consumer of the tenant holds the
///   credential, the consumer is disabled, or the credential no longer
///   works: the consumer's check tells them apart to nobody.
/// - [`Refusal::QuotaSpent`] when its quota for this period is spent.
/// - [`Refusal::Unavailable`] when a store or the counter fails.
async fn consumer_signed_in(
    ports: &ConsumerPorts,
    checking: &Checking<'_>,
    credential: PresentedCredential,
) -> Result<ConsumerAuthority, Refusal> {
    let caller = ConsumerCaller::new(*checking.tenant, credential).charged(checking.charge);
    ports
        .authorities
        .authority(&caller)
        .await
        .map_err(consumer_refusal)
}

/// Where the consumer `claimed` names publishes the keys its tokens are
/// signed with.
///
/// # Errors
///
/// - [`Refusal::UnknownSubject`] when no consumer of the tenant signs
///   tokens as `claimed`'s issuer and subject with a credential that still
///   works.
/// - [`Refusal::Unavailable`] when the consumers cannot be read.
async fn published_keys(
    ports: &ConsumerPorts,
    tenant: &ScopedTenant,
    claimed: &ClaimedToken,
) -> Result<HttpsUrl, Refusal> {
    let consumer = ports
        .consumer_store
        .find_by_jwt_issuer_subject(tenant, &claimed.issuer, &claimed.subject)
        .await
        .map_err(Refusal::unavailable)?
        .ok_or(Refusal::UnknownSubject)?;
    keys_of(&consumer, claimed).ok_or(Refusal::UnknownSubject)
}

/// The keys address of `consumer`'s working credential that signs tokens
/// as `claimed`'s issuer and subject, if it has one.
fn keys_of(consumer: &Consumer<ResolvedTenant>, claimed: &ClaimedToken) -> Option<HttpsUrl> {
    consumer.credentials().live().find_map(|kind| match kind {
        ConsumerCredentialKind::JwtBearer {
            issuer,
            subject,
            jwks_uri,
        } if *issuer == claimed.issuer && *subject == claimed.subject => Some(jwks_uri.clone()),
        ConsumerCredentialKind::ApiKey { .. }
        | ConsumerCredentialKind::ClientCert { .. }
        | ConsumerCredentialKind::JwtBearer { .. } => None,
    })
}

/// The refusal of a consumer its sign-in turned away.
fn consumer_refusal(error: AppError) -> Refusal {
    match error {
        AppError::Unauthenticated => Refusal::UnknownSubject,
        AppError::TooManyRequests(_) => Refusal::QuotaSpent,
        other => Refusal::unavailable(other),
    }
}
