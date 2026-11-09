//! What a request proves about its holder: the `DPoP` key it signed a proof
//! with (RFC 9449), checked here before a token is issued to it or a bound
//! token is taken from it.
//!
//! A request with no `DPoP` header proves nothing, and a client whose
//! tokens must be bound is refused for it. A request whose header does not
//! check out is refused outright rather than read as proving nothing: the
//! proof must be made by the key its signature names, for this method and
//! address, within a minute, and only once.
//!
//! A TLS client certificate never reaches the application: the ingress does
//! not pass one on. So no request proves one, and a client whose tokens are
//! bound to its certificate is refused until it does.

use std::sync::Arc;

use ianua_domain::domains::oauth::grants::token_binding::{
    PresentedCertificate, PresentedProof, ProvenKey,
};
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use time::{Duration, OffsetDateTime};

use crate::error::AppError;
use crate::ports::oauth::{DpopProofVerifier, DpopReplayGuard, DpopUse, SignedDpopProof};
use crate::tenancy::ScopedTenant;

/// How long after it was made a proof is still taken.
const PROOF_LIFETIME: Duration = Duration::seconds(60);

/// How far ahead of this clock a proof's `iat` may be, for a client clock
/// running a little fast.
const CLOCK_SKEW: Duration = Duration::seconds(5);

/// The `DPoP` header a request came with.
#[derive(Clone)]
pub enum DpopHeader {
    /// None.
    NotSent,
    /// This proof, exactly once.
    Sent(Secret),
    /// None now: the proof was spent when the connection opened, and this
    /// is a later check of that same connection. The gateway says so; a
    /// request's header is never read as this.
    ProvenAtOpen,
}

/// What a request carried to prove its holder, and where it was sent, as
/// the API read it.
pub struct SenderEvidence {
    /// Its `DPoP` header.
    pub dpop: DpopHeader,
    /// The method it was sent with, such as `POST`.
    pub method: String,
    /// The address it was sent to, without query or fragment, as this
    /// platform publishes it.
    pub url: String,
}

impl SenderEvidence {
    /// A request that carried nothing to prove its holder.
    #[must_use]
    pub fn nothing(method: &str, url: &str) -> Self {
        Self {
            dpop: DpopHeader::NotSent,
            method: method.to_owned(),
            url: url.to_owned(),
        }
    }
}

/// The ports checking what a request proves about its holder.
#[derive(Clone, ianua_macros::Fakes)]
pub struct SenderProofPorts {
    /// Checks a `DPoP` proof's signature and what it is bound to.
    pub dpop_verifier: Arc<dyn DpopProofVerifier>,
    /// Remembers the proofs already used.
    pub dpop_replays: Arc<dyn DpopReplayGuard>,
}

/// What `evidence`, sent for `sent_for` in `tenant`, proves about its
/// holder.
///
/// # Errors
///
/// - `DomainError::Unauthorized` when a `DPoP` header was sent and does not
///   check out: its signature, type, algorithm or key is refused, it was
///   made for another method, address or access token, it is older than a
///   minute or made ahead of time, or it was used before.
/// - `DomainError::Infrastructure` when the replay record cannot be
///   written.
pub(crate) async fn proven_sender(
    ports: &SenderProofPorts,
    tenant: &ScopedTenant,
    evidence: &SenderEvidence,
    sent_for: DpopUse<'_>,
) -> Result<PresentedProof, DomainError> {
    let DpopHeader::Sent(raw) = &evidence.dpop else {
        return Ok(PresentedProof::nothing());
    };
    let signed = ports.dpop_verifier.verify(raw, sent_for).await?;
    ensure_made_for(&signed, evidence, clock::now())?;
    let first = ports
        .dpop_replays
        .first_use(
            tenant,
            &signed.thumbprint,
            &signed.jti,
            signed.issued_at + PROOF_LIFETIME,
        )
        .await?;
    if !first {
        return Err(DomainError::unauthorized(message!(
            "oauth-this-dpop-proof-was-used-before",
            "this DPoP proof was used before"
        )));
    }
    Ok(PresentedProof {
        dpop: ProvenKey::Proved(signed.thumbprint),
        certificate: PresentedCertificate::NotShown,
    })
}

/// What `evidence`, sent to a resource beside the access token `token`,
/// proves about its holder.
///
/// # Errors
///
/// - `AppError::Unauthenticated` when a `DPoP` header was sent and does not
///   check out, or does not name `token`.
/// - `AppError::Internal` when the replay record cannot be written.
pub(crate) async fn proven_holder(
    ports: &SenderProofPorts,
    tenant: &ScopedTenant,
    evidence: &SenderEvidence,
    token: &Secret,
) -> Result<PresentedProof, AppError> {
    proven_sender(ports, tenant, evidence, DpopUse::AccessToken(token))
        .await
        .map_err(|refusal| match refusal {
            DomainError::Unauthorized(_) => AppError::Unauthenticated,
            other => AppError::internal(other),
        })
}

/// Refuses a proof made for another method or address than `evidence` was
/// sent with, or made outside the minute before `now`.
fn ensure_made_for(
    signed: &SignedDpopProof,
    evidence: &SenderEvidence,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    if !signed.method.eq_ignore_ascii_case(&evidence.method) {
        return Err(DomainError::unauthorized(message!(
            "oauth-this-dpop-proof-was-made-for",
            "this DPoP proof was made for another method"
        )));
    }
    let signed_url = signed.url.split(['?', '#']).next().unwrap_or(&signed.url);
    let requested_url = evidence
        .url
        .split(['?', '#'])
        .next()
        .unwrap_or(&evidence.url);
    if signed_url != requested_url {
        return Err(DomainError::unauthorized(message!(
            "oauth-this-dpop-proof-was-made-for-2",
            "this DPoP proof was made for another address"
        )));
    }
    let fresh = signed.issued_at >= now - PROOF_LIFETIME && signed.issued_at <= now + CLOCK_SKEW;
    if !fresh {
        return Err(DomainError::unauthorized(message!(
            "oauth-this-dpop-proof-is-too-old",
            "this DPoP proof is too old, or made ahead of time"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::grants::token_binding::JwkThumbprint;
    use ianua_domain::types::TokenId;

    use super::*;
    use crate::test_support::oauth::{FakeDpopReplayGuard, FakeDpopVerifier, TEST_DPOP_URL};
    use crate::test_support::{block_on, test_ctx};

    fn key() -> JwkThumbprint {
        JwkThumbprint::new("k".repeat(43)).unwrap()
    }

    /// A proof by `key()` for a `POST` to the test address, made `age` ago.
    fn signed(age: Duration) -> SignedDpopProof {
        SignedDpopProof {
            thumbprint: key(),
            jti: TokenId::new("proof-1").unwrap(),
            method: "POST".to_owned(),
            url: TEST_DPOP_URL.to_owned(),
            issued_at: clock::now() - age,
        }
    }

    fn sent() -> SenderEvidence {
        SenderEvidence {
            dpop: DpopHeader::Sent(Secret::new("a.dpop.proof")),
            method: "POST".to_owned(),
            url: TEST_DPOP_URL.to_owned(),
        }
    }

    fn ports(verifier: FakeDpopVerifier) -> SenderProofPorts {
        SenderProofPorts {
            dpop_verifier: Arc::new(verifier),
            dpop_replays: Arc::new(FakeDpopReplayGuard::default()),
        }
    }

    fn proven(
        ports: &SenderProofPorts,
        evidence: &SenderEvidence,
    ) -> Result<PresentedProof, DomainError> {
        block_on(proven_sender(
            ports,
            &test_ctx().tenant(),
            evidence,
            DpopUse::TokenRequest,
        ))
    }

    /// A request with no `DPoP` header proves nothing, and nothing is
    /// checked.
    #[test]
    fn no_header_proves_nothing() {
        let ports = ports(FakeDpopVerifier::refusing());

        let proof = proven(&ports, &SenderEvidence::nothing("POST", TEST_DPOP_URL)).unwrap();

        assert_eq!(proof, PresentedProof::nothing());
    }

    /// The portal signs a fresh proof for this request. It proves the key.
    #[test]
    fn a_fresh_proof_for_this_request_proves_its_key() {
        let ports = ports(FakeDpopVerifier::accepting(signed(Duration::seconds(5))));

        let proof = proven(&ports, &sent()).unwrap();

        assert_eq!(proof.dpop, ProvenKey::Proved(key()));
    }

    /// A DPoP proof rejected by the signature verifier returns unauthorized.
    #[test]
    fn a_proof_that_does_not_verify_is_refused() {
        let ports = ports(FakeDpopVerifier::refusing());

        assert!(matches!(
            proven(&ports, &sent()),
            Err(DomainError::Unauthorized(_))
        ));
    }

    /// A verified DPoP proof naming another endpoint is refused for this request.
    #[test]
    fn a_proof_for_another_address_is_refused() {
        let mut elsewhere = signed(Duration::seconds(5));
        elsewhere.url = "https://auth.acme.com/oauth/userinfo".to_owned();
        let ports = ports(FakeDpopVerifier::accepting(elsewhere));

        assert!(proven(&ports, &sent()).is_err());
    }

    /// A verified DPoP proof made for GET is refused on a POST request.
    #[test]
    fn a_proof_for_another_method_is_refused() {
        let mut other = signed(Duration::seconds(5));
        other.method = "GET".to_owned();
        let ports = ports(FakeDpopVerifier::accepting(other));

        assert!(proven(&ports, &sent()).is_err());
    }

    /// DPoP proofs dated ten minutes in the past or future are both refused.
    #[test]
    fn a_stale_or_future_proof_is_refused() {
        let stale = ports(FakeDpopVerifier::accepting(signed(Duration::minutes(10))));
        let ahead = ports(FakeDpopVerifier::accepting(signed(-Duration::minutes(10))));

        assert!(proven(&stale, &sent()).is_err());
        assert!(proven(&ahead, &sent()).is_err());
    }

    /// A fresh DPoP proof succeeds once and returns unauthorized when reused.
    #[test]
    fn a_proof_is_taken_once() {
        let ports = ports(FakeDpopVerifier::accepting(signed(Duration::seconds(5))));
        proven(&ports, &sent()).unwrap();

        let again = proven(&ports, &sent());

        assert!(matches!(again, Err(DomainError::Unauthorized(_))));
    }

    /// A proof's address is compared without its query.
    #[test]
    fn the_query_is_left_out_of_the_address() {
        let mut proof = signed(Duration::seconds(5));
        proof.url.push_str("?proof=1#fragment");
        let mut evidence = sent();
        evidence.url.push_str("?request=2#other");

        assert!(ensure_made_for(&proof, &evidence, clock::now()).is_ok());
    }
}
