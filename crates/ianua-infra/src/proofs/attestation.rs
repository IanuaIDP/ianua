//! Platform attestations: how an agent proves where it runs without a
//! stored secret, checked per platform.
//!
//! Each attestor checks one method and refuses every other, and
//! [`MethodAgentAttestor`] hands a presentation to the one registered for
//! its method, refusing a method nobody registered. Anything missing,
//! unreadable or failing is a refusal.
//!
//! Every proof carries the [`AttestationBinding`] of the platform's nonce
//! and the key the bootstrap enrols, so a proof seen before it is used
//! cannot enrol anyone else's key. The bootstrap use case spends the nonce
//! before it asks, so a proof cannot be presented twice either:
//!
//! - a SPIFFE SVID ([`SpiffeAgentAttestor`]) proves its key by signing the
//!   binding;
//! - a TPM quote ([`TpmAgentAttestor`]) carries the binding in what the chip
//!   signed;
//! - a GCP identity token ([`GcpAgentAttestor`]) names the binding as its
//!   audience;
//! - an AWS `sts:GetCallerIdentity` request ([`AwsAgentAttestor`]) carries
//!   the binding in a header the role's credentials signed, and AWS checks
//!   that signature when the attestor forwards the request;
//! - a workload token from Kubernetes, GitHub Actions or another OIDC
//!   issuer ([`JwksWorkloadTokenVerifier`]) names the binding as its only
//!   audience, its issuer's keys read through its discovery document
//!   ([`DiscoveredIssuerKeys`]).
//!
//! An Azure managed identity has no attestor: nothing Azure signs can
//! carry the binding, so no policy may trust it.

mod binding;
mod caller_identities;
mod certificates;
mod discovered;
mod instance_tokens;
mod keys;
mod published;
mod quotes;
mod signed_requests;
mod svids;
mod workload_tokens;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
pub(crate) use binding::AttestationBinding;
pub use caller_identities::AwsAgentAttestor;
pub use discovered::DiscoveredIssuerKeys;
use ianua_app::ports::agents::{AgentAttestor, AttestationPresentation, EnrolledKey};
use ianua_domain::domains::agents::identity::attestation::{AttestationMethod, AttestedIdentity};
use ianua_domain::shared::errors::DomainError;
pub use instance_tokens::GcpAgentAttestor;
pub use published::{FixedIssuerKeys, IssuerKeys, KeyKeeping};
pub(crate) use published::{KeyCache, MOST_KEY_SET_BYTES, Wanted, key_set_in};
pub use quotes::TpmAgentAttestor;
pub use svids::{SpiffeAgentAttestor, SpiffeTrustBundle, service_named_by};
pub use workload_tokens::JwksWorkloadTokenVerifier;

/// The most bytes of material any presentation may carry. A chain of four
/// certificates, a quote, a token or a signed request fit well inside it.
const MOST_MATERIAL: usize = 65_536;

/// A refusal of a presentation, for a reason in fixed words that never
/// quote what was presented.
pub(crate) fn refused(reason: &'static str) -> DomainError {
    DomainError::unauthorized(reason)
}

/// The material of `presentation`, refused unless it is for `method` and
/// no longer than [`MOST_MATERIAL`].
///
/// # Errors
///
/// Returns `DomainError::Unauthorized` for another method or too much
/// material.
pub(crate) fn material_for(
    presentation: &AttestationPresentation,
    method: AttestationMethod,
) -> Result<&str, DomainError> {
    if presentation.method != method {
        return Err(refused("this attestor does not check that method"));
    }
    if presentation.material.len() > MOST_MATERIAL {
        return Err(refused("the attestation is too long"));
    }
    Ok(&presentation.material)
}

/// The binding `presentation`'s proof must carry for enrolling `key`.
///
/// # Errors
///
/// Returns `DomainError::Unauthorized` when `key` cannot be read.
pub(crate) fn binding_for(
    presentation: &AttestationPresentation,
    key: &EnrolledKey,
) -> Result<AttestationBinding, DomainError> {
    AttestationBinding::of(&presentation.proof.nonce, &key.public_key)
}

/// The attestor handing each presentation to the one registered for its
/// method, and refusing a method none is registered for.
#[derive(Default)]
pub struct MethodAgentAttestor {
    attestors: HashMap<AttestationMethod, Arc<dyn AgentAttestor>>,
}

impl MethodAgentAttestor {
    /// An attestor with no method registered, refusing everything.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// This attestor, handing presentations for `method` to `attestor`.
    #[must_use]
    pub fn with(mut self, method: AttestationMethod, attestor: Arc<dyn AgentAttestor>) -> Self {
        self.attestors.insert(method, attestor);
        self
    }
}

#[async_trait]
impl AgentAttestor for MethodAgentAttestor {
    async fn verify(
        &self,
        presentation: &AttestationPresentation,
        key: &EnrolledKey,
    ) -> Result<AttestedIdentity, DomainError> {
        let Some(attestor) = self.attestors.get(&presentation.method) else {
            return Err(refused("no attestor checks this method"));
        };
        attestor.verify(presentation, key).await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use ianua_app::ports::agents::AttestationProof;
    use ianua_domain::domains::agents::identity::attestation::AttestedSubject;
    use ianua_domain::domains::agents::identity::challenge::AttestationNonce;
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
    use ianua_domain::types::PublicKeyPem;
    use p256::pkcs8::{EncodePublicKey as _, LineEnding};

    use super::*;

    /// A fresh Ed25519 key a workload made for itself, as it enrols it.
    pub(crate) fn enrolled_key() -> EnrolledKey {
        let signer = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let pem = signer
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        EnrolledKey {
            algorithm: SigningAlgorithm::EdDsa,
            public_key: PublicKeyPem::new(pem).unwrap(),
        }
    }

    /// An attestor vouching for one subject under any method it is asked.
    struct Vouching;

    #[async_trait]
    impl AgentAttestor for Vouching {
        async fn verify(
            &self,
            presentation: &AttestationPresentation,
            _key: &EnrolledKey,
        ) -> Result<AttestedIdentity, DomainError> {
            Ok(AttestedIdentity::new(
                presentation.method,
                AttestedSubject::new("spiffe://example.org/agent").unwrap(),
            ))
        }
    }

    fn presented(method: AttestationMethod) -> AttestationPresentation {
        AttestationPresentation {
            method,
            material: "material".to_owned(),
            proof: AttestationProof {
                nonce: AttestationNonce::new("n".repeat(40)).unwrap(),
                signature: String::new(),
            },
        }
    }

    /// A presentation reaches the attestor registered for its method.
    #[tokio::test]
    async fn a_presentation_reaches_the_attestor_of_its_method() {
        let attestor =
            MethodAgentAttestor::new().with(AttestationMethod::Spiffe, Arc::new(Vouching));

        let attested = attestor
            .verify(&presented(AttestationMethod::Spiffe), &enrolled_key())
            .await;

        assert!(attested.is_ok());
    }

    /// An unregistered attestation method is rejected rather than routed to another attestor.
    #[tokio::test]
    async fn a_method_nobody_registered_is_refused() {
        let attestor =
            MethodAgentAttestor::new().with(AttestationMethod::Spiffe, Arc::new(Vouching));

        let attested = attestor
            .verify(&presented(AttestationMethod::Tpm), &enrolled_key())
            .await;

        assert!(matches!(attested, Err(DomainError::Unauthorized(_))));
    }

    /// Reading material requires the expected attestation method and enforces the presentation size limit.
    #[test]
    fn material_is_read_only_for_its_method_and_within_its_size() {
        let mut long = presented(AttestationMethod::Tpm);
        long.material = "x".repeat(MOST_MATERIAL + 1);

        assert!(
            material_for(
                &presented(AttestationMethod::Tpm),
                AttestationMethod::Spiffe
            )
            .is_err()
        );
        assert!(material_for(&long, AttestationMethod::Tpm).is_err());
        assert!(material_for(&presented(AttestationMethod::Tpm), AttestationMethod::Tpm).is_ok());
    }
}
