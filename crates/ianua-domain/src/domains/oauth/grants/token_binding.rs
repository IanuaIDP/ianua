//! Tokens bound to their holder: to a key the client proves with each
//! request (`DPoP`, RFC 9449), or to the TLS client certificate it
//! connects with (RFC 8705).
//!
//! A bearer token works for whoever holds it. Mallory copies one out of a
//! log and calls the API as Ann. A bound token works only beside a proof
//! made with the key or certificate it was bound to, which never left Ann's
//! app.

use crate::domains::oauth::clients::client::OAuthClient;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};

text_value! {
    /// The JWK SHA-256 thumbprint of a public key (RFC 7638), base64url
    /// without padding: the `jkt` a `DPoP`-bound token names. 43
    /// characters.
    pub struct JwkThumbprint;
}

impl TextValue for JwkThumbprint {
    const FIELD: &'static str = "jkt";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        sha256_base64url(check)
    }
}

text_value! {
    /// The SHA-256 thumbprint of a TLS client certificate's DER encoding,
    /// base64url without padding: the `x5t#S256` a certificate-bound token
    /// names (RFC 8705 3.1). 43 characters.
    pub struct CertThumbprint;
}

impl TextValue for CertThumbprint {
    const FIELD: &'static str = "x5t#S256";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        sha256_base64url(check)
    }
}

/// A SHA-256 digest written in base64url without padding: 43 characters.
fn sha256_base64url(check: Validator<'_>) -> Validator<'_> {
    check.identifier(
        43..=43,
        Charset::LOWERCASE
            | Charset::UPPERCASE
            | Charset::DIGIT
            | Charset::HYPHEN
            | Charset::UNDERSCORE,
    )
}

/// What a token must be presented with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SenderBinding {
    /// Nothing: whoever holds it may use it.
    Bearer,
    /// A `DPoP` proof signed with the key of this thumbprint.
    DpopKey(JwkThumbprint),
    /// The TLS client certificate of this thumbprint.
    Certificate(CertThumbprint),
}

impl SenderBinding {
    /// Whether a request that proved `proof` may use the token.
    #[must_use]
    pub fn admits(&self, proof: &PresentedProof) -> bool {
        match self {
            Self::Bearer => true,
            Self::DpopKey(bound) => matches!(&proof.dpop, ProvenKey::Proved(key) if key == bound),
            Self::Certificate(bound) => matches!(
                &proof.certificate,
                PresentedCertificate::Presented(thumbprint) if thumbprint == bound
            ),
        }
    }

    /// What a connection's key proof stands for on each later check of the
    /// same connection. A proof may be used only once, and the proof Ann's
    /// app spent to open her WebSocket cannot be sent again, so the key the
    /// token is bound to stands in for it. A certificate binding gets
    /// nothing: no request proves a certificate.
    #[must_use]
    pub fn proof_spent_at_opening(&self) -> PresentedProof {
        match self {
            Self::DpopKey(key) => PresentedProof {
                dpop: ProvenKey::Proved(key.clone()),
                certificate: PresentedCertificate::NotShown,
            },
            Self::Bearer | Self::Certificate(_) => PresentedProof::nothing(),
        }
    }

    /// Refuses a request that did not prove what the token is bound to.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Unauthorized`] when `proof` lacks the key or
    ///   certificate the token is bound to.
    pub fn ensure_admits(&self, proof: &PresentedProof) -> Result<(), DomainError> {
        if self.admits(proof) {
            return Ok(());
        }
        Err(DomainError::unauthorized(message!(
            "oauth-this-token-is-bound-to-a",
            "this token is bound to a key or certificate the request did not prove"
        )))
    }
}

/// The key a request proved holding with a verified `DPoP` proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenKey {
    /// No `DPoP` proof, or none that verified.
    NotShown,
    /// A proof signed with the key of this thumbprint, checked for its
    /// method, address, time and replay.
    Proved(JwkThumbprint),
}

/// The TLS client certificate a request came with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresentedCertificate {
    /// None.
    NotShown,
    /// One with this thumbprint, its private key proved by the handshake.
    Presented(CertThumbprint),
}

/// What a request proved about its holder, as the adapters checked it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedProof {
    /// The `DPoP` key it proved, if any.
    pub dpop: ProvenKey,
    /// The client certificate it came with, if any.
    pub certificate: PresentedCertificate,
}

impl PresentedProof {
    /// A request that proved nothing about its holder.
    #[must_use]
    pub fn nothing() -> Self {
        Self {
            dpop: ProvenKey::NotShown,
            certificate: PresentedCertificate::NotShown,
        }
    }
}

/// What a client's access tokens must be bound to (RFC 9449 5.2
/// `dpop_bound_access_tokens`, RFC 8705 3.4
/// `tls_client_certificate_bound_access_tokens`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderConstraint {
    /// Nothing is required: a token is bound to a `DPoP` key when the
    /// request proved one, and is a bearer token otherwise.
    BearerAllowed,
    /// Every token is bound to a `DPoP` key.
    DpopRequired,
    /// Every token is bound to the client's TLS certificate.
    CertificateRequired,
}

impl SenderConstraint {
    /// What a token issued on a request that proved `proof` is bound to.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Unauthorized`] when the client requires a `DPoP` key
    ///   or a certificate and the request proved none.
    pub fn binding_for(self, proof: &PresentedProof) -> Result<SenderBinding, DomainError> {
        match (self, &proof.dpop, &proof.certificate) {
            (Self::CertificateRequired, _, PresentedCertificate::Presented(thumbprint)) => {
                Ok(SenderBinding::Certificate(thumbprint.clone()))
            }
            (Self::CertificateRequired, ..) => Err(DomainError::unauthorized(message!(
                "oauth-this-client-s-tokens-are-bound",
                "this client's tokens are bound to its certificate, and none was presented"
            ))),
            (_, ProvenKey::Proved(key), _) => Ok(SenderBinding::DpopKey(key.clone())),
            (Self::DpopRequired, ProvenKey::NotShown, _) => {
                Err(DomainError::unauthorized(message!(
                    "oauth-this-client-s-tokens-are-bound-2",
                    "this client's tokens are bound to a DPoP key, and no proof was presented"
                )))
            }
            (Self::BearerAllowed, ProvenKey::NotShown, _) => Ok(SenderBinding::Bearer),
        }
    }
}

/// What a refresh token issued to `client` on a request that proved
/// `proof` is bound to: a public client's to its `DPoP` key, when it proved
/// one (RFC 9449 5). A confidential client proves itself on every refresh,
/// so its refresh tokens stay bearer.
pub(crate) fn refresh_binding<T: TenantScope>(
    client: &OAuthClient<T>,
    proof: &PresentedProof,
) -> SenderBinding {
    let (ProvenKey::Proved(key), true) = (&proof.dpop, client.is_public()) else {
        return SenderBinding::Bearer;
    };
    SenderBinding::DpopKey(key.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A thumbprint of 43 characters.
    fn key(fill: char) -> JwkThumbprint {
        JwkThumbprint::new(fill.to_string().repeat(43)).unwrap()
    }

    /// A request that proved holding `thumbprint`.
    fn proving(thumbprint: JwkThumbprint) -> PresentedProof {
        PresentedProof {
            dpop: ProvenKey::Proved(thumbprint),
            certificate: PresentedCertificate::NotShown,
        }
    }

    /// The certificate thumbprint of `fill` repeated.
    fn certificate(fill: char) -> CertThumbprint {
        CertThumbprint::new(fill.to_string().repeat(43)).unwrap()
    }

    /// A request with the certificate of thumbprint `fill` repeated.
    fn with_certificate(fill: char) -> PresentedProof {
        PresentedProof {
            dpop: ProvenKey::NotShown,
            certificate: PresentedCertificate::Presented(certificate(fill)),
        }
    }

    /// A DPoP binding rejects absent proof and proof of a different key.
    /// Proof of the bound key is accepted.
    #[test]
    fn a_dpop_bound_token_needs_its_own_key() {
        let binding = SenderBinding::DpopKey(key('a'));

        assert!(!binding.admits(&PresentedProof::nothing()));
        assert!(!binding.admits(&proving(key('m'))));
        assert!(binding.admits(&proving(key('a'))));
    }

    /// The token bound to Ann's key is admitted on her open connection's
    /// later checks; a certificate-bound one is not.
    #[test]
    fn a_proof_spent_at_opening_admits_only_a_key_bound_token() {
        let bound = SenderBinding::DpopKey(key('a'));
        let certified = SenderBinding::Certificate(certificate('c'));

        assert!(bound.admits(&bound.proof_spent_at_opening()));
        assert!(!certified.admits(&certified.proof_spent_at_opening()));
    }

    /// A certificate binding accepts its own certificate and reports an
    /// unauthorized request when a different certificate is presented.
    #[test]
    fn a_certificate_bound_token_needs_its_own_certificate() {
        let binding = SenderBinding::Certificate(certificate('c'));

        assert!(binding.ensure_admits(&with_certificate('c')).is_ok());
        assert!(matches!(
            binding.ensure_admits(&with_certificate('m')),
            Err(DomainError::Unauthorized(_))
        ));
    }

    /// A bearer token works with or without a proof.
    #[test]
    fn a_bearer_token_needs_nothing() {
        assert!(SenderBinding::Bearer.admits(&PresentedProof::nothing()));
    }

    /// A client that allows bearer tokens still gets a bound one when its
    /// request proved a key, and a bearer one when it proved nothing.
    #[test]
    fn a_proved_key_binds_the_token_even_when_not_required() {
        let constraint = SenderConstraint::BearerAllowed;

        assert_eq!(
            constraint.binding_for(&proving(key('a'))).unwrap(),
            SenderBinding::DpopKey(key('a'))
        );
        assert_eq!(
            constraint.binding_for(&PresentedProof::nothing()).unwrap(),
            SenderBinding::Bearer
        );
    }

    /// Required DPoP binding rejects absent proof. Required certificate
    /// binding rejects a request that proves only a DPoP key.
    #[test]
    fn a_required_binding_without_its_proof_is_refused() {
        let dpop = SenderConstraint::DpopRequired.binding_for(&PresentedProof::nothing());
        let certificate = SenderConstraint::CertificateRequired.binding_for(&proving(key('a')));

        assert!(matches!(dpop, Err(DomainError::Unauthorized(_))));
        assert!(matches!(certificate, Err(DomainError::Unauthorized(_))));
    }

    /// A thumbprint is 43 base64url characters; anything else is refused.
    #[test]
    fn a_thumbprint_is_43_base64url_characters() {
        assert!(JwkThumbprint::new("a".repeat(42)).is_err());
        assert!(JwkThumbprint::new(format!("{}=", "a".repeat(42))).is_err());
    }
}
