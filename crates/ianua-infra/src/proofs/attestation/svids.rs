//! SPIFFE X.509-SVIDs: a workload's certificate, naming its SPIFFE ID,
//! issued under its trust domain's bundle.
//!
//! The material is the SVID as PEM, the leaf first and any intermediates
//! after it. It is taken when:
//!
//! - the leaf names exactly one URI, a well-formed `spiffe://` ID, and is
//!   no certificate authority itself;
//! - the deployment holds a bundle for that ID's trust domain, and the
//!   chain holds to one of its anchors, so one domain's authority cannot
//!   vouch for another's workloads;
//! - the proof is the leaf key's signature of the binding's signed bytes:
//!   a context string, then the binding of the platform's nonce and the
//!   key being enrolled. A certificate is public and proves nothing by
//!   being shown, and a signature made for one enrolled key is refused for
//!   any other.
//!
//! Revocation lists are not read: SVIDs live for hours, and the platform
//! binds the attested subject to one agent, so a stolen SVID's key, not the
//! certificate, is what an attacker would need.
//!
//! The egress gateway names the service behind a verified client
//! certificate the same way, with [`service_named_by`].

use async_trait::async_trait;
use data_encoding::HEXLOWER;
use der::Decode as _;
use der::asn1::ObjectIdentifier;
use ianua_app::ports::agents::{AgentAttestor, AttestationPresentation, EnrolledKey};
use ianua_domain::domains::agents::identity::attestation::{
    AttestationMethod, AttestedIdentity, AttestedSubject,
};
use ianua_domain::domains::routing::egress::ServiceIdentity;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use sha2::{Digest as _, Sha256};
use x509_cert::Certificate;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;

use crate::proofs::attestation::certificates::{
    TrustAnchors, chain_in, ensure_chain_holds, is_authority, key_of,
};
use crate::proofs::attestation::keys::ensure_binding_signed;
use crate::proofs::attestation::{binding_for, material_for, refused};

/// The OID of the subject alternative name extension.
const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// The scheme every SPIFFE ID starts with.
const SPIFFE_SCHEME: &str = "spiffe://";

/// The longest trust domain name SPIFFE allows.
const LONGEST_TRUST_DOMAIN: usize = 255;

/// The authorities one SPIFFE trust domain issues its SVIDs under.
pub struct SpiffeTrustBundle {
    trust_domain: String,
    anchors: TrustAnchors,
}

impl SpiffeTrustBundle {
    /// The bundle of `trust_domain`, its authorities' certificates in
    /// `anchor_pems`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the trust domain is no
    /// SPIFFE trust domain name, or an anchor cannot be read.
    pub fn new(trust_domain: &str, anchor_pems: &[String]) -> Result<Self, DomainError> {
        if !is_trust_domain(trust_domain) {
            return Err(DomainError::infra_msg(
                "a SPIFFE trust bundle names no trust domain",
            ));
        }
        Ok(Self {
            trust_domain: trust_domain.to_owned(),
            anchors: TrustAnchors::from_pem(anchor_pems)?,
        })
    }
}

/// The attestor of SPIFFE X.509-SVIDs, against the bundles of the trust
/// domains the deployment trusts.
pub struct SpiffeAgentAttestor {
    bundles: Vec<SpiffeTrustBundle>,
}

impl SpiffeAgentAttestor {
    /// An attestor trusting the SVIDs of `bundles`' trust domains alone.
    #[must_use]
    pub fn new(bundles: Vec<SpiffeTrustBundle>) -> Self {
        Self { bundles }
    }

    /// The bundle of the trust domain `id` belongs to.
    fn bundle_for(&self, id: &str) -> Result<&SpiffeTrustBundle, DomainError> {
        let domain = trust_domain_of(id).ok_or_else(|| refused("the SVID names no SPIFFE ID"))?;
        self.bundles
            .iter()
            .find(|bundle| bundle.trust_domain == domain)
            .ok_or_else(|| refused("the SVID's trust domain is not trusted"))
    }
}

#[async_trait]
impl AgentAttestor for SpiffeAgentAttestor {
    async fn verify(
        &self,
        presentation: &AttestationPresentation,
        key: &EnrolledKey,
    ) -> Result<AttestedIdentity, DomainError> {
        let material = material_for(presentation, AttestationMethod::Spiffe)?;
        let binding = binding_for(presentation, key)?;
        let chain = chain_in(material)?;
        let Some(leaf) = chain.first() else {
            return Err(refused("the attestation holds no certificate"));
        };
        if is_authority(leaf) {
            return Err(refused("an SVID is never a certificate authority"));
        }
        let id = spiffe_id(leaf)?;
        let bundle = self.bundle_for(&id)?;
        ensure_chain_holds(&chain, &bundle.anchors, clock::now())?;
        ensure_binding_signed(&key_of(leaf)?, &presentation.proof, &binding)?;
        let subject =
            AttestedSubject::new(id).map_err(|_| refused("the SPIFFE ID is no subject"))?;
        Ok(AttestedIdentity::new(AttestationMethod::Spiffe, subject))
    }
}

/// The service a client certificate names, for the egress gateway once the
/// connection's handshake verified it: its SPIFFE ID when it names exactly
/// one, otherwise `sha256:` and the lower-case hex of the certificate's
/// SHA-256 fingerprint. `None` when `leaf_der` is no certificate.
#[must_use]
pub fn service_named_by(leaf_der: &[u8]) -> Option<ServiceIdentity> {
    let leaf = Certificate::from_der(leaf_der).ok()?;
    if let Ok(id) = spiffe_id(&leaf) {
        return ServiceIdentity::new(id).ok();
    }
    let fingerprint = HEXLOWER.encode(&Sha256::digest(leaf_der));
    ServiceIdentity::new(format!("sha256:{fingerprint}")).ok()
}

/// The one SPIFFE ID `leaf` names, refused when it names none or several.
fn spiffe_id(leaf: &Certificate) -> Result<String, DomainError> {
    let Some(extension) = leaf
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|extension| extension.extn_id == SUBJECT_ALT_NAME)
    else {
        return Err(refused("the SVID names no SPIFFE ID"));
    };
    let names = SubjectAltName::from_der(extension.extn_value.as_bytes())
        .map_err(|_| refused("the SVID's names cannot be read"))?;
    let mut uris = names.0.iter().filter_map(|name| match name {
        GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_str()),
        GeneralName::OtherName(_)
        | GeneralName::Rfc822Name(_)
        | GeneralName::DnsName(_)
        | GeneralName::DirectoryName(_)
        | GeneralName::EdiPartyName(_)
        | GeneralName::IpAddress(_)
        | GeneralName::RegisteredId(_) => None,
    });
    let (Some(uri), None) = (uris.next(), uris.next()) else {
        return Err(refused("an SVID names exactly one URI"));
    };
    if trust_domain_of(uri).is_none() {
        return Err(refused("the SVID's URI is no SPIFFE ID"));
    }
    Ok(uri.to_owned())
}

/// The trust domain of the SPIFFE ID `id`, when it is a well-formed
/// workload ID: a trust domain and a path of plain segments.
fn trust_domain_of(id: &str) -> Option<&str> {
    let (domain, path) = id.strip_prefix(SPIFFE_SCHEME)?.split_once('/')?;
    let plain_path = path.split('/').all(|segment| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
    });
    (is_trust_domain(domain) && plain_path).then_some(domain)
}

/// Whether `domain` is a SPIFFE trust domain name: lower-case letters,
/// digits, dots, dashes and underscores.
fn is_trust_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= LONGEST_TRUST_DOMAIN
        && domain
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.' | '_'))
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ianua_app::ports::agents::AttestationProof;
    use ianua_domain::domains::agents::identity::challenge::AttestationNonce;
    use p256::ecdsa::signature::Signer as _;
    use p256::pkcs8::DecodePrivateKey as _;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};

    use super::*;
    use crate::proofs::attestation::AttestationBinding;
    use crate::proofs::attestation::tests::enrolled_key;

    /// A trust domain's authority, and the SVIDs it issues.
    struct Domain {
        issuer: Issuer<'static, KeyPair>,
        anchor: String,
    }

    impl Domain {
        fn new() -> Self {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(Vec::new()).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let anchor = params.self_signed(&key).unwrap().pem();
            Self {
                issuer: Issuer::new(params, key),
                anchor,
            }
        }

        fn bundle(&self, trust_domain: &str) -> SpiffeTrustBundle {
            SpiffeTrustBundle::new(trust_domain, std::slice::from_ref(&self.anchor)).unwrap()
        }

        /// An SVID naming `uris`, with the key that holds it.
        fn svid(&self, uris: &[&str]) -> (String, KeyPair) {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(Vec::new()).unwrap();
            params.subject_alt_names = uris
                .iter()
                .map(|uri| SanType::URI((*uri).try_into().unwrap()))
                .collect();
            let pem = params.signed_by(&key, &self.issuer).unwrap().pem();
            (pem, key)
        }
    }

    fn nonce() -> AttestationNonce {
        AttestationNonce::new("spiffe-bootstrap-nonce-0123456789abcdef").unwrap()
    }

    /// `bytes` signed by `key`, base64url.
    fn signature_of(key: &KeyPair, bytes: &[u8]) -> String {
        let signer = p256::ecdsa::SigningKey::from_pkcs8_pem(&key.serialize_pem()).unwrap();
        let signature: p256::ecdsa::Signature = signer.sign(bytes);
        URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())
    }

    /// The binding of the nonce and `enrolled` signed by `key`, as the
    /// workload sends it.
    fn signed_by(key: &KeyPair, enrolled: &EnrolledKey) -> String {
        let binding = AttestationBinding::of(&nonce(), &enrolled.public_key).unwrap();
        signature_of(key, &binding.signed_bytes())
    }

    fn presented(material: String, signature: String) -> AttestationPresentation {
        AttestationPresentation {
            method: AttestationMethod::Spiffe,
            material,
            proof: AttestationProof {
                nonce: nonce(),
                signature,
            },
        }
    }

    /// An SVID from a trusted domain, its key signing the binding, attests
    /// the SPIFFE ID it names.
    #[tokio::test]
    async fn an_svid_proving_its_key_attests_its_spiffe_id() {
        let domain = Domain::new();
        let (svid, key) = domain.svid(&["spiffe://example.org/ns/prod/agent"]);
        let attestor = SpiffeAgentAttestor::new(vec![domain.bundle("example.org")]);
        let enrolled = enrolled_key();

        let attested = attestor
            .verify(&presented(svid, signed_by(&key, &enrolled)), &enrolled)
            .await
            .unwrap();

        assert_eq!(attested.method(), AttestationMethod::Spiffe);
        assert_eq!(
            attested.subject().as_str(),
            "spiffe://example.org/ns/prod/agent"
        );
    }

    /// An SVID accompanied by a proof from another private key is unauthorized.
    #[tokio::test]
    async fn an_svid_without_its_key_is_refused() {
        let domain = Domain::new();
        let (svid, _) = domain.svid(&["spiffe://example.org/agent"]);
        let thief = KeyPair::generate().unwrap();
        let attestor = SpiffeAgentAttestor::new(vec![domain.bundle("example.org")]);
        let enrolled = enrolled_key();

        let attested = attestor
            .verify(&presented(svid, signed_by(&thief, &enrolled)), &enrolled)
            .await;

        assert!(matches!(attested, Err(DomainError::Unauthorized(_))));
    }

    /// A valid SVID proof cannot be reused to attest a different enrolled key.
    #[tokio::test]
    async fn a_proof_made_for_another_enrolled_key_is_refused() {
        let domain = Domain::new();
        let (svid, key) = domain.svid(&["spiffe://example.org/agent"]);
        let attestor = SpiffeAgentAttestor::new(vec![domain.bundle("example.org")]);
        let workload = enrolled_key();
        let thief = enrolled_key();

        let attested = attestor
            .verify(&presented(svid, signed_by(&key, &workload)), &thief)
            .await;

        assert!(matches!(attested, Err(DomainError::Unauthorized(_))));
    }

    /// Signing only the nonce does not satisfy the SVID proof's enrolled-key binding.
    #[tokio::test]
    async fn a_signature_over_the_bare_nonce_is_refused() {
        let domain = Domain::new();
        let (svid, key) = domain.svid(&["spiffe://example.org/agent"]);
        let attestor = SpiffeAgentAttestor::new(vec![domain.bundle("example.org")]);
        let bare = signature_of(&key, nonce().as_str().as_bytes());

        let attested = attestor
            .verify(&presented(svid, bare), &enrolled_key())
            .await;

        assert!(matches!(attested, Err(DomainError::Unauthorized(_))));
    }

    /// An authority trusted for one domain cannot attest an SVID naming another domain.
    #[tokio::test]
    async fn an_svid_for_another_trust_domain_is_refused() {
        let ours = Domain::new();
        let theirs = Domain::new();
        let (svid, key) = theirs.svid(&["spiffe://example.org/agent"]);
        let attestor = SpiffeAgentAttestor::new(vec![
            ours.bundle("example.org"),
            theirs.bundle("partner.example"),
        ]);
        let enrolled = enrolled_key();

        let attested = attestor
            .verify(&presented(svid, signed_by(&key, &enrolled)), &enrolled)
            .await;

        assert!(matches!(attested, Err(DomainError::Unauthorized(_))));
    }

    /// Multiple identities, invalid SPIFFE URIs and unsupported identity paths make an SVID unauthorized.
    #[tokio::test]
    async fn an_svid_naming_other_than_one_spiffe_id_is_refused() {
        let domain = Domain::new();
        let attestor = SpiffeAgentAttestor::new(vec![domain.bundle("example.org")]);
        let enrolled = enrolled_key();

        for uris in [
            vec!["spiffe://example.org/a", "spiffe://example.org/b"],
            vec!["https://example.org/a"],
            vec!["spiffe://example.org/../admin"],
        ] {
            let (svid, key) = domain.svid(&uris);

            let attested = attestor
                .verify(&presented(svid, signed_by(&key, &enrolled)), &enrolled)
                .await;

            assert!(
                matches!(attested, Err(DomainError::Unauthorized(_))),
                "{uris:?}"
            );
        }
    }

    /// A different attestation method or unreadable certificate material fails SVID verification.
    #[tokio::test]
    async fn another_method_or_garbled_material_is_refused() {
        let domain = Domain::new();
        let (svid, key) = domain.svid(&["spiffe://example.org/agent"]);
        let attestor = SpiffeAgentAttestor::new(vec![domain.bundle("example.org")]);
        let enrolled = enrolled_key();
        let mut other_method = presented(svid, signed_by(&key, &enrolled));
        other_method.method = AttestationMethod::Tpm;

        let wrong = attestor.verify(&other_method, &enrolled).await;
        let garbled = attestor
            .verify(
                &presented("garbage".to_owned(), signed_by(&key, &enrolled)),
                &enrolled,
            )
            .await;

        assert!(matches!(wrong, Err(DomainError::Unauthorized(_))));
        assert!(matches!(garbled, Err(DomainError::Unauthorized(_))));
    }

    /// Invalid trust-domain configuration, including a name with a path, produces an infrastructure error.
    #[test]
    fn a_bundle_for_no_trust_domain_is_a_configuration_error() {
        let domain = Domain::new();

        let made = SpiffeTrustBundle::new("Example.org/ns", std::slice::from_ref(&domain.anchor));

        assert!(matches!(made, Err(DomainError::Infrastructure(_))));
    }

    /// The DER of the certificate in `pem`.
    fn der_of(pem: &str) -> Vec<u8> {
        let (_, document) = der::Document::from_pem(pem).unwrap();
        document.as_bytes().to_vec()
    }

    /// The egress gateway names a workload by its SPIFFE ID, and a
    /// certificate without exactly one by its fingerprint.
    #[test]
    fn a_service_is_named_by_its_spiffe_id_or_its_fingerprint() {
        let domain = Domain::new();
        let (named, _) = domain.svid(&["spiffe://example.org/ns/svc/sa/fetcher"]);
        let (unnamed, _) = domain.svid(&[]);

        let by_id = service_named_by(&der_of(&named)).unwrap();
        let by_print = service_named_by(&der_of(&unnamed)).unwrap();

        assert_eq!(by_id.as_str(), "spiffe://example.org/ns/svc/sa/fetcher");
        assert!(by_print.as_str().starts_with("sha256:"));
        assert_eq!(by_print.as_str().len(), "sha256:".len() + 64);
        assert!(service_named_by(b"no certificate").is_none());
    }
}
