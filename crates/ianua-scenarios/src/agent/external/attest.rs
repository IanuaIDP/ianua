//! Where an attested agent runs: a SPIFFE trust domain with an authority
//! of its own, and the workloads it issues X.509-SVIDs to.
//!
//! A workload proves itself by signing, with its SVID's key, the binding
//! of the platform's single-use nonce and the key it enrols:
//! `SHA-256("ianua-attestation-binding-v1" 0x00 nonce 0x00 key-DER)` in
//! hex, after the words `ianua-attestation-proof-v1:`. A proof made for
//! one key passes for no other.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use sha2::{Digest as _, Sha256};

use crate::agent::keys::AgentKey;
use crate::wire::agents::attestation::Attestation;

/// The words the binding's hash starts with.
const BINDING_CONTEXT: &[u8] = b"ianua-attestation-binding-v1";

/// The words a workload signs ahead of the binding.
const PROOF_CONTEXT: &str = "ianua-attestation-proof-v1:";

/// The method an SVID attests by.
pub const SPIFFE: &str = "spiffe";

/// A SPIFFE trust domain and the authority that issues its SVIDs.
pub struct TrustDomain {
    name: String,
    authority: CertifiedIssuer<'static, KeyPair>,
}

impl fmt::Debug for TrustDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustDomain")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl TrustDomain {
    /// The trust domain `name`, such as `workloads.scenarios.test`, with
    /// a fresh authority.
    ///
    /// # Errors
    ///
    /// When the authority's certificate cannot be made.
    pub fn new(name: &str) -> Result<Self, rcgen::Error> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, format!("{name} authority"));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        Ok(Self {
            name: name.to_owned(),
            authority: CertifiedIssuer::self_signed(params, KeyPair::generate()?)?,
        })
    }

    /// Authority component shared by the SPIFFE identities issued here.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The SPIFFE ID of the workload at `path`, such as
    /// `spiffe://workloads.scenarios.test/agents/reporter`.
    #[must_use]
    pub fn id_of(&self, path: &str) -> String {
        format!("spiffe://{}/{}", self.name, path.trim_start_matches('/'))
    }

    /// Its bundle, the authority's certificate as PEM, for
    /// `AGENT_SPIFFE_TRUST_BUNDLE_PATH`.
    #[must_use]
    pub fn bundle_pem(&self) -> String {
        self.authority.pem()
    }

    /// The workload at `path`, with an SVID this authority issued it.
    ///
    /// # Errors
    ///
    /// When the SVID cannot be made.
    pub fn workload(&self, path: &str) -> Result<Workload, rcgen::Error> {
        let spiffe_id = self.id_of(path);
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.subject_alt_names = vec![SanType::URI(Ia5String::try_from(spiffe_id.as_str())?)];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let leaf_key = KeyPair::generate()?;
        let svid = params.signed_by(&leaf_key, &*self.authority)?;
        let key = AgentKey::from_pkcs8_der(&leaf_key.serialize_der())
            .map_err(|_| rcgen::Error::CouldNotParseKeyPair)?;
        Ok(Workload {
            spiffe_id,
            svid_pem: svid.pem(),
            key,
        })
    }
}

/// A workload holding an SVID and the key it was issued for.
#[derive(Clone)]
pub struct Workload {
    spiffe_id: String,
    svid_pem: String,
    key: AgentKey,
}

impl fmt::Debug for Workload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Workload")
            .field("spiffe_id", &self.spiffe_id)
            .finish_non_exhaustive()
    }
}

impl Workload {
    /// Workload identity certified by the SVID's URI subject alternative name.
    #[must_use]
    pub fn spiffe_id(&self) -> &str {
        &self.spiffe_id
    }

    /// Its attestation for the challenge `nonce`, bound to `enrolled`, the
    /// key it asks to be enrolled.
    #[must_use]
    pub fn attestation(&self, nonce: &str, enrolled: &AgentKey) -> Attestation {
        let signed = format!(
            "{PROOF_CONTEXT}{}",
            binding_hex(nonce, &enrolled.public_der())
        );
        Attestation {
            method: SPIFFE.to_owned(),
            material: self.svid_pem.clone(),
            nonce: nonce.to_owned(),
            signature: URL_SAFE_NO_PAD.encode(self.key.signed_der(signed.as_bytes())),
        }
    }
}

/// The binding of `nonce` and the key whose SPKI DER is `key_der`, in
/// lowercase hex.
fn binding_hex(nonce: &str, key_der: &[u8]) -> String {
    let digest = Sha256::new()
        .chain_update(BINDING_CONTEXT)
        .chain_update([0_u8])
        .chain_update(nonce.as_bytes())
        .chain_update([0_u8])
        .chain_update(key_der)
        .finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A proof made for one key binds another value than one made for
    /// another key, or for another nonce.
    #[test]
    fn a_binding_names_one_nonce_and_one_key() {
        let ours = AgentKey::generate().public_der();
        let theirs = AgentKey::generate().public_der();

        let bound = binding_hex("nonce-one", &ours);

        assert_eq!(bound.len(), 64);
        assert_ne!(bound, binding_hex("nonce-one", &theirs));
        assert_ne!(bound, binding_hex("nonce-two", &ours));
    }

    /// A workload's SVID names its SPIFFE ID under its trust domain.
    #[test]
    fn a_workload_is_named_under_its_trust_domain() {
        let domain = TrustDomain::new("workloads.scenarios.test").unwrap();

        let workload = domain.workload("agents/reporter").unwrap();

        assert_eq!(
            workload.spiffe_id(),
            "spiffe://workloads.scenarios.test/agents/reporter"
        );
        assert!(
            domain
                .bundle_pem()
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
    }
}
