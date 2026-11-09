//! TPM 2.0 quotes: a machine's chip signing a statement that carries the
//! platform's nonce.
//!
//! The material is JSON: `aik_certificate`, the PEM chain of the chip's
//! attestation identity key, leaf first; `quote`, the `TPMS_ATTEST` the
//! chip produced, in base64; and `signature`, the key's signature of those
//! bytes in base64, as the key's kind signs natively (DER for ECDSA). It
//! is taken when the chain holds to an anchor the deployment trusts, the
//! leaf is certified as an attestation key (the TCG's AIK certificate
//! purpose, `2.23.133.8.3`), the signature checks against the leaf's key,
//! the quote is a genuine quote, and the qualifying data the chip signed
//! is the 32 bytes of the binding of the platform's nonce and the key
//! being enrolled. The AIK's private half never leaves the chip, so a
//! quote over this binding means the chip took part just now, to enrol
//! that key; someone who sees the quote before it is used cannot enrol a
//! key of their own with it.
//!
//! The purpose matters because the quote's header is only bytes: a TPM
//! refuses to sign them with its restricted attestation key unless it
//! made them, but any other key happily signs them. Without the purpose,
//! any certificate the anchor issued, a server's or a person's, would
//! pass for a chip.
//!
//! The PCR values a quote reports are not held to a measured policy: that
//! needs known-good measurements per hardware and firmware, which the
//! deployment does not keep.

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use der::asn1::ObjectIdentifier;
use ianua_app::ports::agents::{AgentAttestor, AttestationPresentation, EnrolledKey};
use ianua_domain::domains::agents::identity::attestation::{
    AttestationMethod, AttestedIdentity, AttestedSubject,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use serde::Deserialize;
use x509_cert::Certificate;

use crate::proofs::attestation::certificates::{
    TrustAnchors, chain_in, common_name, ensure_chain_holds, has_extended_key_usage,
    key_fingerprint, key_of,
};
use crate::proofs::attestation::{binding_for, material_for, refused};

/// `tcg-kp-AIKCertificate`, the purpose a certificate names for a TPM
/// attestation identity key.
const AIK_CERTIFICATE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.8.3");

/// `TPM_GENERATED_VALUE`, the value every structure a TPM itself made
/// starts with.
const TPM_GENERATED_VALUE: u32 = 0xFF54_4347;

/// `TPM_ST_ATTEST_QUOTE`, the type of a quote among attestation
/// structures.
const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

/// The material a TPM attestation carries.
#[derive(Deserialize)]
struct Envelope {
    aik_certificate: String,
    quote: String,
    signature: String,
}

/// The attestor of TPM 2.0 quotes, against the authorities that issue the
/// trusted machines' attestation identity keys.
pub struct TpmAgentAttestor {
    anchors: TrustAnchors,
}

impl TpmAgentAttestor {
    /// An attestor trusting the AIKs issued under `anchor_pems`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when no anchor is given or one
    /// cannot be read.
    pub fn new(anchor_pems: &[String]) -> Result<Self, DomainError> {
        Ok(Self {
            anchors: TrustAnchors::from_pem(anchor_pems)?,
        })
    }

    /// The AIK certificate leading `chain`, once the chain holds to an
    /// anchor and the leaf is certified as an attestation key.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Unauthorized` when the chain does not hold or
    /// its leaf is certified for anything else.
    fn certified_aik<'c>(&self, chain: &'c [Certificate]) -> Result<&'c Certificate, DomainError> {
        let Some(aik) = chain.first() else {
            return Err(refused("the attestation holds no certificate"));
        };
        ensure_chain_holds(chain, &self.anchors, clock::now())?;
        if !has_extended_key_usage(aik, AIK_CERTIFICATE) {
            return Err(refused("the certificate is not for an attestation key"));
        }
        Ok(aik)
    }
}

#[async_trait]
impl AgentAttestor for TpmAgentAttestor {
    async fn verify(
        &self,
        presentation: &AttestationPresentation,
        key: &EnrolledKey,
    ) -> Result<AttestedIdentity, DomainError> {
        let material = material_for(presentation, AttestationMethod::Tpm)?;
        let binding = binding_for(presentation, key)?;
        let envelope: Envelope = serde_json::from_str(material)
            .map_err(|_| refused("the TPM attestation is not the JSON expected"))?;
        let chain = chain_in(&envelope.aik_certificate)?;
        let aik = self.certified_aik(&chain)?;
        let quote = decoded(&envelope.quote)?;
        if !key_of(aik)?.verifies(&quote, &decoded(&envelope.signature)?) {
            return Err(refused("the quote is not signed by the attestation key"));
        }
        let Some(qualifying) = qualifying_data(&quote) else {
            return Err(refused("the quote is no TPM quote"));
        };
        if qualifying != binding.as_bytes() {
            return Err(refused("the quote was not made for this attestation"));
        }
        Ok(AttestedIdentity::new(
            AttestationMethod::Tpm,
            subject_of(aik)?,
        ))
    }
}

/// The bytes the base64 `text` writes.
fn decoded(text: &str) -> Result<Vec<u8>, DomainError> {
    STANDARD
        .decode(text)
        .map_err(|_| refused("the TPM attestation is not base64"))
}

/// The subject a TPM attests: `tpm:cn:` and the AIK certificate's common
/// name, which its authority vouched for, or `tpm:aik:` and its key's
/// fingerprint when it has none.
fn subject_of(aik: &Certificate) -> Result<AttestedSubject, DomainError> {
    let subject = match common_name(aik) {
        Some(name) => format!("tpm:cn:{name}"),
        None => {
            let fingerprint = key_fingerprint(aik)
                .ok_or_else(|| refused("the attestation key cannot be read"))?;
            format!("tpm:aik:{fingerprint}")
        }
    };
    AttestedSubject::new(subject).map_err(|_| refused("the attestation key names no subject"))
}

/// The qualifying data a genuine quote carries, the caller's nonce the
/// chip signed with it; `None` for anything else.
fn qualifying_data(quote: &[u8]) -> Option<&[u8]> {
    let mut reader = Reader(quote);
    if reader.u32()? != TPM_GENERATED_VALUE {
        return None;
    }
    if reader.u16()? != TPM_ST_ATTEST_QUOTE {
        return None;
    }
    reader.sized()?;
    reader.sized()
}

/// A TPM structure read from the front, each field in big-endian.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// The next `count` bytes.
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(count)?;
        self.0 = rest;
        Some(head)
    }

    /// The next two bytes as a number.
    fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .map(u16::from_be_bytes)
    }

    /// The next four bytes as a number.
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(u32::from_be_bytes)
    }

    /// The next sized buffer: its length in two bytes, then that many.
    fn sized(&mut self) -> Option<&'a [u8]> {
        let length = self.u16()?;
        self.take(usize::from(length))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use ianua_app::ports::agents::AttestationProof;
    use ianua_domain::domains::agents::identity::challenge::AttestationNonce;
    use p256::ecdsa::signature::Signer as _;
    use p256::pkcs8::DecodePrivateKey as _;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    };

    use super::*;
    use crate::proofs::attestation::AttestationBinding;
    use crate::proofs::attestation::tests::enrolled_key;

    const NONCE: &str = "tpm-bootstrap-nonce-0123456789abcdef0123";

    /// The key every quote of these tests is made to enrol.
    static ENROLLED: LazyLock<EnrolledKey> = LazyLock::new(enrolled_key);

    /// The binding of the test nonce and [`ENROLLED`], as the chip signs
    /// it.
    fn bound() -> Vec<u8> {
        AttestationBinding::of(&AttestationNonce::new(NONCE).unwrap(), &ENROLLED.public_key)
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    /// A machine's chip: its AIK certificate under a trusted authority.
    struct Chip {
        anchor: String,
        aik_certificate: String,
        aik: KeyPair,
    }

    /// A chip whose key is certified as an attestation key.
    fn new_chip() -> Chip {
        certified_for(vec![ExtendedKeyUsagePurpose::Other(vec![2, 23, 133, 8, 3])])
    }

    /// A key and its certificate under a trusted authority, naming
    /// `purposes`.
    fn certified_for(purposes: Vec<ExtendedKeyUsagePurpose>) -> Chip {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::new(Vec::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let anchor = ca.self_signed(&ca_key).unwrap().pem();
        let aik = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "plant-7-line-2");
        params.extended_key_usages = purposes;
        let aik_certificate = params
            .signed_by(&aik, &Issuer::new(ca, ca_key))
            .unwrap()
            .pem();
        Chip {
            anchor,
            aik_certificate,
            aik,
        }
    }

    /// A quote carrying `qualifying` as its qualifying data.
    fn quote(magic: u32, qualifying: &[u8]) -> Vec<u8> {
        let mut quote = magic.to_be_bytes().to_vec();
        quote.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
        quote.extend_from_slice(&4u16.to_be_bytes());
        quote.extend_from_slice(b"name");
        quote.extend_from_slice(&u16::try_from(qualifying.len()).unwrap().to_be_bytes());
        quote.extend_from_slice(qualifying);
        quote.extend_from_slice(b"clock and pcr digest");
        quote
    }

    fn presented(chip: &Chip, quote: &[u8], signer: &KeyPair) -> AttestationPresentation {
        let key = p256::ecdsa::SigningKey::from_pkcs8_pem(&signer.serialize_pem()).unwrap();
        let signature: p256::ecdsa::Signature = key.sign(quote);
        let material = serde_json::json!({
            "aik_certificate": chip.aik_certificate,
            "quote": STANDARD.encode(quote),
            "signature": STANDARD.encode(signature.to_der().as_bytes()),
        });
        AttestationPresentation {
            method: AttestationMethod::Tpm,
            material: material.to_string(),
            proof: AttestationProof {
                nonce: AttestationNonce::new(NONCE).unwrap(),
                signature: String::new(),
            },
        }
    }

    /// A quote the trusted AIK signed over the binding attests the machine
    /// its certificate names.
    #[tokio::test]
    async fn a_signed_quote_over_the_binding_attests_the_machine() {
        let chip = new_chip();
        let attestor = TpmAgentAttestor::new(std::slice::from_ref(&chip.anchor)).unwrap();
        let quote = quote(TPM_GENERATED_VALUE, &bound());

        let attested = attestor
            .verify(&presented(&chip, &quote, &chip.aik), &ENROLLED)
            .await
            .unwrap();

        assert_eq!(attested.subject().as_str(), "tpm:cn:plant-7-line-2");
    }

    /// Quotes over an earlier challenge or bare nonce are unauthorized for the current binding.
    #[tokio::test]
    async fn a_quote_over_another_nonce_is_refused() {
        let chip = new_chip();
        let attestor = TpmAgentAttestor::new(std::slice::from_ref(&chip.anchor)).unwrap();

        for qualifying in [
            b"an-earlier-nonce-0123456789abcdef0123".as_slice(),
            NONCE.as_bytes(),
        ] {
            let quote = quote(TPM_GENERATED_VALUE, qualifying);

            let attested = attestor
                .verify(&presented(&chip, &quote, &chip.aik), &ENROLLED)
                .await;

            assert!(matches!(attested, Err(DomainError::Unauthorized(_))));
        }
    }

    /// A quote bound to one enrolled key cannot attest a different key.
    #[tokio::test]
    async fn a_quote_made_for_another_key_is_refused() {
        let chip = new_chip();
        let attestor = TpmAgentAttestor::new(std::slice::from_ref(&chip.anchor)).unwrap();
        let quote = quote(TPM_GENERATED_VALUE, &bound());

        let attested = attestor
            .verify(&presented(&chip, &quote, &chip.aik), &enrolled_key())
            .await;

        assert!(matches!(attested, Err(DomainError::Unauthorized(_))));
    }

    /// A quote signed by a key other than the certified attestation key is unauthorized.
    #[tokio::test]
    async fn a_quote_signed_by_another_key_is_refused() {
        let chip = new_chip();
        let attestor = TpmAgentAttestor::new(std::slice::from_ref(&chip.anchor)).unwrap();
        let quote = quote(TPM_GENERATED_VALUE, &bound());

        let attested = attestor
            .verify(
                &presented(&chip, &quote, &KeyPair::generate().unwrap()),
                &ENROLLED,
            )
            .await;

        assert!(matches!(attested, Err(DomainError::Unauthorized(_))));
    }

    /// Incorrect quote magic and truncated quote structures are rejected despite their signatures.
    #[tokio::test]
    async fn a_structure_that_is_no_quote_is_refused() {
        let chip = new_chip();
        let attestor = TpmAgentAttestor::new(std::slice::from_ref(&chip.anchor)).unwrap();
        let forged = quote(0x1234_5678, &bound());
        let short = TPM_GENERATED_VALUE.to_be_bytes().to_vec();

        let forged = attestor
            .verify(&presented(&chip, &forged, &chip.aik), &ENROLLED)
            .await;
        let short = attestor
            .verify(&presented(&chip, &short, &chip.aik), &ENROLLED)
            .await;

        assert!(matches!(forged, Err(DomainError::Unauthorized(_))));
        assert!(matches!(short, Err(DomainError::Unauthorized(_))));
    }

    /// An attestation key certified by an untrusted authority cannot validate a quote.
    #[tokio::test]
    async fn an_aik_from_an_untrusted_authority_is_refused() {
        let stranger = new_chip();
        let chip = new_chip();
        let attestor = TpmAgentAttestor::new(std::slice::from_ref(&stranger.anchor)).unwrap();
        let quote = quote(TPM_GENERATED_VALUE, &bound());

        let attested = attestor
            .verify(&presented(&chip, &quote, &chip.aik), &ENROLLED)
            .await;

        assert!(matches!(attested, Err(DomainError::Unauthorized(_))));
    }

    /// A trusted certificate issued for client authentication cannot serve as an attestation-key certificate.
    #[tokio::test]
    async fn a_key_not_certified_as_an_attestation_key_is_refused() {
        let impostor = certified_for(vec![ExtendedKeyUsagePurpose::ClientAuth]);
        let attestor = TpmAgentAttestor::new(std::slice::from_ref(&impostor.anchor)).unwrap();
        let forged = quote(TPM_GENERATED_VALUE, &bound());

        let attested = attestor
            .verify(&presented(&impostor, &forged, &impostor.aik), &ENROLLED)
            .await;

        assert!(matches!(attested, Err(DomainError::Unauthorized(_))));
    }

    /// Malformed quote JSON fails attestation as unauthorized.
    #[tokio::test]
    async fn malformed_material_is_refused() {
        let chip = new_chip();
        let attestor = TpmAgentAttestor::new(std::slice::from_ref(&chip.anchor)).unwrap();
        let mut garbled = presented(&chip, &quote(TPM_GENERATED_VALUE, &bound()), &chip.aik);
        garbled.material = "{\"quote\": 1}".to_owned();

        let attested = attestor.verify(&garbled, &ENROLLED).await;

        assert!(matches!(attested, Err(DomainError::Unauthorized(_))));
    }
}
