//! The certificates an attestation presents: held to their validity, and
//! chained link by link to the anchors the deployment trusts.
//!
//! A chain is the leaf first, then any intermediates. Every certificate in
//! it must be valid now, each must be signed by the next, every one past
//! the leaf must be a certificate authority allowed to sign certificates
//! at its depth, and the last must be signed by an anchor. A certificate
//! carrying a critical extension this module does not check is refused,
//! as RFC 5280 asks, so a constraint such as a name constraint is never
//! passed over. A signature is checked with the scheme of the signing
//! key, and the certificate must name that same scheme, so a certificate
//! cannot choose how it is checked.

use der::asn1::{ObjectIdentifier, PrintableStringRef, Utf8StringRef};
use der::{Decode as _, Encode as _};
use ianua_domain::shared::errors::DomainError;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use x509_cert::Certificate;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};

use crate::crypto::certificates::pem::{certificates_in, public_key_in};
use crate::proofs::attestation::keys::PresentedKey;
use crate::proofs::attestation::refused;

/// The OID of the basic constraints extension.
const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

/// The OID of the key usage extension.
const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

/// The OID of the extended key usage extension.
const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// The OID of the subject alternative name extension.
const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// The extensions this module, or the attestor reading a leaf, checks. A
/// critical extension outside these is refused.
const UNDERSTOOD: [ObjectIdentifier; 4] = [
    BASIC_CONSTRAINTS,
    KEY_USAGE,
    EXTENDED_KEY_USAGE,
    SUBJECT_ALT_NAME,
];

/// The OID of a name's common name.
const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

/// The most certificates a presented chain may hold, the leaf included.
const LONGEST_CHAIN: usize = 4;

/// The keys the deployment trusts to sign attestations or their chains.
pub(crate) struct TrustAnchors {
    keys: Vec<PresentedKey>,
}

impl TrustAnchors {
    /// The anchors `pems` hold: each a PEM of one or more certificates, or
    /// of one public key.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a PEM cannot be read, holds
    /// a key of a kind no signature is checked with, or none is given: an
    /// attestor trusting nothing is a configuration mistake, not a policy.
    pub(crate) fn from_pem(pems: &[String]) -> Result<Self, DomainError> {
        let keys = pems
            .iter()
            .map(String::as_str)
            .map(keys_in)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        if keys.is_empty() {
            return Err(DomainError::infra_msg("no trust anchor is configured"));
        }
        Ok(Self { keys })
    }

    /// Whether one of the anchors signed `certificate`.
    fn signed(&self, certificate: &Certificate) -> bool {
        self.keys.iter().any(|key| signed_by(certificate, key))
    }
}

/// The keys one configured PEM holds.
fn keys_in(pem: &str) -> Result<Vec<PresentedKey>, DomainError> {
    let unreadable = || DomainError::infra_msg("a trust anchor cannot be read");
    if !pem.contains("-----BEGIN CERTIFICATE-----") {
        let spki = public_key_in(pem).map_err(|_| unreadable())?;
        return Ok(vec![PresentedKey::of(&spki).ok_or_else(unreadable)?]);
    }
    certificates_in(pem)
        .map_err(|_| unreadable())?
        .iter()
        .map(|anchor| PresentedKey::of(&anchor.tbs_certificate.subject_public_key_info))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(unreadable)
}

/// The chain `pem` holds, leaf first, refused when it holds none or more
/// than [`LONGEST_CHAIN`].
///
/// # Errors
///
/// Returns `DomainError::Unauthorized` when the PEM is no chain of a
/// length that is read.
pub(crate) fn chain_in(pem: &str) -> Result<Vec<Certificate>, DomainError> {
    let chain =
        certificates_in(pem).map_err(|_| refused("the attestation holds no certificate"))?;
    if chain.is_empty() || chain.len() > LONGEST_CHAIN {
        return Err(refused("the attestation's chain is empty or too long"));
    }
    Ok(chain)
}

/// Refused unless `chain` holds at `now`, from its leaf to `anchors`.
///
/// # Errors
///
/// Returns `DomainError::Unauthorized` naming the first link that fails.
pub(crate) fn ensure_chain_holds(
    chain: &[Certificate],
    anchors: &TrustAnchors,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    if !chain.iter().all(|certificate| valid_at(certificate, now)) {
        return Err(refused("a certificate of the chain is not valid now"));
    }
    if !chain.iter().all(understands_critical_extensions) {
        return Err(refused(
            "a certificate of the chain carries a critical extension not checked",
        ));
    }
    ensure_intermediates_may_sign(chain)?;
    let linked = chain
        .iter()
        .zip(chain.iter().skip(1))
        .all(|(child, parent)| issued_by(child, parent));
    if !linked {
        return Err(refused(
            "a certificate of the chain is not signed by the next",
        ));
    }
    let Some(top) = chain.last() else {
        return Err(refused("the attestation holds no certificate"));
    };
    if !anchors.signed(top) {
        return Err(refused("the chain is not signed by a trusted authority"));
    }
    Ok(())
}

/// The key `certificate` holds, when it is of a kind signatures are
/// checked with.
///
/// # Errors
///
/// Returns `DomainError::Unauthorized` for any other key.
pub(crate) fn key_of(certificate: &Certificate) -> Result<PresentedKey, DomainError> {
    PresentedKey::of(&certificate.tbs_certificate.subject_public_key_info)
        .ok_or_else(|| refused("the certificate holds a key of a kind not accepted"))
}

/// Refused unless every certificate past the leaf is an authority, may
/// sign certificates by its key usage, and sits no deeper than its path
/// length allows.
///
/// # Errors
///
/// Returns `DomainError::Unauthorized` naming the first rule an
/// intermediate breaks.
fn ensure_intermediates_may_sign(chain: &[Certificate]) -> Result<(), DomainError> {
    let intermediates = || chain.iter().skip(1);
    if !intermediates().all(is_authority) {
        return Err(refused("an intermediate of the chain is no authority"));
    }
    if !intermediates().all(may_sign_certificates) {
        return Err(refused(
            "an intermediate of the chain may not sign certificates",
        ));
    }
    if !intermediates()
        .enumerate()
        .all(|(below, authority)| allows_depth(authority, below))
    {
        return Err(refused(
            "an intermediate of the chain sits deeper than its authority allows",
        ));
    }
    Ok(())
}

/// The extension of `certificate` with the OID `id`, when it carries one.
fn extension_value(certificate: &Certificate, id: ObjectIdentifier) -> Option<&[u8]> {
    certificate
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|extension| extension.extn_id == id)
        .map(|extension| extension.extn_value.as_bytes())
}

/// The basic constraints `certificate` carries, when it carries them
/// readably.
fn basic_constraints(certificate: &Certificate) -> Option<BasicConstraints> {
    extension_value(certificate, BASIC_CONSTRAINTS)
        .and_then(|value| BasicConstraints::from_der(value).ok())
}

/// Whether `certificate` says it is a certificate authority.
pub(crate) fn is_authority(certificate: &Certificate) -> bool {
    basic_constraints(certificate).is_some_and(|constraints| constraints.ca)
}

/// Whether `certificate`'s key may sign certificates: it names no key
/// usage, or one that includes signing certificates. A key usage that
/// does not read allows nothing.
fn may_sign_certificates(certificate: &Certificate) -> bool {
    let Some(value) = extension_value(certificate, KEY_USAGE) else {
        return true;
    };
    KeyUsage::from_der(value).is_ok_and(|usage| usage.key_cert_sign())
}

/// Whether the authority `certificate` may have `below` intermediates
/// between it and the leaf, by its path length constraint.
fn allows_depth(certificate: &Certificate, below: usize) -> bool {
    basic_constraints(certificate)
        .and_then(|constraints| constraints.path_len_constraint)
        .is_none_or(|most| below <= usize::from(most))
}

/// Whether every critical extension `certificate` carries is one this
/// module or its attestors check.
fn understands_critical_extensions(certificate: &Certificate) -> bool {
    certificate
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .filter(|extension| extension.critical)
        .all(|extension| UNDERSTOOD.contains(&extension.extn_id))
}

/// Whether `certificate` names `purpose` among its extended key usages. A
/// certificate naming none, or naming them unreadably, names no purpose.
pub(crate) fn has_extended_key_usage(certificate: &Certificate, purpose: ObjectIdentifier) -> bool {
    extension_value(certificate, EXTENDED_KEY_USAGE)
        .and_then(|value| ExtendedKeyUsage::from_der(value).ok())
        .is_some_and(|usages| usages.0.contains(&purpose))
}

/// The common name `certificate`'s subject carries, when it carries one as
/// text.
pub(crate) fn common_name(certificate: &Certificate) -> Option<String> {
    let value = certificate
        .tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|names| names.0.iter())
        .find(|name| name.oid == COMMON_NAME)
        .map(|name| &name.value)?;
    value
        .decode_as::<Utf8StringRef<'_>>()
        .map(|text| text.as_str().to_owned())
        .or_else(|_| {
            value
                .decode_as::<PrintableStringRef<'_>>()
                .map(|text| text.as_str().to_owned())
        })
        .ok()
}

/// The SHA-256 of `certificate`'s public key, in lower-case hex: a name
/// for the key no one can choose.
pub(crate) fn key_fingerprint(certificate: &Certificate) -> Option<String> {
    let der = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .ok()?;
    Some(data_encoding::HEXLOWER.encode(&Sha256::digest(der)))
}

/// Whether `certificate` is within its validity at `now`.
fn valid_at(certificate: &Certificate, now: OffsetDateTime) -> bool {
    let Ok(now) = u64::try_from(now.unix_timestamp()) else {
        return false;
    };
    let validity = &certificate.tbs_certificate.validity;
    validity.not_before.to_unix_duration().as_secs() <= now
        && now <= validity.not_after.to_unix_duration().as_secs()
}

/// Whether `child` is signed by `parent`'s key and names `parent` as its
/// issuer.
fn issued_by(child: &Certificate, parent: &Certificate) -> bool {
    child.tbs_certificate.issuer == parent.tbs_certificate.subject
        && PresentedKey::of(&parent.tbs_certificate.subject_public_key_info)
            .is_some_and(|key| signed_by(child, &key))
}

/// Whether `certificate` is signed by `key`, under the scheme `key` signs
/// with.
fn signed_by(certificate: &Certificate, key: &PresentedKey) -> bool {
    if certificate.signature_algorithm.oid != key.signature_algorithm() {
        return false;
    }
    let (Ok(signed), Some(signature)) = (
        certificate.tbs_certificate.to_der(),
        certificate.signature.as_bytes(),
    ) else {
        return false;
    };
    key.verifies(&signed, signature)
}

#[cfg(test)]
mod tests {
    use rcgen::{
        BasicConstraints as Constraints, CertificateParams, CustomExtension, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };

    use super::*;

    fn authority() -> (KeyPair, CertificateParams, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = IsCa::Ca(Constraints::Unconstrained);
        let pem = params.self_signed(&key).unwrap().pem();
        (key, params, pem)
    }

    fn leaf_of(issuer: &Issuer<'_, KeyPair>) -> String {
        let key = KeyPair::generate().unwrap();
        CertificateParams::new(Vec::new())
            .unwrap()
            .signed_by(&key, issuer)
            .unwrap()
            .pem()
    }

    /// A leaf the trusted authority signed holds.
    #[test]
    fn a_leaf_signed_by_the_anchor_holds() {
        let (key, params, anchor) = authority();
        let leaf = leaf_of(&Issuer::new(params, key));
        let anchors = TrustAnchors::from_pem(&[anchor]).unwrap();

        let held = ensure_chain_holds(
            &chain_in(&leaf).unwrap(),
            &anchors,
            OffsetDateTime::now_utc(),
        );

        assert!(held.is_ok());
    }

    /// A leaf signed by an authority outside the trusted anchors is unauthorized.
    #[test]
    fn a_leaf_signed_by_another_authority_is_refused() {
        let (_, _, anchor) = authority();
        let (key, params, _) = authority();
        let leaf = leaf_of(&Issuer::new(params, key));
        let anchors = TrustAnchors::from_pem(&[anchor]).unwrap();

        let held = ensure_chain_holds(
            &chain_in(&leaf).unwrap(),
            &anchors,
            OffsetDateTime::now_utc(),
        );

        assert!(matches!(held, Err(DomainError::Unauthorized(_))));
    }

    /// A non-CA leaf cannot act as an intermediate certificate in a trusted chain.
    #[test]
    fn a_leaf_posing_as_an_intermediate_is_refused() {
        let (key, params, anchor) = authority();
        let root = Issuer::new(params, key);
        let middle_key = KeyPair::generate().unwrap();
        let middle_params = CertificateParams::new(Vec::new()).unwrap();
        let middle = middle_params.signed_by(&middle_key, &root).unwrap().pem();
        let leaf = leaf_of(&Issuer::new(middle_params, middle_key));
        let anchors = TrustAnchors::from_pem(&[anchor]).unwrap();

        let held = ensure_chain_holds(
            &chain_in(&format!("{leaf}{middle}")).unwrap(),
            &anchors,
            OffsetDateTime::now_utc(),
        );

        assert!(matches!(held, Err(DomainError::Unauthorized(_))));
    }

    /// A certificate past its validity period cannot authenticate the chain.
    #[test]
    fn a_certificate_past_its_validity_is_refused() {
        let (key, params, anchor) = authority();
        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(Vec::new()).unwrap();
        leaf_params.not_before = OffsetDateTime::now_utc() - time::Duration::days(10);
        leaf_params.not_after = OffsetDateTime::now_utc() - time::Duration::days(1);
        let leaf = leaf_params
            .signed_by(&leaf_key, &Issuer::new(params, key))
            .unwrap()
            .pem();
        let anchors = TrustAnchors::from_pem(&[anchor]).unwrap();

        let held = ensure_chain_holds(
            &chain_in(&leaf).unwrap(),
            &anchors,
            OffsetDateTime::now_utc(),
        );

        assert!(matches!(held, Err(DomainError::Unauthorized(_))));
    }

    /// Missing and unreadable trust anchors fail configuration with an infrastructure error.
    #[test]
    fn missing_or_unreadable_anchors_are_a_configuration_error() {
        assert!(matches!(
            TrustAnchors::from_pem(&[]),
            Err(DomainError::Infrastructure(_))
        ));
        assert!(matches!(
            TrustAnchors::from_pem(&["not a pem".to_owned()]),
            Err(DomainError::Infrastructure(_))
        ));
    }

    /// Non-certificate text fails chain parsing as unauthorized.
    #[test]
    fn material_that_is_no_certificate_is_refused() {
        assert!(matches!(
            chain_in("garbage"),
            Err(DomainError::Unauthorized(_))
        ));
    }

    /// The anchor's PEM, and a chain leaf first through two intermediates:
    /// the upper one, under the anchor, shaped by `shape`, and a lower one
    /// that signed the leaf.
    fn two_deep(shape: impl FnOnce(&mut CertificateParams)) -> (String, String) {
        let (root_key, root_params, anchor) = authority();
        let root = Issuer::new(root_params, root_key);
        let upper_key = KeyPair::generate().unwrap();
        let mut upper_params = CertificateParams::new(Vec::new()).unwrap();
        upper_params.is_ca = IsCa::Ca(Constraints::Unconstrained);
        shape(&mut upper_params);
        let upper = upper_params.signed_by(&upper_key, &root).unwrap().pem();
        let lower_key = KeyPair::generate().unwrap();
        let mut lower_params = CertificateParams::new(Vec::new()).unwrap();
        lower_params.is_ca = IsCa::Ca(Constraints::Unconstrained);
        let lower = lower_params
            .signed_by(&lower_key, &Issuer::new(upper_params, upper_key))
            .unwrap()
            .pem();
        let leaf = leaf_of(&Issuer::new(lower_params, lower_key));
        (anchor, format!("{leaf}{lower}{upper}"))
    }

    /// Whether `chain` holds now to the anchor `anchor`.
    fn held(anchor: String, chain: &str) -> Result<(), DomainError> {
        let anchors = TrustAnchors::from_pem(&[anchor]).unwrap();
        ensure_chain_holds(
            &chain_in(chain).unwrap(),
            &anchors,
            OffsetDateTime::now_utc(),
        )
    }

    /// A leaf two authorities deep holds when neither limits the other.
    #[test]
    fn a_chain_through_two_intermediates_holds() {
        let (anchor, chain) = two_deep(|_| {});

        assert!(held(anchor, &chain).is_ok());
    }

    /// An intermediate below a CA with a zero path-length constraint invalidates the chain.
    #[test]
    fn an_intermediate_past_its_path_length_is_refused() {
        let (anchor, chain) = two_deep(|upper| upper.is_ca = IsCa::Ca(Constraints::Constrained(0)));

        assert!(matches!(
            held(anchor, &chain),
            Err(DomainError::Unauthorized(_))
        ));
    }

    /// An intermediate lacking certificate-signing key usage cannot validate its child certificate.
    #[test]
    fn an_intermediate_whose_key_may_not_sign_certificates_is_refused() {
        let (anchor, chain) =
            two_deep(|upper| upper.key_usages = vec![KeyUsagePurpose::DigitalSignature]);

        assert!(matches!(
            held(anchor, &chain),
            Err(DomainError::Unauthorized(_))
        ));
    }

    /// An unsupported critical certificate extension fails validation rather than being ignored.
    #[test]
    fn a_critical_extension_not_checked_is_refused() {
        let (key, params, anchor) = authority();
        let mut unknown =
            CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 55555, 1], vec![0x05, 0x00]);
        unknown.set_criticality(true);
        let mut leaf_params = CertificateParams::new(Vec::new()).unwrap();
        leaf_params.custom_extensions = vec![unknown];
        let leaf = leaf_params
            .signed_by(&KeyPair::generate().unwrap(), &Issuer::new(params, key))
            .unwrap()
            .pem();

        assert!(matches!(
            held(anchor, &leaf),
            Err(DomainError::Unauthorized(_))
        ));
    }
}
