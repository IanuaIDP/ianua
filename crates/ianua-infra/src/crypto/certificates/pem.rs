//! Certificates, public keys and private keys read out of PEM text, in a
//! way that always ends.
//!
//! The PEM reader `der` puts behind `from_pem`, which `load_pem_chain`
//! calls too, never returns when a block is cut short, so one broken
//! certificate a tenant pastes would hold a worker for ever. Here each
//! block is cut out between its boundaries, its base64 decoded whole, and
//! the bytes read as DER, each step bounded by the text it is given.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use der::Decode;
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use zeroize::Zeroizing;

/// The label a certificate block carries.
const CERTIFICATE: &str = "CERTIFICATE";

/// The label a certificate revocation list block carries.
const REVOCATION_LIST: &str = "X509 CRL";

/// The label a public key block carries.
const PUBLIC_KEY: &str = "PUBLIC KEY";

/// The label a PKCS#8 private key block carries.
const PRIVATE_KEY: &str = "PRIVATE KEY";

/// The label a PKCS#1 RSA private key block carries.
const PKCS1_PRIVATE_KEY: &str = "RSA PRIVATE KEY";

/// The most blocks one text may hold: past any real chain or bundle.
const MOST_BLOCKS: usize = 64;

/// PEM text that holds nothing of the kind asked for, or a block that does
/// not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the text does not hold what it should, readably")]
pub(crate) struct UnreadablePem;

/// Every certificate `pem` holds, in order. Text outside the boundaries,
/// such as a comment above a certificate, is passed over.
///
/// # Errors
///
/// [`UnreadablePem`] when the text holds no certificate, more than
/// [`MOST_BLOCKS`], one without its end, or one that does not decode or
/// read as a certificate.
pub(crate) fn certificates_in(pem: &str) -> Result<Vec<Certificate>, UnreadablePem> {
    read_all(pem, CERTIFICATE)
}

/// Every certificate revocation list `pem` holds, in order.
///
/// # Errors
///
/// [`UnreadablePem`] when the text holds no list, more than
/// [`MOST_BLOCKS`], one without its end, or one that does not decode or
/// read as a revocation list.
pub(crate) fn revocation_lists_in(pem: &str) -> Result<Vec<CertificateList>, UnreadablePem> {
    read_all(pem, REVOCATION_LIST)
}

/// The one certificate `pem` holds.
///
/// # Errors
///
/// [`UnreadablePem`] when it holds none, more than one, or one that does
/// not read.
pub(crate) fn certificate_in(pem: &str) -> Result<Certificate, UnreadablePem> {
    only(read_all(pem, CERTIFICATE)?)
}

/// The one public key `pem` holds.
///
/// # Errors
///
/// [`UnreadablePem`] when it holds none, more than one, or one that does
/// not read.
pub(crate) fn public_key_in(pem: &str) -> Result<SubjectPublicKeyInfoOwned, UnreadablePem> {
    only(read_all(pem, PUBLIC_KEY)?)
}

/// The DER bytes of the one PKCS#8 private key `pem` holds, wiped when
/// dropped. They are not read here: the library that uses the key reads
/// them.
///
/// # Errors
///
/// [`UnreadablePem`] when it holds none, more than one, or one that does
/// not decode.
pub(crate) fn private_key_in(pem: &str) -> Result<Zeroizing<Vec<u8>>, UnreadablePem> {
    only(blocks(pem, PRIVATE_KEY)?).map(Zeroizing::new)
}

/// The DER bytes of the one PKCS#1 RSA private key `pem` holds, wiped when
/// dropped.
///
/// # Errors
///
/// [`UnreadablePem`] when it holds none, more than one, or one that does
/// not decode.
pub(crate) fn pkcs1_private_key_in(pem: &str) -> Result<Zeroizing<Vec<u8>>, UnreadablePem> {
    only(blocks(pem, PKCS1_PRIVATE_KEY)?).map(Zeroizing::new)
}

/// The PKCS#8 private key `der` written as PEM, wiped when dropped.
pub(crate) fn private_key_pem(der: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(written(PRIVATE_KEY, der))
}

/// The SPKI public key `der` written as PEM.
pub(crate) fn public_key_pem(der: &[u8]) -> String {
    written(PUBLIC_KEY, der)
}

/// `der` written as one PEM block labelled `label`, its base64 in lines of
/// 64 characters. The text is sized once, so a private key leaves no copy
/// behind in memory given back while it grows.
fn written(label: &str, der: &[u8]) -> String {
    let encoded = Zeroizing::new(STANDARD.encode(der));
    let room = encoded
        .len()
        .saturating_add(encoded.len().checked_div(64).unwrap_or_default())
        .saturating_add(label.len().saturating_mul(2))
        .saturating_add(64);
    let mut pem = String::with_capacity(room);
    pem.push_str("-----BEGIN ");
    pem.push_str(label);
    pem.push_str("-----\n");
    for line in encoded
        .as_bytes()
        .chunks(64)
        .filter_map(|line| std::str::from_utf8(line).ok())
    {
        pem.push_str(line);
        pem.push('\n');
    }
    pem.push_str("-----END ");
    pem.push_str(label);
    pem.push_str("-----\n");
    pem
}

/// Every block labelled `label` in `pem`, each read as `T`.
fn read_all<T: for<'a> Decode<'a>>(pem: &str, label: &str) -> Result<Vec<T>, UnreadablePem> {
    blocks(pem, label)?
        .iter()
        .map(|bytes| T::from_der(bytes).map_err(|_| UnreadablePem))
        .collect()
}

/// The bytes of every block labelled `label` in `pem`, in order.
fn blocks(pem: &str, label: &str) -> Result<Vec<Vec<u8>>, UnreadablePem> {
    let (begin, end) = (
        format!("-----BEGIN {label}-----"),
        format!("-----END {label}-----"),
    );
    let mut found = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find(&begin) {
        let after = rest
            .get(start.saturating_add(begin.len())..)
            .ok_or(UnreadablePem)?;
        let stop = after.find(&end).ok_or(UnreadablePem)?;
        found.push(decoded(after.get(..stop).ok_or(UnreadablePem)?)?);
        if found.len() > MOST_BLOCKS {
            return Err(UnreadablePem);
        }
        rest = after
            .get(stop.saturating_add(end.len())..)
            .ok_or(UnreadablePem)?;
    }
    if found.is_empty() {
        return Err(UnreadablePem);
    }
    Ok(found)
}

/// The bytes the base64 `body` between two boundaries holds.
fn decoded(body: &str) -> Result<Vec<u8>, UnreadablePem> {
    let encoded: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    STANDARD.decode(encoded).map_err(|_| UnreadablePem)
}

/// The one item of `items`.
fn only<T>(mut items: Vec<T>) -> Result<T, UnreadablePem> {
    match (items.pop(), items.is_empty()) {
        (Some(item), true) => Ok(item),
        _ => Err(UnreadablePem),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::certificates::tests::self_signed;

    /// A self-signed certificate reads back, with text around it passed
    /// over.
    #[test]
    fn a_certificate_reads_back() {
        let (pem, _) = self_signed("acme.example");

        let read = certificate_in(&format!("issued by Acme\n{pem}\n"));

        assert!(read.is_ok());
    }

    /// A chain of two reads as two; as one certificate it is refused.
    #[test]
    fn a_chain_reads_as_its_certificates() {
        let (first, _) = self_signed("one.example");
        let (second, _) = self_signed("two.example");
        let chain = format!("{first}{second}");

        let read = certificates_in(&chain).unwrap();

        assert_eq!(read.len(), 2);
        assert!(certificate_in(&chain).is_err());
    }

    /// Truncated PEM, missing end markers, empty input and junk all return an unreadable-PEM error.
    #[test]
    fn broken_text_is_refused_at_once() {
        let (whole, _) = self_signed("acme.example");
        let cut = format!(
            "{}\n-----END CERTIFICATE-----",
            whole.get(..whole.len() / 2).unwrap()
        );

        for broken in [
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----".to_owned(),
            cut,
            "-----BEGIN CERTIFICATE-----\nMIIBAAAA".to_owned(),
            String::new(),
            "not a certificate".to_owned(),
        ] {
            assert_eq!(
                certificates_in(&broken).err(),
                Some(UnreadablePem),
                "{broken}"
            );
        }
    }

    /// A public key block reads as its key; a certificate is no public key.
    #[test]
    fn a_public_key_reads_back() {
        let key = rcgen::KeyPair::generate().unwrap();
        let (certificate, _) = self_signed("acme.example");

        assert!(public_key_in(&key.public_key_pem()).is_ok());
        assert!(public_key_in(&certificate).is_err());
    }
}
