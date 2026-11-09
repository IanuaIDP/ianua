//! The algorithms a SAML signature may use, the keys it is checked
//! against, and the keys this platform signs with.
//!
//! The algorithm comes from a short list, never from whatever the message
//! names: RSA with SHA-256 or SHA-512, ECDSA on P-256 with SHA-256, and
//! Ed25519; SHA-1 is refused everywhere. A key is checked only for the
//! algorithm its kind signs with, and comes from a certificate the
//! connection or the app registered, never from the message itself.

use der::Encode as _;
use ianua_app::ports::crypto::XmlSigningKey;
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::CertificatePem;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
use rand::RngCore as _;
use rand::rngs::OsRng;
use sha2::{Digest as _, Sha256, Sha384, Sha512};

use crate::crypto::certificates::pem::certificate_in;
use crate::crypto::certificates::rsa_keys::{
    RsaDigest, RsaKeyError, RsaSealingKey, RsaSigningKey, RsaVerifyingKey,
};

/// A signature algorithm a SAML signature may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignatureMethod {
    /// RSA PKCS#1 v1.5 with SHA-256.
    RsaSha256,
    /// RSA PKCS#1 v1.5 with SHA-512.
    RsaSha512,
    /// ECDSA on P-256 with SHA-256, the signature as `r || s`.
    EcdsaSha256,
    /// Signs canonical XML using a 64-byte Edwards-curve signature.
    Ed25519,
}

impl SignatureMethod {
    /// The method `uri` names, if it is one this platform accepts.
    pub(crate) fn from_uri(uri: &str) -> Option<Self> {
        [
            Self::RsaSha256,
            Self::RsaSha512,
            Self::EcdsaSha256,
            Self::Ed25519,
        ]
        .into_iter()
        .find(|method| method.uri() == uri)
    }

    /// The URI XML Signature names the method by.
    pub(crate) fn uri(self) -> &'static str {
        match self {
            Self::RsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            Self::RsaSha512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            Self::EcdsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            Self::Ed25519 => "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519",
        }
    }
}

/// A digest algorithm a SAML signature may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DigestMethod {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl DigestMethod {
    /// The method `uri` names, if it is one this platform accepts.
    pub(crate) fn from_uri(uri: &str) -> Option<Self> {
        [Self::Sha256, Self::Sha384, Self::Sha512]
            .into_iter()
            .find(|method| method.uri() == uri)
    }

    /// The URI XML Signature names the method by.
    pub(crate) fn uri(self) -> &'static str {
        match self {
            Self::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            Self::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
            Self::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
        }
    }

    /// The digest of `data`.
    pub(crate) fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// A public key a signature is checked against, read from a certificate
/// someone registered.
#[derive(Debug, Clone)]
pub(crate) enum TrustedKey {
    /// An RSA key of at least 2048 bits.
    Rsa(RsaVerifyingKey),
    /// An ECDSA key on P-256.
    P256(p256::ecdsa::VerifyingKey),
    /// An Ed25519 key.
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl TrustedKey {
    /// The key `certificate` carries.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when the certificate cannot be
    /// read, or carries a key of a kind or size this platform does not
    /// check signatures with.
    pub(crate) fn from_certificate(certificate: &CertificatePem) -> Result<Self, DomainError> {
        let public_key = public_key_der(certificate)?;
        match RsaVerifyingKey::from_der(&public_key) {
            Ok(key) => return Ok(Self::Rsa(key)),
            Err(RsaKeyError::TooShort) => return Err(too_short()),
            Err(RsaKeyError::Unreadable | RsaKeyError::CouldNotUse) => {}
        }
        if let Ok(key) = p256::ecdsa::VerifyingKey::from_public_key_der(&public_key) {
            return Ok(Self::P256(key));
        }
        ed25519_dalek::VerifyingKey::from_public_key_der(&public_key)
            .map(Self::Ed25519)
            .map_err(|_| {
                DomainError::invalid(message!(
                    "infra-the-certificate-carries-a-key-this",
                    "the certificate carries a key this platform does not check signatures with"
                ))
            })
    }

    /// The keys of every certificate in `certificates` that can be read.
    /// One that cannot is left out; it can never check a signature, so
    /// leaving it out trusts nobody more.
    pub(crate) fn all<'a>(certificates: impl IntoIterator<Item = &'a CertificatePem>) -> Vec<Self> {
        certificates
            .into_iter()
            .filter_map(|certificate| Self::from_certificate(certificate).ok())
            .collect()
    }

    /// Whether `signature` is this key's signature of `data` by `method`.
    /// A method another kind of key signs with never verifies.
    pub(crate) fn verifies(&self, method: SignatureMethod, data: &[u8], signature: &[u8]) -> bool {
        match (self, method) {
            (Self::Rsa(key), SignatureMethod::RsaSha256) => {
                key.verifies(RsaDigest::Sha256, data, signature)
            }
            (Self::Rsa(key), SignatureMethod::RsaSha512) => {
                key.verifies(RsaDigest::Sha512, data, signature)
            }
            (Self::P256(key), SignatureMethod::EcdsaSha256) => {
                p256::ecdsa::Signature::from_slice(signature)
                    .is_ok_and(|signature| key.verify(data, &signature).is_ok())
            }
            (Self::Ed25519(key), SignatureMethod::Ed25519) => {
                ed25519_dalek::Signature::from_slice(signature)
                    .is_ok_and(|signature| key.verify(data, &signature).is_ok())
            }
            (Self::Rsa(_) | Self::P256(_) | Self::Ed25519(_), _) => false,
        }
    }
}

/// The RSA key `certificate` carries, for sealing to it.
///
/// # Errors
///
/// Returns `DomainError::Validation` when the certificate cannot be read
/// or carries no RSA key of at least 2048 bits.
pub(crate) fn rsa_key_of(certificate: &CertificatePem) -> Result<RsaSealingKey, DomainError> {
    let public_key = public_key_der(certificate)?;
    RsaSealingKey::from_spki_der(&public_key).map_err(|refused| match refused {
        RsaKeyError::TooShort => too_short(),
        RsaKeyError::Unreadable | RsaKeyError::CouldNotUse => DomainError::invalid(message!(
            "infra-the-certificate-carries-no-rsa-key",
            "the certificate carries no RSA key"
        )),
    })
}

/// A key this platform signs with: the tenant's, read for its algorithm.
pub(crate) enum PrivateKey {
    /// An RSA key, signing with SHA-256.
    Rsa(Box<RsaSigningKey>),
    /// An ECDSA key on P-256.
    P256(p256::ecdsa::SigningKey),
    /// An Ed25519 key.
    Ed25519(ed25519_dalek::SigningKey),
}

impl PrivateKey {
    /// The private half of `key`, read as a key of its algorithm.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it is not a PKCS#8 key
    /// of that algorithm. The error names no part of the key.
    pub(crate) fn of(key: &XmlSigningKey<'_>) -> Result<Self, DomainError> {
        let pem = key.private_key.expose();
        let read = match key.algorithm {
            SigningAlgorithm::Rs256 => RsaSigningKey::from_pkcs8_pem(pem)
                .ok()
                .map(|key| Self::Rsa(Box::new(key))),
            SigningAlgorithm::Es256 => p256::ecdsa::SigningKey::from_pkcs8_pem(pem)
                .ok()
                .map(Self::P256),
            SigningAlgorithm::EdDsa => ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
                .ok()
                .map(Self::Ed25519),
        };
        read.ok_or_else(|| DomainError::infra_msg("the signing key is not a key of its algorithm"))
    }

    /// The method this key signs with.
    pub(crate) fn method(&self) -> SignatureMethod {
        match self {
            Self::Rsa(_) => SignatureMethod::RsaSha256,
            Self::P256(_) => SignatureMethod::EcdsaSha256,
            Self::Ed25519(_) => SignatureMethod::Ed25519,
        }
    }

    /// This key's signature of `data`, in the form XML Signature writes it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the key cannot sign.
    pub(crate) fn sign(&self, data: &[u8]) -> Result<Vec<u8>, DomainError> {
        match self {
            Self::Rsa(key) => key.sign_sha256(data).map_err(DomainError::infra),
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(data);
                Ok(signature.to_bytes().to_vec())
            }
            Self::Ed25519(key) => Ok(key.sign(data).to_bytes().to_vec()),
        }
    }
}

/// `N` bytes from the operating system's secure generator.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the generator cannot be
/// read.
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], DomainError> {
    let mut bytes = [0_u8; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(DomainError::infra)?;
    Ok(bytes)
}

/// The DER of the public key `certificate` carries.
fn public_key_der(certificate: &CertificatePem) -> Result<Vec<u8>, DomainError> {
    let unreadable = || {
        DomainError::invalid(message!(
            "infra-the-certificate-cannot-be-read",
            "the certificate cannot be read"
        ))
    };
    let parsed = certificate_in(certificate.as_str()).map_err(|_| unreadable())?;
    parsed
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| unreadable())
}

/// The refusal of a certificate whose RSA key is too short to trust.
fn too_short() -> DomainError {
    DomainError::invalid(message!(
        "infra-the-certificate-s-rsa-key-is",
        "the certificate's RSA key is shorter than 2048 bits"
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{KeyId, PublicKeyPem};

    use super::*;
    use crate::crypto::certificates::rsa_keys::tests::fresh_pkcs8_pem;

    /// A key pair of `algorithm` and the self-signed certificate carrying
    /// its public half, as an identity provider or an app would register.
    pub(crate) struct TestKey {
        pub(crate) kid: KeyId,
        pub(crate) algorithm: SigningAlgorithm,
        pub(crate) private_key: Secret,
        pub(crate) public_key: PublicKeyPem,
        pub(crate) certificate: CertificatePem,
    }

    impl TestKey {
        /// A fresh key of `algorithm`.
        pub(crate) fn new(algorithm: SigningAlgorithm) -> Self {
            let pair = key_pair(algorithm);
            let private_pem = pair.serialize_pem();
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "https://idp.acme.com");
            let certificate = params.self_signed(&pair).unwrap();
            Self {
                kid: KeyId::new("key-1").unwrap(),
                algorithm,
                private_key: Secret::new(private_pem),
                public_key: PublicKeyPem::new(pair.public_key_pem()).unwrap(),
                certificate: CertificatePem::new(certificate.pem()).unwrap(),
            }
        }

        /// The key as the XML signing ports take it.
        pub(crate) fn signing(&self) -> XmlSigningKey<'_> {
            XmlSigningKey {
                kid: &self.kid,
                algorithm: self.algorithm,
                private_key: &self.private_key,
                public_key: &self.public_key,
            }
        }

        /// The key a signature by this one is checked against.
        pub(crate) fn trusted(&self) -> TrustedKey {
            TrustedKey::from_certificate(&self.certificate).unwrap()
        }
    }

    /// A fresh key pair of `algorithm`. RSA keys are drawn by aws-lc-rs,
    /// since the certificate library makes none of its own.
    fn key_pair(algorithm: SigningAlgorithm) -> rcgen::KeyPair {
        match algorithm {
            SigningAlgorithm::Rs256 => rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(
                &fresh_pkcs8_pem(),
                &rcgen::PKCS_RSA_SHA256,
            )
            .unwrap(),
            SigningAlgorithm::Es256 => {
                rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap()
            }
            SigningAlgorithm::EdDsa => rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap(),
        }
    }

    /// Each kind of key signs, its certificate's key checks the signature,
    /// and changed data does not check.
    #[test]
    fn each_kind_of_key_signs_and_checks() {
        for algorithm in [
            SigningAlgorithm::Rs256,
            SigningAlgorithm::Es256,
            SigningAlgorithm::EdDsa,
        ] {
            let key = TestKey::new(algorithm);
            let signer = PrivateKey::of(&key.signing()).unwrap();

            let signature = signer.sign(b"signed info").unwrap();

            let trusted = key.trusted();
            assert!(
                trusted.verifies(signer.method(), b"signed info", &signature),
                "{algorithm:?}"
            );
            assert!(
                !trusted.verifies(signer.method(), b"signed infO", &signature),
                "{algorithm:?}"
            );
        }
    }

    /// SHA-1 identifiers are unsupported, and a P-256 key refuses RSA and Ed25519 methods.
    #[test]
    fn the_method_is_pinned_to_the_kind_of_key() {
        let key = TestKey::new(SigningAlgorithm::Es256);
        let signature = PrivateKey::of(&key.signing())
            .unwrap()
            .sign(b"data")
            .unwrap();

        assert_eq!(
            SignatureMethod::from_uri("http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
            None
        );
        assert_eq!(
            DigestMethod::from_uri("http://www.w3.org/2000/09/xmldsig#sha1"),
            None
        );
        assert!(
            !key.trusted()
                .verifies(SignatureMethod::RsaSha256, b"data", &signature)
        );
        assert!(
            !key.trusted()
                .verifies(SignatureMethod::Ed25519, b"data", &signature)
        );
    }

    /// Unreadable certificate text yields no key; a mixed collection still retains its valid key.
    #[test]
    fn an_unreadable_certificate_gives_no_key() {
        let junk =
            CertificatePem::new("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")
                .unwrap();
        let good = TestKey::new(SigningAlgorithm::Es256);

        assert!(TrustedKey::from_certificate(&junk).is_err());
        assert_eq!(TrustedKey::all([&junk, &good.certificate]).len(), 1);
    }
}
