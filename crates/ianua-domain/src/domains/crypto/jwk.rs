//! The public key fields of a JSON Web Key.
//!
//! Each key type has its own fields for a JWK entry, as RFC 7517 defines
//! them. The domain defines the shape. Infrastructure turns a PEM into these
//! fields.

use crate::domains::crypto::signing_key::SigningAlgorithm;

/// Structured public key material for a JWK entry.
///
/// Each variant carries the fields its algorithm needs to verify signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwkComponents {
    /// RSA key components (RFC 7518 §6.3).
    Rsa {
        /// Key ID.
        kid: String,
        /// Base64url-encoded modulus.
        n: String,
        /// Base64url-encoded exponent.
        e: String,
    },
    /// EC key components for P-256 (RFC 7518 §6.2).
    Ec {
        /// Key ID.
        kid: String,
        /// Curve name (e.g. "P-256").
        crv: String,
        /// Base64url-encoded x coordinate.
        x: String,
        /// Base64url-encoded y coordinate.
        y: String,
    },
    /// OKP key components for Ed25519 (RFC 8037).
    Okp {
        /// Key ID.
        kid: String,
        /// Curve name (e.g. "Ed25519").
        crv: String,
        /// Base64url-encoded public key.
        x: String,
    },
}

impl JwkComponents {
    /// The key ID across all variants.
    #[must_use]
    pub fn kid(&self) -> &str {
        match self {
            Self::Rsa { kid, .. } | Self::Ec { kid, .. } | Self::Okp { kid, .. } => kid,
        }
    }

    /// The JWK `kty` field value.
    #[must_use]
    pub fn kty(&self) -> &'static str {
        match self {
            Self::Rsa { .. } => "RSA",
            Self::Ec { .. } => "EC",
            Self::Okp { .. } => "OKP",
        }
    }

    /// The JWK `alg` field value derived from the signing algorithm.
    #[must_use]
    pub fn alg(algorithm: SigningAlgorithm) -> &'static str {
        match algorithm {
            SigningAlgorithm::Rs256 => "RS256",
            SigningAlgorithm::Es256 => "ES256",
            SigningAlgorithm::EdDsa => "EdDSA",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An RSA, an EC and an OKP key each report their own `kid`, `kty` and
    /// `alg`. A relying party picks its key by `kid` and reads the other two
    /// to know how to verify.
    #[test]
    fn a_published_key_names_the_kid_type_and_algorithm_a_verifier_needs() {
        let rsa = JwkComponents::Rsa {
            kid: "key-1".to_owned(),
            n: "modulus".to_owned(),
            e: "AQAB".to_owned(),
        };
        let ec = JwkComponents::Ec {
            kid: "key-2".to_owned(),
            crv: "P-256".to_owned(),
            x: "x".to_owned(),
            y: "y".to_owned(),
        };
        let okp = JwkComponents::Okp {
            kid: "key-3".to_owned(),
            crv: "Ed25519".to_owned(),
            x: "x".to_owned(),
        };

        assert_eq!(rsa.kid(), "key-1");
        assert_eq!(ec.kid(), "key-2");
        assert_eq!(okp.kid(), "key-3");

        assert_eq!(rsa.kty(), "RSA");
        assert_eq!(ec.kty(), "EC");
        assert_eq!(okp.kty(), "OKP");

        assert_eq!(JwkComponents::alg(SigningAlgorithm::Rs256), "RS256");
        assert_eq!(JwkComponents::alg(SigningAlgorithm::Es256), "ES256");
        assert_eq!(JwkComponents::alg(SigningAlgorithm::EdDsa), "EdDSA");
    }
}
