//! A tenant's mutual TLS settings: whether clients must present a
//! certificate, which certificate authorities may have signed it, and the
//! lists of certificates those authorities revoked.
//!
//! Revocation is checked in the handshake against the lists the tenant
//! gives, never by asking a responder on the network while the client
//! waits. A tenant that gives lists has every client certificate held to
//! them, and fails closed: a certificate whose issuer no list covers, or a
//! list past the date it said it would be replaced by, refuses the
//! certificate. With certificates required the handshake is refused; with
//! them optional the connection carries no certificate, and every route
//! that needs one refuses.

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_count;
use crate::types::{CertificatePem, RevocationListPem};

/// Whether the tenant asks clients for a certificate in mutual TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MtlsMode {
    /// mTLS is not used. Standard TLS only.
    Disabled,
    /// mTLS is accepted but not required. Clients with a valid certificate
    /// get more trust. Others use normal TLS.
    Optional,
    /// mTLS is required. Clients without a valid certificate are refused at
    /// the TLS layer.
    Required,
}

/// mTLS configuration for a tenant.
///
/// A mode that asks for client certificates always trusts at least one
/// authority to have signed them. Read from JSON through
/// [`new`](Self::new), so a stored one is held to that too.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "MtlsConfigWire"))]
pub struct MtlsConfig {
    /// How mTLS is enforced.
    mode: MtlsMode,
    /// PEM-encoded CA certificates trusted to sign client certificates.
    /// Only certificates chaining to one of these are accepted. A domain name
    /// cannot check a signature, so this holds the CA certificates themselves.
    trusted_ca_certs: Vec<CertificatePem>,
    /// The revocation lists client certificates are checked against. None
    /// means revocation is not checked.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    revocation_lists: Vec<RevocationListPem>,
}

/// An [`MtlsConfig`] as JSON spells it, before it is checked.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct MtlsConfigWire {
    mode: MtlsMode,
    trusted_ca_certs: Vec<CertificatePem>,
    #[serde(default)]
    revocation_lists: Vec<RevocationListPem>,
}

#[cfg(feature = "serde")]
impl TryFrom<MtlsConfigWire> for MtlsConfig {
    type Error = DomainError;

    fn try_from(wire: MtlsConfigWire) -> Result<Self, Self::Error> {
        Self::new(wire.mode, wire.trusted_ca_certs)?.with_revocation_lists(wire.revocation_lists)
    }
}

impl MtlsConfig {
    /// Creates a new mTLS configuration.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `mode` asks for client certificates
    ///   but no authority is trusted to sign one. `Required` would turn every
    ///   client away. `Optional` would offer trust no certificate can earn.
    pub fn new(mode: MtlsMode, trusted_ca_certs: Vec<CertificatePem>) -> Result<Self, DomainError> {
        let asks_for_certificates = match mode {
            MtlsMode::Disabled => false,
            MtlsMode::Optional | MtlsMode::Required => true,
        };
        if asks_for_certificates && trusted_ca_certs.is_empty() {
            return Err(DomainError::invalid(message!(
                "tenant-mutual-tls-needs-at-least-one",
                "mutual TLS needs at least one trusted certificate authority"
            )));
        }
        Ok(Self {
            mode,
            trusted_ca_certs,
            revocation_lists: Vec::new(),
        })
    }

    /// The most revocation lists one tenant gives.
    pub const MAX_REVOCATION_LISTS: usize = 32;

    /// This configuration, with client certificates checked against
    /// `lists` in place of any given before. An empty `lists` stops the
    /// check.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when lists are given with mutual TLS
    ///   off: they would read as a check that never runs.
    /// - [`DomainError::Validation`] when more than
    ///   [`MAX_REVOCATION_LISTS`](Self::MAX_REVOCATION_LISTS) are given.
    pub fn with_revocation_lists(self, lists: Vec<RevocationListPem>) -> Result<Self, DomainError> {
        validate_count(
            "revocation_lists",
            lists.len(),
            0..=Self::MAX_REVOCATION_LISTS,
        )?;
        if self.mode == MtlsMode::Disabled && !lists.is_empty() {
            return Err(DomainError::invalid(message!(
                "tenant-revocation-lists-need-mutual-tls-to",
                "revocation lists need mutual TLS to be on"
            )));
        }
        Ok(Self {
            revocation_lists: lists,
            ..self
        })
    }

    /// A configuration with mTLS off and no authority trusted.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            mode: MtlsMode::Disabled,
            trusted_ca_certs: Vec::new(),
            revocation_lists: Vec::new(),
        }
    }

    /// How mTLS is enforced.
    #[must_use]
    pub fn mode(&self) -> MtlsMode {
        self.mode
    }

    /// PEM-encoded trusted CA certificates.
    #[must_use]
    pub fn trusted_ca_certs(&self) -> &[CertificatePem] {
        &self.trusted_ca_certs
    }

    /// The revocation lists client certificates are checked against.
    #[must_use]
    pub fn revocation_lists(&self) -> &[RevocationListPem] {
        &self.revocation_lists
    }

    /// Whether client certificates are checked for revocation.
    #[must_use]
    pub fn checks_revocation(&self) -> bool {
        !self.revocation_lists.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tenant starts with mTLS off and no certificate authority trusted,
    /// so nothing is admitted on a client certificate until it is set up.
    #[test]
    fn mtls_starts_disabled_trusting_no_authority() {
        let config = MtlsConfig::disabled();

        assert_eq!(config.mode(), MtlsMode::Disabled);
        assert!(config.trusted_ca_certs().is_empty());
    }

    /// A tenant sets mTLS to required or optional with no trusted authority.
    /// Both are refused, since no certificate could ever pass. Disabled with
    /// none is fine.
    #[test]
    fn asking_for_certificates_without_an_authority_is_refused() {
        assert!(MtlsConfig::new(MtlsMode::Required, Vec::new()).is_err());
        assert!(MtlsConfig::new(MtlsMode::Optional, Vec::new()).is_err());
        assert!(MtlsConfig::new(MtlsMode::Disabled, Vec::new()).is_ok());
    }

    /// A tenant requires mTLS with one trusted CA. The mode and that exact
    /// certificate read back.
    #[test]
    fn a_configuration_keeps_the_mode_and_authorities_it_was_given() {
        let pem =
            CertificatePem::new("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")
                .unwrap();

        let config = MtlsConfig::new(MtlsMode::Required, vec![pem.clone()]).unwrap();

        assert_eq!(config.mode(), MtlsMode::Required);
        assert_eq!(config.trusted_ca_certs(), [pem]);
    }

    fn ca() -> CertificatePem {
        CertificatePem::new("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----").unwrap()
    }

    fn crl() -> RevocationListPem {
        RevocationListPem::new("-----BEGIN X509 CRL-----\nMIIB\n-----END X509 CRL-----").unwrap()
    }

    /// A tenant requiring mTLS gives its authority's revocation list.
    /// Client certificates are checked against it from then on.
    #[test]
    fn revocation_lists_turn_the_check_on() {
        let config = MtlsConfig::new(MtlsMode::Required, vec![ca()])
            .unwrap()
            .with_revocation_lists(vec![crl()])
            .unwrap();

        assert!(config.checks_revocation());
        assert_eq!(config.revocation_lists(), [crl()]);
        assert!(!MtlsConfig::disabled().checks_revocation());
    }

    /// Revocation lists are rejected while mutual TLS is disabled, rather
    /// than retained as a check that cannot run.
    #[test]
    fn revocation_lists_with_mtls_off_are_refused() {
        let result = MtlsConfig::disabled().with_revocation_lists(vec![crl()]);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    #[test]
    fn more_revocation_lists_than_the_limit_are_refused() {
        let lists = vec![crl(); MtlsConfig::MAX_REVOCATION_LISTS + 1];

        let result = MtlsConfig::new(MtlsMode::Optional, vec![ca()])
            .unwrap()
            .with_revocation_lists(lists);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A stored setting without lists reads as one checking no revocation,
    /// and one with lists keeps them.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_setting_reads_back_with_its_lists() {
        let without: MtlsConfig = serde_json::from_value(serde_json::json!({
            "mode": "Required",
            "trusted_ca_certs": [ca().as_str()],
        }))
        .unwrap();
        let with = MtlsConfig::new(MtlsMode::Required, vec![ca()])
            .unwrap()
            .with_revocation_lists(vec![crl()])
            .unwrap();

        let read: MtlsConfig =
            serde_json::from_value(serde_json::to_value(&with).unwrap()).unwrap();

        assert!(!without.checks_revocation());
        assert_eq!(read.revocation_lists(), [crl()]);
    }
}
