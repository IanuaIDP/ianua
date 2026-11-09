//! X.509 certificates: checking that PEM text holds certificates, reading
//! the chain a tenant uploads for a domain, and the authority that signs
//! the client certificates LDAP binds with; the private authority of the
//! link the nameservers outside the cluster follow the zones over; the
//! connector authority, which signs the certificates tenants' connectors
//! hold their links to the gateway with; and the
//! RSA keys certificates and tokens are signed and sealed with, held by
//! aws-lc-rs.
//!
//! Nothing here builds a chain or checks a signature on an uploaded
//! certificate: that is the TLS layer's, where the certificate is used.

mod connector;
mod ldap;
mod link;
mod parser;
pub(crate) mod pem;
pub(crate) mod rsa_keys;

use ianua_app::ports::crypto::CertPemValidator;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CertificatePem, RevocationListPem};

pub use self::connector::{
    ConnectorCaError, ConnectorIdentity, ConnectorPki, ConnectorPkiValidity, NoConnectorAuthority,
    RcgenConnectorAuthority, connector_identity, issue_connector_pki,
};
pub use self::ldap::{LdapCaError, NoLdapCertificateAuthority, RcgenLdapCertificateAuthority};
pub use self::link::{
    InternalLeaf, InternalListener, InternalPki, KeyedCertificate, LinkClient, LinkPki,
    LinkValidity, issue_internal_pki, issue_link_pki,
};
pub use self::parser::X509CertificateParser;
use self::pem::{certificates_in, revocation_lists_in};

/// The check that PEM text holds at least one well-formed certificate, as
/// a tenant's mTLS trust anchor must.
#[derive(Debug, Clone, Copy, Default)]
pub struct X509CertPemValidator;

impl CertPemValidator for X509CertPemValidator {
    fn validate_cert_pem(&self, pem: &CertificatePem) -> Result<(), DomainError> {
        certificates_in(pem.as_str()).map(|_| ()).map_err(|_| {
            DomainError::invalid(message!(
                "infra-the-text-holds-no-well-formed",
                "the text holds no well-formed certificate"
            ))
        })
    }

    fn validate_revocation_list_pem(&self, pem: &RevocationListPem) -> Result<(), DomainError> {
        revocation_lists_in(pem.as_str()).map(|_| ()).map_err(|_| {
            DomainError::invalid(message!(
                "infra-the-text-holds-no-well-formed-2",
                "the text holds no well-formed revocation list"
            ))
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer,
        IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose,
    };

    use super::*;

    /// A self-signed certificate for `domain`, and its key, as PEM.
    pub(crate) fn self_signed(domain: &str) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec![domain.to_owned()]).unwrap();
        let certificate = params.self_signed(&key).unwrap();
        (certificate.pem(), key.serialize_pem())
    }

    /// A self-signed certificate passes, and so does a chain of two.
    #[test]
    fn a_certificate_or_a_chain_passes() {
        let (one, _) = self_signed("acme.example");
        let (two, _) = self_signed("ca.acme.example");

        assert!(
            X509CertPemValidator
                .validate_cert_pem(&CertificatePem::new(one.clone()).unwrap())
                .is_ok()
        );
        assert!(
            X509CertPemValidator
                .validate_cert_pem(&CertificatePem::new(format!("{one}{two}")).unwrap())
                .is_ok()
        );
    }

    /// Certificate-shaped PEM containing invalid certificate bytes returns a validation error.
    #[test]
    fn text_that_is_no_certificate_is_refused() {
        let fake = "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n";

        let read = X509CertPemValidator.validate_cert_pem(&CertificatePem::new(fake).unwrap());

        assert!(matches!(read, Err(DomainError::Validation(_))));
    }

    /// A revocation list an authority signed passes.
    #[test]
    fn a_signed_revocation_list_passes() {
        let mut ca = CertificateParams::new(Vec::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let authority = CertifiedIssuer::self_signed(ca, KeyPair::generate().unwrap()).unwrap();
        let now = time::OffsetDateTime::now_utc();
        let list = CertificateRevocationListParams {
            this_update: now,
            next_update: now + time::Duration::days(7),
            crl_number: 1u64.into(),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&authority)
        .unwrap()
        .pem()
        .unwrap();

        let read = X509CertPemValidator
            .validate_revocation_list_pem(&RevocationListPem::new(list).unwrap());

        assert!(read.is_ok());
    }

    /// Invalid revocation-list bytes are rejected even when wrapped in the expected PEM markers.
    #[test]
    fn text_that_is_no_revocation_list_is_refused() {
        let fake = "-----BEGIN X509 CRL-----\nbm90IGEgbGlzdA==\n-----END X509 CRL-----\n";

        let read = X509CertPemValidator
            .validate_revocation_list_pem(&RevocationListPem::new(fake).unwrap());

        assert!(matches!(read, Err(DomainError::Validation(_))));
    }
}
