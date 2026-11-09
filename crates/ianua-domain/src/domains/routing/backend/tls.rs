//! How the gateway speaks TLS to an upstream on a private PKI.
//!
//! A service inside a company network often holds a certificate from the
//! company's own CA, answers to an internal name, and asks its callers for a
//! client certificate. Without these settings the gateway trusts only public
//! roots, so such a service cannot be reached over HTTPS at all.
//!
//! Verification is never switched off. A service whose certificate the
//! gateway cannot check names the CA that signed it instead.

use crate::message;
use crate::shared::validation::ValidationError;
use crate::types::{CertificatePem, DomainName, SealedSecret, Setting};

/// Which certificate authorities an upstream's certificate must chain to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum UpstreamTrust {
    /// The public web roots, as for any site on the internet.
    #[default]
    PublicRoots,
    /// Only the CA certificates in this bundle. The public roots are not
    /// trusted for this service, so a public certificate for its name does
    /// not pass.
    PrivateCa(CertificatePem),
}

/// The certificate the gateway presents to an upstream that asks for one.
///
/// The private key is sealed by the crypto adapter. The domain never reads
/// it, and it never prints.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpstreamClientCertificate {
    certificate: CertificatePem,
    private_key: SealedSecret,
}

impl UpstreamClientCertificate {
    /// The certificate chain `certificate`, with its sealed `private_key`.
    #[must_use]
    pub fn new(certificate: CertificatePem, private_key: SealedSecret) -> Self {
        Self {
            certificate,
            private_key,
        }
    }

    /// The certificate chain presented.
    #[must_use]
    pub fn certificate(&self) -> &CertificatePem {
        &self.certificate
    }

    /// The private key, sealed.
    #[must_use]
    pub fn private_key(&self) -> &SealedSecret {
        &self.private_key
    }
}

/// The settings upstream TLS is built from.
pub struct UpstreamTlsParams {
    /// Which CAs the upstream's certificate must chain to.
    pub trust: UpstreamTrust,
    /// The certificate presented when the upstream asks for one.
    pub client_certificate: Setting<UpstreamClientCertificate>,
    /// The name sent as SNI and checked against the upstream's certificate,
    /// when it is not the host in the upstream's address.
    pub server_name: Setting<DomainName>,
}

/// How the gateway opens TLS to an upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "UpstreamTlsRecord", into = "UpstreamTlsRecord")
)]
pub struct UpstreamTls {
    trust: UpstreamTrust,
    client_certificate: Setting<UpstreamClientCertificate>,
    server_name: Setting<DomainName>,
}

impl UpstreamTls {
    /// Checked upstream TLS settings.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when the server name is a wildcard. The gateway
    ///   sends one name and checks the certificate against it, so
    ///   `*.internal` would match nothing it can send.
    pub fn new(params: UpstreamTlsParams) -> Result<Self, ValidationError> {
        if params
            .server_name
            .value()
            .is_some_and(DomainName::is_wildcard)
        {
            return Err(ValidationError::Custom {
                field: "server_name",
                code: "invalid_upstream_tls".to_owned(),
                message: message!(
                    "routing-the-server-name-sent-to-an",
                    "the server name sent to an upstream is one name, never a wildcard"
                ),
            });
        }
        Ok(Self {
            trust: params.trust,
            client_certificate: params.client_certificate,
            server_name: params.server_name,
        })
    }

    /// Which CAs the upstream's certificate must chain to.
    #[must_use]
    pub fn trust(&self) -> &UpstreamTrust {
        &self.trust
    }

    /// The certificate presented when the upstream asks for one, if any.
    #[must_use]
    pub fn client_certificate(&self) -> Option<&UpstreamClientCertificate> {
        self.client_certificate.value()
    }

    /// The same trust and server name, presenting no client certificate.
    #[must_use]
    pub fn without_client_certificate(&self) -> Self {
        Self {
            trust: self.trust.clone(),
            client_certificate: Setting::Unset,
            server_name: self.server_name.clone(),
        }
    }

    /// The name sent as SNI and checked against the certificate, when it is
    /// not the host in the upstream's address.
    #[must_use]
    pub fn server_name(&self) -> Option<&DomainName> {
        self.server_name.value()
    }
}

/// [`UpstreamTls`] as stored, read back through [`UpstreamTls::new`].
#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct UpstreamTlsRecord {
    #[serde(default)]
    trust: UpstreamTrust,
    #[serde(default)]
    client_certificate: Setting<UpstreamClientCertificate>,
    #[serde(default)]
    server_name: Setting<DomainName>,
}

#[cfg(feature = "serde")]
impl TryFrom<UpstreamTlsRecord> for UpstreamTls {
    type Error = ValidationError;

    fn try_from(record: UpstreamTlsRecord) -> Result<Self, Self::Error> {
        Self::new(UpstreamTlsParams {
            trust: record.trust,
            client_certificate: record.client_certificate,
            server_name: record.server_name,
        })
    }
}

#[cfg(feature = "serde")]
impl From<UpstreamTls> for UpstreamTlsRecord {
    fn from(tls: UpstreamTls) -> Self {
        Self {
            trust: tls.trust,
            client_certificate: tls.client_certificate,
            server_name: tls.server_name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> UpstreamTlsParams {
        UpstreamTlsParams {
            trust: UpstreamTrust::PublicRoots,
            client_certificate: Setting::Unset,
            server_name: Setting::Unset,
        }
    }

    /// Ann's payroll service answers as `payroll.corp.internal` behind an
    /// address the gateway dials by IP. The name is kept and sent as SNI.
    #[test]
    fn a_server_name_override_is_kept() {
        let tls = UpstreamTls::new(UpstreamTlsParams {
            server_name: Setting::Set(DomainName::new("payroll.corp.internal").unwrap()),
            ..params()
        })
        .unwrap();

        assert_eq!(
            tls.server_name().map(DomainName::as_str),
            Some("payroll.corp.internal")
        );
    }

    /// Upstream TLS settings reject a wildcard server name.
    #[test]
    fn a_wildcard_server_name_is_refused() {
        let result = UpstreamTls::new(UpstreamTlsParams {
            server_name: Setting::Set(DomainName::new("*.corp.internal").unwrap()),
            ..params()
        });

        assert!(result.is_err());
    }

    /// Debug formatting of TLS settings conceals the sealed client key.
    #[test]
    fn the_client_key_never_prints() {
        let tls = UpstreamTls::new(UpstreamTlsParams {
            client_certificate: Setting::Set(UpstreamClientCertificate::new(
                CertificatePem::new(
                    "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
                )
                .unwrap(),
                SealedSecret::new("v1.sealed-client-key").unwrap(),
            )),
            ..params()
        })
        .unwrap();

        assert!(!format!("{tls:?}").contains("sealed-client-key"));
    }

    /// Settings with no field written read back as public roots, no client
    /// certificate and no name override.
    #[cfg(feature = "serde")]
    #[test]
    fn empty_stored_settings_trust_the_public_roots_only() {
        let tls: UpstreamTls = serde_json::from_value(serde_json::json!({})).unwrap();

        assert_eq!(tls.trust(), &UpstreamTrust::PublicRoots);
        assert!(tls.client_certificate().is_none());
        assert!(tls.server_name().is_none());
    }
}
