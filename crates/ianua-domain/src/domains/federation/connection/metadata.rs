//! What a SAML provider's metadata says about it, once read.
//!
//! An admin points a connection at the provider's metadata, by its URL or
//! as the document, instead of copying each endpoint and certificate by
//! hand. The adapter reads the document; this holds the facts it found.

use crate::domains::federation::connection::config::SamlConfig;
use crate::domains::federation::connection::saml_keys::{
    AssertionDecryption, AuthnRequestSigning, IdpCertificates,
};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_count;
use crate::types::{CertificatePem, HttpsUrl, PublicHttpsUrl, SamlNameIdFormat, Setting};

/// What a provider's metadata document says, as the adapter read it.
#[derive(Debug)]
pub struct IdpMetadataFacts {
    /// Its `entityID`.
    pub entity_id: HttpsUrl,
    /// Its single sign-on endpoint.
    pub sso_url: HttpsUrl,
    /// Its single logout endpoint, when it lists one.
    pub slo_url: Setting<HttpsUrl>,
    /// The certificates it lists for signing, current first.
    pub signing_certificates: Vec<CertificatePem>,
}

/// A provider's metadata, read and checked: the facts that replace a SAML
/// connection's endpoints and certificates when it is imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedIdpMetadata {
    entity_id: HttpsUrl,
    sso_url: HttpsUrl,
    slo_url: Setting<HttpsUrl>,
    certificates: IdpCertificates,
    source: Setting<PublicHttpsUrl>,
}

impl ImportedIdpMetadata {
    /// The metadata `facts` describe.
    ///
    /// A provider lists one signing certificate, or two while it rolls its
    /// key over: the first is the current one, the second the next.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it lists no signing certificate,
    ///   more than two, or the same one twice.
    pub fn new(facts: IdpMetadataFacts) -> Result<Self, DomainError> {
        validate_count(
            "signing_certificates",
            facts.signing_certificates.len(),
            1..=2,
        )?;
        let mut listed = facts.signing_certificates.into_iter();
        let Some(current) = listed.next() else {
            return Err(DomainError::invalid(message!(
                "federation-the-metadata-lists-no-signing-certificate",
                "the metadata lists no signing certificate"
            )));
        };
        let certificates = match listed.next() {
            Some(next) => IdpCertificates::rolling_over(current, next)?,
            None => IdpCertificates::single(current),
        };
        Ok(Self {
            entity_id: facts.entity_id,
            sso_url: facts.sso_url,
            slo_url: facts.slo_url,
            certificates,
            source: Setting::Unset,
        })
    }

    /// This metadata, read from the address `url` the provider publishes it
    /// at. A connection made or updated from it follows that address.
    #[must_use]
    pub fn published_at(mut self, url: PublicHttpsUrl) -> Self {
        self.source = Setting::Set(url);
        self
    }

    /// The address it was read from, or unset for a pasted document.
    #[must_use]
    pub fn source(&self) -> &Setting<PublicHttpsUrl> {
        &self.source
    }

    /// The provider's entity id.
    #[must_use]
    pub fn entity_id(&self) -> &HttpsUrl {
        &self.entity_id
    }

    /// The certificates it signs with.
    #[must_use]
    pub fn certificates(&self) -> &IdpCertificates {
        &self.certificates
    }

    /// A configuration for a new connection to this provider: its
    /// endpoints and certificates, the persistent `NameID` format, unsigned
    /// requests and readable assertions, which an admin may change after.
    ///
    /// # Errors
    ///
    /// - Never fails in practice: the persistent format passes its rules.
    pub fn into_config(self) -> Result<SamlConfig, DomainError> {
        Ok(SamlConfig {
            entity_id: self.entity_id,
            sso_url: self.sso_url,
            slo_url: self.slo_url,
            certificates: self.certificates,
            name_id_format: SamlNameIdFormat::new(SamlNameIdFormat::PERSISTENT)?,
            request_signing: AuthnRequestSigning::Unsigned,
            assertion_decryption: AssertionDecryption::NotExpected,
            metadata_url: self.source,
        })
    }

    /// `config` with its endpoints and certificates replaced by these, and
    /// following the address they were read from, keeping its own choices
    /// of format, signing and encryption.
    pub(crate) fn applied_to(self, config: SamlConfig) -> SamlConfig {
        SamlConfig {
            entity_id: self.entity_id,
            sso_url: self.sso_url,
            slo_url: self.slo_url,
            certificates: self.certificates,
            metadata_url: self.source,
            ..config
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate(body: &str) -> CertificatePem {
        CertificatePem::new(format!(
            "-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----"
        ))
        .unwrap()
    }

    fn facts(certificates: Vec<CertificatePem>) -> IdpMetadataFacts {
        IdpMetadataFacts {
            entity_id: HttpsUrl::new("https://idp.acme.com").unwrap(),
            sso_url: HttpsUrl::new("https://idp.acme.com/sso").unwrap(),
            slo_url: Setting::Unset,
            signing_certificates: certificates,
        }
    }

    /// Okta's metadata lists its current and its next certificate. Both
    /// are taken, the first as current.
    #[test]
    fn two_listed_certificates_are_current_and_next() {
        let imported =
            ImportedIdpMetadata::new(facts(vec![certificate("MIIC"), certificate("MIID")]))
                .unwrap();

        assert_eq!(imported.certificates().current(), &certificate("MIIC"));
        assert_eq!(
            imported.certificates().upcoming(),
            Some(&certificate("MIID"))
        );
    }

    /// Metadata listing no signing certificate, or three, is refused: there
    /// would be nothing, or too much, to check answers against.
    #[test]
    fn metadata_without_one_or_two_certificates_is_refused() {
        let none = ImportedIdpMetadata::new(facts(Vec::new()));
        let three = ImportedIdpMetadata::new(facts(vec![
            certificate("MIIC"),
            certificate("MIID"),
            certificate("MIIE"),
        ]));

        assert!(matches!(none, Err(DomainError::Validation(_))));
        assert!(matches!(three, Err(DomainError::Validation(_))));
    }

    /// A new connection made from metadata names people by the persistent
    /// format, as every sign-in connection must.
    #[test]
    fn a_configuration_from_metadata_uses_the_persistent_format() {
        let config = ImportedIdpMetadata::new(facts(vec![certificate("MIIC")]))
            .unwrap()
            .into_config()
            .unwrap();

        assert!(config.name_id_format.names_one_person_for_good());
        assert_eq!(config.sso_url.as_str(), "https://idp.acme.com/sso");
    }
}
