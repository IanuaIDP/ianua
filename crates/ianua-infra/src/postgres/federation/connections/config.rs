//! How a connection's settings are kept: two JSON columns, the one of its
//! protocol filled and the other empty.
//!
//! The OIDC settings are kept as the domain writes them. The SAML settings
//! hold certificates and keys built through their own checks, which a
//! derived reader would step around, so they are kept in a shape of this
//! store's own and rebuilt through those checks. A tenant's connections and
//! an organization's own provider share these settings, so both keep them
//! in this one shape, each under its own columns.

use ianua_domain::domains::federation::connection::{
    AssertionDecryption, AuthnRequestSigning, ConnectionConfig, IdpCertificates, OidcConfig,
    SamlConfig, SpEncryptionKey,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    CertificatePem, HttpsUrl, PublicHttpsUrl, SamlNameIdFormat, SealedSecret, Setting,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::Stored;

/// The two settings columns of one kind of row.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ConfigColumns {
    /// What the row is, so a refusal names it.
    pub(crate) row: Stored,
    /// The column of the SAML settings.
    pub(crate) saml: Kept,
    /// The column of the OIDC settings.
    pub(crate) oidc: Kept,
}

impl ConfigColumns {
    /// The two columns `config` is written to: the one of its protocol
    /// filled, the other empty.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the settings cannot be
    /// written out as JSON.
    pub(crate) fn of(
        self,
        config: &ConnectionConfig,
    ) -> Result<(Option<Value>, Option<Value>), DomainError> {
        match config {
            ConnectionConfig::Saml(saml) => {
                Ok((Some(self.saml.seal(&StoredSaml::of(saml))?), None))
            }
            ConnectionConfig::Oidc(oidc) => Ok((None, Some(self.oidc.seal(oidc)?))),
        }
    }

    /// The settings the two columns hold.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when both columns or neither
    /// hold settings, or the settings no longer pass their checks.
    pub(crate) fn read(
        self,
        saml: Option<Value>,
        oidc: Option<Value>,
    ) -> Result<ConnectionConfig, DomainError> {
        match (saml, oidc) {
            (Some(saml), None) => {
                let stored: StoredSaml = self.saml.open(saml)?;
                stored
                    .into_config(self.row)
                    .map(|saml| ConnectionConfig::Saml(Box::new(saml)))
            }
            (None, Some(oidc)) => self
                .oidc
                .open::<OidcConfig>(oidc)
                .map(ConnectionConfig::Oidc),
            (Some(_), Some(_)) | (None, None) => Err(DomainError::corrupt_row(
                self.row.0,
                "settings for both protocols, or for neither",
            )),
        }
    }
}

/// SAML settings as they are kept, every value as plain text.
#[derive(Serialize, Deserialize)]
pub(crate) struct StoredSaml {
    entity_id: String,
    sso_url: String,
    slo_url: Option<String>,
    certificate: String,
    next_certificate: Option<String>,
    name_id_format: String,
    request_signing: StoredSigning,
    assertion_encryption: Option<StoredEncryptionKey>,
    metadata_url: Option<String>,
}

/// Whether sign-in requests sent to the provider are signed.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredSigning {
    Unsigned,
    Signed,
}

/// This platform's key for assertions encrypted to it, its private key
/// sealed.
#[derive(Serialize, Deserialize)]
struct StoredEncryptionKey {
    certificate: String,
    sealed_private_key: String,
}

impl StoredSaml {
    /// `saml` as it is kept.
    pub(crate) fn of(saml: &SamlConfig) -> Self {
        let assertion_encryption = match &saml.assertion_decryption {
            AssertionDecryption::NotExpected => None,
            AssertionDecryption::Required(key) => Some(StoredEncryptionKey {
                certificate: key.certificate().as_str().to_owned(),
                sealed_private_key: key.sealed_private_key().as_str().to_owned(),
            }),
        };
        let request_signing = match saml.request_signing {
            AuthnRequestSigning::Unsigned => StoredSigning::Unsigned,
            AuthnRequestSigning::Signed => StoredSigning::Signed,
        };
        Self {
            entity_id: saml.entity_id.as_str().to_owned(),
            sso_url: saml.sso_url.as_str().to_owned(),
            slo_url: saml.slo_url.value().map(|url| url.as_str().to_owned()),
            certificate: saml.certificates.current().as_str().to_owned(),
            next_certificate: saml
                .certificates
                .upcoming()
                .map(|next| next.as_str().to_owned()),
            name_id_format: saml.name_id_format.as_str().to_owned(),
            request_signing,
            assertion_encryption,
            metadata_url: saml.metadata_url.value().map(|url| url.as_str().to_owned()),
        }
    }

    /// The settings it keeps, each value read through its own checks, a
    /// refusal naming `row`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules.
    pub(crate) fn into_config(self, row: Stored) -> Result<SamlConfig, DomainError> {
        let request_signing = match self.request_signing {
            StoredSigning::Unsigned => AuthnRequestSigning::Unsigned,
            StoredSigning::Signed => AuthnRequestSigning::Signed,
        };
        Ok(SamlConfig {
            entity_id: row.value("entity id", HttpsUrl::new(self.entity_id))?,
            sso_url: row.value("sign-in url", HttpsUrl::new(self.sso_url))?,
            slo_url: Setting::from_stored(
                self.slo_url
                    .map(|url| row.value("single logout url", HttpsUrl::new(url)))
                    .transpose()?,
            ),
            certificates: certificates_from(row, self.certificate, self.next_certificate)?,
            name_id_format: row
                .value("name id format", SamlNameIdFormat::new(self.name_id_format))?,
            request_signing,
            assertion_decryption: decryption_from(row, self.assertion_encryption)?,
            metadata_url: Setting::from_stored(
                self.metadata_url
                    .map(|url| row.value("metadata url", PublicHttpsUrl::new(url)))
                    .transpose()?,
            ),
        })
    }
}

fn certificates_from(
    row: Stored,
    current: String,
    next: Option<String>,
) -> Result<IdpCertificates, DomainError> {
    let current = row.value("certificate", CertificatePem::new(current))?;
    let Some(next) = next else {
        return Ok(IdpCertificates::single(current));
    };
    let next = row.value("next certificate", CertificatePem::new(next))?;
    IdpCertificates::rolling_over(current, next).map_err(DomainError::infra)
}

fn decryption_from(
    row: Stored,
    key: Option<StoredEncryptionKey>,
) -> Result<AssertionDecryption, DomainError> {
    let Some(key) = key else {
        return Ok(AssertionDecryption::NotExpected);
    };
    Ok(AssertionDecryption::Required(SpEncryptionKey::new(
        row.value(
            "encryption certificate",
            CertificatePem::new(key.certificate),
        )?,
        row.value("encryption key", SealedSecret::new(key.sealed_private_key))?,
    )))
}
