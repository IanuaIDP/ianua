//! Turning the configuration an administrator gives into the one a
//! connection keeps.
//!
//! An OIDC client secret arrives in plain text. Stored that way, anyone who
//! could read the connections table could authenticate to the customer's
//! identity provider as this platform, so it is encrypted before the
//! connection holds it. A SAML provider given by its metadata has the
//! document fetched or read first. Creating a connection and changing its
//! config both go through here, so neither can store a secret as typed.

use ianua_domain::domains::federation::connection::{
    AssertionDecryption, ConnectionConfig, ImportedIdpMetadata, OidcConfig,
};

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{SealedFor, SecretEncryptor};
use crate::ports::federation::{MetadataSource, SamlMetadataReader};
use crate::use_cases::federation::connections::{OidcProviderConfig, ProviderConfig};

/// Where the parts of a configuration are sealed and read.
#[derive(Clone, Copy)]
pub(in crate::use_cases::federation::connections) struct ConfigSources<'a> {
    /// Seals an OIDC client secret.
    pub(in crate::use_cases::federation::connections) encryptor: &'a dyn SecretEncryptor,
    /// Fetches and reads a SAML provider's metadata.
    pub(in crate::use_cases::federation::connections) metadata: &'a dyn SamlMetadataReader,
}

/// A configuration ready for the connection: settings to replace its own,
/// or a provider's metadata to take its endpoints and certificates from.
pub(in crate::use_cases::federation::connections) enum StoredConfig {
    /// The whole configuration.
    Config(ConnectionConfig),
    /// What the provider's metadata says.
    Metadata(Box<ImportedIdpMetadata>),
}

impl ConfigSources<'_> {
    /// `config` as the connection keeps it: its secret sealed for `place`,
    /// its metadata read, a SAML key for sealed assertions kept as `kept`
    /// says.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the metadata cannot be fetched, is not an
    ///   identity provider's, or lists no certificate, more than two or one
    ///   twice.
    /// - `AppError::Internal` if the secret cannot be encrypted.
    pub(in crate::use_cases::federation::connections) async fn stored(
        self,
        config: ProviderConfig,
        kept: AssertionDecryption,
        place: &SealedFor,
    ) -> Result<StoredConfig, AppError> {
        match config {
            ProviderConfig::Saml(saml) => Ok(StoredConfig::Config(ConnectionConfig::Saml(
                Box::new(saml.keeping(kept)),
            ))),
            ProviderConfig::SamlMetadata(source) => self
                .imported(&source)
                .await
                .map(|metadata| StoredConfig::Metadata(Box::new(metadata))),
            ProviderConfig::Oidc(oidc) => self
                .sealed_oidc(oidc, place)
                .await
                .map(|oidc| StoredConfig::Config(ConnectionConfig::Oidc(oidc))),
        }
    }

    /// What the metadata at `source` says, read and checked. Metadata read
    /// from an address keeps it, so the connection follows that address.
    async fn imported(&self, source: &MetadataSource) -> Result<ImportedIdpMetadata, AppError> {
        match source {
            MetadataSource::Url(url) => {
                let document = self
                    .metadata
                    .fetch(url)
                    .await
                    .map_err(AppError::from_domain)?;
                Ok(self.read(&document)?.published_at(url.clone()))
            }
            MetadataSource::Document(document) => self.read(document),
        }
    }

    /// What the metadata `document` says, read and checked.
    fn read(&self, document: &str) -> Result<ImportedIdpMetadata, AppError> {
        let facts = self
            .metadata
            .read(document)
            .map_err(AppError::from_domain)?;
        ImportedIdpMetadata::new(facts).map_err(AppError::from_domain)
    }

    /// `oidc` with its client secret encrypted for storage at `place`.
    async fn sealed_oidc(
        &self,
        oidc: OidcProviderConfig,
        place: &SealedFor,
    ) -> Result<OidcConfig, AppError> {
        let encrypted_client_secret = self
            .encryptor
            .encrypt(oidc.client_secret.expose().as_bytes(), place)
            .await
            .or_internal()?;
        Ok(OidcConfig {
            issuer: oidc.issuer,
            client_id: oidc.client_id,
            encrypted_client_secret,
            scopes: oidc.scopes,
        })
    }
}

impl StoredConfig {
    /// The configuration a new connection starts with: the one given, or
    /// the one the metadata makes.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` if the persistent `NameID` format is refused,
    ///   which it never is.
    pub(in crate::use_cases::federation::connections) fn into_new(
        self,
    ) -> Result<ConnectionConfig, AppError> {
        match self {
            Self::Config(config) => Ok(config),
            Self::Metadata(metadata) => metadata
                .into_config()
                .map(|saml| ConnectionConfig::Saml(Box::new(saml)))
                .or_internal(),
        }
    }
}

/// The key `config` takes sealed assertions with, or none for an OIDC
/// connection.
pub(in crate::use_cases::federation::connections) fn decryption_of(
    config: &ConnectionConfig,
) -> AssertionDecryption {
    match config {
        ConnectionConfig::Saml(saml) => saml.assertion_decryption.clone(),
        ConnectionConfig::Oidc(_) => AssertionDecryption::NotExpected,
    }
}
