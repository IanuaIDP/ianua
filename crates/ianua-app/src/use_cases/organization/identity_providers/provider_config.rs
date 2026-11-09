//! How the organization's provider is reached, as an owner gives it and as
//! it is kept.
//!
//! An OIDC client secret arrives in plain text and is sealed before the
//! provider keeps it, so nobody who reads the store can sign in to the
//! company directory as this platform. It is opened again only to talk to
//! the provider. An OIDC issuer is checked to publish its configuration
//! before it is kept, so a typo shows when it is saved, not at a member's
//! sign-in.

use ianua_domain::domains::federation::connection::{
    AssertionDecryption, ConnectionConfig, OidcConfig,
};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConnectionId, OrganizationId};

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use crate::ports::federation::OidcValidator;
use crate::use_cases::federation::connections::{OidcProviderConfig, ProviderConfig};

/// Where `organization`'s provider `provider` keeps its OIDC client
/// secret.
pub(in crate::use_cases::organization) fn provider_secret_place(
    organization: &OrganizationId,
    provider: &ConnectionId,
) -> SealedFor {
    SealedFor::new(
        SealOwner::Organization(*organization),
        SealedField::OrgProviderClientSecret,
        provider,
    )
}

/// What a configuration is checked and sealed with before it is kept.
#[derive(Clone, Copy)]
pub(in crate::use_cases::organization) struct ProviderSealing<'a> {
    /// Seals the OIDC client secret.
    pub(in crate::use_cases::organization) encryptor: &'a dyn SecretEncryptor,
    /// Checks an OIDC issuer publishes its configuration.
    pub(in crate::use_cases::organization) oidc_validator: &'a dyn OidcValidator,
}

impl ProviderSealing<'_> {
    /// `config` as the provider keeps it: an OIDC issuer checked and its
    /// client secret sealed for `place`, a SAML configuration as it is.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the OIDC issuer publishes no usable
    ///   configuration, or a SAML provider is given by its metadata.
    /// - `AppError::Internal` when the secret cannot be sealed.
    pub(in crate::use_cases::organization) async fn stored(
        &self,
        config: ProviderConfig,
        place: &SealedFor,
    ) -> Result<ConnectionConfig, AppError> {
        match config {
            ProviderConfig::Saml(saml) => Ok(ConnectionConfig::Saml(Box::new(
                saml.keeping(AssertionDecryption::NotExpected),
            ))),
            ProviderConfig::SamlMetadata(_) => {
                Err(AppError::from_domain(DomainError::invalid(message!(
                    "organization-an-organization-s-provider-is-given",
                    "an organization's provider is given by its settings, not its metadata"
                ))))
            }
            ProviderConfig::Oidc(oidc) => self
                .sealed_oidc(oidc, place)
                .await
                .map(ConnectionConfig::Oidc),
        }
    }

    /// `oidc` with its issuer checked and its client secret sealed for
    /// `place`.
    async fn sealed_oidc(
        &self,
        oidc: OidcProviderConfig,
        place: &SealedFor,
    ) -> Result<OidcConfig, AppError> {
        self.oidc_validator
            .confirm_issuer(&oidc.issuer)
            .await
            .map_err(AppError::from_domain)?;
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
