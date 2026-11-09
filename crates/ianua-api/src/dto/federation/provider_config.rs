//! How a connection reaches its provider, as an administrator gives it:
//! SAML by hand or by the provider's metadata, or OIDC.

use ianua_app::ports::federation::MetadataSource;
use ianua_app::use_cases::federation::connections::{
    OidcProviderConfig, ProviderConfig, SamlProviderConfig,
};
use ianua_domain::domains::federation::connection::{
    AuthnRequestSigning, IdpCertificates, ScopeToken,
};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    CertificatePem, HttpsUrl, Label, PublicHttpsUrl, SamlNameIdFormat, Setting,
};
use serde::Deserialize;

use crate::error::ApiError;

/// How a connection reaches its provider, as `{"Saml": {...}}`,
/// `{"SamlMetadata": {"url": ...}}`, `{"SamlMetadata": {"document": ...}}`
/// or `{"Oidc": {...}}`.
#[derive(Deserialize)]
pub(crate) enum ConnectionConfigBody {
    /// SAML 2.0, each setting given by hand.
    Saml(Box<SamlConfigBody>),
    /// SAML 2.0, its endpoints and certificates read from the provider's
    /// metadata.
    SamlMetadata(MetadataSourceBody),
    /// OpenID Connect.
    Oidc(OidcConfigBody),
}

impl TryFrom<ConnectionConfigBody> for ProviderConfig {
    type Error = ApiError;

    fn try_from(body: ConnectionConfigBody) -> Result<Self, ApiError> {
        Ok(match body {
            ConnectionConfigBody::Saml(saml) => Self::Saml(Box::new((*saml).try_into()?)),
            ConnectionConfigBody::SamlMetadata(source) => Self::SamlMetadata(source.into()),
            ConnectionConfigBody::Oidc(oidc) => Self::Oidc(oidc.into()),
        })
    }
}

/// A SAML provider as an administrator gives it by hand.
#[derive(Deserialize)]
pub(crate) struct SamlConfigBody {
    /// The provider's entity id.
    pub entity_id: HttpsUrl,
    /// Where sign-in requests go.
    pub sso_url: HttpsUrl,
    /// Where logout requests go; single logout with it is off without one.
    #[serde(default)]
    pub slo_url: Option<HttpsUrl>,
    /// The certificate its answers are signed with, PEM.
    pub certificate: CertificatePem,
    /// The certificate it will sign with next, while it rolls its key
    /// over, PEM.
    #[serde(default)]
    pub next_certificate: Option<CertificatePem>,
    /// The `NameID` format it names people by; a sign-in connection takes
    /// only the persistent one.
    pub name_id_format: SamlNameIdFormat,
    /// Whether the sign-in requests sent to it are signed.
    #[serde(default)]
    pub sign_requests: bool,
}

impl TryFrom<SamlConfigBody> for SamlProviderConfig {
    type Error = ApiError;

    fn try_from(body: SamlConfigBody) -> Result<Self, ApiError> {
        let certificates = match body.next_certificate {
            Some(next) => IdpCertificates::rolling_over(body.certificate, next)
                .map_err(ApiError::validation)?,
            None => IdpCertificates::single(body.certificate),
        };
        Ok(Self {
            entity_id: body.entity_id,
            sso_url: body.sso_url,
            slo_url: Setting::from_stored(body.slo_url),
            certificates,
            name_id_format: body.name_id_format,
            request_signing: if body.sign_requests {
                AuthnRequestSigning::Signed
            } else {
                AuthnRequestSigning::Unsigned
            },
        })
    }
}

/// Where a SAML provider's metadata comes from.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MetadataSourceBody {
    /// Fetched from the provider's public metadata address.
    Url(PublicHttpsUrl),
    /// The document itself, as pasted.
    Document(String),
}

impl From<MetadataSourceBody> for MetadataSource {
    fn from(body: MetadataSourceBody) -> Self {
        match body {
            MetadataSourceBody::Url(url) => Self::Url(url),
            MetadataSourceBody::Document(document) => Self::Document(document),
        }
    }
}

/// An OIDC provider, as an administrator gives it.
#[derive(Deserialize)]
pub(crate) struct OidcConfigBody {
    /// The issuer, whose discovery document names its endpoints.
    pub issuer: HttpsUrl,
    /// The client id this platform is registered under at the provider.
    pub client_id: Label,
    /// The client secret, as the provider issued it. It is sealed before
    /// it is stored; the field keeps the name the dashboard sends.
    pub encrypted_client_secret: String,
    /// The scopes to ask for.
    #[serde(default)]
    pub scopes: Vec<ScopeToken>,
}

impl From<OidcConfigBody> for OidcProviderConfig {
    fn from(oidc: OidcConfigBody) -> Self {
        Self {
            issuer: oidc.issuer,
            client_id: oidc.client_id,
            client_secret: Secret::new(oidc.encrypted_client_secret),
            scopes: oidc.scopes,
        }
    }
}
