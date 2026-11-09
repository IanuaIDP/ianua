//! SAML app bodies: the outside services a tenant's people sign in to, with
//! this platform as their identity provider.

use ianua_app::use_cases::federation::service_providers::{CreateRequest, UpdateRequest};
use ianua_domain::domains::federation::connection_status::ConnectionStatus;
use ianua_domain::domains::federation::saml::name_id::NameIdFormat;
use ianua_domain::domains::federation::service_provider::{
    AccountAttribute, AcsUrls, AssertionEncryption, AttributeNameFormat, AttributeStatement,
    AttributeStatements, RequestSigningRule, SamlAttributeName, SamlServiceProvider,
    SamlServiceProviderChange, SamlServiceProviderSettings, SignedParts,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{
    CertificatePem, HttpsUrl, Label, SamlEntityId, SamlServiceProviderId, Setting,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::ApiError;

/// How an app is told who a person is.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NameIdFormatBody {
    /// The same id for the person at this app for good, a different one at
    /// every other app.
    #[default]
    Persistent,
    /// The person's verified address.
    EmailAddress,
    /// A fresh random id at every sign-in.
    Transient,
}

impl From<NameIdFormatBody> for NameIdFormat {
    fn from(body: NameIdFormatBody) -> Self {
        match body {
            NameIdFormatBody::Persistent => Self::Persistent,
            NameIdFormatBody::EmailAddress => Self::EmailAddress,
            NameIdFormatBody::Transient => Self::Transient,
        }
    }
}

impl From<NameIdFormat> for NameIdFormatBody {
    fn from(format: NameIdFormat) -> Self {
        match format {
            NameIdFormat::Persistent => Self::Persistent,
            NameIdFormat::EmailAddress => Self::EmailAddress,
            NameIdFormat::Transient => Self::Transient,
        }
    }
}

/// One of a person's attributes an app can be sent.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AccountAttributeBody {
    /// Their address.
    Email,
    /// The name shown for them.
    DisplayName,
    /// The language they chose.
    Locale,
    /// The timezone they chose.
    Timezone,
    /// Their account's id in the tenant.
    AccountId,
    /// The names of the roles they hold.
    Roles,
    /// The names of the groups they belong to.
    Groups,
}

impl From<AccountAttributeBody> for AccountAttribute {
    fn from(body: AccountAttributeBody) -> Self {
        match body {
            AccountAttributeBody::Email => Self::Email,
            AccountAttributeBody::DisplayName => Self::DisplayName,
            AccountAttributeBody::Locale => Self::Locale,
            AccountAttributeBody::Timezone => Self::Timezone,
            AccountAttributeBody::AccountId => Self::AccountId,
            AccountAttributeBody::Roles => Self::Roles,
            AccountAttributeBody::Groups => Self::Groups,
        }
    }
}

impl From<AccountAttribute> for AccountAttributeBody {
    fn from(attribute: AccountAttribute) -> Self {
        match attribute {
            AccountAttribute::Email => Self::Email,
            AccountAttribute::DisplayName => Self::DisplayName,
            AccountAttribute::Locale => Self::Locale,
            AccountAttribute::Timezone => Self::Timezone,
            AccountAttribute::AccountId => Self::AccountId,
            AccountAttribute::Roles => Self::Roles,
            AccountAttribute::Groups => Self::Groups,
        }
    }
}

/// How an attribute's name is to be read, SAML's `NameFormat`.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AttributeNameFormatBody {
    /// The app reads the name as it likes.
    Unspecified,
    /// A plain name, such as `email`.
    #[default]
    Basic,
    /// An attribute name expressed as a URI rather than a plain label.
    Uri,
}

impl From<AttributeNameFormatBody> for AttributeNameFormat {
    fn from(body: AttributeNameFormatBody) -> Self {
        match body {
            AttributeNameFormatBody::Unspecified => Self::Unspecified,
            AttributeNameFormatBody::Basic => Self::Basic,
            AttributeNameFormatBody::Uri => Self::Uri,
        }
    }
}

impl From<AttributeNameFormat> for AttributeNameFormatBody {
    fn from(format: AttributeNameFormat) -> Self {
        match format {
            AttributeNameFormat::Unspecified => Self::Unspecified,
            AttributeNameFormat::Basic => Self::Basic,
            AttributeNameFormat::Uri => Self::Uri,
        }
    }
}

/// What is signed in an answer to an app.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SignedPartsBody {
    /// Only the assertion.
    #[default]
    Assertion,
    /// The assertion and the response around it.
    AssertionAndResponse,
}

impl From<SignedPartsBody> for SignedParts {
    fn from(body: SignedPartsBody) -> Self {
        match body {
            SignedPartsBody::Assertion => Self::Assertion,
            SignedPartsBody::AssertionAndResponse => Self::AssertionAndResponse,
        }
    }
}

impl From<SignedParts> for SignedPartsBody {
    fn from(parts: SignedParts) -> Self {
        match parts {
            SignedParts::Assertion => Self::Assertion,
            SignedParts::AssertionAndResponse => Self::AssertionAndResponse,
        }
    }
}

/// One attribute an app is sent, and the name it reads it by.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct AttributeStatementBody {
    /// Which of the person's attributes is sent.
    pub source: AccountAttributeBody,
    /// The name the app reads it by, such as `email`.
    pub name: String,
    /// How that name is to be read; `basic` when left out.
    #[serde(default)]
    pub name_format: AttributeNameFormatBody,
}

impl From<&AttributeStatement> for AttributeStatementBody {
    fn from(statement: &AttributeStatement) -> Self {
        Self {
            source: statement.source.into(),
            name: statement.name.as_str().to_owned(),
            name_format: statement.name_format.into(),
        }
    }
}

/// Request body for adding a SAML app.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateSamlAppBody {
    /// The app's name, as people see it.
    pub name: String,
    /// The app's SAML entity id.
    pub entity_id: String,
    /// Where its assertions may be posted; the first is used when a request
    /// names none.
    pub acs_urls: Vec<String>,
    /// Where logout requests and answers to it go; without one, single
    /// logout with it is off.
    #[serde(default)]
    pub logout_url: Option<String>,
    /// How people are named to it; `persistent` when left out.
    #[serde(default)]
    pub name_id_format: NameIdFormatBody,
    /// What it is sent, under which names; the address as `email` and the
    /// display name as `displayName` when left out.
    #[serde(default)]
    pub attributes: Option<Vec<AttributeStatementBody>>,
    /// What is signed in an answer to it; `assertion` when left out.
    #[serde(default)]
    pub signing: SignedPartsBody,
    /// The certificate its assertions are encrypted to, PEM; readable
    /// assertions when left out.
    #[serde(default)]
    pub encryption_certificate: Option<String>,
    /// The certificate its sign-in requests must be signed with, PEM; any
    /// request naming it is answered when left out.
    #[serde(default)]
    pub request_signing_certificate: Option<String>,
}

impl TryFrom<CreateSamlAppBody> for CreateRequest {
    type Error = ApiError;

    fn try_from(body: CreateSamlAppBody) -> Result<Self, ApiError> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            entity_id: SamlEntityId::new(body.entity_id).map_err(ApiError::validation)?,
            settings: SamlServiceProviderSettings {
                acs_urls: acs_urls(body.acs_urls)?,
                logout_url: logout_url(body.logout_url)?,
                name_id_format: body.name_id_format.into(),
                attributes: statements(body.attributes)?,
                signing: body.signing.into(),
                encryption: encryption(body.encryption_certificate)?,
                request_signing: request_signing(body.request_signing_certificate)?,
            },
        })
    }
}

/// Request body for changing a SAML app. A field left out keeps its value;
/// `null` clears a field that may be cleared.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateSamlAppBody {
    /// A new name.
    pub name: Option<String>,
    /// New assertion addresses, the first the default, replacing the old.
    pub acs_urls: Option<Vec<String>>,
    /// A new logout address, or `null` to switch single logout off.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    #[schema(value_type = Option<String>)]
    pub logout_url: Option<Option<String>>,
    /// A new way of naming people.
    pub name_id_format: Option<NameIdFormatBody>,
    /// New attribute statements, replacing the old.
    pub attributes: Option<Vec<AttributeStatementBody>>,
    /// A new choice of what is signed.
    pub signing: Option<SignedPartsBody>,
    /// A new certificate to encrypt assertions to, or `null` for readable
    /// assertions.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    #[schema(value_type = Option<String>)]
    pub encryption_certificate: Option<Option<String>>,
    /// A new certificate its requests must be signed with, or `null` to
    /// answer unsigned requests.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    #[schema(value_type = Option<String>)]
    pub request_signing_certificate: Option<Option<String>>,
}

impl UpdateSamlAppBody {
    /// The changes to the app `id` this body asks for.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when a value breaks its rules.
    pub(crate) fn changes_to(self, id: SamlServiceProviderId) -> Result<UpdateRequest, ApiError> {
        use SamlServiceProviderChange as Change;
        let changes = [
            self.name.map(|name| {
                Label::new("name", name)
                    .map_err(ApiError::validation)
                    .map(Change::Rename)
            }),
            self.acs_urls
                .map(|urls| acs_urls(urls).map(Change::AcsUrls)),
            self.logout_url
                .map(|url| logout_url(url).map(Change::LogoutUrl)),
            self.name_id_format
                .map(|format| Ok(Change::NameIdFormat(format.into()))),
            self.attributes
                .map(|statements_body| statements(Some(statements_body)).map(Change::Attributes)),
            self.signing.map(|parts| Ok(Change::Signing(parts.into()))),
            self.encryption_certificate
                .map(|certificate| encryption(certificate).map(Change::Encryption)),
            self.request_signing_certificate
                .map(|certificate| request_signing(certificate).map(Change::RequestSigning)),
        ];
        Ok(UpdateRequest {
            id,
            changes: changes.into_iter().flatten().collect::<Result<_, _>>()?,
        })
    }
}

/// `raw` as an address.
fn https_url(raw: String) -> Result<HttpsUrl, ApiError> {
    HttpsUrl::new(raw).map_err(ApiError::validation)
}

/// `urls` as assertion addresses, the first the default.
fn acs_urls(urls: Vec<String>) -> Result<AcsUrls, ApiError> {
    let mut urls = urls.into_iter().map(https_url);
    let Some(default) = urls.next() else {
        return Err(ApiError::validation(message!(
            "api-name-at-least-one-assertion-address",
            "name at least one assertion address"
        )));
    };
    AcsUrls::new(default?, urls.collect::<Result<_, _>>()?).map_err(ApiError::validation)
}

/// `url` as a logout address, unset when there is none.
fn logout_url(url: Option<String>) -> Result<Setting<HttpsUrl>, ApiError> {
    Ok(Setting::from_stored(url.map(https_url).transpose()?))
}

/// `raw` as a certificate.
fn certificate(raw: String) -> Result<CertificatePem, ApiError> {
    CertificatePem::new(raw).map_err(ApiError::validation)
}

/// Assertions encrypted to `pem`, or readable when there is none.
fn encryption(pem: Option<String>) -> Result<AssertionEncryption, ApiError> {
    Ok(pem.map(certificate).transpose()?.map_or(
        AssertionEncryption::Plain,
        AssertionEncryption::EncryptedFor,
    ))
}

/// Requests signed with `pem`, or any request when there is none.
fn request_signing(pem: Option<String>) -> Result<RequestSigningRule, ApiError> {
    Ok(pem.map(certificate).transpose()?.map_or(
        RequestSigningRule::NotRequired,
        RequestSigningRule::Required,
    ))
}

/// `bodies` as attribute statements, the standard ones when there are none.
fn statements(
    bodies: Option<Vec<AttributeStatementBody>>,
) -> Result<AttributeStatements, ApiError> {
    let Some(bodies) = bodies else {
        return AttributeStatements::standard().map_err(ApiError::validation);
    };
    let statements = bodies
        .into_iter()
        .map(|body| {
            Ok(AttributeStatement {
                source: body.source.into(),
                name: SamlAttributeName::new(body.name).map_err(ApiError::validation)?,
                name_format: body.name_format.into(),
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    AttributeStatements::new(statements).map_err(ApiError::validation)
}

/// A SAML app as the dashboard shows it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SamlAppResponse {
    /// The app's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: SamlServiceProviderId,
    /// The label administrators use to identify this SAML application.
    pub name: String,
    /// Its SAML entity id.
    pub entity_id: String,
    /// `Active` or `Disabled`.
    #[schema(schema_with = crate::dto::schemas::connection_status)]
    pub status: ConnectionStatus,
    /// Where its assertions may be posted, the default first.
    pub acs_urls: Vec<String>,
    /// Where logout requests and answers to it go, if anywhere.
    pub logout_url: Option<String>,
    /// How people are named to it.
    pub name_id_format: NameIdFormatBody,
    /// What it is sent, under which names.
    pub attributes: Vec<AttributeStatementBody>,
    /// What is signed in an answer to it.
    pub signing: SignedPartsBody,
    /// The certificate its assertions are encrypted to, if they are.
    pub encryption_certificate: Option<String>,
    /// The certificate its requests must be signed with, if they must.
    pub request_signing_certificate: Option<String>,
    /// When it was added.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<SamlServiceProvider<ResolvedTenant>> for SamlAppResponse {
    fn from(app: SamlServiceProvider<ResolvedTenant>) -> Self {
        let settings = app.settings();
        Self {
            id: *app.id(),
            name: app.name().as_str().to_owned(),
            entity_id: app.entity_id().as_str().to_owned(),
            status: app.status(),
            acs_urls: std::iter::once(settings.acs_urls.default_url())
                .chain(settings.acs_urls.others())
                .map(|url| url.as_str().to_owned())
                .collect(),
            logout_url: settings
                .logout_url
                .value()
                .map(|url| url.as_str().to_owned()),
            name_id_format: settings.name_id_format.into(),
            attributes: settings
                .attributes
                .statements()
                .iter()
                .map(AttributeStatementBody::from)
                .collect(),
            signing: settings.signing.into(),
            encryption_certificate: encryption_certificate(&settings.encryption),
            request_signing_certificate: request_signing_certificate(&settings.request_signing),
            created_at: app.created_at(),
            updated_at: app.updated_at(),
        }
    }
}

/// The certificate `encryption` seals to, if it seals.
fn encryption_certificate(encryption: &AssertionEncryption) -> Option<String> {
    match encryption {
        AssertionEncryption::Plain => None,
        AssertionEncryption::EncryptedFor(pem) => Some(pem.as_str().to_owned()),
    }
}

/// The certificate `rule` asks requests to be signed with, if it asks.
fn request_signing_certificate(rule: &RequestSigningRule) -> Option<String> {
    match rule {
        RequestSigningRule::NotRequired => None,
        RequestSigningRule::Required(pem) => Some(pem.as_str().to_owned()),
    }
}

/// A SAML app just added.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreateSamlAppResponse {
    /// The new app's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: SamlServiceProviderId,
}
