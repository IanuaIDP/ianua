//! Connection bodies: a tenant's connections to SAML and OIDC identity
//! providers, and what each lets its provider do.

use std::collections::HashMap;

use ianua_app::listing::{PageRequest, SortOrder};
use ianua_app::ports::federation::ConnectionSortField;
use ianua_app::use_cases::federation::connections::{
    AccountProvisioning, ConnectionFilter, CreateRequest, ListRequest, ProviderConfig,
    UpdateRequest,
};
use ianua_domain::domains::federation::connection::{
    AssertionDecryption, AssuranceTrust, AuthnRequestSigning, ConnectionConfig, EmailTrust,
    FederatedIdpConnection, FederationProtocol, JitProvisioning, ProfileField,
};
use ianua_domain::domains::federation::connection_status::ConnectionStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{ConnectionId, DomainName, Label, RoleId, Setting};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::dto::federation::groups::GroupMappingBody;
use crate::dto::federation::provider_config::ConnectionConfigBody;
use crate::error::ApiError;

/// Request body for creating a connection.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateConnectionBody {
    /// The provider's name, as people see it, such as `Okta`.
    pub provider_name: String,
    /// How the connection reaches its provider: `{"Saml": {...}}`,
    /// `{"SamlMetadata": {...}}` or `{"Oidc": {...}}`.
    #[schema(value_type = Object)]
    pub config: ConnectionConfigBody,
    /// Email domains the provider may sign in, each a verified domain of the
    /// tenant. Omitted or empty, the connection signs in nobody.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

impl TryFrom<CreateConnectionBody> for CreateRequest {
    type Error = ApiError;

    fn try_from(body: CreateConnectionBody) -> Result<Self, ApiError> {
        Ok(Self {
            provider_name: Label::new("provider_name", body.provider_name)
                .map_err(ApiError::validation)?,
            config: ProviderConfig::try_from(body.config)?,
            allowed_domains: domain_names(&body.allowed_domains)?,
        })
    }
}

/// Whether a connection makes an account on someone's first sign-in.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ProvisioningBody {
    /// Whether a first sign-in makes an account.
    pub enabled: bool,
    /// The role a new account starts with, on top of the tenant's defaults;
    /// `null` for none.
    #[serde(default)]
    #[schema(value_type = Option<String>, format = Uuid)]
    pub default_role_id: Option<RoleId>,
}

impl From<ProvisioningBody> for AccountProvisioning {
    fn from(body: ProvisioningBody) -> Self {
        if !body.enabled {
            return Self::Disabled;
        }
        Self::Enabled(Setting::from_stored(body.default_role_id))
    }
}

/// Whether a provider's word on an address is enough to sign in to the
/// account with that address.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) enum EmailTrustBody {
    /// Only an address the provider says it verified counts.
    Unverified,
    /// The provider assigns these addresses and its users cannot change
    /// them.
    Authoritative,
}

impl From<EmailTrustBody> for EmailTrust {
    fn from(body: EmailTrustBody) -> Self {
        match body {
            EmailTrustBody::Unverified => Self::Unverified,
            EmailTrustBody::Authoritative => Self::Authoritative,
        }
    }
}

impl From<EmailTrust> for EmailTrustBody {
    fn from(trust: EmailTrust) -> Self {
        match trust {
            EmailTrust::Unverified => Self::Unverified,
            EmailTrust::Authoritative => Self::Authoritative,
        }
    }
}

/// Whether a provider's report of how someone signed in there counts.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) enum AssuranceTrustBody {
    /// A sign-in through it counts as one factor, whatever it reports.
    Untrusted,
    /// Its report of a multi-factor or hardware-key sign-in is believed.
    Trusted,
}

impl From<AssuranceTrustBody> for AssuranceTrust {
    fn from(body: AssuranceTrustBody) -> Self {
        match body {
            AssuranceTrustBody::Untrusted => Self::Untrusted,
            AssuranceTrustBody::Trusted => Self::Trusted,
        }
    }
}

impl From<AssuranceTrust> for AssuranceTrustBody {
    fn from(trust: AssuranceTrust) -> Self {
        match trust {
            AssuranceTrust::Untrusted => Self::Untrusted,
            AssuranceTrust::Trusted => Self::Trusted,
        }
    }
}

/// Request body for changing a connection. A field left out keeps its
/// value.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateConnectionBody {
    /// A new provider name.
    pub provider_name: Option<String>,
    /// A new configuration, at the same provider.
    #[schema(value_type = Option<Object>)]
    pub config: Option<ConnectionConfigBody>,
    /// New email domains the provider may sign in.
    pub allowed_domains: Option<Vec<String>>,
    /// Whether a first sign-in makes an account, and with which role.
    pub provisioning: Option<ProvisioningBody>,
    /// The allowed domain that sends people straight to this connection, or
    /// `null` for none.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    #[schema(value_type = Option<String>)]
    pub domain_hint: Option<Option<String>>,
    /// Which provider claim fills which profile field: `display_name`,
    /// `locale` or `timezone`. Replaces the whole mapping.
    pub attribute_mapping: Option<HashMap<String, String>>,
    /// Whether the provider's addresses are taken on its word.
    pub email_trust: Option<EmailTrustBody>,
    /// Whether the provider's report of factors is taken on its word.
    pub assurance_trust: Option<AssuranceTrustBody>,
}

impl UpdateConnectionBody {
    /// The change to `connection_id` this body asks for.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when the name, a domain, a claim or a
    ///   profile field is not a valid one.
    pub(crate) fn change_of(self, connection_id: ConnectionId) -> Result<UpdateRequest, ApiError> {
        Ok(UpdateRequest {
            connection_id,
            provider_name: self
                .provider_name
                .map(|name| Label::new("provider_name", name))
                .transpose()
                .map_err(ApiError::validation)?,
            config: self.config.map(ProviderConfig::try_from).transpose()?,
            provisioning: self.provisioning.map(AccountProvisioning::from),
            domain_hint: self.domain_hint.map(domain_hint).transpose()?,
            allowed_domains: self
                .allowed_domains
                .as_deref()
                .map(domain_names)
                .transpose()?,
            attribute_mapping: self.attribute_mapping.map(attribute_mapping).transpose()?,
            email_trust: self.email_trust.map(EmailTrust::from),
            assurance_trust: self.assurance_trust.map(AssuranceTrust::from),
        })
    }
}

/// Validates every configured hostname, refusing the list if any is invalid.
fn domain_names(domains: &[String]) -> Result<Vec<DomainName>, ApiError> {
    domains
        .iter()
        .map(|raw| DomainName::new(raw.as_str()).map_err(ApiError::validation))
        .collect()
}

/// `hint` as the domain hint, unset when there is none.
fn domain_hint(hint: Option<String>) -> Result<Setting<DomainName>, ApiError> {
    let domain = hint
        .map(|raw| DomainName::new(raw.as_str()).map_err(ApiError::validation))
        .transpose()?;
    Ok(Setting::from_stored(domain))
}

/// `mapping` as claims filling profile fields.
fn attribute_mapping(
    mapping: HashMap<String, String>,
) -> Result<HashMap<Label, ProfileField>, ApiError> {
    mapping
        .into_iter()
        .map(|(claim, field)| {
            let claim = Label::new("claim", claim).map_err(ApiError::validation)?;
            let field = ProfileField::parse(&field).ok_or_else(|| {
                ApiError::validation(message!(
                    "api-is-not-a-profile-field-a",
                    format!("{field} is not a profile field a claim may fill")
                ))
            })?;
            Ok((claim, field))
        })
        .collect()
}

/// Query parameters for filtering a connection listing.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ConnectionFilterParams {
    /// Filter by status (`Active` or `Disabled`). Omit to return all.
    #[param(value_type = Option<String>)]
    pub status: Option<ConnectionStatus>,
}

impl ConnectionFilterParams {
    /// The listing asked for: these connections, in `sort` order, the page
    /// `pagination` names.
    #[must_use]
    pub(crate) fn listing(
        self,
        sort: SortOrder<ConnectionSortField>,
        pagination: PageRequest,
    ) -> ListRequest {
        ListRequest {
            filter: ConnectionFilter {
                status: self.status,
            },
            sort,
            page: pagination,
        }
    }
}

/// A SAML connection's own settings, without any key.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SamlSettingsResponse {
    /// Whether the sign-in requests sent to the provider are signed.
    pub signs_requests: bool,
    /// Whether the provider must encrypt its assertions to this platform.
    pub requires_encrypted_assertions: bool,
    /// The certificate the provider encrypts to, when it must.
    pub encryption_certificate: Option<String>,
    /// Whether a next certificate is waiting to be rolled over to.
    pub has_next_certificate: bool,
    /// Whether the provider takes logout requests.
    pub single_logout: bool,
}

/// A connection, without its configuration's secrets.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ConnectionResponse {
    /// The connection's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: ConnectionId,
    /// The provider's name.
    pub provider_name: String,
    /// `Saml` or `Oidc`.
    #[schema(schema_with = crate::dto::schemas::federation_protocol)]
    pub protocol: FederationProtocol,
    /// `Active` or `Disabled`.
    #[schema(schema_with = crate::dto::schemas::connection_status)]
    pub status: ConnectionStatus,
    /// Whether a first sign-in makes an account.
    pub jit_provisioning: bool,
    /// Email domains the provider may sign in.
    pub allowed_domains: Vec<String>,
    /// When it was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The role a new account starts with, if any.
    #[schema(value_type = Option<String>, format = Uuid)]
    pub jit_default_role_id: Option<RoleId>,
    /// The allowed domain that sends people straight to this connection.
    pub domain_hint: Option<String>,
    /// Which provider claim fills which profile field.
    pub attribute_mapping: HashMap<String, String>,
    /// Whether the provider's addresses are taken on its word.
    pub email_trust: EmailTrustBody,
    /// Whether the provider's report of factors is taken on its word.
    pub assurance_trust: AssuranceTrustBody,
    /// The provider's groups mapped to roles and groups here, if mapping
    /// is on.
    pub group_mapping: Option<GroupMappingBody>,
    /// A SAML connection's own settings; `null` for OIDC.
    pub saml: Option<SamlSettingsResponse>,
}

impl From<FederatedIdpConnection<ResolvedTenant>> for ConnectionResponse {
    fn from(connection: FederatedIdpConnection<ResolvedTenant>) -> Self {
        Self {
            id: *connection.id(),
            provider_name: connection.provider_name().as_str().to_owned(),
            protocol: connection.protocol(),
            status: connection.status(),
            jit_provisioning: connection.jit_provisioning() == JitProvisioning::Enabled,
            allowed_domains: connection
                .allowed_domains()
                .iter()
                .map(|domain| domain.as_str().to_owned())
                .collect(),
            created_at: connection.created_at(),
            jit_default_role_id: connection.jit_default_role_id().copied(),
            domain_hint: connection
                .domain_hint()
                .map(|domain| domain.as_str().to_owned()),
            attribute_mapping: connection
                .attribute_mapping()
                .iter()
                .map(|(claim, field)| (claim.as_str().to_owned(), field.as_str().to_owned()))
                .collect(),
            email_trust: connection.email_trust().into(),
            assurance_trust: connection.assurance_trust().into(),
            group_mapping: GroupMappingBody::of(connection.group_mapping()),
            saml: saml_settings(connection.config()),
        }
    }
}

/// The SAML settings `config` holds, or none for OIDC.
fn saml_settings(config: &ConnectionConfig) -> Option<SamlSettingsResponse> {
    let ConnectionConfig::Saml(saml) = config else {
        return None;
    };
    let encryption_certificate = match &saml.assertion_decryption {
        AssertionDecryption::NotExpected => None,
        AssertionDecryption::Required(key) => Some(key.certificate().as_str().to_owned()),
    };
    Some(SamlSettingsResponse {
        signs_requests: saml.request_signing == AuthnRequestSigning::Signed,
        requires_encrypted_assertions: encryption_certificate.is_some(),
        encryption_certificate,
        has_next_certificate: saml.certificates.upcoming().is_some(),
        single_logout: saml.slo_url.value().is_some(),
    })
}

/// A connection just created.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreateConnectionResponse {
    /// The new connection's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: ConnectionId,
}
