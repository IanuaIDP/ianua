//! Identity provider bodies: the organization's own SAML or OIDC provider,
//! which signs its members in to the dashboard.

use ianua_app::services::authentication::fresh_proof::ReenteredProof;
use ianua_app::use_cases::federation::connections::ProviderConfig;
use ianua_app::use_cases::organization::identity_providers::{
    AddOrgRequest, ChangeOrgRequest, OrgProviderEdit, SwitchOrgRequest,
};
use ianua_domain::domains::federation::connection::FederationProtocol;
use ianua_domain::domains::federation::connection_status::ConnectionStatus;
use ianua_domain::domains::organization::access::identity_provider::OrgIdentityProvider;
use ianua_domain::types::{ConnectionId, Label};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::dto::federation::connections::{AssuranceTrustBody, EmailTrustBody};
use crate::dto::federation::provider_config::ConnectionConfigBody;
use crate::dto::organization::proof::ReenteredProofBody;
use crate::error::ApiError;

/// The organization's identity provider, without its configuration.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgIdentityProviderResponse {
    /// The provider's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: ConnectionId,
    /// The name members see on the sign-in page.
    pub name: String,
    /// `Saml` or `Oidc`.
    #[schema(schema_with = crate::dto::schemas::federation_protocol)]
    pub protocol: FederationProtocol,
    /// `Active` or `Disabled`.
    #[schema(schema_with = crate::dto::schemas::connection_status)]
    pub status: ConnectionStatus,
    /// Whether the addresses it reports are taken as proven.
    pub email_trust: EmailTrustBody,
    /// Whether its report of a multi-factor sign-in is believed.
    pub assurance_trust: AssuranceTrustBody,
    /// When it was added.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<OrgIdentityProvider> for OrgIdentityProviderResponse {
    fn from(provider: OrgIdentityProvider) -> Self {
        Self {
            id: *provider.id(),
            name: provider.name().as_str().to_owned(),
            protocol: provider.protocol(),
            status: provider.status(),
            email_trust: provider.email_trust().into(),
            assurance_trust: provider.assurance_trust().into(),
            created_at: provider.created_at(),
        }
    }
}

/// Request body adding the organization's identity provider. Holds an OIDC
/// client secret, so it has no `Debug`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AddOrgProviderBody {
    /// The name members see on the sign-in page.
    pub name: String,
    /// How it is reached: `{"Saml": {...}}` or `{"Oidc": {...}}`, as a
    /// tenant's connection is configured.
    #[schema(value_type = Object)]
    pub config: ConnectionConfigBody,
}

impl TryFrom<AddOrgProviderBody> for AddOrgRequest {
    type Error = ApiError;

    fn try_from(body: AddOrgProviderBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: provider_name(body.name)?,
            config: ProviderConfig::try_from(body.config)?,
        })
    }
}

/// Request body changing the organization's identity provider. A field
/// left out keeps its value. Holds a password and possibly an OIDC client
/// secret, so it has no `Debug`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeOrgProviderBody {
    /// A new name.
    #[serde(default)]
    pub name: Option<String>,
    /// New settings for reaching it.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub config: Option<ConnectionConfigBody>,
    /// Whether its addresses are taken on its word.
    #[serde(default)]
    pub email_trust: Option<EmailTrustBody>,
    /// Whether its report of factors is taken on its word.
    #[serde(default)]
    pub assurance_trust: Option<AssuranceTrustBody>,
    /// The caller's password typed again, with a code from their second
    /// factor when they have one.
    pub proof: ReenteredProofBody,
}

impl TryFrom<ChangeOrgProviderBody> for ChangeOrgRequest {
    type Error = ApiError;

    fn try_from(body: ChangeOrgProviderBody) -> Result<Self, Self::Error> {
        let rename = body.name.map(provider_name).transpose()?;
        let reconfigure = body.config.map(ProviderConfig::try_from).transpose()?;
        let edits = rename
            .map(OrgProviderEdit::Rename)
            .into_iter()
            .chain(reconfigure.map(OrgProviderEdit::Reconfigure))
            .chain(
                body.email_trust
                    .map(|trust| OrgProviderEdit::TrustEmail(trust.into())),
            )
            .chain(
                body.assurance_trust
                    .map(|trust| OrgProviderEdit::TrustAssurance(trust.into())),
            )
            .collect();
        Ok(Self {
            edits,
            proof: ReenteredProof::from(body.proof),
        })
    }
}

/// Request body switching the organization's identity provider on or off.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SwitchOrgProviderBody {
    /// `Active` or `Disabled`.
    #[schema(schema_with = crate::dto::schemas::connection_status)]
    pub status: ConnectionStatus,
    /// The caller's password typed again, with a code from their second
    /// factor when they have one.
    pub proof: ReenteredProofBody,
}

impl From<SwitchOrgProviderBody> for SwitchOrgRequest {
    fn from(body: SwitchOrgProviderBody) -> Self {
        Self {
            to: body.status,
            proof: ReenteredProof::from(body.proof),
        }
    }
}

/// `raw` as the name members see.
fn provider_name(raw: String) -> Result<Label, ApiError> {
    Label::new("name", raw).map_err(ApiError::validation)
}
