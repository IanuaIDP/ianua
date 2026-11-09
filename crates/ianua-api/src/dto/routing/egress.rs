//! Egress policy bodies: where a service that agents can reach may itself
//! go.

use ianua_app::use_cases::routing::egress::{CreatePolicyRequest, UpdatePolicyRequest};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::routing::egress::{EgressDestination, EgressPolicy, ServiceIdentity};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{DomainName, EgressPolicyId, Label, PrincipalRef};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;

/// One host and port.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct EgressDestinationBody {
    /// An exact host name; wildcards are refused.
    pub host: String,
    /// The destination socket number paired with the exact host name.
    pub port: u16,
}

impl TryFrom<EgressDestinationBody> for EgressDestination {
    type Error = ApiError;

    fn try_from(body: EgressDestinationBody) -> Result<Self, Self::Error> {
        let host = DomainName::new(body.host).map_err(ApiError::validation)?;
        Self::new(host, body.port).map_err(ApiError::validation)
    }
}

impl From<&EgressDestination> for EgressDestinationBody {
    fn from(destination: &EgressDestination) -> Self {
        Self {
            host: destination.host().as_str().to_owned(),
            port: destination.port(),
        }
    }
}

/// Reads destinations, refusing the first one that does not parse.
fn destinations(bodies: Vec<EgressDestinationBody>) -> Result<Vec<EgressDestination>, ApiError> {
    bodies
        .into_iter()
        .map(EgressDestination::try_from)
        .collect()
}

/// Request body for creating an egress policy.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateEgressPolicyBody {
    /// A name people recognise the service by.
    pub name: String,
    /// The service: its SPIFFE ID, or `sha256:<fingerprint>` of its client
    /// certificate.
    pub service: String,
    /// Where it may go. At least one, at most 32.
    pub destinations: Vec<EgressDestinationBody>,
    /// The most sensitive data an agent may have touched for a call it caused
    /// to be let out. Omit for `Internal`.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub max_data_class: Option<DataClassLevel>,
}

impl TryFrom<CreateEgressPolicyBody> for CreatePolicyRequest {
    type Error = ApiError;

    fn try_from(body: CreateEgressPolicyBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            service: ServiceIdentity::new(body.service).map_err(ApiError::validation)?,
            destinations: destinations(body.destinations)?,
            max_data_class: body.max_data_class.unwrap_or(DataClassLevel::Internal),
        })
    }
}

/// Request body for changing an egress policy. An omitted field is left as
/// it is.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateEgressPolicyBody {
    /// A new name, unique within the tenant.
    #[serde(default)]
    pub name: Option<String>,
    /// Replaces the destination list.
    #[serde(default)]
    pub destinations: Option<Vec<EgressDestinationBody>>,
    /// Replaces the data ceiling.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub max_data_class: Option<DataClassLevel>,
}

impl UpdateEgressPolicyBody {
    /// The change this body asks of `policy`.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::validation`] for an invalid name or a destination
    /// that does not parse.
    pub(crate) fn into_request(
        self,
        policy: EgressPolicyId,
    ) -> Result<UpdatePolicyRequest, ApiError> {
        Ok(UpdatePolicyRequest {
            policy_id: policy,
            name: self
                .name
                .map(|name| Label::new("name", name))
                .transpose()
                .map_err(ApiError::validation)?,
            destinations: self.destinations.map(destinations).transpose()?,
            max_data_class: self.max_data_class,
        })
    }
}

/// The destinations and data classification ceiling permitted for an upstream service.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct EgressPolicyResponse {
    /// The policy.
    pub id: Uuid,
    /// The label administrators use to distinguish this outbound access rule.
    pub name: String,
    /// The upstream name whose outbound requests this rule governs.
    pub service: String,
    /// Where the service may go.
    pub destinations: Vec<EgressDestinationBody>,
    /// The data ceiling.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub max_data_class: DataClassLevel,
    /// Who made it.
    pub created_by: CreatorResponse,
    /// When.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Last change.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<&EgressPolicy<ResolvedTenant>> for EgressPolicyResponse {
    fn from(p: &EgressPolicy<ResolvedTenant>) -> Self {
        Self {
            id: *p.id().as_uuid(),
            name: p.name().as_str().to_owned(),
            service: p.service().as_str().to_owned(),
            destinations: p
                .destinations()
                .iter()
                .map(EgressDestinationBody::from)
                .collect(),
            max_data_class: p.max_data_class(),
            created_by: CreatorResponse::from(p.created_by()),
            created_at: p.created_at(),
            updated_at: p.updated_at(),
        }
    }
}

/// Who made something: a kind and an id.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreatorResponse {
    /// Kind of principal.
    pub kind: CreatorKind,
    /// Identifier of the principal.
    pub id: Uuid,
}

/// The kind of principal that made something.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CreatorKind {
    /// A tenant user.
    User,
    /// An organization member, on the management plane.
    OrgUser,
    /// An automation identity acting within its delegated authority.
    Agent,
    /// A consumer: a non-human caller outside the platform.
    Consumer,
}

impl From<&PrincipalRef> for CreatorResponse {
    fn from(principal: &PrincipalRef) -> Self {
        let kind = match principal {
            PrincipalRef::User(_) => CreatorKind::User,
            PrincipalRef::OrgUser(_) => CreatorKind::OrgUser,
            PrincipalRef::Agent(_) => CreatorKind::Agent,
            PrincipalRef::Consumer(_) => CreatorKind::Consumer,
        };
        Self {
            kind,
            id: principal.id(),
        }
    }
}
