//! Connector bodies: the agents inside a tenant's private network that the
//! gateway reaches upstreams with no public address through, the code an
//! agent enrolls with, and the certificates it holds its link with.

use ianua_app::use_cases::routing::connectors::{
    ChangeScopeRequest, CreateRequest, CreatedConnector, EnrollRequest, IssuedConnector,
    RenewRequest,
};
use ianua_domain::domains::routing::connector::scope::ConnectorScope;
use ianua_domain::domains::routing::connector::{
    ConnectorEnrollment, ConnectorStatus, LastSeen, PrivateConnector,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificateRequestPem, ConnectorId, Label};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;

/// Request body for adding a connector.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateConnectorBody {
    /// Name, unique within the tenant.
    pub name: String,
    /// What it may be asked to dial: `{"networks": ["10.20.0.0/16"],
    /// "domains": ["*.corp.internal"]}`, at least one entry and at most 64.
    #[schema(value_type = Object)]
    pub scope: ConnectorScope,
}

impl TryFrom<CreateConnectorBody> for CreateRequest {
    type Error = ApiError;

    fn try_from(body: CreateConnectorBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            scope: body.scope,
        })
    }
}

/// A connector just added, with the code its agent enrolls with. The code
/// is shown this once; only its hash is kept.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreateConnectorResponse {
    /// The new connector.
    pub id: Uuid,
    /// The one-time enrollment code for the agent.
    pub enrollment_code: String,
    /// When the code stops being good.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

impl From<CreatedConnector> for CreateConnectorResponse {
    fn from(created: CreatedConnector) -> Self {
        Self {
            id: *created.connector_id.as_uuid(),
            enrollment_code: created.enrollment_code.expose().to_owned(),
            expires_at: created.expires_at,
        }
    }
}

/// Request body for changing what a connector may dial.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeConnectorScopeBody {
    /// The networks and domains it may be asked to dial from now on.
    #[schema(value_type = Object)]
    pub scope: ConnectorScope,
}

impl ChangeConnectorScopeBody {
    /// The change this body asks of `connector`.
    #[must_use]
    pub(crate) fn into_request(self, connector: ConnectorId) -> ChangeScopeRequest {
        ChangeScopeRequest {
            connector_id: connector,
            scope: self.scope,
        }
    }
}

/// Where a connector's enrollment stands.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum ConnectorEnrollmentView {
    /// Waiting for its agent to present the one-time code.
    Awaiting {
        /// When the code stops being good.
        expires_at: OffsetDateTime,
    },
    /// Enrolled: the link is held with a certificate for this key.
    Enrolled {
        /// The pin of the agent's key: the SHA-256 of its public key,
        /// `sha256:<hex>`.
        key: String,
        /// When the certificate signed last stops being good. The agent
        /// renews it in its last eight hours.
        certificate_expires_at: OffsetDateTime,
        /// When it enrolled.
        enrolled_at: OffsetDateTime,
    },
}

impl From<&ConnectorEnrollment> for ConnectorEnrollmentView {
    fn from(enrollment: &ConnectorEnrollment) -> Self {
        match enrollment {
            ConnectorEnrollment::Awaiting { expires_at, .. } => Self::Awaiting {
                expires_at: *expires_at,
            },
            ConnectorEnrollment::Enrolled {
                key,
                certificate_expires_at,
                enrolled_at,
            } => Self::Enrolled {
                key: key.to_string(),
                certificate_expires_at: *certificate_expires_at,
                enrolled_at: *enrolled_at,
            },
        }
    }
}

/// A private network gateway's allowed destinations, enrollment and current state.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ConnectorResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// The label administrators use to distinguish this private network gateway.
    pub name: String,
    /// The networks and domains it may be asked to dial.
    #[schema(value_type = Object)]
    pub scope: ConnectorScope,
    /// `Active` or `Revoked`.
    #[schema(schema_with = crate::dto::schemas::connector_status)]
    pub status: ConnectorStatus,
    /// Whether its agent has enrolled.
    pub enrollment: ConnectorEnrollmentView,
    /// When the gateway last saw a link of it open, or `null` when none
    /// has opened yet.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_seen_at: Option<OffsetDateTime>,
    /// When it was added.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<PrivateConnector<ResolvedTenant>> for ConnectorResponse {
    fn from(c: PrivateConnector<ResolvedTenant>) -> Self {
        Self {
            id: *c.id().as_uuid(),
            name: c.name().as_str().to_owned(),
            scope: c.scope().clone(),
            status: c.status(),
            enrollment: ConnectorEnrollmentView::from(c.enrollment()),
            last_seen_at: last_seen_at(c.last_seen()),
            created_at: c.created_at(),
            updated_at: c.updated_at(),
        }
    }
}

/// When a link was last seen, as the API writes it.
fn last_seen_at(last_seen: LastSeen) -> Option<OffsetDateTime> {
    match last_seen {
        LastSeen::Never => None,
        LastSeen::At(at) => Some(at),
    }
}

/// Request body an agent enrolls with.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct EnrollConnectorBody {
    /// The one-time code the administrator was shown.
    pub code: String,
    /// A PEM certificate signing request (PKCS #10) for the key the agent
    /// holds its link with, carrying no extensions.
    pub csr: String,
}

impl TryFrom<EnrollConnectorBody> for EnrollRequest {
    type Error = ApiError;

    fn try_from(body: EnrollConnectorBody) -> Result<Self, Self::Error> {
        Ok(Self {
            code: Secret::new(body.code),
            request: CertificateRequestPem::new(body.csr).map_err(ApiError::validation)?,
        })
    }
}

/// Request body an agent renews its certificate with.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RenewConnectorBody {
    /// A new PEM certificate signing request for the key the agent
    /// enrolled with.
    pub csr: String,
}

impl RenewConnectorBody {
    /// The renewal this body asks of `connector`.
    ///
    /// # Errors
    ///
    /// [`ApiError`] when the request is not PEM text of one.
    pub(crate) fn into_request(self, connector: ConnectorId) -> Result<RenewRequest, ApiError> {
        Ok(RenewRequest {
            connector_id: connector,
            request: CertificateRequestPem::new(self.csr).map_err(ApiError::validation)?,
        })
    }
}

/// The certificate an agent holds its link to the gateway with.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ConnectorCertificateResponse {
    /// The connector.
    pub id: Uuid,
    /// The connector's certificate, PEM, good for client authentication on
    /// the gateway's connector listener.
    pub certificate: String,
    /// The connector authority's certificate, PEM: the gateway's listener
    /// is checked against it.
    pub authority: String,
    /// When the certificate stops being good.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// From when the agent asks for the next one.
    #[serde(with = "time::serde::rfc3339")]
    pub renew_after: OffsetDateTime,
}

impl From<IssuedConnector> for ConnectorCertificateResponse {
    fn from(issued: IssuedConnector) -> Self {
        Self {
            id: *issued.connector_id.as_uuid(),
            certificate: issued.certificate_pem,
            authority: issued.authority_pem,
            expires_at: issued.expires_at,
            renew_after: issued.renew_after,
        }
    }
}
