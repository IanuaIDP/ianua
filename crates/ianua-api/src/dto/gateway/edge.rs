//! The edge of a gateway document beside HTTP, as it travels: stream routes,
//! where services may send traffic out, and the consumers let in.
//!
//! A consumer's API key is never written down, only the prefix that tells
//! it apart, so a document can be committed without leaking a credential.

use ianua_app::use_cases::gateway::document::{
    ConsumerCredentialDeclaration, ConsumerDeclaration, EgressPolicyDeclaration,
    StreamAccessDeclaration, StreamRouteDeclaration,
};
use ianua_domain::domains::consumers::consumer::ConsumerStatus;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::routing::egress::{EgressDestination, ServiceIdentity};
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::domains::routing::stream::{
    ListenPort, StreamBackend, StreamPolicy, StreamProtocol, StreamTimeouts,
};
use ianua_domain::types::{
    CertificateFingerprint, Expiry, FederatedSubject, HttpsUrl, Issuer, KeyPrefix, Label,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::dto::consumers::{QuotaBody, expiry, quota};
use crate::dto::routing::egress::EgressDestinationBody;
use crate::dto::routing::stream_routes::{StreamBackendBody, StreamSniBody, StreamTimeoutsBody};
use crate::error::ApiError;

/// A port below HTTP, as declared.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct StreamRouteConfigBody {
    /// Unique within the tenant.
    pub name: String,
    /// `tcp`, `tls` or `udp`.
    #[schema(schema_with = crate::dto::schemas::stream_protocol)]
    pub protocol: StreamProtocol,
    /// The port the gateway listens on.
    pub listen_port: u16,
    /// Which handshakes it answers. Defaults to every one.
    #[serde(default)]
    pub sni: StreamSniBody,
    /// How the connection is let in.
    #[schema(schema_with = crate::dto::schemas::stream_policy)]
    pub policy: StreamPolicy,
    /// Who may open a connection. Defaults to anyone holding a certificate
    /// the tenant trusts.
    #[serde(default)]
    pub access: StreamAccessConfigBody,
    /// Where connections go.
    pub backends: Vec<StreamBackendBody>,
    /// How long it waits. Defaults to the platform's.
    #[serde(default)]
    pub timeouts: StreamTimeoutsBody,
    /// Whether it serves.
    #[serde(default = "active")]
    #[schema(schema_with = crate::dto::schemas::route_status)]
    pub status: RouteStatus,
}

/// Who may open a stream route's connections, as declared.
#[derive(Serialize, Deserialize, Default, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum StreamAccessConfigBody {
    /// Anyone holding a certificate the tenant trusts.
    #[default]
    AnyHolder,
    /// The people a route policy lets in.
    People {
        /// The policy they are held to.
        #[schema(value_type = Object)]
        policy: RoutePolicy,
    },
    /// These consumers only, by name.
    Consumers {
        /// The consumers' names, as the document gives them.
        consumers: Vec<String>,
    },
}

/// Where a service may send traffic, as declared.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct EgressPolicyConfigBody {
    /// A name people recognise the service by.
    pub name: String,
    /// The service: its SPIFFE ID, or `sha256:<fingerprint>` of its client
    /// certificate. The document keys the policy by it.
    pub service: String,
    /// Where it may go.
    pub destinations: Vec<EgressDestinationBody>,
    /// The most sensitive data an agent may have touched for a call it
    /// caused to be let out. Defaults to `Internal`.
    #[serde(default = "internal")]
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub max_data_class: DataClassLevel,
}

/// A non-human caller, as declared.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct ConsumerConfigBody {
    /// Unique within the tenant.
    pub name: String,
    /// The credential it signs in with, without any secret.
    pub credential: ConsumerCredentialConfigBody,
    /// When its credential stops working; left out, never.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub credential_expires_at: Option<OffsetDateTime>,
    /// Its own allowance; left out, unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<QuotaBody>,
    /// The most sensitive data it may receive. Defaults to `Internal`.
    #[serde(default = "internal")]
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub clearance: DataClassLevel,
    /// `Active` or `Disabled`. Defaults to `Active`.
    #[serde(default = "enabled")]
    #[schema(schema_with = crate::dto::schemas::consumer_status)]
    pub status: ConsumerStatus,
}

/// A consumer's credential in a document: what tells it apart, never what
/// proves it.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "credential_kind", rename_all = "snake_case")]
pub(crate) enum ConsumerCredentialConfigBody {
    /// An API key, by the prefix that tells it apart. The key itself is
    /// made and shown once, when the consumer is created by hand.
    ApiKey {
        /// The key's first characters, such as `sk_live_abc`.
        key_prefix: String,
    },
    /// A client certificate, by its SHA-256 fingerprint.
    ClientCert {
        /// Hex-encoded SHA-256 fingerprint.
        fingerprint: String,
    },
    /// A JWT the consumer signs itself.
    JwtBearer {
        /// The expected `iss` claim.
        issuer: String,
        /// The expected `sub` claim.
        subject: String,
        /// Where the consumer publishes its keys.
        jwks_uri: String,
    },
}

/// A declared resource serves unless it says otherwise.
fn active() -> RouteStatus {
    RouteStatus::Active
}

/// A declared consumer may send traffic unless it says otherwise.
fn enabled() -> ConsumerStatus {
    ConsumerStatus::Active
}

/// Declared data is internal unless it says otherwise.
fn internal() -> DataClassLevel {
    DataClassLevel::Internal
}

/// Reads a name, which is how the document addresses everything in it.
fn label(value: String) -> Result<Label, ApiError> {
    Label::new("name", value).map_err(ApiError::validation)
}

impl TryFrom<StreamRouteConfigBody> for StreamRouteDeclaration {
    type Error = ApiError;

    fn try_from(body: StreamRouteConfigBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: label(body.name)?,
            protocol: body.protocol,
            listen_port: ListenPort::new(body.listen_port).map_err(ApiError::validation)?,
            sni: body.sni.try_into()?,
            policy: body.policy,
            access: body.access.try_into()?,
            backends: body
                .backends
                .into_iter()
                .map(StreamBackend::try_from)
                .collect::<Result<_, _>>()?,
            timeouts: StreamTimeouts::try_from(body.timeouts)?,
            status: body.status,
        })
    }
}

impl TryFrom<StreamAccessConfigBody> for StreamAccessDeclaration {
    type Error = ApiError;

    fn try_from(body: StreamAccessConfigBody) -> Result<Self, Self::Error> {
        match body {
            StreamAccessConfigBody::AnyHolder => Ok(Self::AnyHolder),
            StreamAccessConfigBody::People { policy } => Ok(Self::People(policy)),
            StreamAccessConfigBody::Consumers { consumers } => consumers
                .into_iter()
                .map(label)
                .collect::<Result<_, _>>()
                .map(Self::Consumers),
        }
    }
}

impl TryFrom<EgressPolicyConfigBody> for EgressPolicyDeclaration {
    type Error = ApiError;

    fn try_from(body: EgressPolicyConfigBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: label(body.name)?,
            service: ServiceIdentity::new(body.service).map_err(ApiError::validation)?,
            destinations: body
                .destinations
                .into_iter()
                .map(EgressDestination::try_from)
                .collect::<Result<_, _>>()?,
            max_data_class: body.max_data_class,
        })
    }
}

impl TryFrom<ConsumerConfigBody> for ConsumerDeclaration {
    type Error = ApiError;

    fn try_from(body: ConsumerConfigBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: label(body.name)?,
            credential: body.credential.try_into()?,
            credential_expiry: expiry(body.credential_expires_at),
            quota: quota(body.quota)?,
            clearance: body.clearance,
            status: body.status,
        })
    }
}

impl TryFrom<ConsumerCredentialConfigBody> for ConsumerCredentialDeclaration {
    type Error = ApiError;

    fn try_from(body: ConsumerCredentialConfigBody) -> Result<Self, Self::Error> {
        match body {
            ConsumerCredentialConfigBody::ApiKey { key_prefix } => Ok(Self::ApiKey {
                prefix: KeyPrefix::new(key_prefix).map_err(ApiError::validation)?,
            }),
            ConsumerCredentialConfigBody::ClientCert { fingerprint } => Ok(Self::ClientCert {
                fingerprint: CertificateFingerprint::parse(&fingerprint)
                    .map_err(ApiError::validation)?,
            }),
            ConsumerCredentialConfigBody::JwtBearer {
                issuer,
                subject,
                jwks_uri,
            } => Ok(Self::JwtBearer {
                issuer: Issuer::new(issuer).map_err(ApiError::validation)?,
                subject: FederatedSubject::new(subject).map_err(ApiError::validation)?,
                jwks_uri: HttpsUrl::new(jwks_uri).map_err(ApiError::validation)?,
            }),
        }
    }
}

impl From<StreamRouteDeclaration> for StreamRouteConfigBody {
    fn from(declaration: StreamRouteDeclaration) -> Self {
        Self {
            name: declaration.name.as_str().to_owned(),
            protocol: declaration.protocol,
            listen_port: declaration.listen_port.get(),
            sni: StreamSniBody::from(&declaration.sni),
            policy: declaration.policy,
            access: declaration.access.into(),
            backends: declaration
                .backends
                .iter()
                .map(StreamBackendBody::from)
                .collect(),
            timeouts: declaration.timeouts.into(),
            status: declaration.status,
        }
    }
}

impl From<StreamAccessDeclaration> for StreamAccessConfigBody {
    fn from(declaration: StreamAccessDeclaration) -> Self {
        match declaration {
            StreamAccessDeclaration::AnyHolder => Self::AnyHolder,
            StreamAccessDeclaration::People(policy) => Self::People { policy },
            StreamAccessDeclaration::Consumers(names) => Self::Consumers {
                consumers: names.iter().map(|name| name.as_str().to_owned()).collect(),
            },
        }
    }
}

impl From<EgressPolicyDeclaration> for EgressPolicyConfigBody {
    fn from(declaration: EgressPolicyDeclaration) -> Self {
        Self {
            name: declaration.name.as_str().to_owned(),
            service: declaration.service.as_str().to_owned(),
            destinations: declaration
                .destinations
                .iter()
                .map(EgressDestinationBody::from)
                .collect(),
            max_data_class: declaration.max_data_class,
        }
    }
}

impl From<ConsumerDeclaration> for ConsumerConfigBody {
    fn from(declaration: ConsumerDeclaration) -> Self {
        Self {
            name: declaration.name.as_str().to_owned(),
            credential: declaration.credential.into(),
            credential_expires_at: match declaration.credential_expiry {
                Expiry::Never => None,
                Expiry::At(at) => Some(at),
            },
            quota: QuotaBody::of(declaration.quota),
            clearance: declaration.clearance,
            status: declaration.status,
        }
    }
}

impl From<ConsumerCredentialDeclaration> for ConsumerCredentialConfigBody {
    fn from(declaration: ConsumerCredentialDeclaration) -> Self {
        match declaration {
            ConsumerCredentialDeclaration::ApiKey { prefix } => Self::ApiKey {
                key_prefix: prefix.as_str().to_owned(),
            },
            ConsumerCredentialDeclaration::ClientCert { fingerprint } => Self::ClientCert {
                fingerprint: String::from(fingerprint),
            },
            ConsumerCredentialDeclaration::JwtBearer {
                issuer,
                subject,
                jwks_uri,
            } => Self::JwtBearer {
                issuer: issuer.as_str().to_owned(),
                subject: subject.as_str().to_owned(),
                jwks_uri: jwks_uri.as_str().to_owned(),
            },
        }
    }
}
