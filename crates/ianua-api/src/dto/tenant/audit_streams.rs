//! Audit stream bodies: where a tenant's audit records go and which, with
//! the credentials as typed, and the stream as read back without them.

use ianua_app::use_cases::tenant::audit_streams::destination::{StreamTarget, TypedAuthorization};
use ianua_app::use_cases::tenant::audit_streams::{CreateRequest, ReconfigureRequest};
use ianua_domain::domains::audit::streaming::{
    DatadogSite, HttpAuthorization, SYSLOG_TLS_PORT, SplunkIndex, SplunkIndexName,
    StreamDestination, StreamFilter, StreamHeaderName, SyslogPort, SyslogTarget,
};
use ianua_domain::domains::tenant::audit_streams::{AuditStream, StreamState};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    AuditStreamId, EventType, HeaderName, HostName, Label, PublicHost, PublicHttpsUrl,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::dto::tenant::proof::FreshProofBody;
use crate::error::ApiError;

/// A stream to add or the whole of one to change, with a fresh proof of
/// the person. Holds credentials, so it has no `Debug`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AuditStreamBody {
    /// What it is called, such as "Splunk production".
    pub name: String,
    /// Where records go, with its credential as typed.
    pub destination: StreamTargetBody,
    /// The event types sent, such as `authentication.login_failed`; every
    /// record when omitted or `null`.
    #[serde(default)]
    pub events: Option<Vec<String>>,
    /// The person making the change, proved again.
    pub proof: FreshProofBody,
}

/// Where a stream sends records, by `kind`. Holds credentials, so it has
/// no `Debug`.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum StreamTargetBody {
    /// A Splunk HTTP Event Collector.
    Splunk {
        /// Where the collector listens, a public HTTPS address.
        endpoint: String,
        /// The collector token.
        token: String,
        /// The index records go to; the token's own when omitted.
        #[serde(default)]
        index: Option<String>,
    },
    /// A Datadog account's log intake.
    Datadog {
        /// The site the account lives on: `us1`, `us3`, `us5`, `eu1`,
        /// `ap1` or `us1_fed`.
        site: String,
        /// The credential that authorizes log intake for the Datadog account.
        api_key: String,
    },
    /// A syslog collector over TLS.
    Syslog {
        /// The collector's public host name.
        host: String,
        /// Its port; 6514 when omitted.
        #[serde(default)]
        port: Option<u16>,
    },
    /// Any public HTTPS endpoint.
    Http {
        /// Where records are sent.
        endpoint: String,
        /// A header each request carries to show where it came from.
        #[serde(default)]
        header: Option<StreamHeaderBody>,
    },
}

/// A header an HTTPS endpoint asks each request to carry. Holds its value,
/// so it has no `Debug`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct StreamHeaderBody {
    /// The header, such as `authorization`.
    pub name: String,
    /// The text sent with this header, which may contain a delivery credential.
    pub value: String,
}

impl AuditStreamBody {
    /// The stream this body adds.
    ///
    /// # Errors
    ///
    /// A validation error for a name, address, credential or event type
    /// that is not a valid one.
    pub(crate) fn into_create(self) -> Result<CreateRequest, ApiError> {
        Ok(CreateRequest {
            name: Label::new("name", self.name).map_err(ApiError::validation)?,
            target: self.destination.try_into()?,
            filter: stream_filter(self.events)?,
            proof: self.proof.try_into()?,
        })
    }

    /// The change this body makes to the stream `stream_id`.
    ///
    /// # Errors
    ///
    /// As [`Self::into_create`].
    pub(crate) fn into_reconfigure(
        self,
        stream_id: AuditStreamId,
    ) -> Result<ReconfigureRequest, ApiError> {
        Ok(ReconfigureRequest {
            stream_id,
            name: Label::new("name", self.name).map_err(ApiError::validation)?,
            target: self.destination.try_into()?,
            filter: stream_filter(self.events)?,
            proof: self.proof.try_into()?,
        })
    }
}

impl TryFrom<StreamTargetBody> for StreamTarget {
    type Error = ApiError;

    fn try_from(body: StreamTargetBody) -> Result<Self, Self::Error> {
        match body {
            StreamTargetBody::Splunk {
                endpoint,
                token,
                index,
            } => Ok(Self::Splunk {
                endpoint: public_url(endpoint)?,
                token: Secret::new(token),
                index: splunk_index(index)?,
            }),
            StreamTargetBody::Datadog { site, api_key } => Ok(Self::Datadog {
                site: DatadogSite::parse(&site).ok_or_else(|| {
                    ApiError::validation(message!(
                        "api-site-is-us1-us3-us5-eu1",
                        "site is us1, us3, us5, eu1, ap1 or us1_fed"
                    ))
                })?,
                api_key: Secret::new(api_key),
            }),
            StreamTargetBody::Syslog { host, port } => Ok(Self::Syslog(syslog_target(host, port)?)),
            StreamTargetBody::Http { endpoint, header } => Ok(Self::Http {
                endpoint: public_url(endpoint)?,
                authorization: typed_authorization(header)?,
            }),
        }
    }
}

/// `endpoint` as a public HTTPS address.
fn public_url(endpoint: String) -> Result<PublicHttpsUrl, ApiError> {
    PublicHttpsUrl::new(endpoint).map_err(ApiError::validation)
}

/// The Splunk index `index` names, or the token's own when it names none.
fn splunk_index(index: Option<String>) -> Result<SplunkIndex, ApiError> {
    let Some(name) = index else {
        return Ok(SplunkIndex::TokenDefault);
    };
    SplunkIndexName::new(name)
        .map(SplunkIndex::Named)
        .map_err(ApiError::validation)
}

/// The syslog collector at `host`, on `port` or syslog over TLS's own.
fn syslog_target(host: String, port: Option<u16>) -> Result<SyslogTarget, ApiError> {
    let host = HostName::new(host)
        .and_then(PublicHost::new)
        .map_err(ApiError::validation)?;
    let port = SyslogPort::new(port.unwrap_or(SYSLOG_TLS_PORT)).map_err(ApiError::validation)?;
    Ok(SyslogTarget::new(host, port))
}

/// The header `header` describes, or none.
fn typed_authorization(header: Option<StreamHeaderBody>) -> Result<TypedAuthorization, ApiError> {
    let Some(header) = header else {
        return Ok(TypedAuthorization::Unauthenticated);
    };
    Ok(TypedAuthorization::Header {
        name: HeaderName::new(header.name)
            .and_then(StreamHeaderName::new)
            .map_err(ApiError::validation)?,
        value: Secret::new(header.value),
    })
}

/// The records `events` lets through: every one when it names none.
fn stream_filter(events: Option<Vec<String>>) -> Result<StreamFilter, ApiError> {
    let Some(names) = events else {
        return Ok(StreamFilter::everything());
    };
    let events = names
        .iter()
        .map(|name| {
            EventType::parse(name).ok_or_else(|| {
                ApiError::validation(message!(
                    "api-no-event-type-is-named",
                    format!("no event type is named {name}")
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    StreamFilter::only(events).map_err(ApiError::validation)
}

/// A stream just added.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AuditStreamCreatedResponse {
    /// The stream's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: AuditStreamId,
}

/// A tenant's audit stream as read back. No credential is ever shown.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AuditStreamResponse {
    /// The stream's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: AuditStreamId,
    /// What it is called.
    pub name: String,
    /// Where records go, without its credential.
    pub destination: StreamDestinationResponse,
    /// The event types sent, or `null` for every record.
    pub events: Option<Vec<&'static str>>,
    /// `active`, `failing` or `paused`.
    pub state: &'static str,
    /// Since when its sends fail, while it is failing.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub failing_since: Option<OffsetDateTime>,
    /// How many sends in a row failed, while it is failing.
    pub failures: Option<u32>,
    /// Why it stopped, while it is paused: `by_administrator` or
    /// `after_failures`.
    pub paused_reason: Option<&'static str>,
    /// Since when it is paused.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub paused_at: Option<OffsetDateTime>,
    /// When it was added.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Where a stream sends records, without its credential.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct StreamDestinationResponse {
    /// `splunk`, `datadog`, `syslog` or `http`.
    pub kind: &'static str,
    /// The collector or endpoint address, for Splunk and HTTP.
    pub endpoint: Option<String>,
    /// The Splunk index, or `null` for the token's own.
    pub index: Option<String>,
    /// The Datadog site.
    pub site: Option<&'static str>,
    /// The syslog collector's host.
    pub host: Option<String>,
    /// The syslog collector's port.
    pub port: Option<u16>,
    /// The header an HTTPS endpoint gets, by name only.
    pub header_name: Option<String>,
}

impl From<&AuditStream<ResolvedTenant>> for AuditStreamResponse {
    fn from(stream: &AuditStream<ResolvedTenant>) -> Self {
        let state = StreamStateParts::from(stream.state());
        Self {
            id: *stream.id(),
            name: stream.name().as_str().to_owned(),
            destination: StreamDestinationResponse::from(stream.destination()),
            events: stream
                .filter()
                .events()
                .map(|events| events.iter().map(EventType::as_str).collect()),
            state: state.name,
            failing_since: state.failing_since,
            failures: state.failures,
            paused_reason: state.paused_reason,
            paused_at: state.paused_at,
            created_at: stream.created_at(),
            updated_at: stream.updated_at(),
        }
    }
}

/// A stream's state spread over the response's fields.
struct StreamStateParts {
    name: &'static str,
    failing_since: Option<OffsetDateTime>,
    failures: Option<u32>,
    paused_reason: Option<&'static str>,
    paused_at: Option<OffsetDateTime>,
}

impl From<StreamState> for StreamStateParts {
    fn from(state: StreamState) -> Self {
        let none = Self {
            name: "active",
            failing_since: None,
            failures: None,
            paused_reason: None,
            paused_at: None,
        };
        match state {
            StreamState::Active => none,
            StreamState::Failing { since, failures } => Self {
                name: "failing",
                failing_since: Some(since),
                failures: Some(failures),
                ..none
            },
            StreamState::Paused { reason, at } => Self {
                name: "paused",
                paused_reason: Some(reason.as_str()),
                paused_at: Some(at),
                ..none
            },
        }
    }
}

impl StreamDestinationResponse {
    /// Names the destination before adding the fields exposed for its provider.
    fn named(kind: &'static str) -> Self {
        Self {
            kind,
            endpoint: None,
            index: None,
            site: None,
            host: None,
            port: None,
            header_name: None,
        }
    }
}

impl From<&StreamDestination> for StreamDestinationResponse {
    fn from(destination: &StreamDestination) -> Self {
        let blank = Self::named(destination.kind().as_str());
        match destination {
            StreamDestination::Splunk(target) => Self {
                endpoint: Some(target.endpoint().as_str().to_owned()),
                index: match target.index() {
                    SplunkIndex::TokenDefault => None,
                    SplunkIndex::Named(name) => Some(name.as_str().to_owned()),
                },
                ..blank
            },
            StreamDestination::Datadog(target) => Self {
                site: Some(target.site().as_str()),
                ..blank
            },
            StreamDestination::Syslog(target) => Self {
                host: Some(target.host().as_str().to_owned()),
                port: Some(target.port().get()),
                ..blank
            },
            StreamDestination::Http(target) => Self {
                endpoint: Some(target.endpoint().as_str().to_owned()),
                header_name: match target.authorization() {
                    HttpAuthorization::Unauthenticated => None,
                    HttpAuthorization::Header { name, .. } => Some(name.as_str().to_owned()),
                },
                ..blank
            },
        }
    }
}
