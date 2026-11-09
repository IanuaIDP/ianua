//! An audit stream as its row holds it: read back into the aggregate, and
//! written out from it. The destination is one JSON value, its credential
//! kept in the sealed form the stream was made with.

use ianua_domain::domains::audit::streaming::{
    DatadogSite, DatadogTarget, HttpAuthorization, HttpTarget, SplunkIndex, SplunkIndexName,
    SplunkTarget, StreamDestination, StreamFilter, StreamHeaderName, SyslogPort, SyslogTarget,
};
use ianua_domain::domains::tenant::audit_streams::{AuditStream, AuditStreamRow, StreamState};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    AuditStreamId, EventType, HeaderName, HostName, Label, PublicHost, PublicHttpsUrl, SealedSecret,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const STREAM: Stored = Stored("audit stream");

const DESTINATION: Kept = Kept {
    entity: STREAM.0,
    column: "destination",
    shape: 1,
};

/// A destination as the column keeps it, each credential sealed.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum StoredDestination {
    Splunk {
        endpoint: String,
        token: String,
        index: Option<String>,
    },
    Datadog {
        site: String,
        api_key: String,
    },
    Syslog {
        host: String,
        port: u16,
    },
    Http {
        endpoint: String,
        header: Option<StoredHeader>,
    },
}

/// A header an HTTPS endpoint is sent, its value sealed.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct StoredHeader {
    name: String,
    value: String,
}

impl StoredDestination {
    fn of(destination: &StreamDestination) -> Self {
        match destination {
            StreamDestination::Splunk(target) => Self::Splunk {
                endpoint: target.endpoint().as_str().to_owned(),
                token: target.token().as_str().to_owned(),
                index: match target.index() {
                    SplunkIndex::TokenDefault => None,
                    SplunkIndex::Named(name) => Some(name.as_str().to_owned()),
                },
            },
            StreamDestination::Datadog(target) => Self::Datadog {
                site: target.site().as_str().to_owned(),
                api_key: target.api_key().as_str().to_owned(),
            },
            StreamDestination::Syslog(target) => Self::Syslog {
                host: target.host().as_str().to_owned(),
                port: target.port().get(),
            },
            StreamDestination::Http(target) => Self::Http {
                endpoint: target.endpoint().as_str().to_owned(),
                header: match target.authorization() {
                    HttpAuthorization::Unauthenticated => None,
                    HttpAuthorization::Header { name, value } => Some(StoredHeader {
                        name: name.as_str().to_owned(),
                        value: value.as_str().to_owned(),
                    }),
                },
            },
        }
    }

    fn into_destination(self) -> Result<StreamDestination, DomainError> {
        match self {
            Self::Splunk {
                endpoint,
                token,
                index,
            } => Ok(StreamDestination::Splunk(SplunkTarget::new(
                url(endpoint)?,
                sealed(token)?,
                splunk_index(index)?,
            ))),
            Self::Datadog { site, api_key } => {
                let site = DatadogSite::parse(&site)
                    .ok_or_else(|| DomainError::corrupt_row(STREAM.0, "an unknown Datadog site"))?;
                Ok(StreamDestination::Datadog(DatadogTarget::new(
                    site,
                    sealed(api_key)?,
                )))
            }
            Self::Syslog { host, port } => Ok(StreamDestination::Syslog(SyslogTarget::new(
                public_host(host)?,
                STREAM.value("syslog port", SyslogPort::new(port))?,
            ))),
            Self::Http { endpoint, header } => Ok(StreamDestination::Http(HttpTarget::new(
                url(endpoint)?,
                authorization(header)?,
            ))),
        }
    }
}

/// Rebuilds the explicitly named Splunk index or retains the token's default.
fn splunk_index(index: Option<String>) -> Result<SplunkIndex, DomainError> {
    match index {
        None => Ok(SplunkIndex::TokenDefault),
        Some(name) => Ok(SplunkIndex::Named(
            STREAM.value("splunk index", SplunkIndexName::new(name))?,
        )),
    }
}

fn url(endpoint: String) -> Result<PublicHttpsUrl, DomainError> {
    STREAM.value("endpoint", PublicHttpsUrl::new(endpoint))
}

fn sealed(credential: String) -> Result<SealedSecret, DomainError> {
    STREAM.value("credential", SealedSecret::new(credential))
}

fn public_host(host: String) -> Result<PublicHost, DomainError> {
    let name = STREAM.value("host", HostName::new(host))?;
    STREAM.value("host", PublicHost::new(name))
}

fn authorization(header: Option<StoredHeader>) -> Result<HttpAuthorization, DomainError> {
    let Some(header) = header else {
        return Ok(HttpAuthorization::Unauthenticated);
    };
    Ok(HttpAuthorization::Header {
        name: STREAM.value(
            "header",
            HeaderName::new(header.name).and_then(StreamHeaderName::new),
        )?,
        value: sealed(header.value)?,
    })
}

/// A stream as it is read. The store's checked queries fill it.
pub(super) struct StreamRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) destination: Value,
    pub(super) events: Option<Vec<String>>,
    pub(super) state: String,
    pub(super) state_since: Option<OffsetDateTime>,
    pub(super) failures: i32,
    pub(super) pause_reason: Option<String>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl StreamRecord {
    /// The stream the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the stream
    /// keeps.
    pub(super) fn into_stream(self) -> Result<AuditStream<ResolvedTenant>, DomainError> {
        let destination: StoredDestination = DESTINATION.open(self.destination)?;
        let state = state_of(
            &self.state,
            self.state_since,
            self.failures,
            self.pause_reason.as_deref(),
        )?;
        AuditStream::reconstitute(AuditStreamRow {
            id: AuditStreamId::from_uuid(self.id),
            name: STREAM.value("name", Label::new("name", self.name))?,
            destination: destination.into_destination()?,
            filter: filter_of(self.events)?,
            state,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// The filter `events` keeps: every record when there are none.
fn filter_of(events: Option<Vec<String>>) -> Result<StreamFilter, DomainError> {
    let Some(events) = events else {
        return Ok(StreamFilter::everything());
    };
    let events = events
        .iter()
        .map(|event| {
            EventType::parse(event)
                .ok_or_else(|| DomainError::corrupt_row(STREAM.0, "an unknown event type"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    STREAM.value("events", StreamFilter::only(events))
}

/// The state the columns keep.
fn state_of(
    state: &str,
    since: Option<OffsetDateTime>,
    failures: i32,
    reason: Option<&str>,
) -> Result<StreamState, DomainError> {
    let failures = u32::try_from(failures)
        .map_err(|_| DomainError::corrupt_row(STREAM.0, "failures below zero"))?;
    match (state, since, reason) {
        ("active", None, None) => Ok(StreamState::Active),
        ("failing", Some(since), None) => Ok(StreamState::Failing { since, failures }),
        ("paused", Some(at), Some(reason)) => Ok(StreamState::Paused {
            reason: STREAM.choice(reason)?,
            at,
        }),
        _ => Err(DomainError::corrupt_row(STREAM.0, "an unknown state")),
    }
}

/// A stream's columns, as they are written.
pub(super) struct StreamColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) destination: Value,
    pub(super) events: Option<Vec<String>>,
    pub(super) state: &'static str,
    pub(super) state_since: Option<OffsetDateTime>,
    pub(super) failures: i32,
    pub(super) pause_reason: Option<&'static str>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> StreamColumns<'a> {
    /// The columns `stream` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the destination cannot be
    /// written out.
    pub(super) fn of(stream: &'a AuditStream<ResolvedTenant>) -> Result<Self, DomainError> {
        let (state, state_since, failures, pause_reason) = match stream.state() {
            StreamState::Active => ("active", None, 0, None),
            StreamState::Failing { since, failures } => (
                "failing",
                Some(since),
                i32::try_from(failures).unwrap_or(i32::MAX),
                None,
            ),
            StreamState::Paused { reason, at } => ("paused", Some(at), 0, Some(reason.word())),
        };
        Ok(Self {
            id: stream.id().as_uuid(),
            name: stream.name().as_str(),
            destination: DESTINATION.seal(&StoredDestination::of(stream.destination()))?,
            events: stream.filter().events().map(|events| {
                events
                    .iter()
                    .map(|event| event.as_str().to_owned())
                    .collect()
            }),
            state,
            state_since,
            failures,
            pause_reason,
            created_at: stream.created_at(),
            updated_at: stream.updated_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// A Splunk collector with a named index, in the shape the column
    /// keeps.
    fn stored_splunk() -> Value {
        json!({"v": 1, "value": {
            "kind": "splunk",
            "endpoint": "https://splunk.acme.com:8088/services/collector",
            "token": "v1.c3BsdW5r",
            "index": "ianua_audit"
        }})
    }

    /// An HTTPS endpoint sent a sealed header, in the shape the column
    /// keeps.
    fn stored_http() -> Value {
        json!({"v": 1, "value": {
            "kind": "http",
            "endpoint": "https://logs.acme.com/ingest",
            "header": {"name": "authorization", "value": "v1.QmVhcmVy"}
        }})
    }

    /// A destination stored in the shape pinned here reads back, and is
    /// written again in the same shape.
    #[test]
    fn a_destination_is_stored_in_its_pinned_shape() {
        for stored in [stored_splunk(), stored_http()] {
            let read: StoredDestination = DESTINATION.open(stored.clone()).unwrap();
            let destination = read.into_destination().unwrap();

            assert_eq!(
                DESTINATION
                    .seal(&StoredDestination::of(&destination))
                    .unwrap(),
                stored
            );
        }
    }

    /// A stored syslog destination naming the internal metadata host is
    /// rejected as corrupt.
    #[test]
    fn a_destination_pointing_inside_the_network_is_refused() {
        let inside = StoredDestination::Syslog {
            host: "metadata.google.internal".to_owned(),
            port: 6514,
        };

        assert!(matches!(
            inside.into_destination(),
            Err(DomainError::Infrastructure(_))
        ));
    }
}
