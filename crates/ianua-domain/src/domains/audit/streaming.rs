//! Where a tenant's audit records are streamed to, and which of them.
//!
//! A security team keeps its own copy of every record in the SIEM it runs:
//! Splunk, Datadog, a syslog collector, or any HTTPS endpoint. These are
//! the values that describe such a destination. Every credential in them
//! is sealed and never prints, and every place they point to is on the
//! public internet, so a destination cannot turn the platform into a way
//! into its own network.

use std::fmt;

use crate::message;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::{validate_count, validate_range};
use crate::shared::validation::{Charset, TextValue, ValidationError, Validator, text_value};
use crate::types::{EventType, HeaderName, PublicHost, PublicHttpsUrl, SealedSecret};

/// The most event types one stream may pick out.
pub(crate) const MAX_FILTERED_EVENTS: usize = 200;

/// The port syslog over TLS listens on unless told otherwise (RFC 5425).
pub const SYSLOG_TLS_PORT: u16 = 6514;

text_value! {
    /// The name of a Splunk index, such as `ianua_audit`: lower-case
    /// letters, digits, underscores and hyphens.
    pub struct SplunkIndexName;
}

impl TextValue for SplunkIndexName {
    const FIELD: &'static str = "splunk_index";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            1..=80,
            Charset::LOWERCASE | Charset::DIGIT | Charset::UNDERSCORE | Charset::HYPHEN,
        )
    }
}

/// Which Splunk index records go to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplunkIndex {
    /// The index the collector's token is set up with.
    TokenDefault,
    /// This index.
    Named(SplunkIndexName),
}

/// A Splunk HTTP Event Collector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplunkTarget {
    endpoint: PublicHttpsUrl,
    token: SealedSecret,
    index: SplunkIndex,
}

impl SplunkTarget {
    /// The collector at `endpoint`, authenticated with the sealed `token`,
    /// writing into `index`.
    #[must_use]
    pub fn new(endpoint: PublicHttpsUrl, token: SealedSecret, index: SplunkIndex) -> Self {
        Self {
            endpoint,
            token,
            index,
        }
    }

    /// Where the collector listens.
    #[must_use]
    pub fn endpoint(&self) -> &PublicHttpsUrl {
        &self.endpoint
    }

    /// The collector token, sealed.
    #[must_use]
    pub fn token(&self) -> &SealedSecret {
        &self.token
    }

    /// Which index records go to.
    #[must_use]
    pub fn index(&self) -> &SplunkIndex {
        &self.index
    }
}

/// The Datadog site an account lives on. Each site has its own intake, and
/// an API key works on its own site only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DatadogSite {
    /// `datadoghq.com`.
    Us1,
    /// `us3.datadoghq.com`.
    Us3,
    /// `us5.datadoghq.com`.
    Us5,
    /// `datadoghq.eu`.
    Eu1,
    /// `ap1.datadoghq.com`.
    Ap1,
    /// `ddog-gov.com`, for US government accounts.
    Us1Fed,
}

impl DatadogSite {
    /// Every site.
    pub const ALL: [Self; 6] = [
        Self::Us1,
        Self::Us3,
        Self::Us5,
        Self::Eu1,
        Self::Ap1,
        Self::Us1Fed,
    ];

    /// The stable name storage and the API use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Us1 => "us1",
            Self::Us3 => "us3",
            Self::Us5 => "us5",
            Self::Eu1 => "eu1",
            Self::Ap1 => "ap1",
            Self::Us1Fed => "us1_fed",
        }
    }

    /// The site stored under `value`, or `None` for a name the domain does
    /// not define, which storage reports as corrupt.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|site| site.as_str() == value)
    }

    /// The site's own domain, such as `datadoghq.eu`. Records only ever go
    /// to Datadog's intake under it, never to a host the tenant typed.
    #[must_use]
    pub fn domain(self) -> &'static str {
        match self {
            Self::Us1 => "datadoghq.com",
            Self::Us3 => "us3.datadoghq.com",
            Self::Us5 => "us5.datadoghq.com",
            Self::Eu1 => "datadoghq.eu",
            Self::Ap1 => "ap1.datadoghq.com",
            Self::Us1Fed => "ddog-gov.com",
        }
    }

    /// The host this site's log intake takes records on.
    #[must_use]
    pub fn log_intake_host(self) -> &'static str {
        match self {
            Self::Us1 => "http-intake.logs.datadoghq.com",
            Self::Us3 => "http-intake.logs.us3.datadoghq.com",
            Self::Us5 => "http-intake.logs.us5.datadoghq.com",
            Self::Eu1 => "http-intake.logs.datadoghq.eu",
            Self::Ap1 => "http-intake.logs.ap1.datadoghq.com",
            Self::Us1Fed => "http-intake.logs.ddog-gov.com",
        }
    }
}

/// A Datadog account's log intake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatadogTarget {
    site: DatadogSite,
    api_key: SealedSecret,
}

impl DatadogTarget {
    /// The intake of `site`, authenticated with the sealed `api_key`.
    #[must_use]
    pub fn new(site: DatadogSite, api_key: SealedSecret) -> Self {
        Self { site, api_key }
    }

    /// The site the account lives on.
    #[must_use]
    pub fn site(&self) -> DatadogSite {
        self.site
    }

    /// The API key, sealed.
    #[must_use]
    pub fn api_key(&self) -> &SealedSecret {
        &self.api_key
    }
}

/// The port a syslog collector listens on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyslogPort(u16);

impl SyslogPort {
    /// Checks that `port` is a port a collector can listen on.
    ///
    /// # Errors
    ///
    /// - [`ValidationError::OutOfRange`] for port 0.
    pub fn new(port: u16) -> Result<Self, ValidationError> {
        validate_range("syslog_port", port, 1..=u16::MAX)?;
        Ok(Self(port))
    }

    /// The port number.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }
}

/// A syslog collector, reached over TLS (RFC 5425).
///
/// There is no plain TCP or UDP choice. Audit records name people, their
/// addresses and what they did, and a collector sits outside the platform,
/// across networks nobody here controls. Sent in the clear, every record
/// could be read or altered on the way, and UDP would also drop them
/// without anyone knowing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogTarget {
    host: PublicHost,
    port: SyslogPort,
}

impl SyslogTarget {
    /// The collector at `host` on `port`.
    #[must_use]
    pub fn new(host: PublicHost, port: SyslogPort) -> Self {
        Self { host, port }
    }

    /// Where the collector is.
    #[must_use]
    pub fn host(&self) -> &PublicHost {
        &self.host
    }

    /// The port it listens on.
    #[must_use]
    pub fn port(&self) -> SyslogPort {
        self.port
    }
}

/// Headers the platform sets on every request it sends, or that shape how
/// the request is framed and carried. A stream's credential may not take
/// any of their names.
const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "content-type",
    "content-encoding",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "expect",
    "proxy-authorization",
    "proxy-connection",
];

/// The header an HTTPS stream sends its credential in, such as
/// `authorization` or `x-siem-key`.
///
/// It is a plain HTTP header name, so it holds no control character, and it
/// is none of [`RESERVED_HEADERS`]. Named `host` or `transfer-encoding`,
/// the credential's value would steer where the request goes or how it is
/// read, and could smuggle a second request to the endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamHeaderName(HeaderName);

impl StreamHeaderName {
    /// Checks that `name` is a header a stream may send its credential in.
    ///
    /// # Errors
    ///
    /// - [`ValidationError::Custom`] when `name` is one the platform sets or
    ///   one that shapes how the request is carried.
    pub fn new(name: HeaderName) -> Result<Self, ValidationError> {
        if RESERVED_HEADERS.contains(&name.as_str()) {
            return Err(ValidationError::Custom {
                field: "stream_header",
                code: "reserved".to_owned(),
                message: message!(
                    "audit-this-header-is-set-by-the",
                    "this header is set by the platform or carries the request, so it cannot hold a credential"
                ),
            });
        }
        Ok(Self(name))
    }

    /// The header's name, in lower case.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// How an HTTPS endpoint knows the records come from the platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpAuthorization {
    /// The endpoint asks for nothing.
    Unauthenticated,
    /// Each request carries this header, its value sealed.
    Header {
        /// The header, such as `authorization`.
        name: StreamHeaderName,
        /// Its value, sealed.
        value: SealedSecret,
    },
}

/// Any HTTPS endpoint that takes records as JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpTarget {
    endpoint: PublicHttpsUrl,
    authorization: HttpAuthorization,
}

impl HttpTarget {
    /// The endpoint at `endpoint`, sent `authorization` with every request.
    #[must_use]
    pub fn new(endpoint: PublicHttpsUrl, authorization: HttpAuthorization) -> Self {
        Self {
            endpoint,
            authorization,
        }
    }

    /// Where records are sent.
    #[must_use]
    pub fn endpoint(&self) -> &PublicHttpsUrl {
        &self.endpoint
    }

    /// What each request carries to show where it came from.
    #[must_use]
    pub fn authorization(&self) -> &HttpAuthorization {
        &self.authorization
    }
}

/// Where a stream sends a tenant's audit records.
///
/// `Debug` prints no credential: every one is a [`SealedSecret`], and URLs
/// print only their origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamDestination {
    /// A Splunk HTTP Event Collector.
    Splunk(SplunkTarget),
    /// A Datadog account's log intake.
    Datadog(DatadogTarget),
    /// A syslog collector over TLS.
    Syslog(SyslogTarget),
    /// Any HTTPS endpoint.
    Http(HttpTarget),
}

impl StreamDestination {
    /// What kind of destination this is, which records may name.
    #[must_use]
    pub fn kind(&self) -> StreamDestinationKind {
        match self {
            Self::Splunk(_) => StreamDestinationKind::Splunk,
            Self::Datadog(_) => StreamDestinationKind::Datadog,
            Self::Syslog(_) => StreamDestinationKind::Syslog,
            Self::Http(_) => StreamDestinationKind::Http,
        }
    }
}

/// The kind of a [`StreamDestination`], without where it points or what it
/// is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDestinationKind {
    /// Delivers records to an HTTP Event Collector.
    Splunk,
    /// Delivers records to the configured regional log intake.
    Datadog,
    /// Syslog over TLS.
    Syslog,
    /// An HTTPS endpoint.
    Http,
}

impl StreamDestinationKind {
    /// The stable name storage and records use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Splunk => "splunk",
            Self::Datadog => "datadog",
            Self::Syslog => "syslog",
            Self::Http => "http",
        }
    }
}

impl fmt::Display for StreamDestinationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which audit records a stream sends.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Selection {
    Everything,
    Only(Vec<EventType>),
}

/// Which audit records a stream sends: all of them, or those of some event
/// types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFilter(Selection);

impl StreamFilter {
    /// Every record.
    #[must_use]
    pub fn everything() -> Self {
        Self(Selection::Everything)
    }

    /// Only records of `events`.
    ///
    /// # Errors
    ///
    /// - [`ValidationError::Count`] when `events` is empty or longer than
    ///   `MAX_FILTERED_EVENTS`.
    /// - [`ValidationError::Custom`] when it names an event type twice.
    pub fn only(events: Vec<EventType>) -> Result<Self, ValidationError> {
        validate_count("stream_events", events.len(), 1..=MAX_FILTERED_EVENTS)?;
        if first_repeat(events.iter().copied()).is_some() {
            return Err(ValidationError::Custom {
                field: "stream_events",
                code: "repeated".to_owned(),
                message: message!(
                    "audit-each-event-type-is-named-once",
                    "each event type is named once"
                ),
            });
        }
        Ok(Self(Selection::Only(events)))
    }

    /// The event types picked out, or `None` when every record is sent.
    #[must_use]
    pub fn events(&self) -> Option<&[EventType]> {
        match &self.0 {
            Selection::Everything => None,
            Selection::Only(events) => Some(events.as_slice()),
        }
    }

    /// Whether a record of `event` is sent.
    #[must_use]
    pub fn admits(&self, event: EventType) -> bool {
        match &self.0 {
            Selection::Everything => true,
            Selection::Only(events) => events.contains(&event),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HostName;
    use crate::types::event_type::{AuthenticationEvent, TenantEvent};

    fn sealed(value: &str) -> SealedSecret {
        SealedSecret::new(value).unwrap()
    }

    /// Ann's Splunk collector is set up with its token. Printing the
    /// destination, as a log line would, shows no part of the token.
    #[test]
    fn a_destination_never_prints_its_credential() {
        let destination = StreamDestination::Splunk(SplunkTarget::new(
            PublicHttpsUrl::new("https://splunk.acme.com:8088/services/collector").unwrap(),
            sealed("v1.c3BsdW5rLXRva2Vu"),
            SplunkIndex::TokenDefault,
        ));

        let printed = format!("{destination:?}");

        assert!(!printed.contains("c3BsdW5rLXRva2Vu"), "{printed}");
    }

    /// A header credential for an HTTPS endpoint prints no part of its
    /// value either.
    #[test]
    fn a_header_credential_never_prints() {
        let destination = StreamDestination::Http(HttpTarget::new(
            PublicHttpsUrl::new("https://logs.acme.com/ingest").unwrap(),
            HttpAuthorization::Header {
                name: StreamHeaderName::new(HeaderName::new("authorization").unwrap()).unwrap(),
                value: sealed("v1.QmVhcmVyIHNlY3JldA"),
            },
        ));

        assert!(!format!("{destination:?}").contains("QmVhcmVyIHNlY3JldA"));
    }

    /// Credential headers cannot use host, length, transfer or connection
    /// headers, including mixed-case names. Authorization and a custom SIEM
    /// header remain valid choices.
    #[test]
    fn a_credential_header_never_takes_a_name_that_carries_the_request() {
        for name in [
            "Host",
            "content-length",
            "Transfer-Encoding",
            "connection",
            "TE",
        ] {
            let name = HeaderName::new(name).unwrap();

            assert!(StreamHeaderName::new(name).is_err());
        }
        for name in ["Authorization", "x-siem-key"] {
            let name = HeaderName::new(name).unwrap();

            assert!(StreamHeaderName::new(name).is_ok());
        }
    }

    /// A private IP endpoint and a cloud metadata host are refused before
    /// either can become an audit stream destination.
    #[test]
    fn a_destination_never_points_inside_the_network() {
        assert!(PublicHttpsUrl::new("https://10.0.0.5/ingest").is_err());
        assert!(PublicHost::new(HostName::new("metadata.google.internal").unwrap()).is_err());
    }

    /// Port 0 is no port a collector listens on, and is refused; the syslog
    /// TLS port is accepted.
    #[test]
    fn a_syslog_port_is_a_real_port() {
        assert!(SyslogPort::new(0).is_err());
        assert_eq!(SyslogPort::new(SYSLOG_TLS_PORT).unwrap().get(), 6514);
    }

    /// `ianua_audit` is a Splunk index name; `Audit Log` is not.
    #[test]
    fn a_splunk_index_name_is_lower_case_letters_digits_and_marks() {
        assert!(SplunkIndexName::new("ianua_audit").is_ok());
        assert!(SplunkIndexName::new("Audit Log").is_err());
    }

    /// Each Datadog site reads back from its stored name, and the EU site
    /// sends to Datadog's EU domain.
    #[test]
    fn every_datadog_site_reads_back() {
        for site in DatadogSite::ALL {
            assert_eq!(DatadogSite::parse(site.as_str()), Some(site));
        }
        assert_eq!(DatadogSite::Eu1.domain(), "datadoghq.eu");
    }

    /// A stream filtered to sign-ins sends sign-ins and nothing else; an
    /// unfiltered one sends everything.
    #[test]
    fn a_filter_sends_only_what_it_names() {
        let sign_ins = EventType::Authentication(AuthenticationEvent::LoginSucceeded);
        let renamed = EventType::Tenant(TenantEvent::Renamed);

        let filter = StreamFilter::only(vec![sign_ins]).unwrap();

        assert!(filter.admits(sign_ins));
        assert!(!filter.admits(renamed));
        assert!(StreamFilter::everything().admits(renamed));
    }

    /// A filter naming nothing, or one event type twice, is refused.
    #[test]
    fn a_filter_names_at_least_one_type_once_each() {
        let renamed = EventType::Tenant(TenantEvent::Renamed);

        assert!(StreamFilter::only(Vec::new()).is_err());
        assert!(StreamFilter::only(vec![renamed, renamed]).is_err());
    }
}
