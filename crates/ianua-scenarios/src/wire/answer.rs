//! The API's answer to one request: its status, its headers, and its body
//! read as what was asked for or as the problem it refused with.

use reqwest::header::HeaderMap;
use serde::de::DeserializeOwned;

use super::problem::ScimError;
use super::{Exchange, Problem};
use crate::wire::Status;

/// How the body read.
enum Body<T> {
    /// As the type asked for, on a success.
    Read(T),
    /// As the API's problem, on a refusal.
    Refused(Problem),
    /// As neither: why, in words.
    Unreadable(String),
}

/// The answer to one request.
pub struct Answer<T> {
    status: Status,
    headers: HeaderMap,
    body: Body<T>,
    exchange: Exchange,
}

/// An answer as it arrived, before its body is read.
pub(crate) struct Arrived {
    /// HTTP outcome used to choose success or problem decoding.
    pub(crate) status: Status,
    /// Response metadata retained for cookie and header assertions.
    pub(crate) headers: HeaderMap,
    /// Its body.
    pub(crate) bytes: Vec<u8>,
    /// The request and answer, redacted.
    pub(crate) exchange: Exchange,
}

impl<T: DeserializeOwned> Answer<T> {
    /// The answer `arrived`, its body read as `T` on a success and as a
    /// [`Problem`] otherwise. An empty body reads as JSON `null`, so `()`
    /// takes a `Status::NO_CONTENT`.
    pub(crate) fn read(arrived: Arrived) -> Self {
        let json: &[u8] = if arrived.bytes.is_empty() {
            b"null"
        } else {
            &arrived.bytes
        };
        let body = match arrived.status.is_success() {
            true => serde_json::from_slice(json)
                .map(Body::Read)
                .unwrap_or_else(|error| {
                    Body::Unreadable(format!("not the answer expected: {error}"))
                }),
            false => refusal(json),
        };
        Self {
            status: arrived.status,
            headers: arrived.headers,
            body,
            exchange: arrived.exchange,
        }
    }
}

impl Answer<String> {
    /// The answer `arrived`, its body read as text on a success, such as
    /// an XML document, and as a [`Problem`] otherwise.
    pub(crate) fn read_text(arrived: Arrived) -> Self {
        let Arrived {
            status,
            headers,
            bytes,
            exchange,
        } = arrived;
        let body = match status.is_success() {
            true => String::from_utf8(bytes)
                .map(Body::Read)
                .unwrap_or_else(|_| Body::Unreadable("a body that is not text".to_owned())),
            false => refusal(&bytes),
        };
        Self {
            status,
            headers,
            body,
            exchange,
        }
    }
}

/// A refusal's body read as the API's [`Problem`], or as a SCIM error
/// made into one.
fn refusal<T>(bytes: &[u8]) -> Body<T> {
    serde_json::from_slice::<Problem>(bytes)
        .or_else(|_| serde_json::from_slice::<ScimError>(bytes).map(Problem::from))
        .map(Body::Refused)
        .unwrap_or_else(|_| Body::Unreadable("a refusal with no problem body".to_owned()))
}

impl<T> Answer<T> {
    /// The HTTP status.
    #[must_use]
    pub fn status(&self) -> Status {
        self.status
    }

    /// The header `name`, when it was sent and is text.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    /// The problem the API refused with, when it refused with one.
    #[must_use]
    pub fn problem(&self) -> Option<&Problem> {
        match &self.body {
            Body::Refused(problem) => Some(problem),
            Body::Read(_) | Body::Unreadable(_) => None,
        }
    }

    /// The body read as asked, when the API succeeded and it read.
    #[must_use]
    pub fn value(&self) -> Option<&T> {
        match &self.body {
            Body::Read(value) => Some(value),
            Body::Refused(_) | Body::Unreadable(_) => None,
        }
    }

    /// The request and answer, redacted, for a failure's message.
    #[must_use]
    pub fn exchange(&self) -> &Exchange {
        &self.exchange
    }

    /// The correlation id the request carried.
    #[must_use]
    pub fn correlation_id(&self) -> &str {
        self.exchange.correlation_id()
    }

    /// The status and what the body said, in a few words.
    #[must_use]
    pub fn summary(&self) -> String {
        match &self.body {
            Body::Read(_) => format!("{}", self.status),
            Body::Refused(problem) => format!("{} {problem}", self.status),
            Body::Unreadable(why) => format!("{} ({why})", self.status),
        }
    }

    /// The body, read as asked, of a success.
    ///
    /// # Panics
    ///
    /// When the API refused, or answered what does not read as `T`,
    /// naming the status, the problem and the correlation id, with the
    /// redacted exchange.
    pub fn ok(self) -> T {
        let summary = self.summary();
        let Body::Read(value) = self.body else {
            panic!(
                "expected {} to succeed, got {summary}\n{}",
                self.exchange.request_line(),
                self.exchange
            );
        };
        value
    }

    /// The problem of a refusal with `status` and the code `code`.
    ///
    /// # Panics
    ///
    /// When the answer is anything else, naming what it was, with the
    /// redacted exchange.
    pub fn refused(self, status: Status, code: &str) -> Problem {
        let matching = self
            .problem()
            .is_some_and(|problem| self.status == status && problem.code() == code);
        if !matching {
            panic!(
                "expected {} to be refused with {status} {code}, got {}\n{}",
                self.exchange.request_line(),
                self.summary(),
                self.exchange
            );
        }
        let Body::Refused(problem) = self.body else {
            unreachable!("a matching answer is a refusal");
        };
        problem
    }
}
