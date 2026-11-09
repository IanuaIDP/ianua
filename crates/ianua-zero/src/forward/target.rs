//! Where an admitted request goes, as the handler hands it over.

use std::fmt;
use std::sync::Arc;

use http::HeaderValue;
use ianua_domain::domains::proxy::request::body::ByteCap;

use super::pool::ServicePool;
use super::upgrade::UpgradeTerms;

/// Where a request goes and how its answer is held.
pub(crate) struct ForwardTarget {
    /// The pool of the service the route names.
    pub pool: Arc<ServicePool>,
    /// The path the backend sees, as the route rewrote it, without a
    /// query. The request's own query is appended to it.
    pub path: String,
    /// The largest request body the pipeline takes, as
    /// `Pipeline::body_limit` gives it. A longer body is refused, and the
    /// backend never receives the part past the limit.
    pub body_limit: ByteCap,
    /// The `Host` the client addressed, sent on when the service preserves
    /// it.
    pub client_host: Option<HeaderValue>,
    /// What to pin the caller to one backend by, when the service pins.
    pub affinity: Option<AffinityKey>,
    /// Whether the pipeline reads the answer, and so holds it to a size.
    pub inspection: ResponseInspection,
    /// Whether the route marks its answers long-lived.
    pub span: ResponseSpan,
    /// Whether the request may switch protocols, and what a tunnel it
    /// opens is held to.
    pub upgrade: UpgradeTerms,
}

/// What a caller is pinned to one backend by: a user or consumer id, a
/// cookie or header value, a source address.
///
/// It may be a session cookie's value, so it never prints.
#[derive(Clone)]
pub(crate) struct AffinityKey(String);

impl AffinityKey {
    /// A key of `value`.
    #[must_use]
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The key.
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AffinityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AffinityKey(..)")
    }
}

/// Whether the pipeline reads the backend's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponseInspection {
    /// Nothing reads it; it streams to the client whatever its length.
    Streamed,
    /// A response stage reads it, so it is held to this many bytes, and a
    /// longer one is refused rather than read without end.
    Inspected(ByteCap),
}

/// How long a backend's answer is meant to last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponseSpan {
    /// An ordinary answer, done by the gateway's response deadline. An
    /// answer of server-sent events is held as long-lived whatever this
    /// says.
    Bounded,
    /// One the route marks as staying open, such as a chunked stream of
    /// updates: it may last as long as it keeps sending, and is cut off
    /// once it goes quiet for the gateway's idle limit.
    LongLived,
}

impl ResponseInspection {
    /// The most bytes the answer may carry, when it is held to a size.
    pub(super) fn limit(self) -> Option<u64> {
        match self {
            Self::Streamed => None,
            Self::Inspected(cap) => Some(cap.get()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_affinity_key_never_prints() {
        let key = AffinityKey::new("session=secret-value");

        assert_eq!(format!("{key:?}"), "AffinityKey(..)");
    }

    #[test]
    fn only_an_inspected_answer_is_held_to_a_size() {
        let cap = ByteCap::new(1_024).unwrap();

        assert_eq!(ResponseInspection::Streamed.limit(), None);
        assert_eq!(ResponseInspection::Inspected(cap).limit(), Some(1_024));
    }
}
