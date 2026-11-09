//! A request's headers and cookies as a route's conditions read them.

use http::HeaderMap;
use ianua_domain::domains::routing::matching::request_match::RequestValues;
use ianua_domain::types::{CookieName, Fact, HeaderName};

use crate::request::cookies::{CookieRead, read};

/// The headers of an admitted request, read by route conditions.
///
/// Built after [`admit`](crate::request::admit), so a condition never sees a
/// header the proxy owns. A value that is not text, or a cookie sent twice,
/// reads as not sent: a condition cannot hold on a value the gateway could
/// read two ways.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RequestHeaders<'a>(&'a HeaderMap);

impl<'a> RequestHeaders<'a> {
    /// The request's headers, for route matching.
    #[must_use]
    pub(crate) fn new(headers: &'a HeaderMap) -> Self {
        Self(headers)
    }
}

impl RequestValues for RequestHeaders<'_> {
    fn header(&self, name: &HeaderName) -> Fact<&str> {
        let first = self
            .0
            .get(name.as_str())
            .and_then(|value| value.to_str().ok());
        Fact::from_option(first)
    }

    fn cookie(&self, name: &CookieName) -> Fact<&str> {
        match read(self.0, name.as_str()) {
            CookieRead::One(value) => Fact::Known(value),
            CookieRead::Absent | CookieRead::Ambiguous => Fact::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    fn map(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(*name, HeaderValue::from_static(value));
        }
        headers
    }

    #[test]
    fn a_header_reads_its_first_value_whatever_its_case() {
        let headers = map(&[("x-canary", "on"), ("x-canary", "off")]);
        let values = RequestHeaders::new(&headers);

        assert_eq!(
            values.header(&HeaderName::new("X-Canary").unwrap()),
            Fact::Known("on")
        );
        assert_eq!(
            values.header(&HeaderName::new("x-other").unwrap()),
            Fact::Unknown
        );
    }

    #[test]
    fn a_cookie_sent_twice_reads_as_not_sent() {
        let headers = map(&[("cookie", "beta=1; beta=2"), ("cookie", "lang=en")]);
        let values = RequestHeaders::new(&headers);

        assert_eq!(
            values.cookie(&CookieName::new("beta").unwrap()),
            Fact::Unknown
        );
        assert_eq!(
            values.cookie(&CookieName::new("lang").unwrap()),
            Fact::Known("en")
        );
    }
}
