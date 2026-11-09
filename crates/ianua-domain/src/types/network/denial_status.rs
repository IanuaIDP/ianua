use std::fmt;

use crate::shared::validation::ValidationError;
use crate::shared::validation::numeric::validate_range;

/// The HTTP status a refused request is answered with: a 4xx or a 5xx.
///
/// A refusal answered with a 200 or a redirect would read to the client, and
/// to any cache in between, as the request going through. So only an error
/// status is accepted. A stage may answer with any error code, such as 451 for a
/// resource withheld for legal reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u16", into = "u16"))]
pub struct DenialStatus(u16);

impl DenialStatus {
    /// 400 Bad Request: the request itself was malformed.
    pub const BAD_REQUEST: Self = Self(400);
    /// 401 Unauthorized: the caller did not prove who they are.
    pub const UNAUTHORIZED: Self = Self(401);
    /// 403 Forbidden: the caller may not do this.
    pub const FORBIDDEN: Self = Self(403);
    /// 404 Not Found: nothing answers at the address.
    pub const NOT_FOUND: Self = Self(404);
    /// 413 Content Too Large: the request is larger than accepted.
    pub const CONTENT_TOO_LARGE: Self = Self(413);
    /// 421 Misdirected Request: the connection was made for another host.
    pub const MISDIRECTED_REQUEST: Self = Self(421);
    /// 429 Too Many Requests: the caller hit a rate limit.
    pub const TOO_MANY_REQUESTS: Self = Self(429);
    /// 502 Bad Gateway: the upstream could not be reached.
    pub const BAD_GATEWAY: Self = Self(502);
    /// 503 Service Unavailable: something the decision needs is unreachable.
    pub const SERVICE_UNAVAILABLE: Self = Self(503);
    /// 504 Gateway Timeout: the upstream did not answer in time.
    pub const GATEWAY_TIMEOUT: Self = Self(504);

    /// The lowest code accepted, the first client error.
    const LOWEST: u16 = 400;
    /// The highest code accepted, the last server error.
    const HIGHEST: u16 = 599;

    /// A denial answered with `code`.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when `code` is not from 400 to 599.
    pub fn new(code: u16) -> Result<Self, ValidationError> {
        validate_range("denial_status", code, Self::LOWEST..=Self::HIGHEST)?;
        Ok(Self(code))
    }

    /// The numeric status code sent on the wire.
    #[must_use]
    pub fn code(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for DenialStatus {
    type Error = ValidationError;

    fn try_from(code: u16) -> Result<Self, Self::Error> {
        Self::new(code)
    }
}

impl From<DenialStatus> for u16 {
    fn from(status: DenialStatus) -> Self {
        status.code()
    }
}

impl fmt::Display for DenialStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Informational, successful and redirect status codes cannot represent
    /// a denial.
    #[test]
    fn a_success_or_redirect_status_is_not_a_denial() {
        for code in [100, 200, 204, 302, 399] {
            assert!(DenialStatus::new(code).is_err(), "{code}");
        }
    }

    /// A client error such as 403 or 451 and a server error such as 503 are
    /// accepted and keep their number.
    #[test]
    fn a_client_or_server_error_is_a_denial() {
        for code in [400, 403, 451, 503, 599] {
            assert_eq!(DenialStatus::new(code).unwrap().code(), code);
        }
    }

    /// A code past the server errors, such as 600, is refused.
    #[test]
    fn a_code_above_the_server_errors_is_refused() {
        assert!(DenialStatus::new(600).is_err());
    }

    /// A stored 200 is refused as a denial, while 429 loads as the rate-limit
    /// refusal status.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_success_status_does_not_load_as_a_denial() {
        assert!(serde_json::from_str::<DenialStatus>("200").is_err());
        assert_eq!(
            serde_json::from_str::<DenialStatus>("429").unwrap(),
            DenialStatus::TOO_MANY_REQUESTS
        );
    }
}
