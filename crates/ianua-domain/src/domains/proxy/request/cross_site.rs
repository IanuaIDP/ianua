//! Whether a request that rides on a cookie was sent by a page allowed to
//! send it.
//!
//! A browser attaches a cookie to every request for its host, including one
//! a page on another site makes it send. A bearer token is different: a
//! page has to read it to attach it, and another site's page cannot. So a
//! request authenticated by a cookie has to show it was not forged by
//! another site before it may change anything.
//!
//! It can show that two ways. A page on the host itself, or on an origin
//! the host trusts, sent it. Or it echoes the CSRF cookie's value in the
//! CSRF header: another site can make the browser send the cookie, but it
//! cannot read its value to copy into the header.

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::security::constant_time::same_secret;
use crate::shared::security::secret::Secret;
use crate::types::HttpMethod;

/// Which page sent a request, as its `Origin` or `Referer` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageOrigin {
    /// A page on the host itself, or on an origin the host trusts.
    Trusted,
    /// Any other page, or one that did not say.
    Elsewhere,
}

/// The double-submit pair a request carried: the CSRF cookie's value and
/// what the CSRF header echoed.
///
/// `Debug` shows neither value, since [`Secret`] never prints.
#[derive(Debug, Clone, Default)]
pub struct CsrfEcho {
    cookie: Option<Secret>,
    header: Option<Secret>,
}

impl CsrfEcho {
    /// The pair as the request carried it, either half missing.
    #[must_use]
    pub fn new(cookie: Option<Secret>, header: Option<Secret>) -> Self {
        Self { cookie, header }
    }

    /// Whether both halves are there, not empty, and the same, compared in
    /// a time that does not show where they differ.
    #[must_use]
    pub fn matches(&self) -> bool {
        let (Some(cookie), Some(header)) = (&self.cookie, &self.header) else {
            return false;
        };
        !cookie.expose().is_empty()
            && same_secret(cookie.expose().as_bytes(), header.expose().as_bytes())
    }
}

/// A request a cookie authenticated, with what it shows about where it
/// came from.
#[derive(Debug, Clone)]
pub struct CookieRequest {
    /// The method it was sent with.
    pub method: HttpMethod,
    /// The page that sent it.
    pub origin: PageOrigin,
    /// The CSRF pair it carried.
    pub echo: CsrfEcho,
}

impl CookieRequest {
    /// Refuses a request another site's page could have forged.
    ///
    /// A request that only reads (`GET`, `HEAD`, `OPTIONS`) passes, since a
    /// forged one achieves nothing. So does one a trusted page sent. Any
    /// other has to echo the CSRF cookie in the CSRF header.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the request changes something, no
    ///   trusted page sent it, and its CSRF pair is missing or differs.
    pub fn ensure_not_forged(&self) -> Result<(), DomainError> {
        if self.method.is_safe() || self.origin == PageOrigin::Trusted || self.echo.matches() {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "proxy-a-cookie-request-from-another-site",
            "a cookie request from another site carried no CSRF proof"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo(cookie: Option<&str>, header: Option<&str>) -> CsrfEcho {
        CsrfEcho::new(cookie.map(Secret::new), header.map(Secret::new))
    }

    fn request(method: HttpMethod, origin: PageOrigin, echo: CsrfEcho) -> CookieRequest {
        CookieRequest {
            method,
            origin,
            echo,
        }
    }

    /// Ann's browser loads a page with her cookie, from a link on another
    /// site. Reading changes nothing, so it passes without a CSRF proof.
    #[test]
    fn a_request_that_only_reads_needs_no_proof() {
        for method in [HttpMethod::Get, HttpMethod::Head, HttpMethod::Options] {
            let read = request(method, PageOrigin::Elsewhere, CsrfEcho::default());

            assert!(read.ensure_not_forged().is_ok(), "{method:?}");
        }
    }

    /// Ann's own page on the app posts a form. It came from the host, so it
    /// passes without echoing the CSRF cookie.
    #[test]
    fn a_change_from_a_trusted_page_passes() {
        let post = request(HttpMethod::Post, PageOrigin::Trusted, CsrfEcho::default());

        assert!(post.ensure_not_forged().is_ok());
    }

    /// Ann's page script echoes the CSRF cookie in the header of a delete.
    /// It passes.
    #[test]
    fn a_change_echoing_the_csrf_cookie_passes() {
        let delete = request(
            HttpMethod::Delete,
            PageOrigin::Elsewhere,
            echo(Some("t0k3n"), Some("t0k3n")),
        );

        assert!(delete.ensure_not_forged().is_ok());
    }

    /// A cookie-authenticated POST from an untrusted origin is forbidden
    /// when either CSRF value is missing, the values differ, or both are empty.
    #[test]
    fn a_forged_change_is_refused() {
        for forged in [
            echo(None, None),
            echo(Some("t0k3n"), None),
            echo(None, Some("t0k3n")),
            echo(Some("t0k3n"), Some("guess")),
            echo(Some(""), Some("")),
        ] {
            let post = request(HttpMethod::Post, PageOrigin::Elsewhere, forged);

            assert!(matches!(
                post.ensure_not_forged(),
                Err(DomainError::Forbidden(_))
            ));
        }
    }
}
