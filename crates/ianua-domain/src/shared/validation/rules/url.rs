//! The one way the domain reads a URL.
//!
//! A URL is checked with the parser the HTTP clients use. It is only
//! accepted when every reader would agree on where it points. The host is
//! taken from the parsed URL, never from the text. So a check on it sees the
//! address a client connects to. Forms that some readers rewrite and others
//! do not are refused, not guessed at:
//!
//! - an IPv4 address written as one number, or with short, hex or octal
//!   octets, which a client reads as an ordinary address
//! - a backslash, which a browser-style parser treats as a slash, so the
//!   host moves
//! - whitespace or control characters, which a parser drops, joining the
//!   pieces around them
//! - credentials before the host. They end up in logs, and are the usual
//!   way to make a URL look like it goes somewhere else.
//! - a host written with percent-escapes
//! - a scheme in any form but `scheme://`

use std::net::{IpAddr, Ipv6Addr};

use crate::shared::validation::error::ValidationError;
use crate::shared::validation::validator::Validator;

/// Where a URL points: a name to be resolved, or an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlHost<'a> {
    /// A DNS name, screened again once it resolves.
    Name(&'a str),
    /// An IP address, written as one.
    Address(IpAddr),
}

/// What a URL may carry after its host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UrlShape {
    /// A path, a query and a fragment are all allowed.
    Any,
    /// Nothing after the host and port: the shape of a web origin.
    OriginOnly,
}

/// The rules a URL is read under.
#[derive(Debug, Clone, Copy)]
pub(crate) struct UrlRules {
    /// The schemes it may use, in lower case.
    pub(crate) schemes: &'static [&'static str],
    /// The longest it may be, in bytes.
    pub(crate) max_len: usize,
    /// What it may carry after its host.
    pub(crate) shape: UrlShape,
}

/// An `http://` or `https://` URL of at most 2048 bytes, with anything after
/// its host.
pub(crate) const WEB: UrlRules = UrlRules {
    schemes: &["http", "https"],
    max_len: 2048,
    shape: UrlShape::Any,
};

/// Reads `value` as a URL under `rules`.
///
/// # Errors
///
/// Returns [`ValidationError`] naming `field` for empty, oversized or non-ASCII
/// text, controls, whitespace or backslashes; a disallowed scheme or unreadable
/// URL; credentials, a missing or noncanonical host, or a suffix the shape forbids.
pub(crate) fn parse(
    field: &'static str,
    value: &str,
    rules: UrlRules,
) -> Result<url::Url, ValidationError> {
    Validator::new(field, value)
        .not_empty()
        .max_bytes(rules.max_len)
        .ascii_only()
        .no_control_chars()
        .no_whitespace()
        .no_backslash()
        .validate_first()?;

    let after_scheme = after_scheme(value, rules.schemes).ok_or_else(|| {
        invalid(
            field,
            "invalid_scheme",
            format!("{field} must start with {}.", scheme_list(rules.schemes)),
        )
    })?;
    let parsed = url::Url::parse(value)
        .map_err(|_| invalid(field, "invalid_url", format!("{field} is not a valid URL.")))?;

    ensure_no_credentials(field, &parsed)?;
    ensure_host_as_written(field, after_scheme, &parsed)?;
    ensure_shape(field, value, &parsed, rules.shape)?;
    Ok(parsed)
}

impl Validator<'_> {
    /// Requires a URL under `rules`, as [`parse`] reads it.
    #[must_use]
    pub(crate) fn web_url(mut self, rules: UrlRules) -> Self {
        if let Err(error) = parse(self.field, self.value, rules) {
            self.errors.push(error);
        }
        self
    }
}

/// Where a parsed URL points.
///
/// A URL from [`parse`] always has a host. One without reads as an empty
/// name, which no address check admits.
#[must_use]
pub(crate) fn host_of(url: &url::Url) -> UrlHost<'_> {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => UrlHost::Address(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => UrlHost::Address(IpAddr::V6(ip)),
        Some(url::Host::Domain(name)) => UrlHost::Name(name),
        None => UrlHost::Name(""),
    }
}

/// What `value` says after `scheme://`, when it starts with one of `schemes`.
fn after_scheme<'v>(value: &'v str, schemes: &[&str]) -> Option<&'v str> {
    schemes.iter().find_map(|scheme| {
        value
            .strip_prefix(scheme)
            .and_then(|rest| rest.strip_prefix("://"))
    })
}

fn scheme_list(schemes: &[&str]) -> String {
    schemes
        .iter()
        .map(|scheme| format!("{scheme}://"))
        .collect::<Vec<_>>()
        .join(" or ")
}

fn ensure_no_credentials(field: &'static str, parsed: &url::Url) -> Result<(), ValidationError> {
    if parsed.username().is_empty() && parsed.password().is_none() {
        return Ok(());
    }
    Err(invalid(
        field,
        "credentials_in_url",
        format!("{field} must not carry a user name or password."),
    ))
}

/// Refuses a host the parser had to rewrite, because it was written in a
/// form readers disagree on.
fn ensure_host_as_written(
    field: &'static str,
    after_scheme: &str,
    parsed: &url::Url,
) -> Result<(), ValidationError> {
    let written = written_host(after_scheme);
    let agrees = match parsed.host() {
        Some(url::Host::Ipv6(ip)) => bracketed_v6(written) == Some(ip),
        Some(url::Host::Ipv4(ip)) => written == ip.to_string(),
        Some(url::Host::Domain(name)) => !name.is_empty() && written.eq_ignore_ascii_case(name),
        None => false,
    };
    if agrees {
        return Ok(());
    }
    Err(invalid(
        field,
        "invalid_host",
        format!("{field} must name its host plainly, as a name or an ordinary IP address."),
    ))
}

/// The host as written: the authority without its port.
fn written_host(after_scheme: &str) -> &str {
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    if authority.starts_with('[') {
        return authority.split_inclusive(']').next().unwrap_or(authority);
    }
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
}

fn bracketed_v6(written: &str) -> Option<Ipv6Addr> {
    written.strip_prefix('[')?.strip_suffix(']')?.parse().ok()
}

fn ensure_shape(
    field: &'static str,
    value: &str,
    parsed: &url::Url,
    shape: UrlShape,
) -> Result<(), ValidationError> {
    let has_query = parsed.query().is_some() || parsed.fragment().is_some();
    let fits = match shape {
        UrlShape::Any => true,
        UrlShape::OriginOnly => !has_query && parsed.path() == "/" && !value.ends_with('/'),
    };
    if fits {
        return Ok(());
    }
    Err(invalid(
        field,
        "invalid_url_shape",
        format!("{field} must be a scheme, a host and an optional port, with nothing after."),
    ))
}

fn invalid(field: &'static str, code: &str, message: String) -> ValidationError {
    ValidationError::Custom {
        field,
        code: code.to_owned(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEB: UrlRules = UrlRules {
        schemes: &["http", "https"],
        max_len: 2048,
        shape: UrlShape::Any,
    };

    fn host(value: &str) -> Option<String> {
        parse("url", value, WEB)
            .ok()
            .map(|url| format!("{:?}", host_of(&url)))
    }

    /// A name with port, path and query gives the name `api.acme.com`. An
    /// IPv4 and an IPv6 address give the address, the IPv6 one in short form.
    #[test]
    fn an_ordinary_url_names_its_host() {
        assert_eq!(
            host("https://api.acme.com:8443/v1?x=1"),
            Some(r#"Name("api.acme.com")"#.to_owned())
        );
        assert_eq!(
            host("http://10.0.0.1/"),
            Some("Address(10.0.0.1)".to_owned())
        );
        assert_eq!(
            host("http://[fd00:0:0::1]:80/"),
            Some("Address(fd00::1)".to_owned())
        );
    }

    /// Ambiguous numeric hosts, escaped hostnames, and backslash forms yield no validated URL host.
    #[test]
    fn a_host_a_parser_would_rewrite_is_refused() {
        for value in [
            "http://2130706433/",
            "http://0x7f.0.0.1/",
            "http://127.1/",
            "http://ex%61mple.com/",
            "http://acme.com\\@10.0.0.1/",
        ] {
            assert_eq!(host(value), None, "{value} was accepted");
        }
    }

    /// `API.acme.com` is accepted and read as `api.acme.com`. DNS names
    /// ignore case, so this is not a rewrite.
    #[test]
    fn a_host_in_upper_case_is_the_same_host() {
        assert_eq!(
            host("https://API.acme.com/"),
            Some(r#"Name("api.acme.com")"#.to_owned())
        );
    }

    /// An uppercase scheme, `https:` with no slashes or one slash, and `ftp`
    /// are all refused. Only `http://` and `https://` written in lowercase
    /// pass.
    #[test]
    fn a_scheme_in_any_other_form_is_refused() {
        for value in [
            "HTTPS://acme.com/",
            "https:acme.com",
            "https:/acme.com",
            "ftp://acme.com/",
        ] {
            assert_eq!(host(value), None, "{value} was accepted");
        }
    }

    /// Under the origin shape, a host with a port passes. A trailing slash,
    /// a path or a query is refused, since a browser origin has none of them.
    #[test]
    fn an_origin_has_nothing_after_its_host_and_port() {
        let origin = UrlRules {
            shape: UrlShape::OriginOnly,
            ..WEB
        };

        assert!(parse("origin", "https://app.acme.com:8443", origin).is_ok());
        assert!(parse("origin", "https://app.acme.com/", origin).is_err());
        assert!(parse("origin", "https://app.acme.com/x", origin).is_err());
        assert!(parse("origin", "https://app.acme.com?x", origin).is_err());
    }
}
