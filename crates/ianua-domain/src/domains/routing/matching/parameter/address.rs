//! Whether a value names an address, and which host it names.

use crate::types::DomainName;

/// The host a URL or bare host name names. `None` for anything with user
/// info, an address literal, or no plain host.
pub(super) fn host_of(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let rest = match trimmed.split_once("://") {
        Some((scheme, rest))
            if matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") =>
        {
            rest
        }
        Some(_) => return None,
        None => trimmed,
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.contains('@') || authority.starts_with('[') {
        return None;
    }
    let host = authority
        .rsplit_once(':')
        .filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit()))
        .map_or(authority, |(host, _)| host);
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    DomainName::new(host)
        .ok()
        .filter(|name| !name.is_wildcard())
        .map(|name| name.as_str().to_owned())
}

/// Schemes a fetching service follows.
const FETCHABLE_SCHEMES: [&str; 16] = [
    "http", "https", "ws", "wss", "ftp", "ftps", "sftp", "file", "gopher", "dict", "ldap", "ldaps",
    "smb", "tftp", "jar", "netdoc",
];

/// Whether a value could name somewhere to go, read the way a lenient URL
/// parser or resolver would read it.
///
/// When in doubt, it says yes. Each of these counts as an address:
/// - A URL with a fetchable scheme in any spelling, such as `https://`,
///   `https:host` or `https:\\host`.
/// - A network path, such as `//host` or `\\host`.
/// - A percent-escape, or a full-width dot.
/// - An IP address in any form a resolver accepts.
/// - A dotted host name, with or without a trailing dot.
/// - A host with a port, even an empty one, or with anything after it, such
///   as `evil.net/x` or `evil.net?x`.
/// - `localhost`, or a single label with a port.
///
/// A label with `_` or a non-ASCII letter counts, since resolvers and IDNA
/// mapping accept them. A bare decimal number does not count. Refusing those
/// would refuse every numeric id, and a route cannot allow a field that
/// names no host.
pub(super) fn names_an_address(value: &str) -> bool {
    let read = as_url_parsers_read(value);
    let trimmed = read.as_str();
    let lowered = trimmed.to_ascii_lowercase();
    let host = HostPart::of(&lowered);
    has_fetchable_scheme(&lowered)
        || lowered.contains("://")
        || trimmed.starts_with("//")
        || has_percent_escape(trimmed)
        || trimmed.contains(['\u{3002}', '\u{FF0E}', '\u{FF61}'])
        || ip_literal(trimmed)
        || ip_literal(host.name)
        || numeric_ip_spelling(host.name)
        || host.is_host_shaped()
}

/// `value` as a WHATWG URL parser reads it before parsing. Browsers and
/// Node's `URL` are such parsers.
///
/// Control characters and spaces are dropped from both ends. Tabs and line
/// breaks are removed throughout, and backslashes read as slashes. So
/// `/\evil.net`, `/<tab>/evil.net` and `<U+0001>//evil.net` all reach a
/// service as `//evil.net`, and are judged as that.
fn as_url_parsers_read(value: &str) -> String {
    value
        .trim_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .map(|c| if c == '\\' { '/' } else { c })
        .collect()
}

/// The part of a value a resolver would read as a host. It runs up to the
/// first `/`, `?`, `#` or `\`, and drops a port and a trailing dot.
struct HostPart<'a> {
    name: &'a str,
    port: PortNumber,
}

/// Whether a host was followed by a port with at least one digit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PortNumber {
    /// A `:` and digits followed the host.
    Given,
    /// No port followed, or only a bare `:`.
    Absent,
}

impl<'a> HostPart<'a> {
    fn of(lowered: &'a str) -> Self {
        let authority = lowered
            .split(['/', '?', '#', '\\'])
            .next()
            .unwrap_or(lowered);
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, "")) => (host, PortNumber::Absent),
            Some((host, digits)) if digits.bytes().all(|b| b.is_ascii_digit()) => {
                (host, PortNumber::Given)
            }
            _ => (authority, PortNumber::Absent),
        };
        Self {
            name: host.strip_suffix('.').unwrap_or(host),
            port,
        }
    }

    /// Whether this looks like a host name. That is one with dots,
    /// `localhost`, or any single label followed by a port.
    fn is_host_shaped(&self) -> bool {
        let label_chars = |label: &str| {
            !label.is_empty()
                && label
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        };
        let labels: Vec<&str> = self.name.split('.').collect();
        let well_formed = labels.iter().all(|label| label_chars(label));
        let dotted_name = labels.len() > 1
            && labels
                .last()
                .is_some_and(|tld| tld.chars().any(char::is_alphabetic));
        well_formed && (dotted_name || self.name == "localhost" || self.port == PortNumber::Given)
    }
}

fn has_fetchable_scheme(lowered: &str) -> bool {
    lowered
        .split_once(':')
        .is_some_and(|(scheme, _)| FETCHABLE_SCHEMES.contains(&scheme))
}

fn has_percent_escape(value: &str) -> bool {
    value.as_bytes().windows(3).any(
        |w| matches!(w, [b'%', high, low] if high.is_ascii_hexdigit() && low.is_ascii_hexdigit()),
    )
}

/// Whether `lowered` is a form a resolver reads as an IPv4 address, other
/// than a bare decimal. Examples are `127.1`, `0x7f.0.0.1`, `0x7f000001` and
/// `017700000001.`.
fn numeric_ip_spelling(lowered: &str) -> bool {
    let value = lowered.strip_suffix('.').unwrap_or(lowered);
    let parts: Vec<&str> = value.split('.').collect();
    let numeric = |part: &&str| {
        let digits = part.strip_prefix("0x").unwrap_or(part);
        !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_hexdigit())
            && (part.starts_with("0x") || part.bytes().all(|b| b.is_ascii_digit()))
    };
    let dotted = (2..=4).contains(&parts.len()) && parts.iter().all(numeric);
    let hex = parts.len() == 1 && value.starts_with("0x") && numeric(&value);
    dotted || hex
}

fn ip_literal(value: &str) -> bool {
    if value.parse::<std::net::IpAddr>().is_ok() || value.parse::<std::net::SocketAddr>().is_ok() {
        return true;
    }
    value
        .strip_prefix('[')
        .and_then(|rest| rest.split(']').next())
        .is_some_and(|inner| inner.parse::<std::net::Ipv6Addr>().is_ok())
}
