//! What is wrong with a host name, if anything: the rules a domain name and an address keep.

/// What is wrong with a domain name that ends in a number, if anything.
///
/// Resolvers and URL parsers read such a name as an IPv4 address, and accept
/// forms like `127.1`, `0x7f.0.0.1` or `0177.0.0.1` for it. Only the ordinary
/// dotted form is allowed, so an address check reads the same address they
/// connect to.
pub(super) fn unusual_ipv4_problem(value: &str) -> Option<&'static str> {
    let last = value.rsplit('.').next()?;
    let hex = last
        .strip_prefix("0x")
        .or_else(|| last.strip_prefix("0X"))
        .is_some_and(|digits| digits.bytes().all(|b| b.is_ascii_hexdigit()));
    let numeric = hex || last.bytes().all(|b| b.is_ascii_digit());
    if !numeric || value.parse::<std::net::Ipv4Addr>().is_ok() {
        return None;
    }
    Some("ends in a number but is not an ordinary IPv4 address like 192.0.2.1")
}

/// What is wrong with an IPv6 address carrying an interface zone, as
/// `fe80::1%eth0`, if anything.
///
/// A zone only means something on a link-local address. It names an
/// interface, so it is 1 to 15 letters, digits, `.`, `_` and `-`. Anything
/// else after the `%` would pass unchecked into wherever the host is written,
/// a line break included.
fn zoned_address_problem(address: &str, zone: &str) -> Option<&'static str> {
    let link_local = address.parse::<std::net::Ipv6Addr>().is_ok_and(|ip| {
        ip.segments()
            .first()
            .is_some_and(|first| first & 0xffc0 == 0xfe80)
    });
    if !link_local {
        return Some("may carry an interface zone only on a link-local IPv6 address");
    }
    let interface = (1..=15).contains(&zone.len())
        && zone
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !interface {
        return Some("names its interface zone with only letters, digits, '.', '_' and '-'");
    }
    None
}

/// What is wrong with a host to connect to, if anything.
pub(super) fn host_problem(host: &str) -> Option<&'static str> {
    if let Some((address, zone)) = host.split_once('%') {
        return zoned_address_problem(address, zone);
    }
    if host.parse::<std::net::Ipv6Addr>().is_ok() || host.parse::<std::net::Ipv4Addr>().is_ok() {
        return None;
    }
    if host.is_empty() || host.len() > 253 {
        return Some("must be between 1 and 253 characters long");
    }
    let legal = host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'));
    if !legal {
        return Some("may hold only letters, digits, '-' and '.', or be an IP address");
    }
    host.split('.')
        .find_map(domain_label_problem)
        .or_else(|| unusual_ipv4_problem(host))
}

/// What is wrong with one label of a domain name, if anything.
pub(super) fn domain_label_problem(label: &str) -> Option<&'static str> {
    if label.is_empty() {
        return Some("contains an empty label (leading, trailing, or consecutive dots)");
    }
    if label.len() > 63 {
        return Some("contains a label longer than 63 characters");
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Some("contains a label that starts or ends with a hyphen");
    }
    None
}
