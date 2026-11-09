//! The local targets the connector may dial, and the check of every target
//! the gateway asks for against them.
//!
//! Deny by default. A target is dialled only when the list names it: a
//! host name and its port, an address and its port, or a network and a
//! port. An address the list does not name is refused even when it is
//! private and a listed name lives there, so the gateway can never be made
//! to reach the domain controller next to the wiki. A listed name is
//! trusted to say where it lives, except that it may not lead to a
//! loopback, link-local, unspecified or multicast address unless that
//! address is listed itself: a name pointed at the cloud's metadata
//! service reaches nothing.

use std::fmt;
use std::net::IpAddr;

use ipnet::IpNet;

/// The longest host name read.
const MAX_NAME: usize = 253;

/// Why an allow list entry or a requested target was not read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub(crate) struct TargetError(&'static str);

/// One entry of the allow list.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    /// A host name, matched without regard to case.
    Name { name: String, port: u16 },
    /// An exact IP and socket number that may be dialled without DNS.
    Address { address: IpAddr, port: u16 },
    /// Every address in a network.
    Network { network: IpNet, port: u16 },
}

/// A target the gateway asked for: a host name or an address, and a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A host name, lower-cased.
    Name {
        /// Lowercase DNS host checked against the local allow list before resolution.
        name: String,
        /// Socket number required by the matching host-name allowance.
        port: u16,
    },
    /// A literal IP destination checked without a DNS lookup.
    Address {
        /// Canonical IP that must be listed or covered by an allowed network.
        address: IpAddr,
        /// Socket number required by the matching IP or network allowance.
        port: u16,
    },
}

impl Target {
    /// The target `authority`, as a `CONNECT` names it: `host:port`, an
    /// IPv6 address in brackets.
    ///
    /// # Errors
    ///
    /// [`TargetError`] when it is not a host or address and a port.
    pub(crate) fn parse(authority: &str) -> Result<Self, TargetError> {
        let (host, port) = split_port(authority)?;
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok(Self::Address {
                address: address.to_canonical(),
                port,
            });
        }
        Ok(Self::Name {
            name: checked_name(host)?,
            port,
        })
    }

    /// Socket number dialled after the destination passes local screening.
    #[must_use]
    pub fn port(&self) -> u16 {
        match self {
            Self::Name { port, .. } | Self::Address { port, .. } => *port,
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name { name, port } => write!(f, "{name}:{port}"),
            Self::Address { address, port } => {
                write!(f, "{}", std::net::SocketAddr::new(*address, *port))
            }
        }
    }
}

/// The local targets the connector may dial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AllowList {
    entries: Vec<Entry>,
}

impl AllowList {
    /// The list `entries` names, each `host:port`, `address:port`,
    /// `[ipv6]:port` or `network/prefix:port`.
    ///
    /// # Errors
    ///
    /// [`TargetError`] when it names nothing, or an entry does not read.
    pub(crate) fn parse<'a>(
        entries: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, TargetError> {
        let entries = entries
            .into_iter()
            .map(entry_of)
            .collect::<Result<Vec<_>, _>>()?;
        if entries.is_empty() {
            return Err(TargetError("the allow list names no target"));
        }
        Ok(Self { entries })
    }

    /// Whether `target` may be dialled: a name the list names with its
    /// port, or an address the list names or holds in a network, with its
    /// port.
    #[must_use]
    pub(crate) fn permits(&self, target: &Target) -> bool {
        match target {
            Target::Name { name, port } => self.names(name, *port),
            Target::Address { address, port } => self.lists_address(*address, *port),
        }
    }

    /// Whether a listed name may lead to `address` on `port`: any address
    /// but a loopback, link-local, unspecified or multicast one, which only
    /// when it is listed itself.
    #[must_use]
    pub(crate) fn admits_resolved(&self, address: IpAddr, port: u16) -> bool {
        let address = address.to_canonical();
        !is_special(address) || self.lists_address(address, port)
    }

    fn names(&self, wanted: &str, wanted_port: u16) -> bool {
        self.entries.iter().any(|entry| {
            matches!(entry, Entry::Name { name, port } if name == wanted && *port == wanted_port)
        })
    }

    fn lists_address(&self, wanted: IpAddr, wanted_port: u16) -> bool {
        self.entries.iter().any(|entry| match entry {
            Entry::Address { address, port } => *address == wanted && *port == wanted_port,
            Entry::Network { network, port } => network.contains(&wanted) && *port == wanted_port,
            Entry::Name { .. } => false,
        })
    }
}

/// One entry of the list.
fn entry_of(text: &str) -> Result<Entry, TargetError> {
    let (host, port) = split_port(text.trim())?;
    if host.contains('/') {
        let network = host
            .parse::<IpNet>()
            .map_err(|_| TargetError("a network entry is not an address and a prefix"))?;
        return Ok(Entry::Network {
            network: network.trunc(),
            port,
        });
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(Entry::Address {
            address: address.to_canonical(),
            port,
        });
    }
    Ok(Entry::Name {
        name: checked_name(host)?,
        port,
    })
}

/// The host and port of `text`, the host unbracketed.
fn split_port(text: &str) -> Result<(&str, u16), TargetError> {
    let (host, port) = match text.strip_prefix('[') {
        Some(rest) => rest
            .split_once("]:")
            .ok_or(TargetError("a bracketed address is not followed by a port"))?,
        None => text
            .rsplit_once(':')
            .ok_or(TargetError("a target names no port"))?,
    };
    if host.is_empty() || (text.starts_with('[') && !host.contains(':')) {
        return Err(TargetError("a target names no host"));
    }
    if !text.starts_with('[') && host.contains(':') {
        return Err(TargetError("an IPv6 address is written in brackets"));
    }
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(TargetError("a target's port is not a port"))?;
    Ok((host, port))
}

/// `host` as a lower-case host name, refused when it is not one.
fn checked_name(host: &str) -> Result<String, TargetError> {
    let name = host.to_ascii_lowercase();
    let labels_read = name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    });
    if name.len() > MAX_NAME || !labels_read {
        return Err(TargetError("a target's host is not a host name"));
    }
    Ok(name)
}

/// Whether `address` is one a name may not lead to unless it is listed.
fn is_special(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &[&str]) -> AllowList {
        AllowList::parse(entries.iter().copied()).unwrap()
    }

    fn target(text: &str) -> Target {
        Target::parse(text).unwrap()
    }

    /// Acme lists its wiki by name. The gateway asks for it in any case
    /// and is let through.
    #[test]
    fn a_listed_name_is_permitted() {
        let allowed = list(&["wiki.corp.internal:443"]);

        assert!(allowed.permits(&target("Wiki.Corp.Internal:443")));
    }

    /// Listing the wiki on port 443 permits neither a different host nor
    /// the wiki's SSH port.
    #[test]
    fn a_target_not_listed_is_refused() {
        let allowed = list(&["wiki.corp.internal:443"]);

        assert!(!allowed.permits(&target("dc.corp.internal:443")));
        assert!(!allowed.permits(&target("wiki.corp.internal:22")));
    }

    /// A hostname allowance grants no access to either of two unlisted
    /// private IP targets.
    #[test]
    fn a_private_address_not_listed_is_refused() {
        let allowed = list(&["wiki.corp.internal:443"]);

        assert!(!allowed.permits(&target("10.0.0.5:443")));
        assert!(!allowed.permits(&target("10.0.0.6:443")));
    }

    /// A network entry lets in an address inside it on its port, and
    /// nothing outside it or on another port.
    #[test]
    fn a_network_entry_admits_its_addresses_on_its_port() {
        let allowed = list(&["10.0.0.0/24:8080"]);

        assert!(allowed.permits(&target("10.0.0.77:8080")));
        assert!(!allowed.permits(&target("10.0.0.77:8081")));
        assert!(!allowed.permits(&target("10.0.1.1:8080")));
    }

    /// An IPv6 address is listed and asked for in brackets.
    #[test]
    fn an_ipv6_address_entry_is_read_in_brackets() {
        let allowed = list(&["[fd00::5]:443"]);

        assert!(allowed.permits(&target("[fd00::5]:443")));
        assert!(!allowed.permits(&target("[fd00::6]:443")));
    }

    /// A listed name cannot resolve to metadata, loopback or link-local
    /// addresses, while its ordinary private address remains permitted.
    #[test]
    fn a_listed_name_never_leads_to_a_special_address() {
        let allowed = list(&["wiki.corp.internal:443"]);

        assert!(!allowed.admits_resolved("169.254.169.254".parse().unwrap(), 443));
        assert!(!allowed.admits_resolved("127.0.0.1".parse().unwrap(), 443));
        assert!(!allowed.admits_resolved("fe80::1".parse().unwrap(), 443));
        assert!(allowed.admits_resolved("10.0.0.5".parse().unwrap(), 443));
    }

    /// A loopback service listed by its own address may be reached through
    /// a name that leads there.
    #[test]
    fn a_special_address_listed_itself_is_admitted() {
        let allowed = list(&["wiki.local:8080", "127.0.0.1:8080"]);

        assert!(allowed.admits_resolved("127.0.0.1".parse().unwrap(), 8080));
    }

    /// An empty list, a missing port, a wildcard and an unbracketed IPv6
    /// address are refused when the list is read.
    #[test]
    fn odd_entries_are_refused() {
        assert!(AllowList::parse(Vec::<&str>::new()).is_err());
        for entry in [
            "wiki.corp.internal",
            "*.corp.internal:443",
            "fd00::5:443",
            "host:0",
        ] {
            assert!(AllowList::parse([entry]).is_err(), "{entry}");
        }
    }
}
