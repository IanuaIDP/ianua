//! The network settings both composition roots read the same way: a
//! listener's certificate and key, the peers whose word on the client's
//! address is believed, and the internal networks tenants' addresses may
//! reach.

use std::path::PathBuf;

use ianua_domain::domains::proxy::request::forwarded::TrustedProxies;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;

use crate::env::{ConfigError, Env, Read};

/// A certificate and its key, as file paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemFiles {
    /// The certificate's file.
    pub certificate: PathBuf,
    /// The key's file.
    pub key: PathBuf,
}

impl Env {
    /// The certificate and key the settings `certificate` and `key` name:
    /// both or neither.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Contradicts`] naming the one set without the other.
    pub fn pem_files(&self, certificate: &str, key: &str) -> Read<Option<PemFiles>> {
        match (self.path(certificate)?, self.path(key)?) {
            (Some(certificate), Some(key)) => Ok(Some(PemFiles { certificate, key })),
            (None, None) => Ok(None),
            (Some(_), None) => Err(ConfigError::contradicts(
                certificate,
                format!("is set without {key}"),
            )),
            (None, Some(_)) => Err(ConfigError::contradicts(
                key,
                format!("is set without {certificate}"),
            )),
        }
    }

    /// The addresses and CIDR blocks `name` lists, as peers to believe;
    /// empty believes nobody.
    ///
    /// The domain drops an entry it cannot read, trusting less; at start a
    /// typo is refused instead, since believing nobody by mistake records
    /// every client as the proxy in front and puts all of them under one
    /// rate limit.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] naming the first entry that is no address
    /// or block.
    pub fn peers(&self, name: &str) -> Read<TrustedProxies> {
        let entries = self.list(name)?;
        let unreadable = entries
            .iter()
            .find(|entry| TrustedProxies::parse(entry).is_empty());
        if let Some(entry) = unreadable {
            return Err(ConfigError::invalid(
                name,
                format!("must list addresses and CIDR blocks, got {entry:?}"),
            ));
        }
        Ok(TrustedProxies::parse(&entries.join(",")))
    }

    /// The internal networks `name` lists as CIDR blocks, beside public
    /// addresses; public addresses only when unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Rejected`] for an entry that is no CIDR block.
    pub fn networks(&self, name: &str) -> Read<UpstreamNetworks> {
        Ok(self
            .parsed(name, |list| UpstreamNetworks::parse_list(&list))?
            .unwrap_or_else(UpstreamNetworks::public_only))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Configured PEM paths form a pair; omitting both leaves TLS unconfigured.
    #[test]
    fn a_certificate_and_its_key_are_read_together() {
        let vars = Env::of([("CERT", "/run/pki/a.crt"), ("KEY", "/run/pki/a.key")]);

        let files = vars.pem_files("CERT", "KEY").unwrap().unwrap();

        assert_eq!(files.certificate, PathBuf::from("/run/pki/a.crt"));
        assert!(Env::of([]).pem_files("CERT", "KEY").unwrap().is_none());
    }

    /// Half of a pair is refused, naming the half that was set.
    #[test]
    fn half_a_pair_is_refused() {
        let read = Env::of([("KEY", "/run/pki/a.key")]).pem_files("CERT", "KEY");

        assert!(matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "KEY"));
    }

    /// Peers take addresses and CIDR blocks.
    #[test]
    fn peers_take_addresses_and_blocks() {
        let vars = Env::of([("PEERS", "10.0.0.0/8, 192.168.1.1")]);

        let peers = vars.peers("PEERS").unwrap();

        assert!(peers.contains("10.1.2.3".parse().unwrap()));
        assert!(peers.contains("192.168.1.1".parse().unwrap()));
        assert!(!peers.contains("192.168.1.2".parse().unwrap()));
    }

    /// A malformed CIDR entry refuses the peer list and names its setting.
    #[test]
    fn a_peer_that_is_no_address_is_refused() {
        let read = Env::of([("PEERS", "10.0.0.0/8, 10.0.0/8")]).peers("PEERS");

        assert!(matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "PEERS"));
    }

    /// Unset networks are public addresses only, and a range that does not
    /// read is refused.
    #[test]
    fn networks_are_public_only_unless_listed() {
        let vars = Env::of([("BAD", "10.0.0.0/8, 10.0.0.0")]);

        assert_eq!(
            vars.networks("UNSET").unwrap(),
            UpstreamNetworks::public_only()
        );
        assert!(matches!(
            vars.networks("BAD"),
            Err(ConfigError::Rejected { name, .. }) if name == "BAD"
        ));
    }
}
