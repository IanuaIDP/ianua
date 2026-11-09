//! The private authority the two ends of an internal link authenticate
//! each other with, and the certificates it issues: the control plane and
//! the nameservers outside the cluster, or the gateway's workflow listener
//! and the worker.
//!
//! Private on purpose: a public root would let any certificate on the
//! internet open the link, which is the same as no check at all. The
//! authority signs leaves and nothing else, a server certificate serves
//! and cannot be used as a client, and a client certificate is the other
//! way round, so a nameserver taken over cannot pose as the control plane
//! to the other nameserver.

use std::fmt;

use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use time::Duration;

use crate::crypto::certificates::connector::subject_name;
use crate::crypto::certificates::ldap::fresh_serial;

/// How long the link's certificates are good for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkValidity {
    /// The authority's lifetime. Long, as replacing it means issuing every
    /// certificate under it again at the same moment.
    pub authority: Duration,
    /// Each server and client certificate's lifetime.
    pub leaf: Duration,
}

impl Default for LinkValidity {
    /// Ten years for the authority, one for each leaf.
    fn default() -> Self {
        Self {
            authority: Duration::days(3_650),
            leaf: Duration::days(365),
        }
    }
}

/// A certificate and its private key, both PEM. `Debug` shows no key.
pub struct KeyedCertificate {
    /// Public identity presented to the peer during TLS authentication.
    pub certificate_pem: String,
    /// Proves possession of the public identity during the TLS handshake.
    pub private_key_pem: Secret,
}

impl fmt::Debug for KeyedCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyedCertificate")
            .field("private_key_pem", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// One nameserver's identity on the link.
#[derive(Debug)]
pub struct LinkClient {
    /// What it is called, such as `ns1`, and the name its files carry.
    pub name: String,
    /// Its certificate and key.
    pub keyed: KeyedCertificate,
}

/// Everything both ends of the link authenticate each other with.
#[derive(Debug)]
pub struct LinkPki {
    /// The authority. Its key signs everything else and belongs on neither
    /// end of the link.
    pub authority: KeyedCertificate,
    /// The control plane's listener.
    pub server: KeyedCertificate,
    /// One identity per nameserver.
    pub clients: Vec<LinkClient>,
}

/// Which end of the link a certificate is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    Server,
    Client,
}

/// Issues a fresh authority, the listener's certificate for
/// `server_name` (a hostname, or an address), and one client certificate
/// per name in `clients`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a key cannot be made or
/// signed, or `server_name` is neither a hostname nor an address.
pub fn issue_link_pki(
    server_name: &str,
    clients: &[String],
    validity: LinkValidity,
) -> Result<LinkPki, DomainError> {
    let (params, key, authority_pem) = authority(validity.authority)?;
    let authority_key = Secret::new(key.serialize_pem());
    let issuer = Issuer::new(params, key);
    let server = leaf(&issuer, server_name, End::Server, validity.leaf)?;
    let clients = clients
        .iter()
        .map(|name| {
            Ok(LinkClient {
                name: name.clone(),
                keyed: leaf(&issuer, name, End::Client, validity.leaf)?,
            })
        })
        .collect::<Result<Vec<_>, DomainError>>()?;
    Ok(LinkPki {
        authority: KeyedCertificate {
            certificate_pem: authority_pem,
            private_key_pem: authority_key,
        },
        server,
        clients,
    })
}

/// One listener of the internal links: what its files are called, such as
/// `gateway`, and the name or address callers dial it by.
#[derive(Debug, Clone, Copy)]
pub struct InternalListener<'a> {
    /// What its files are called.
    pub name: &'a str,
    /// The name or address it is dialed by, which its certificate names.
    pub host: &'a str,
}

/// One end's certificate on the internal links, by what its files are
/// called.
#[derive(Debug)]
pub struct InternalLeaf {
    /// What its files are called, such as `gateway` or `worker`.
    pub name: String,
    /// Its certificate and key.
    pub keyed: KeyedCertificate,
}

/// Everything the internal links authenticate with: one authority, a
/// server certificate per listener and a client certificate per caller.
#[derive(Debug)]
pub struct InternalPki {
    /// The authority. Its key signs everything else and belongs on no end.
    pub authority: KeyedCertificate,
    /// One server certificate per listener.
    pub servers: Vec<InternalLeaf>,
    /// One client certificate per caller.
    pub clients: Vec<InternalLeaf>,
}

/// Issues a fresh authority, a server certificate for each of `servers`
/// and a client certificate for each name in `clients`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a key cannot be made or
/// signed, or a listener's host is neither a hostname nor an address.
pub fn issue_internal_pki(
    servers: &[InternalListener<'_>],
    clients: &[&str],
    validity: LinkValidity,
) -> Result<InternalPki, DomainError> {
    let (params, key, authority_pem) = authority(validity.authority)?;
    let authority_key = Secret::new(key.serialize_pem());
    let issuer = Issuer::new(params, key);
    let servers = servers
        .iter()
        .map(|server| {
            Ok(InternalLeaf {
                name: server.name.to_owned(),
                keyed: leaf(&issuer, server.host, End::Server, validity.leaf)?,
            })
        })
        .collect::<Result<Vec<_>, DomainError>>()?;
    let clients = clients
        .iter()
        .map(|name| {
            Ok(InternalLeaf {
                name: (*name).to_owned(),
                keyed: leaf(&issuer, name, End::Client, validity.leaf)?,
            })
        })
        .collect::<Result<Vec<_>, DomainError>>()?;
    Ok(InternalPki {
        authority: KeyedCertificate {
            certificate_pem: authority_pem,
            private_key_pem: authority_key,
        },
        servers,
        clients,
    })
}

/// The authority, able to sign leaves and no further authority, so one
/// stolen key cannot make an authority of its own.
fn authority(lifetime: Duration) -> Result<(CertificateParams, KeyPair, String), DomainError> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.serial_number = Some(fresh_serial()?);
    let now = clock::now();
    params.not_before = now;
    params.not_after = now.saturating_add(lifetime);
    params.distinguished_name = common_name("Ianua internal link");
    let key = KeyPair::generate().map_err(DomainError::infra)?;
    let pem = params.self_signed(&key).map_err(DomainError::infra)?.pem();
    Ok((params, key, pem))
}

/// One certificate for `end`, named `name`, signed by `issuer`.
fn leaf(
    issuer: &Issuer<'_, KeyPair>,
    name: &str,
    end: End,
    lifetime: Duration,
) -> Result<KeyedCertificate, DomainError> {
    let mut params = CertificateParams::default();
    params.serial_number = Some(fresh_serial()?);
    let now = clock::now();
    params.not_before = now;
    params.not_after = now.saturating_add(lifetime);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![purpose_of(end)];
    params.distinguished_name = common_name(name);
    params.subject_alt_names = vec![subject_name(name)?];
    let key = KeyPair::generate().map_err(DomainError::infra)?;
    let certificate_pem = params
        .signed_by(&key, issuer)
        .map_err(DomainError::infra)?
        .pem();
    Ok(KeyedCertificate {
        certificate_pem,
        private_key_pem: Secret::new(key.serialize_pem()),
    })
}

/// The one use a certificate for `end` is good for.
fn purpose_of(end: End) -> ExtendedKeyUsagePurpose {
    match end {
        End::Server => ExtendedKeyUsagePurpose::ServerAuth,
        End::Client => ExtendedKeyUsagePurpose::ClientAuth,
    }
}

/// A subject naming `name` alone.
fn common_name(name: &str) -> DistinguishedName {
    let mut subject = DistinguishedName::new();
    subject.push(DnType::CommonName, name);
    subject
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pki() -> LinkPki {
        issue_link_pki(
            "grpc.ianua.test",
            &["ns1".to_owned(), "ns2".to_owned()],
            LinkValidity::default(),
        )
        .unwrap()
    }

    /// The authority, the listener and each named nameserver get a
    /// certificate.
    #[test]
    fn every_identity_is_issued() {
        let pki = pki();

        assert!(pki.authority.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(pki.server.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(pki.clients.len(), 2);
        assert_eq!(pki.clients[0].name, "ns1");
    }

    /// The two nameserver clients receive different private keys.
    #[test]
    fn each_nameserver_gets_its_own_key() {
        let pki = pki();

        assert_ne!(
            pki.clients[0].keyed.private_key_pem.expose(),
            pki.clients[1].keyed.private_key_pem.expose()
        );
    }

    /// The link PKI's debug output omits private-key PEM text.
    #[test]
    fn a_key_never_prints() {
        let pki = pki();

        assert!(!format!("{pki:?}").contains("PRIVATE KEY"));
    }

    /// A listener named by address is issued with an address entry.
    #[test]
    fn a_listener_named_by_address_is_issued() {
        let pki = issue_link_pki("203.0.113.10", &["ns1".to_owned()], LinkValidity::default());

        assert!(pki.is_ok());
    }

    /// The internal links get one authority, a certificate per listener by
    /// its file name and one per caller, each with a key of its own, and
    /// no key prints.
    #[test]
    fn every_internal_listener_and_caller_is_issued() {
        let listeners = [
            InternalListener {
                name: "workflow-listener",
                host: "gateway.ianua.test",
            },
            InternalListener {
                name: "relay-listener",
                host: "10.0.0.7",
            },
        ];

        let pki = issue_internal_pki(&listeners, &["worker", "gateway"], LinkValidity::default())
            .unwrap();

        let names: Vec<&str> = pki
            .servers
            .iter()
            .chain(&pki.clients)
            .map(|leaf| leaf.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["workflow-listener", "relay-listener", "worker", "gateway"]
        );
        assert_ne!(
            pki.clients[0].keyed.private_key_pem.expose(),
            pki.clients[1].keyed.private_key_pem.expose()
        );
        assert!(!format!("{pki:?}").contains("PRIVATE KEY"));
    }
}
