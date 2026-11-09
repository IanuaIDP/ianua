//! Tenants' own domains: the proxy's address, the nameservers names are
//! delegated to, the certificate authority, how long claims hold, and the
//! listener the nameservers follow the zones on.

use std::net::SocketAddr;
use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{DomainName, Email, IpAddress};
use ianua_grpc::{GrpcConfig, GrpcTls};
use ianua_infra::tls::AcmeDirectory;

const MINUTE: Duration = Duration::from_secs(60);
const DAY: Duration = Duration::from_secs(86_400);

/// The certificate authority custom domains' certificates come from.
#[derive(Debug, Clone)]
pub(crate) struct AcmeConfig {
    /// `ACME_DIRECTORY_URL`: the authority's directory.
    pub directory: AcmeDirectory,
    /// `ACME_CONTACT_EMAIL`: where it writes about expiry and revocation.
    pub contact: Option<Email>,
}

/// The setting that says custom domains' TLS is ended in front of the
/// gateway.
const TERMINATED_UPSTREAM: &str = "TLS_TERMINATED_UPSTREAM";

/// Where custom domains' certificates come from.
#[derive(Debug, Clone)]
pub(crate) enum CertificateSource {
    /// No automatic issuance; custom domains require uploaded certificates.
    UploadedOnly,
    /// Ordered from the authority `ACME_DIRECTORY_URL` names.
    Acme(AcmeConfig),
    /// Signed here, because `TLS_TERMINATED_UPSTREAM` says browsers meet a
    /// certificate in front of the gateway and never this one.
    EndedUpstream,
    /// Signed here outside production, with neither set. Browsers warn on
    /// these.
    SelfSignedInDevelopment,
}

/// Tenants' own domains.
#[derive(Debug, Clone)]
pub(crate) struct DomainsConfig {
    /// `PROXY_PUBLIC_ADDRESS`: the gateway's public address, for a domain
    /// at a zone apex and a delegated one.
    pub proxy_address: Option<IpAddress>,
    /// `DNS_NAMESERVERS`: the nameservers a tenant delegates a name to;
    /// empty keeps every domain managed by its tenant.
    pub nameservers: Vec<DomainName>,
    /// `DNS_RESOLVERS`: the recursive resolvers a domain proof asks, such as
    /// `1.1.1.1, 9.9.9.9:53`, in place of the host's own. A proof by `TXT`
    /// or `CNAME` record is read through them, and a delegation's parent
    /// zone and its servers are found through them before those servers are
    /// asked directly. Empty asks the host's resolvers, which inside a
    /// cluster may be a split-horizon or caching resolver that answers for
    /// names differently than the public DNS a customer wrote their record
    /// in.
    pub resolvers: Vec<SocketAddr>,
    /// `ACME_DIRECTORY_URL` and `ACME_CONTACT_EMAIL`, or
    /// `TLS_TERMINATED_UPSTREAM`; absent in production means uploaded certificates only.
    pub certificates: CertificateSource,
    /// `ACME_DNS_PROPAGATION_TIMEOUT_SECONDS` (120): the longest wait for a
    /// DNS proof to be seen.
    pub proof_wait: Duration,
    /// `ACME_DNS_POLL_INTERVAL_SECONDS` (3): how often it is looked for.
    pub proof_poll: Duration,
    /// `DOMAIN_UNPROVED_CLAIM_TTL_DAYS` (7): how long a claim never proved
    /// holds its name against other tenants.
    pub unproved_claim_ttl: Duration,
    /// `DOMAIN_FAILED_CLAIM_GRACE_DAYS` (14): how long a claim whose proof
    /// failed keeps its name.
    pub failed_claim_grace: Duration,
    /// `TLS_RENEWAL_THRESHOLD_DAYS` (30): how long before expiry a
    /// certificate is renewed.
    pub tls_renewal_threshold: Duration,
    /// `TLS_PENDING_STALE_MINUTES` (30): how long an order may sit before
    /// it is tried again.
    pub tls_pending_stale_after: Duration,
    /// The listener nameservers outside the cluster follow the zones on,
    /// over mutual TLS: `GRPC_LISTEN`, such as `0.0.0.0:50051`, with the
    /// certificate chain in `GRPC_TLS_CERT_PATH`, its key in
    /// `GRPC_TLS_KEY_PATH`, and in `GRPC_CLIENT_CA_PATH` the deployment's
    /// own authority the nameservers' certificates chain to. None opens no
    /// listener; API nodes open it.
    pub grpc: Option<GrpcConfig>,
}

impl DomainsConfig {
    /// The domain settings `vars` holds.
    ///
    /// # Errors
    ///
    /// A setting that does not read, a contact with no authority, both an
    /// authority and `TLS_TERMINATED_UPSTREAM`, or
    /// the nameserver listener without all of its files.
    pub(crate) fn read(vars: &Env, environment: Environment) -> Read<Self> {
        let mut nameservers = Vec::new();
        for entry in vars.list("DNS_NAMESERVERS")? {
            nameservers.push(
                DomainName::new(entry)
                    .map_err(|cause| ConfigError::rejected("DNS_NAMESERVERS", cause))?,
            );
        }
        Ok(Self {
            proxy_address: vars.parsed("PROXY_PUBLIC_ADDRESS", IpAddress::new)?,
            nameservers,
            resolvers: resolvers(vars)?,
            certificates: certificates(vars, environment)?,
            proof_wait: vars.seconds("ACME_DNS_PROPAGATION_TIMEOUT_SECONDS", 2 * MINUTE)?,
            proof_poll: vars.seconds("ACME_DNS_POLL_INTERVAL_SECONDS", Duration::from_secs(3))?,
            unproved_claim_ttl: vars.days("DOMAIN_UNPROVED_CLAIM_TTL_DAYS", 7 * DAY)?,
            failed_claim_grace: vars.days("DOMAIN_FAILED_CLAIM_GRACE_DAYS", 14 * DAY)?,
            tls_renewal_threshold: vars.days("TLS_RENEWAL_THRESHOLD_DAYS", 30 * DAY)?,
            tls_pending_stale_after: vars.minutes("TLS_PENDING_STALE_MINUTES", 30 * MINUTE)?,
            grpc: grpc(vars)?,
        })
    }
}

/// `DNS_RESOLVERS`: addresses, each with its port or on port 53.
fn resolvers(vars: &Env) -> Read<Vec<SocketAddr>> {
    let name = "DNS_RESOLVERS";
    vars.list(name)?
        .into_iter()
        .map(|entry| {
            resolver_address(&entry).ok_or_else(|| {
                ConfigError::invalid(
                    name,
                    format!("must list IP addresses, each with an optional port, got {entry:?}"),
                )
            })
        })
        .collect()
}

/// `entry` as a resolver's address: an address and port, or an IP address
/// on port 53.
fn resolver_address(entry: &str) -> Option<SocketAddr> {
    entry.parse().ok().or_else(|| {
        entry
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, DNS_PORT))
    })
}

/// The port resolvers listen on unless told otherwise.
const DNS_PORT: u16 = 53;

/// Where certificates come from: the authority, TLS ended in front of the
/// gateway, or, outside production only, certificates signed here.
fn certificates(vars: &Env, environment: Environment) -> Read<CertificateSource> {
    let ended_upstream = vars.flag(TERMINATED_UPSTREAM, false)?;
    match (acme(vars)?, ended_upstream) {
        (Some(_), true) => Err(ConfigError::contradicts(
            TERMINATED_UPSTREAM,
            "is set beside ACME_DIRECTORY_URL: certificates are either ordered here or met in front of the gateway",
        )),
        (Some(acme), false) => Ok(CertificateSource::Acme(acme)),
        (None, true) => Ok(CertificateSource::EndedUpstream),
        (None, false) if environment.is_production() => Ok(CertificateSource::UploadedOnly),
        (None, false) => Ok(CertificateSource::SelfSignedInDevelopment),
    }
}

/// The certificate authority, when its directory is set.
fn acme(vars: &Env) -> Read<Option<AcmeConfig>> {
    let contact = vars.parsed("ACME_CONTACT_EMAIL", Email::new)?;
    let Some(directory) = vars.optional("ACME_DIRECTORY_URL")? else {
        if contact.is_some() {
            return Err(ConfigError::contradicts(
                "ACME_CONTACT_EMAIL",
                "is set without ACME_DIRECTORY_URL",
            ));
        }
        return Ok(None);
    };
    let directory = AcmeDirectory::parse(&directory)
        .map_err(|cause| ConfigError::rejected("ACME_DIRECTORY_URL", cause))?;
    Ok(Some(AcmeConfig { directory, contact }))
}

/// The nameserver listener: its address and all three files, or nothing.
fn grpc(vars: &Env) -> Read<Option<GrpcConfig>> {
    let files = [
        "GRPC_TLS_CERT_PATH",
        "GRPC_TLS_KEY_PATH",
        "GRPC_CLIENT_CA_PATH",
    ];
    let Some(listen) = vars.parsed("GRPC_LISTEN", |address| address.parse::<SocketAddr>())? else {
        for name in files {
            if vars.optional(name)?.is_some() {
                return Err(ConfigError::contradicts(name, "is set without GRPC_LISTEN"));
            }
        }
        return Ok(None);
    };
    let read = |name: &str| {
        vars.file_text(name)?
            .ok_or_else(|| ConfigError::missing(name))
    };
    Ok(Some(GrpcConfig {
        listen,
        tls: GrpcTls {
            certificate_pem: read("GRPC_TLS_CERT_PATH")?,
            private_key_pem: Secret::new(read("GRPC_TLS_KEY_PATH")?),
            client_ca_pem: read("GRPC_CLIENT_CA_PATH")?,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The domain settings `vars` holds, read outside production.
    fn development(vars: &Env) -> Read<DomainsConfig> {
        DomainsConfig::read(vars, Environment::Development)
    }

    /// With nothing set, domains are managed by their tenants, certificates
    /// are signed here, and no nameserver listener opens.
    #[test]
    fn with_nothing_set_nothing_is_delegated_or_ordered() {
        let config = development(&Env::of([])).unwrap();

        assert!(config.nameservers.is_empty());
        assert!(config.resolvers.is_empty());
        assert!(matches!(
            config.certificates,
            CertificateSource::SelfSignedInDevelopment
        ));
        assert!(config.grpc.is_none());
        assert_eq!(config.unproved_claim_ttl, 7 * DAY);
    }

    /// A nameserver list containing an invalid domain is refused, naming
    /// the nameserver setting.
    #[test]
    fn a_nameserver_that_is_no_domain_is_refused() {
        let read = development(&Env::of([(
            "DNS_NAMESERVERS",
            "ns1.example.com, not a name",
        )]));

        assert!(
            matches!(read, Err(ConfigError::Rejected { name, .. }) if name == "DNS_NAMESERVERS")
        );
    }

    /// The resolvers domain proofs ask are read with their ports, or on
    /// port 53.
    #[test]
    fn resolvers_are_read_with_their_ports() {
        let config = development(&Env::of([("DNS_RESOLVERS", "1.1.1.1, 127.0.0.1:5353")])).unwrap();

        assert_eq!(
            config.resolvers,
            vec![
                "1.1.1.1:53".parse::<SocketAddr>().unwrap(),
                "127.0.0.1:5353".parse().unwrap()
            ]
        );
    }

    /// A resolver hostname is refused because configuration requires a
    /// numeric address.
    #[test]
    fn a_resolver_that_is_no_address_is_refused() {
        let read = development(&Env::of([("DNS_RESOLVERS", "dns.google")]));

        assert!(matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "DNS_RESOLVERS"));
    }

    /// An authority over plain HTTP elsewhere than this machine is refused.
    #[test]
    fn an_authority_over_plain_http_is_refused() {
        let read = development(&Env::of([(
            "ACME_DIRECTORY_URL",
            "http://acme.example.com/directory",
        )]));

        assert!(read.is_err());
    }

    /// Production without a certificate authority selects uploaded
    /// certificates as its only certificate source.
    #[test]
    fn production_without_an_authority_requires_uploaded_certificates() {
        let config = DomainsConfig::read(&Env::of([]), Environment::Production).unwrap();
        assert!(matches!(
            config.certificates,
            CertificateSource::UploadedOnly
        ));
    }

    /// Production may sign its own where TLS is ended in front of the
    /// gateway, as the setting says.
    #[test]
    fn production_with_tls_ended_upstream_signs_its_own() {
        let vars = Env::of([(TERMINATED_UPSTREAM, "true")]);

        let config = DomainsConfig::read(&vars, Environment::Production).unwrap();

        assert!(matches!(
            config.certificates,
            CertificateSource::EndedUpstream
        ));
    }

    /// Configuring both an ACME authority and upstream TLS termination is
    /// refused as contradictory configuration.
    #[test]
    fn an_authority_beside_tls_ended_upstream_is_refused() {
        let vars = Env::of([
            (
                "ACME_DIRECTORY_URL",
                "https://acme-v02.api.letsencrypt.org/directory",
            ),
            (TERMINATED_UPSTREAM, "true"),
        ]);

        let read = DomainsConfig::read(&vars, Environment::Production);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == TERMINATED_UPSTREAM)
        );
    }

    /// A contact with no authority to give it to is refused.
    #[test]
    fn a_contact_with_no_authority_is_refused() {
        let read = development(&Env::of([("ACME_CONTACT_EMAIL", "ops@example.com")]));

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "ACME_CONTACT_EMAIL")
        );
    }

    /// A nameserver listener address without TLS files is refused, naming
    /// the missing certificate setting.
    #[test]
    fn the_nameserver_listener_without_its_files_is_refused() {
        let read = development(&Env::of([("GRPC_LISTEN", "0.0.0.0:50051")]));

        assert!(matches!(read, Err(ConfigError::Missing { name }) if name == "GRPC_TLS_CERT_PATH"));
    }

    /// The listener's files without its address are refused.
    #[test]
    fn the_listeners_files_without_its_address_are_refused() {
        let read = development(&Env::of([("GRPC_TLS_CERT_PATH", "/run/pki/server.crt")]));

        assert!(matches!(read, Err(ConfigError::Contradicts { .. })));
    }

    /// A proxy address that is no IP address is refused.
    #[test]
    fn a_proxy_address_that_is_no_ip_is_refused() {
        assert!(development(&Env::of([("PROXY_PUBLIC_ADDRESS", "proxy.example.com")])).is_err());
    }
}
