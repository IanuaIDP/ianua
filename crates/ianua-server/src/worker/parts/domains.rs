//! The provisioners certificates are ordered through, built once for the
//! certificate handler and the domain sweeps alike, over the platform's
//! DNS lookups.
//!
//! With a certificate authority set up, a domain the tenant points at us
//! is proved over HTTP-01, answered by the gateway from the challenges
//! kept in the database, and a domain delegated to us over DNS-01, the
//! proof written into our own zone and looked for until it is seen.
//! Without one, every certificate is signed by itself, which only
//! development uses.

use std::sync::Arc;

use ianua_app::ports::domain::{DnsResolver, TlsProvisioner};
use ianua_app::use_cases::domain::certificates::TlsProvisioners;
use ianua_infra::postgres::domain::{
    PgAcmeAccountStore, PgAcmeChallengeStore, PgCrossTenantDomainStore, PgDnsZoneWriter,
    PgPlatformDnsChallenges,
};
use ianua_infra::tls::{
    AcmeAccountStore, AcmeSettings, AcmeTlsProvisioner, DnsProofs, NoTlsProvisioner,
    SelfSignedTlsProvisioner, VisibilityWait, ZoneAcmeDnsChallengeStore,
};

use crate::config::Config;
use crate::config::serving::domains::{AcmeConfig, CertificateSource};
use crate::platform::Platform;

/// The provisioners certificates are ordered through: the authority the
/// configuration names, or self-signed ones where TLS ends in front of the
/// gateway or outside production.
pub(super) fn provisioners(
    platform: &Platform,
    config: &Config,
    resolver: &Arc<dyn DnsResolver>,
) -> TlsProvisioners {
    let acme = match &config.domains.certificates {
        CertificateSource::UploadedOnly => {
            return TlsProvisioners::uniform(Arc::new(NoTlsProvisioner));
        }
        CertificateSource::Acme(acme) => acme,
        CertificateSource::EndedUpstream | CertificateSource::SelfSignedInDevelopment => {
            let signed: Arc<dyn TlsProvisioner> = Arc::new(SelfSignedTlsProvisioner);
            return TlsProvisioners::uniform(signed);
        }
    };
    TlsProvisioners {
        self_managed: over_http(platform, acme),
        delegated: over_dns(platform, config, acme, resolver),
    }
}

/// Issues platform pairs only through DNS-01 in the deployment's own zones.
pub(super) fn platform_provisioner(
    platform: &Platform,
    config: &Config,
    resolver: &Arc<dyn DnsResolver>,
) -> Arc<dyn TlsProvisioner> {
    let CertificateSource::Acme(acme) = &config.domains.certificates else {
        return Arc::new(NoTlsProvisioner);
    };
    Arc::new(AcmeTlsProvisioner::over_dns(
        settings(acme),
        accounts(platform),
        DnsProofs {
            store: Arc::new(PgPlatformDnsChallenges::new(Arc::clone(
                &platform.databases,
            ))),
            resolver: Arc::clone(resolver),
            wait: VisibilityWait {
                longest: config.domains.proof_wait,
                every: config.domains.proof_poll,
            },
        },
    ))
}

/// The account the platform holds with each authority, sealed at rest.
fn accounts(platform: &Platform) -> Arc<dyn AcmeAccountStore> {
    Arc::new(PgAcmeAccountStore::new(
        Arc::clone(&platform.databases),
        platform.secrets.encryptor.clone(),
    ))
}

/// The authority's settings, with the times a production order keeps to.
fn settings(acme: &AcmeConfig) -> AcmeSettings {
    AcmeSettings::standard(acme.directory.clone(), acme.contact.clone())
}

/// Orders proved over HTTP-01, the gateway answering from the challenges
/// kept in the database.
fn over_http(platform: &Platform, acme: &AcmeConfig) -> Arc<dyn TlsProvisioner> {
    Arc::new(AcmeTlsProvisioner::over_http(
        settings(acme),
        accounts(platform),
        Arc::new(PgAcmeChallengeStore::new(Arc::clone(&platform.databases))),
    ))
}

/// Orders proved over DNS-01, the proof written into the zone delegated to
/// us and looked for through `resolver` until it is seen.
fn over_dns(
    platform: &Platform,
    config: &Config,
    acme: &AcmeConfig,
    resolver: &Arc<dyn DnsResolver>,
) -> Arc<dyn TlsProvisioner> {
    let databases = &platform.databases;
    let domains = &config.domains;
    let challenges = Arc::new(ZoneAcmeDnsChallengeStore::new(
        Arc::new(PgCrossTenantDomainStore::new(Arc::clone(databases))),
        Arc::new(PgDnsZoneWriter::new(
            Arc::clone(databases),
            domains.nameservers.clone(),
        )),
    ));
    Arc::new(AcmeTlsProvisioner::over_dns(
        settings(acme),
        accounts(platform),
        DnsProofs {
            store: challenges,
            resolver: Arc::clone(resolver),
            wait: VisibilityWait {
                longest: domains.proof_wait,
                every: domains.proof_poll,
            },
        },
    ))
}
