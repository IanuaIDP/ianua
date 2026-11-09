//! The custom domain use cases the API serves: registering a domain,
//! proving it, its certificate, handing it to another tenant, and the
//! records of a zone delegated to us.

use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_app::use_cases::domain::certificates;
use ianua_app::use_cases::domain::dns_records::zone::ZonePorts;
use ianua_app::use_cases::domain::dns_records::{ListUseCase, RemoveUseCase, SetPorts, SetUseCase};
use ianua_app::use_cases::domain::handover::{
    AcceptDomainPorts, AcceptDomainUseCase, OfferDomainPorts, OfferDomainUseCase,
};
use ianua_app::use_cases::domain::registration::{
    AddDomainPorts, AddDomainUseCase, DelegationOffer, GetDomainPorts, GetDomainUseCase,
    ListDomainsPorts, ListDomainsUseCase, RemoveDomainPorts, RemoveDomainUseCase,
};
use ianua_app::use_cases::domain::verification::proof::ProofRules;
use ianua_app::use_cases::domain::verification::verified::CertificateQueue;
use ianua_app::use_cases::domain::verification::{VerifyDomainPorts, VerifyDomainUseCase};
use ianua_domain::domains::tenant::custom_domains::registered_domain::ClaimLifetimes;
use ianua_domain::domains::tenant::custom_domains::trusted_domains::TrustedDomains;
use ianua_domain::domains::tenant::hosts::PlatformAddressing;
use ianua_domain::types::{DomainName, IpAddress};

use crate::deps::{Adapters, Settings};

/// The deployment facts a domain's DNS instructions are built from.
pub struct DnsFacts {
    /// Nameservers a tenant delegates a hostname to.
    pub nameservers: Vec<DomainName>,
    /// The proxy's public address, when the operator set one.
    pub proxy_address: Option<IpAddress>,
    /// Parent domains the operator vouches for, whose names need no proof.
    pub trusted: TrustedDomains,
    /// The domain each tenant's platform subdomains sit under.
    pub base_domain: DomainName,
    /// Whether random tenant roots resolve through platform DNS.
    pub addressing: PlatformAddressing,
}

/// What this deployment offers a tenant's custom domains: where a delegated
/// domain is handed, what a delegated name answers with, which names it
/// vouches for without proof, and how long an unproved claim holds a name.
#[derive(Clone)]
pub struct CustomDomainSettings {
    /// Nameservers a tenant delegates a hostname to. Empty turns delegation
    /// off.
    pub nameservers: Vec<DomainName>,
    /// The proxy's public address, for a delegated name, and for a tenant
    /// whose domain is a zone apex. `None` when the operator set none.
    pub proxy_address: Option<IpAddress>,
    /// Parent domains the operator vouches for, whose names need no DNS
    /// proof. Empty on every deployment serving more than one organization.
    pub trusted: TrustedDomains,
    /// How long a claim without a standing proof holds its name against
    /// other tenants.
    pub claim_lifetimes: ClaimLifetimes,
}

/// The custom domain use cases, and the deployment facts their answers
/// name.
#[derive(Clone)]
pub struct DomainState {
    pub registration: RegistrationUseCases,
    pub verify: Arc<VerifyDomainUseCase>,
    pub certificates: CertificateUseCases,
    pub handover: HandoverUseCases,
    pub dns_records: DnsRecordUseCases,
    /// What a domain's DNS instructions name: the deployment's nameservers,
    /// proxy address and vouched-for domains, and the platform's base
    /// domain.
    pub dns: Arc<DnsFacts>,
}

/// Registering, listing and removing a tenant's domains.
#[derive(Clone)]
pub struct RegistrationUseCases {
    pub add: Arc<AddDomainUseCase>,
    pub get: Arc<GetDomainUseCase>,
    pub list: Arc<ListDomainsUseCase>,
    pub remove: Arc<RemoveDomainUseCase>,
}

/// A verified domain's certificate: asked for through ACME, or uploaded,
/// replaced and removed by the tenant.
#[derive(Clone)]
pub struct CertificateUseCases {
    pub request: Arc<certificates::RequestTlsUseCase>,
    pub upload: Arc<certificates::UploadUseCase>,
    pub remove: Arc<certificates::RemoveUseCase>,
}

/// Handing a domain from one tenant to another.
#[derive(Clone)]
pub struct HandoverUseCases {
    pub offer: Arc<OfferDomainUseCase>,
    pub accept: Arc<AcceptDomainUseCase>,
}

/// The record sets of a zone delegated to us.
#[derive(Clone)]
pub struct DnsRecordUseCases {
    pub list: Arc<ListUseCase>,
    pub set: Arc<SetUseCase>,
    pub remove: Arc<RemoveUseCase>,
}

/// Builds the custom domain use cases over `a`, under the deployment's `s`.
pub fn build(a: &Adapters, s: &Settings) -> DomainState {
    let domains = &s.custom_domains;
    let rules = ProofRules::new(domains.nameservers.clone(), domains.trusted.clone());
    DomainState {
        registration: registration(a, s, rules.clone(), certificate_queue(a, s)),
        verify: Arc::new(VerifyDomainUseCase::new(
            VerifyDomainPorts {
                domain_store: a.registered_domain_store.clone(),
                dns_resolver: a.dns_resolver.clone(),
                certificates: certificate_queue(a, s),
                unit_of_work: a.unit_of_work.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
            rules,
        )),
        certificates: certificate_use_cases(a, s),
        handover: handover(a),
        dns_records: dns_records(a),
        dns: Arc::new(DnsFacts {
            nameservers: domains.nameservers.clone(),
            proxy_address: domains.proxy_address.clone(),
            trusted: domains.trusted.clone(),
            base_domain: s.base_domain.clone(),
            addressing: s.platform_addressing,
        }),
    }
}

/// The use cases that add, list and remove a tenant's custom domains.
fn registration(
    a: &Adapters,
    s: &Settings,
    rules: ProofRules,
    certificates: CertificateQueue,
) -> RegistrationUseCases {
    RegistrationUseCases {
        add: Arc::new(add_domain(a, s, rules, certificates)),
        get: Arc::new(GetDomainUseCase::new(GetDomainPorts {
            domain_store: a.registered_domain_store.clone(),
            certificate_store: a.certificate_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        list: Arc::new(ListDomainsUseCase::new(ListDomainsPorts {
            domain_store: a.registered_domain_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        remove: Arc::new(RemoveDomainUseCase::new(RemoveDomainPorts {
            domain_store: a.registered_domain_store.clone(),
            dns_zones: a.dns_zone_writer.clone(),
            tenants: a.tenant_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}

/// Claims custom domains using the deployment's delegation and proof rules.
fn add_domain(
    a: &Adapters,
    s: &Settings,
    rules: ProofRules,
    certificates: CertificateQueue,
) -> AddDomainUseCase {
    let domains = &s.custom_domains;
    let delegation = DelegationOffer {
        nameservers: domains.nameservers.clone(),
        proxy_address: domains.proxy_address.clone(),
    };
    AddDomainUseCase::new(
        AddDomainPorts {
            domain_store: a.registered_domain_store.clone(),
            cross_tenant_domains: a.cross_tenant_domain_store.clone(),
            certificates,
            dns_zones: a.dns_zone_writer.clone(),
            limit_enforcer: a.limit_enforcer.clone(),
            tenants: a.tenant_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
            site_rules: a.site_rules.clone(),
        },
        delegation,
        rules,
        domains.claim_lifetimes,
    )
    .with_platform_base(s.base_domain.clone())
}

/// The use cases that ask for a domain's certificate, and upload, replace
/// and remove the tenant's own.
fn certificate_use_cases(a: &Adapters, s: &Settings) -> CertificateUseCases {
    CertificateUseCases {
        request: Arc::new(certificates::RequestTlsUseCase::new(
            certificates::RequestTlsPorts {
                domain_store: a.registered_domain_store.clone(),
                certificates: certificate_queue(a, s),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        upload: Arc::new(certificates::UploadUseCase::new(
            certificates::UploadPorts {
                domain_store: a.registered_domain_store.clone(),
                certificate_store: a.certificate_store.clone(),
                certificate_parser: a.certificate_parser.clone(),
                tenants: a.tenant_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        remove: Arc::new(certificates::RemoveUseCase::new(
            certificates::RemovePorts {
                domain_store: a.registered_domain_store.clone(),
                certificate_store: a.certificate_store.clone(),
                tenants: a.tenant_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// The use cases that offer a domain to another tenant and accept it there.
fn handover(a: &Adapters) -> HandoverUseCases {
    HandoverUseCases {
        offer: Arc::new(OfferDomainUseCase::new(OfferDomainPorts {
            domain_store: a.registered_domain_store.clone(),
            tenants: a.tenant_store.clone(),
            offers: a.handover_offer_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        accept: Arc::new(AcceptDomainUseCase::new(AcceptDomainPorts {
            domain_store: a.registered_domain_store.clone(),
            tenants: a.tenant_store.clone(),
            offers: a.handover_offer_store.clone(),
            dns_zones: a.dns_zone_writer.clone(),
            unit_of_work: a.unit_of_work.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
            limit_enforcer: a.limit_enforcer.clone(),
        })),
    }
}

/// The use cases that list, set and remove records in a delegated zone.
fn dns_records(a: &Adapters) -> DnsRecordUseCases {
    DnsRecordUseCases {
        list: Arc::new(ListUseCase::new(zone(a))),
        set: Arc::new(SetUseCase::new(SetPorts {
            zone: zone(a),
            limit_enforcer: a.limit_enforcer.clone(),
        })),
        remove: Arc::new(RemoveUseCase::new(zone(a))),
    }
}

/// What reaches a delegated zone.
fn zone(a: &Adapters) -> ZonePorts {
    ZonePorts {
        domain_store: a.registered_domain_store.clone(),
        dns_zones: a.dns_zone_writer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    }
}

/// Where certificate requests are queued, and how often each is tried. A
/// configured count of none still tries once.
fn certificate_queue(a: &Adapters, s: &Settings) -> CertificateQueue {
    CertificateQueue {
        queue: a.job_queue.clone(),
        attempts: NonZeroU32::new(s.tunables.certificate_attempts).unwrap_or(NonZeroU32::MIN),
    }
}
