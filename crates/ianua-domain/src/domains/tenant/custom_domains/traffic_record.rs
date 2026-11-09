//! The DNS records that bring a domain's traffic to the proxy.
//!
//! Verifying a domain proves a tenant owns it, but routes nothing. For a
//! request to arrive, the name must also point at the proxy. That is a
//! second record, and this module spells it out. Without it, a tenant adds
//! the verification record, sees "Verified" and waits for traffic that never
//! comes.
//!
//! A name reaches us in one of two ways, never both.
//!
//! A tenant who keeps their DNS writes a record that refers to us. DNS
//! forbids a `CNAME` on a zone apex. An apex must carry its zone's `NS`
//! records, and a `CNAME` may not sit beside any other record. So a
//! subdomain aliases our hostname, and a bare domain points at our address.
//! The string alone does not say whether a name is an apex. `acme.co.uk` is
//! an apex with as many labels as `hello.acme.com`, which is not. So both
//! records are offered, each named for the case it serves.
//!
//! A tenant who delegates writes `NS` records instead, handing the hostname
//! to us. They add nothing else inside that name, because the zone is now
//! ours. An `NS` record is legal at an apex, so the apex question does not
//! come up.
//!
//! The `NS` records name this registration's own nameservers, not a pair
//! every tenant shares. So they prove whose delegation it is, not only that
//! one happened. See
//! [`DelegationLabel`](crate::domains::tenant::custom_domains::dns_zone::DelegationLabel).

use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_count;
use crate::types::{DomainName, Fact, IpAddress};

/// A DNS record a tenant adds to route traffic to the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficRecord {
    /// For a subdomain: an alias to the tenant's platform hostname.
    ///
    /// It is the better choice where it is legal, because the target is a
    /// name. If the proxy changes address, every tenant using one follows.
    Alias {
        /// The name the tenant creates the record at.
        name: DomainName,
        /// The hostname it aliases.
        target: DomainName,
    },
    /// For a bare domain, which may not hold an alias: our address.
    ///
    /// It names a fixed address, so a tenant using one must be told before
    /// the proxy moves.
    Address {
        /// The name the tenant creates the record at.
        name: DomainName,
        /// The address it points at.
        target: IpAddress,
    },
    /// For a delegated hostname: one of the nameservers that answers for it.
    ///
    /// It does not point at us. It hands the name over. Once it resolves,
    /// every record under that hostname is ours.
    Delegation {
        /// The name the tenant creates the record at.
        name: DomainName,
        /// The nameserver it hands the name to.
        target: DomainName,
    },
}

impl TrafficRecord {
    /// The record type, as a DNS zone file spells it.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Alias { .. } => "CNAME",
            Self::Address { .. } => "A",
            Self::Delegation { .. } => "NS",
        }
    }

    /// The name the record is created at.
    #[must_use]
    pub fn name(&self) -> &DomainName {
        match self {
            Self::Alias { name, .. }
            | Self::Address { name, .. }
            | Self::Delegation { name, .. } => name,
        }
    }

    /// What the record points at.
    #[must_use]
    pub fn target(&self) -> String {
        match self {
            Self::Alias { target, .. } | Self::Delegation { target, .. } => {
                target.as_str().to_owned()
            }
            Self::Address { target, .. } => target.as_str().to_owned(),
        }
    }
}

/// Everything a tenant must add to their DNS, and nothing more.
///
/// The two variants are the two ways a name reaches us, and a domain is only
/// ever one of them. A delegated tenant shown a `CNAME` could not act on it,
/// because the zone is no longer theirs to write in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficInstructions {
    /// The tenant keeps the zone and points one record at us.
    SelfManaged {
        /// The record a subdomain uses.
        alias: TrafficRecord,
        /// The record a bare domain uses. It is unknown until an operator
        /// sets the proxy's address, and never made up.
        address: Fact<TrafficRecord>,
    },
    /// The tenant hands the hostname over and writes nothing else.
    Delegated {
        /// One `NS` record per nameserver. All of them are added.
        ///
        /// Named after this registration, so writing them says both that the
        /// name was handed over and whose it is.
        nameservers: Vec<TrafficRecord>,
    },
}

impl TrafficInstructions {
    /// Builds the instructions for pointing `domain` at us.
    ///
    /// `platform_host` is the tenant's own hostname on the platform, which
    /// always resolves. `proxy_address` is known only when an operator has
    /// set one. Without it the bare-domain record is left out rather than
    /// given a made-up address.
    #[must_use]
    pub fn self_managed(
        domain: &DomainName,
        platform_host: DomainName,
        proxy_address: Fact<IpAddress>,
    ) -> Self {
        Self::SelfManaged {
            alias: TrafficRecord::Alias {
                name: domain.clone(),
                target: platform_host,
            },
            address: proxy_address.map(|target| TrafficRecord::Address {
                name: domain.clone(),
                target,
            }),
        }
    }

    /// Builds the instructions for handing `domain` over to `nameservers`.
    ///
    /// `nameservers` are this registration's own, not the shared base names.
    /// See
    /// [`DelegationLabel`](crate::domains::tenant::custom_domains::dns_zone::DelegationLabel).
    /// Writing them says both that the name was handed over and whose it is.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `nameservers` is empty. Such
    ///   instructions would read as "you are done" while the name still
    ///   resolves where it always did.
    pub fn delegated(domain: &DomainName, nameservers: &[DomainName]) -> Result<Self, DomainError> {
        validate_count("nameservers", nameservers.len(), 1..=usize::MAX)?;

        Ok(Self::Delegated {
            nameservers: nameservers
                .iter()
                .map(|target| TrafficRecord::Delegation {
                    name: domain.clone(),
                    target: target.clone(),
                })
                .collect(),
        })
    }

    /// The record a subdomain uses, when the tenant holds the zone.
    #[must_use]
    pub fn alias(&self) -> Option<&TrafficRecord> {
        match self {
            Self::SelfManaged { alias, .. } => Some(alias),
            Self::Delegated { .. } => None,
        }
    }

    /// The record a bare domain uses, when the tenant holds the zone and an
    /// address is known.
    #[must_use]
    pub fn address(&self) -> Option<&TrafficRecord> {
        match self {
            Self::SelfManaged { address, .. } => address.known(),
            Self::Delegated { .. } => None,
        }
    }

    /// The `NS` records a delegated hostname needs. Empty when self-managed.
    #[must_use]
    pub fn nameservers(&self) -> &[TrafficRecord] {
        match self {
            Self::SelfManaged { .. } => &[],
            Self::Delegated { nameservers, .. } => nameservers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(value: &str) -> DomainName {
        DomainName::new(value).unwrap()
    }

    fn instructions(proxy_address: Fact<&str>) -> TrafficInstructions {
        TrafficInstructions::self_managed(
            &domain("hello.acme.com"),
            domain("acme-prod.ianua.example.com"),
            proxy_address.map(|a| IpAddress::new(a).unwrap()),
        )
    }

    /// Acme points `hello.acme.com` at us and keeps its own DNS. It is told to
    /// add a `CNAME` there to its platform hostname.
    #[test]
    fn a_subdomain_aliases_the_tenants_platform_hostname() {
        let alias = instructions(Fact::Unknown)
            .alias()
            .expect("self-managed")
            .clone();

        assert_eq!(alias.kind(), "CNAME");
        assert_eq!(alias.name().as_str(), "hello.acme.com");
        assert_eq!(alias.target(), "acme-prod.ianua.example.com");
    }

    /// The operator set the proxy address `203.0.113.10`. The tenant is also
    /// offered an `A` record pointing its name there.
    #[test]
    fn a_bare_domain_points_at_the_proxy_address() {
        let address = instructions(Fact::Known("203.0.113.10"))
            .address()
            .expect("an address was configured")
            .clone();

        assert_eq!(address.kind(), "A");
        assert_eq!(address.name().as_str(), "hello.acme.com");
        assert_eq!(address.target(), "203.0.113.10");
    }

    /// No proxy address is set. Only the `CNAME` is offered, since a tenant
    /// following a made-up `A` record would get no traffic and no error.
    #[test]
    fn without_a_configured_address_only_the_alias_is_offered() {
        let instructions = instructions(Fact::Unknown);

        assert!(instructions.address().is_none());
        assert_eq!(instructions.alias().unwrap().kind(), "CNAME");
    }

    /// With or without a proxy address, the `CNAME` is offered. Most custom
    /// domains are subdomains, and an alias keeps working when the proxy
    /// moves.
    #[test]
    fn the_alias_is_offered_whether_or_not_an_address_is_known() {
        assert_eq!(instructions(Fact::Unknown).alias().unwrap().kind(), "CNAME");
        assert_eq!(
            instructions(Fact::Known("203.0.113.10"))
                .alias()
                .unwrap()
                .kind(),
            "CNAME"
        );
    }

    /// The proxy address is `2001:db8::1`. The offered record targets that
    /// IPv6 address exactly as given.
    #[test]
    fn an_ipv6_address_is_carried_as_given() {
        let address = TrafficInstructions::self_managed(
            &domain("hello.acme.com"),
            domain("acme-prod.ianua.example.com"),
            Fact::Known(IpAddress::new("2001:db8::1").unwrap()),
        );

        assert_eq!(address.address().unwrap().target(), "2001:db8::1");
    }

    /// Acme delegates `auth.acme.com` to two nameservers. It is told to add
    /// two `NS` records at that name, one for each, in order.
    #[test]
    fn a_delegated_domain_gets_one_ns_record_per_nameserver() {
        let instructions = TrafficInstructions::delegated(
            &domain("auth.acme.com"),
            &[domain("ns1.ianua.example"), domain("ns2.ianua.example")],
        )
        .unwrap();

        let records = instructions.nameservers();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|r| r.kind() == "NS"));
        assert!(records.iter().all(|r| r.name().as_str() == "auth.acme.com"));
        assert_eq!(records[0].target(), "ns1.ianua.example");
        assert_eq!(records[1].target(), "ns2.ianua.example");
    }

    /// A delegated domain offers no `CNAME` and no `A` record. The tenant no
    /// longer holds the zone, so they could not add either.
    #[test]
    fn a_delegated_domain_offers_no_self_managed_record() {
        let instructions = TrafficInstructions::delegated(
            &domain("auth.acme.com"),
            &[domain("ns1.ianua.example")],
        )
        .unwrap();

        assert!(instructions.alias().is_none());
        assert!(instructions.address().is_none());
    }

    /// A delegation to no nameservers is refused. It would read as "you are
    /// done" while the name still resolves where it always did.
    #[test]
    fn delegating_to_no_nameservers_is_refused() {
        let result = TrafficInstructions::delegated(&domain("auth.acme.com"), &[]);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A self-managed domain with a known proxy address offers no `NS`
    /// records. It has no delegation to make.
    #[test]
    fn a_self_managed_domain_offers_no_nameservers() {
        assert!(
            instructions(Fact::Known("203.0.113.10"))
                .nameservers()
                .is_empty()
        );
    }
}
