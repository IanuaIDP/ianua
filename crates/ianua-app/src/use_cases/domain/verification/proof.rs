//! What proves a domain belongs to the tenant who registered it.
//!
//! One function, used by everything that asks the question: the first check,
//! the retry for one that has not passed yet, and the periodic re-check of one
//! that has. They have to agree. A domain proved one way and re-checked
//! another is marked failed on every run no matter what the tenant does, and
//! a retry looking for the wrong thing can never lift it back.

use ianua_domain::domains::tenant::custom_domains::dns_zone::{
    DelegationLabel, RecordName, TxtValue,
};
use ianua_domain::domains::tenant::custom_domains::registered_domain::{
    ProofRoute, RegisteredDomain,
};
use ianua_domain::domains::tenant::custom_domains::trusted_domains::TrustedDomains;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::DomainName;

use crate::ports::domain::{DnsResolver, RegisteredDomainStore};
use crate::tenancy::ScopedTenant;

/// What this deployment accepts as proof that a domain is a tenant's.
///
/// One value, handed to every use case that asks, for the same reason
/// `is_proven` is one function: a domain registered under one set of rules
/// and re-checked under another fails on every run.
#[derive(Debug, Clone, Default)]
pub struct ProofRules {
    nameservers: Vec<DomainName>,
    trusted: TrustedDomains,
}

impl ProofRules {
    /// Rules for a deployment whose delegated domains point at `nameservers`
    /// and whose operator vouches for everything `trusted` covers.
    #[must_use]
    pub fn new(nameservers: Vec<DomainName>, trusted: TrustedDomains) -> Self {
        Self {
            nameservers,
            trusted,
        }
    }

    /// Whether `domain` needs no proof at all, because the operator vouches
    /// for it.
    #[must_use]
    pub fn vouches_for(&self, domain: &DomainName) -> bool {
        self.trusted.covers(domain)
    }
}

/// Where [`is_proven`] finds its answers.
#[derive(Clone, Copy)]
pub(crate) struct ProofSources<'a> {
    /// The DNS lookups that prove ownership (`TXT` or `NS`).
    pub resolver: &'a dyn DnsResolver,
    /// The tenant's registrations, for the parent a wildcard stands on.
    pub domains: &'a dyn RegisteredDomainStore,
    /// What this deployment accepts as proof.
    pub rules: &'a ProofRules,
}

/// Whether the tenant `tenant` has done what this domain's mode asks of
/// them.
///
/// A domain the operator vouches for is proven without asking DNS anything,
/// see [`TrustedDomains`]. Checking it anyway would mark it failed on every
/// health check wherever the name is not published, which on an internal
/// network is most of them.
///
/// A wildcard is proven through its parent: the tenant's own registration
/// of the name it stands in front of, which must still carry it and whose
/// own proof must hold now. The wildcard has no zone, token or delegation of
/// its own. Asking DNS for its delegation would mark it lost on every check.
///
/// Otherwise the answer has to establish two things: that whoever answers
/// for the parent zone agreed to this, and that the tenant asking is the one
/// who arranged it.
///
/// A tenant-managed domain does both with a `TXT` record holding a token only
/// this registration was given. Writing it takes possession, and the token
/// itself names the registration.
///
/// A delegated domain does both with the `NS` records alone, because the
/// nameserver names it is told to point at are its own, see
/// [`DelegationLabel`]. Only the parent's operator can write the records, and
/// only this registration was ever told those names. With every tenant
/// pointed at the same names, a name still delegated after its registration
/// was deleted would verify for whoever claimed it next.
///
/// # Errors
///
/// Returns whatever the resolver or the store returns, and
/// [`DomainError::Validation`] if the token cannot be written as a record.
/// A caller must treat an error as "not known" rather than "not proved". A
/// resolver that timed out and a record that was withdrawn are the same
/// silence, and only one of them should cost a tenant their domain.
pub(crate) async fn is_proven(
    sources: ProofSources<'_>,
    tenant: &ScopedTenant,
    domain: &RegisteredDomain<ResolvedTenant>,
) -> Result<bool, DomainError> {
    if sources.rules.vouches_for(domain.domain()) {
        return Ok(true);
    }
    let ProofRoute::Parent(parent) = domain.proof_route() else {
        return own_proof(sources, domain).await;
    };
    let Some(held) = sources
        .domains
        .find_by_tenant_and_name(tenant, &parent)
        .await?
    else {
        return Ok(false);
    };
    let Ok(()) = held.ensure_carries_wildcard(domain.domain()) else {
        return Ok(false);
    };
    own_proof(sources, &held).await
}

/// Whether `domain`'s own token or delegation holds. A domain proved
/// through a parent has neither; the parent a wildcard stands on is never a
/// wildcard itself.
async fn own_proof(
    sources: ProofSources<'_>,
    domain: &RegisteredDomain<ResolvedTenant>,
) -> Result<bool, DomainError> {
    match domain.proof_route() {
        ProofRoute::Token => token_published(sources.resolver, domain).await,
        ProofRoute::Delegation => delegated_to_us(sources.resolver, domain, sources.rules).await,
        ProofRoute::Parent(_) => Ok(false),
    }
}

/// Whether `_ianua-verify.{domain}` holds the registration's token.
async fn token_published(
    resolver: &dyn DnsResolver,
    domain: &RegisteredDomain<ResolvedTenant>,
) -> Result<bool, DomainError> {
    let lookup = RecordName::new(format!("_ianua-verify.{}", domain.domain().as_str()))?;
    let expected = TxtValue::new(format!(
        "ianua-verify={}",
        domain.dns_challenge_token().as_str()
    ))?;
    resolver.verify_txt_record(&lookup, &expected).await
}

/// Whether the domain is delegated to this registration's own nameservers.
async fn delegated_to_us(
    resolver: &dyn DnsResolver,
    domain: &RegisteredDomain<ResolvedTenant>,
    rules: &ProofRules,
) -> Result<bool, DomainError> {
    let assigned =
        DelegationLabel::for_registration(domain.id()).nameservers(&rules.nameservers)?;
    resolver.verify_delegation(domain.domain(), &assigned).await
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ianua_domain::domains::tenant::custom_domains::registered_domain::DomainConnection;

    use super::*;
    use crate::test_support::domain::{DomainSeed, FakeDomainStore, TEST_CHALLENGE_TOKEN};
    use crate::test_support::{block_on, test_ctx};

    fn domain(connection: DomainConnection) -> RegisteredDomain<ResolvedTenant> {
        let seed = DomainSeed::pending("app.acme.test");
        match connection {
            DomainConnection::SelfManaged => seed.build(),
            DomainConnection::Delegated => seed.delegated().build(),
        }
    }

    fn nameservers() -> Vec<DomainName> {
        vec![DomainName::new("ns1.ianua.test").unwrap()]
    }

    fn rules() -> ProofRules {
        ProofRules::new(nameservers(), TrustedDomains::default())
    }

    fn trusting(parent: &str) -> ProofRules {
        ProofRules::new(
            nameservers(),
            TrustedDomains::new([DomainName::new(parent).unwrap()]).unwrap(),
        )
    }

    /// Records each question it was asked, and answers them all alike.
    struct Watcher {
        answer: bool,
        asked: Mutex<Vec<String>>,
    }

    impl Watcher {
        fn answering(answer: bool) -> Self {
            Self {
                answer,
                asked: Mutex::new(Vec::new()),
            }
        }

        fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().clone()
        }

        /// Keeps the question for assertions and supplies the configured answer.
        fn note(&self, question: String) -> bool {
            self.asked.lock().unwrap().push(question);
            self.answer
        }
    }

    #[async_trait]
    impl DnsResolver for Watcher {
        async fn verify_txt_record(
            &self,
            name: &RecordName,
            expected: &TxtValue,
        ) -> Result<bool, DomainError> {
            Ok(self.note(format!("txt {} {}", name.as_str(), expected.as_str())))
        }

        async fn verify_cname(&self, _: &DomainName, _: &DomainName) -> Result<bool, DomainError> {
            Ok(self.note("cname".to_owned()))
        }

        async fn verify_delegation(
            &self,
            _: &DomainName,
            expected: &[DomainName],
        ) -> Result<bool, DomainError> {
            let names: Vec<&str> = expected.iter().map(DomainName::as_str).collect();
            Ok(self.note(format!("delegation {}", names.join(","))))
        }
    }

    /// Whether `domain` is proven under `rules`, for a tenant holding no
    /// other registration.
    fn proven_under(
        resolver: &dyn DnsResolver,
        domain: &RegisteredDomain<ResolvedTenant>,
        rules: &ProofRules,
    ) -> bool {
        let domains = FakeDomainStore::empty();
        let sources = ProofSources {
            resolver,
            domains: &domains,
            rules,
        };
        block_on(is_proven(sources, &test_ctx().tenant(), domain)).unwrap()
    }

    fn proven(connection: DomainConnection, resolver: &dyn DnsResolver) -> bool {
        proven_under(resolver, &domain(connection), &rules())
    }

    /// Acme registered `app.acme.test` and later deleted it; Mallory claims
    /// it next while it is still delegated to Acme's nameservers. The two
    /// registrations are checked against different names, so Acme's old
    /// delegation cannot prove Mallory's claim.
    #[test]
    fn one_registrations_delegation_cannot_prove_anothers() {
        let first = Watcher::answering(true);
        let second = Watcher::answering(true);

        proven(DomainConnection::Delegated, &first);
        proven(DomainConnection::Delegated, &second);

        assert_eq!(first.asked().len(), 1);
        assert_ne!(first.asked(), second.asked());
    }

    /// A delegation is checked against the registration's own nameservers,
    /// the ones its zone answers with, or no correct delegation would ever
    /// match.
    #[test]
    fn a_delegation_is_checked_against_this_registrations_own_names() {
        let registration = domain(DomainConnection::Delegated);
        let expected: Vec<String> = DelegationLabel::for_registration(registration.id())
            .nameservers(&nameservers())
            .unwrap()
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect();
        let resolver = Watcher::answering(true);

        proven_under(&resolver, &registration, &rules());

        assert_eq!(
            resolver.asked(),
            [format!("delegation {}", expected.join(","))]
        );
    }

    /// Acme delegated its domain. It proves itself with the `NS` records
    /// alone; it was never given a token to publish.
    #[test]
    fn a_delegated_domain_is_asked_only_for_its_delegation() {
        let resolver = Watcher::answering(true);

        assert!(proven(DomainConnection::Delegated, &resolver));
        assert_eq!(resolver.asked().len(), 1);
        assert!(resolver.asked()[0].starts_with("delegation "));
    }

    /// Acme runs its own DNS. It proves itself with the token under
    /// `_ianua-verify`.
    #[test]
    fn a_self_managed_domain_is_asked_for_its_token() {
        let resolver = Watcher::answering(true);

        assert!(proven(DomainConnection::SelfManaged, &resolver));
        assert_eq!(
            resolver.asked(),
            [format!(
                "txt _ianua-verify.app.acme.test ianua-verify={TEST_CHALLENGE_TOKEN}"
            )]
        );
    }

    /// Acme has not set anything up yet. Neither kind of domain is proven.
    #[test]
    fn a_domain_that_has_not_been_set_up_is_not_proven() {
        let resolver = Watcher::answering(false);

        assert!(!proven(DomainConnection::Delegated, &resolver));
        assert!(!proven(DomainConnection::SelfManaged, &resolver));
    }

    /// The operator vouches for `acme.test`. Acme's domain under it is proven
    /// without a lookup, so a health check on a network with no public DNS
    /// cannot mark it failed.
    #[test]
    fn a_vouched_for_domain_is_proven_without_asking_dns() {
        let resolver = Watcher::answering(false);

        let proven = proven_under(
            &resolver,
            &domain(DomainConnection::SelfManaged),
            &trusting("acme.test"),
        );

        assert!(proven);
        assert!(resolver.asked().is_empty());
    }

    /// The operator vouches for `other.test` only. Acme's domain still needs
    /// its token.
    #[test]
    fn a_domain_outside_the_vouched_for_parents_still_needs_its_proof() {
        let resolver = Watcher::answering(false);

        let proven = proven_under(
            &resolver,
            &domain(DomainConnection::SelfManaged),
            &trusting("other.test"),
        );

        assert!(!proven);
        assert_eq!(resolver.asked().len(), 1);
    }

    /// Acme's `*.app.acme.test` stands on its delegated `app.acme.test`.
    /// The wildcard is proven by the parent's delegation alone; nothing is
    /// asked about the wildcard's own name.
    #[test]
    fn a_wildcard_is_proven_by_its_parents_delegation() {
        let parent = DomainSeed::verified("app.acme.test").delegated().build();
        let wildcard = DomainSeed::verified("*.app.acme.test").delegated().build();
        let expected: Vec<String> = DelegationLabel::for_registration(parent.id())
            .nameservers(&nameservers())
            .unwrap()
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect();
        let domains = FakeDomainStore::holding(test_ctx().tenant_id(), [parent]);
        let resolver = Watcher::answering(true);
        let sources = ProofSources {
            resolver: &resolver,
            domains: &domains,
            rules: &rules(),
        };

        let proven = block_on(is_proven(sources, &test_ctx().tenant(), &wildcard)).unwrap();

        assert!(proven);
        assert_eq!(
            resolver.asked(),
            [format!("delegation {}", expected.join(","))]
        );
    }
}
