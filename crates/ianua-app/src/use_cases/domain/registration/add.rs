//! Add domain: register a custom domain for the caller's tenant, to be
//! proved over DNS.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::tenant::control::TenantControl;
use ianua_domain::domains::tenant::custom_domains::dns_zone::{
    DelegationLabel, RecordName, RecordSet, RecordValue, Ttl,
};
use ianua_domain::domains::tenant::custom_domains::registered_domain::{
    ClaimLifetimes, DomainConnection, DomainVerificationToken, NewDomain, RegisteredDomain,
};
use ianua_domain::domains::tenant::custom_domains::verification_status::VerificationStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{DomainName, IpAddress};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::domain::{CrossTenantDomainStore, DnsZoneWriter, RegisteredDomainStore};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::shared::SiteRules;
use crate::ports::tenant::TenantStore;
use crate::use_case::Command;
use crate::use_cases::domain::limits::ensure_within_limit;
use crate::use_cases::domain::lookup::acting_tenant;
use crate::use_cases::domain::verification::proof::ProofRules;
use crate::use_cases::domain::verification::verified::{CertificateQueue, request_certificate};

/// The ports [`AddDomainUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AddDomainPorts {
    /// Registers the domain, its claim checked against the names above and
    /// below it in the same step, and finds the parent of a wildcard.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// Answers who holds a name, across every tenant, and releases a lapsed
    /// claim on it.
    pub cross_tenant_domains: Arc<dyn CrossTenantDomainStore>,
    /// Queues the certificate of a domain that arrives proved.
    pub certificates: CertificateQueue,
    /// Opens a zone when a domain is delegated to us.
    pub dns_zones: Arc<dyn DnsZoneWriter>,
    /// Checks the plan's ceiling on registered domains.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// Loads the tenant the domain is registered for.
    pub tenants: Arc<dyn TenantStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Tells a public suffix, which nobody may claim, from a registered
    /// name.
    pub site_rules: Arc<dyn SiteRules>,
}

/// What has to be true before a domain can be delegated to us.
///
/// Delegation only helps if we can answer for the name, which needs two
/// things an operator provides: nameservers for the tenant to point at, and
/// an address to answer with. Without either, a delegated domain would
/// resolve to nothing, which is worse than leaving it tenant-managed.
///
/// So their absence is not an error. Delegation is then not on offer, and
/// every domain stays [`SelfManaged`](DomainConnection::SelfManaged).
#[derive(Clone, Default)]
pub struct DelegationOffer {
    /// Nameservers a tenant delegates to. Empty means delegation is off.
    pub nameservers: Vec<DomainName>,
    /// The address a delegated hostname answers with.
    pub proxy_address: Option<IpAddress>,
}

impl DelegationOffer {
    /// Whether we can serve a delegated name at all.
    fn is_available(&self) -> bool {
        !self.nameservers.is_empty() && self.proxy_address.is_some()
    }

    /// The connection a tenant asking for `wanted` gets.
    ///
    /// Only ever narrows. A tenant who keeps their own DNS keeps it; one who
    /// asks us to run it gets that only where this deployment can answer.
    fn connection_for(&self, wanted: DomainConnection) -> DomainConnection {
        match wanted {
            DomainConnection::Delegated if self.is_available() => DomainConnection::Delegated,
            DomainConnection::Delegated | DomainConnection::SelfManaged => {
                DomainConnection::SelfManaged
            }
        }
    }
}

/// A domain to register, and who the tenant wants running its DNS.
pub struct AddDomainRequest {
    /// The domain to register.
    pub domain: DomainName,
    /// Who the tenant wants running its DNS. What the domain is for is not
    /// asked: whether traffic arrives is decided by the record they create.
    pub connection: DomainConnection,
}

/// Registers a new domain for a tenant.
pub struct AddDomainUseCase {
    ports: AddDomainPorts,
    delegation: DelegationOffer,
    rules: ProofRules,
    lifetimes: ClaimLifetimes,
    platform_base: Option<DomainName>,
}

impl AddDomainUseCase {
    /// A use case working through `ports`.
    ///
    /// `delegation` is what this deployment can serve for a delegated name,
    /// `rules` decide which names arrive already proved, and `lifetimes` how
    /// long a claim without a standing proof holds its name against other
    /// tenants.
    #[must_use]
    pub fn new(
        ports: AddDomainPorts,
        delegation: DelegationOffer,
        rules: ProofRules,
        lifetimes: ClaimLifetimes,
    ) -> Self {
        Self {
            ports,
            delegation,
            rules,
            lifetimes,
            platform_base: None,
        }
    }

    /// Keeps the deployment's apps namespace out of tenant domain registrations.
    #[must_use]
    pub fn with_platform_base(mut self, base: DomainName) -> Self {
        self.platform_base = Some(base);
        self
    }
}

impl Command for AddDomainUseCase {
    type Caller = CallerContext;
    type Input = AddDomainRequest;
    type Output = Result<RegisteredDomain<ResolvedTenant>, AppError>;

    /// Registers the domain for the caller's tenant and records
    /// `tenant.domain_registered`.
    ///
    /// The order carries meaning. Whether the caller may claim names is
    /// settled before anything else, and the plan ceiling before anything is
    /// claimed: a hostname is taken globally the moment it is registered,
    /// proved or not. The zone is opened once the registration is saved,
    /// because its nameservers are named after it, and so that a request
    /// that lost the name to another arriving at once opens none. A domain
    /// that arrives proved (one the operator vouches for, or a wildcard over
    /// a delegated parent) is verified here and nowhere else, so this is its
    /// one chance to have its certificate asked for.
    ///
    /// A wildcard is always delegated: it lives inside its parent's zone and
    /// can only be proved over DNS-01.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without domain-add rights or with a full plan.
    /// - `AppError::Domain` for a public suffix or a wildcard without a verified, delegated parent in this tenant.
    /// - `AppError::Conflict` for a claimed name, including concurrent claims, another tenant's ancestor/descendant name, or another tenant's zone.
    /// - `AppError::NotFound` for a missing caller tenant; `Internal` on zone creation, persistence or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: AddDomainRequest,
    ) -> Result<RegisteredDomain<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let scope = acting_tenant(self.ports.tenants.as_ref(), caller).await?;
        let mut domain = new_registration(&self.delegation, request, &scope, &authority)?;
        ensure_outside_platform(domain.domain(), self.platform_base.as_ref())?;
        ensure_claimable(&self.ports, &self.lifetimes, caller, domain.domain()).await?;
        prove_on_arrival(&self.rules, &mut domain)?;
        self.ports
            .domain_store
            .register(&caller.tenant(), &domain, &self.lifetimes, clock::now())
            .await
            .map_err(AppError::from_domain)?;
        zone_opened_or_withdrawn(&self.ports, &self.delegation, caller, &domain).await?;
        if domain.verification_status() == VerificationStatus::Verified {
            request_certificate(&self.ports.certificates, &caller.tenant_id(), &domain).await;
        }
        auditor
            .dispatch_by(&caller.actor(), domain.take_events(&caller.tenant()))
            .await
            .or_internal()?;
        Ok(domain)
    }
}

/// Refuses claims inside or above the platform namespace, including wildcard claims.
fn ensure_outside_platform(name: &DomainName, base: Option<&DomainName>) -> Result<(), AppError> {
    let Some(base) = base else {
        return Ok(());
    };
    let name = name.as_str().strip_prefix("*.").unwrap_or(name.as_str());
    let base = base.as_str();
    if name == base || name.ends_with(&format!(".{base}")) || base.ends_with(&format!(".{name}")) {
        return Err(refused(
            "the platform's apps namespace cannot be registered as a custom domain".to_owned(),
        ));
    }
    Ok(())
}

/// Refuses a name this tenant may not claim now: past the plan's ceiling, a
/// public suffix, a wildcard without its parent, or a name another claim
/// still holds. A name above or below another tenant's claim is refused by
/// the registration itself, in the one step that claims the name.
async fn ensure_claimable(
    ports: &AddDomainPorts,
    lifetimes: &ClaimLifetimes,
    caller: &CallerContext,
    name: &DomainName,
) -> Result<(), AppError> {
    ensure_within_limit(ports.limit_enforcer.as_ref(), caller, ResourceKind::Domains).await?;
    ensure_registrable(ports.site_rules.as_ref(), name)?;
    ensure_wildcard_parent(ports.domain_store.as_ref(), caller, name).await?;
    ensure_unclaimed(ports.cross_tenant_domains.as_ref(), lifetimes, name).await
}

/// Refuses a wildcard unless the tenant holds its parent, delegated to us
/// and verified.
///
/// A wildcard is not a zone of its own: `*.auth.acme.com` is a record inside
/// the zone for `auth.acme.com`, and both the DNS-01 proof and the `NS`
/// records that make it answerable belong to that parent.
async fn ensure_wildcard_parent(
    store: &dyn RegisteredDomainStore,
    caller: &CallerContext,
    name: &DomainName,
) -> Result<(), AppError> {
    let Some(parent) = name.wildcard_parent() else {
        return Ok(());
    };
    let held = store
        .find_by_tenant_and_name(&caller.tenant(), &parent)
        .await
        .or_internal()?;
    let Some(held) = held else {
        return Err(refused(format!(
            "a wildcard lives inside its parent's zone, and {parent} is not one of your \
             domains; register and delegate {parent} first"
        )));
    };
    held.ensure_carries_wildcard(name)
        .map_err(AppError::from_domain)
}

/// Refuses a public suffix such as `co.uk` or `github.io`, under which
/// anyone may register a name.
///
/// A claim on a name also holds every name below it. Mallory claims
/// `co.uk` and never proves it. Without this, nobody else could claim a
/// name ending in `.co.uk` until her claim lapsed.
fn ensure_registrable(rules: &dyn SiteRules, name: &DomainName) -> Result<(), AppError> {
    if !rules.is_public_suffix(name) {
        return Ok(());
    }
    Err(AppError::Domain(DomainError::invalid(message!(
        "domain-a-public-suffix-such-as-co",
        "a public suffix such as co.uk cannot be claimed; add a name registered under it"
    ))))
}

/// Refuses a name another claim still holds.
///
/// A claim stops holding its name once it lapses, see
/// [`RegisteredDomain::has_lapsed`]. A lapsed claim is released here, zone
/// and all, so a squatter cannot keep a name from its owner by never
/// proving it, or a seller keep a name after its proof failed for good. The
/// release removes only a claim still lapsed, so one proved in the
/// meantime keeps its name.
async fn ensure_unclaimed(
    store: &dyn CrossTenantDomainStore,
    lifetimes: &ClaimLifetimes,
    name: &DomainName,
) -> Result<(), AppError> {
    let Some(existing) = store.find_by_domain(name).await.or_internal()? else {
        return Ok(());
    };
    let now = clock::now();
    if !existing.has_lapsed(now, lifetimes) {
        return Err(already_claimed());
    }
    let released = store
        .release_lapsed_claim(name, lifetimes, now)
        .await
        .or_internal()?;
    if !released {
        return Err(already_claimed());
    }
    Ok(())
}

/// The registration `request` asks for, of the tenant `scope` stands for,
/// once `by` may claim domains for it.
fn new_registration(
    delegation: &DelegationOffer,
    request: AddDomainRequest,
    scope: &ResolvedTenant,
    by: &TenantAuthority,
) -> Result<RegisteredDomain<ResolvedTenant>, AppError> {
    let connection = match request.domain.is_wildcard() {
        true => DomainConnection::Delegated,
        false => delegation.connection_for(request.connection),
    };
    let token = DomainVerificationToken::new(uuid::Uuid::now_v7().to_string()).or_internal()?;
    let new = NewDomain {
        domain: request.domain,
        connection,
        dns_challenge_token: token,
    };
    RegisteredDomain::register(new, scope, TenantControl::new(by)).map_err(AppError::from_domain)
}

/// Opens the zone of the registration just saved, or withdraws the
/// registration when the zone cannot be opened, so no domain is kept
/// delegated with nothing behind it.
async fn zone_opened_or_withdrawn(
    ports: &AddDomainPorts,
    delegation: &DelegationOffer,
    caller: &CallerContext,
    registration: &RegisteredDomain<ResolvedTenant>,
) -> Result<(), AppError> {
    let Err(failed) = open_zone(ports, delegation, caller, registration).await else {
        return Ok(());
    };
    ports
        .domain_store
        .delete(&caller.tenant(), registration.id())
        .await
        .or_internal()?;
    Err(failed)
}

/// Opens the zone of a delegated domain and points it at the proxy.
///
/// The address is written now rather than after the tenant delegates, so
/// there is nothing left to do once they have: the nameservers withhold it
/// until the claim is proved and release it the moment it is. A wildcard
/// opens no zone; it lives inside its parent's.
async fn open_zone(
    ports: &AddDomainPorts,
    delegation: &DelegationOffer,
    caller: &CallerContext,
    registration: &RegisteredDomain<ResolvedTenant>,
) -> Result<(), AppError> {
    let opens_a_zone =
        registration.connection() == DomainConnection::Delegated && !registration.is_wildcard();
    if !opens_a_zone {
        return Ok(());
    }
    let domain = registration.domain();
    let label = DelegationLabel::for_registration(registration.id());
    ports
        .dns_zones
        .create_zone(&caller.tenant_id(), domain, &label)
        .await
        .map_err(AppError::from_domain)?;
    let Some(address) = delegation.proxy_address.clone() else {
        return Ok(());
    };
    let apex = RecordSet::new(
        RecordName::from(domain),
        Ttl::standard(),
        vec![RecordValue::Address(address)],
    )
    .map_err(AppError::from_domain)?;
    ports
        .dns_zones
        .replace_record_set(&caller.tenant_id(), domain, &apex)
        .await
        .map_err(AppError::from_domain)
}

/// Marks `domain` verified when it is proved the moment it is registered:
/// a name the operator vouches for, or a wildcard, whose delegated and
/// verified parent [`ensure_wildcard_parent`] already required.
fn prove_on_arrival(
    rules: &ProofRules,
    domain: &mut RegisteredDomain<ResolvedTenant>,
) -> Result<(), AppError> {
    if !(domain.is_wildcard() || rules.vouches_for(domain.domain())) {
        return Ok(());
    }
    domain.prove_on_arrival().map_err(AppError::from_domain)
}

/// A registration refused for `reason`.
fn refused(reason: String) -> AppError {
    AppError::Domain(DomainError::invalid(reason))
}

/// The refusal of a name another claim holds.
fn already_claimed() -> AppError {
    AppError::Conflict(message!(
        "domain-domain-already-claimed",
        "domain already claimed"
    ))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{DomainAction, SystemPermission};
    use ianua_domain::domains::tenant::custom_domains::dns_zone::RecordKind;
    use ianua_domain::domains::tenant::custom_domains::trusted_domains::TrustedDomains;
    use ianua_domain::types::{DomainId, Lifetime, TenantId};
    use time::Duration;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::domain::{
        DomainSeed, FakeDnsZoneWriter, FakeDomainStore, certificates,
    };
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{
        FakeEventDispatcher, FakeLimitEnforcer, RejectingLimitEnforcer, block_on, test_auditor,
        test_ctx,
    };
    use crate::use_cases::domain::verification::verified::PROVISION_TLS_JOB;

    /// Claims overlapping the platform namespace are rejected without
    /// registrations, zones or audit entries; an unrelated custom domain
    /// can still be registered.
    #[test]
    fn platform_names_cannot_be_claimed_as_custom_domains() {
        let mut f = fixture(Setup::default());
        f.use_case = f
            .use_case
            .with_platform_base(nameserver("apps.example.com"));
        for name in [
            "apps.example.com",
            "example.com",
            "*.example.com",
            "wiki.k7f3q9.apps.example.com",
        ] {
            assert!(matches!(add_own(&f, name), Err(AppError::Domain(_))));
        }
        assert_eq!(f.domains.count(), 0);
        assert!(f.zones.opened().is_empty());
        assert!(f.audit.records.lock().unwrap().is_empty());
        assert!(add_own(&f, "shop.acme.com").is_ok());
    }

    /// What a test changes about the deployment and the caller.
    struct Setup {
        domains: FakeDomainStore,
        delegation: DelegationOffer,
        trusted: TrustedDomains,
        limits: Arc<dyn LimitEnforcer>,
        authorities: FakeTenantAuthorities,
        claims_as_read: Option<Arc<FakeDomainStore>>,
    }

    impl Default for Setup {
        fn default() -> Self {
            Self {
                claims_as_read: None,
                domains: FakeDomainStore::empty(),
                delegation: DelegationOffer::default(),
                trusted: TrustedDomains::default(),
                limits: Arc::new(FakeLimitEnforcer),
                authorities: FakeTenantAuthorities::holding_everything(),
            }
        }
    }

    struct Fixture {
        use_case: AddDomainUseCase,
        domains: Arc<FakeDomainStore>,
        zones: Arc<FakeDnsZoneWriter>,
        queue: Arc<FakeJobQueue>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn nameserver(value: &str) -> DomainName {
        DomainName::new(value).unwrap()
    }

    fn days(count: i64) -> Lifetime {
        Lifetime::new(Duration::days(count)).unwrap()
    }

    /// Keeps unproved claims for one week and lost proofs for two weeks.
    fn claim_lifetimes() -> ClaimLifetimes {
        ClaimLifetimes {
            unproved: days(7),
            failed_grace: days(14),
        }
    }

    /// Registers against the configured claims, DNS service and caller authority.
    fn fixture(setup: Setup) -> Fixture {
        let domains = Arc::new(setup.domains);
        let zones = Arc::new(FakeDnsZoneWriter::with_nameservers(vec![nameserver(
            "ns1.ianua.test",
        )]));
        let queue = Arc::new(FakeJobQueue::new());
        let claims = setup.claims_as_read.unwrap_or_else(|| domains.clone());
        let use_case = AddDomainUseCase::new(
            AddDomainPorts {
                domain_store: domains.clone(),
                cross_tenant_domains: claims,
                certificates: certificates(queue.clone()),
                dns_zones: zones.clone(),
                limit_enforcer: setup.limits,
                tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                tenant_authorities: Arc::new(setup.authorities),
                site_rules: Arc::new(crate::test_support::ParentDomainSites),
            },
            setup.delegation,
            ProofRules::new(vec![nameserver("ns1.ianua.test")], setup.trusted),
            claim_lifetimes(),
        );
        Fixture {
            use_case,
            domains,
            zones,
            queue,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn delegation_available() -> DelegationOffer {
        DelegationOffer {
            nameservers: vec![nameserver("ns1.ianua.test")],
            proxy_address: Some(IpAddress::new("203.0.113.10").unwrap()),
        }
    }

    fn trusting(parent: &str) -> TrustedDomains {
        TrustedDomains::new([DomainName::new(parent).unwrap()]).unwrap()
    }

    fn add(
        f: &Fixture,
        name: &str,
        connection: DomainConnection,
    ) -> Result<RegisteredDomain<ResolvedTenant>, AppError> {
        block_on(f.use_case.execute(
            &test_ctx(),
            &test_auditor(f.audit.clone()),
            AddDomainRequest {
                domain: DomainName::new(name).unwrap(),
                connection,
            },
        ))
    }

    fn add_own(f: &Fixture, name: &str) -> Result<RegisteredDomain<ResolvedTenant>, AppError> {
        add(f, name, DomainConnection::SelfManaged)
    }

    /// A store in which another tenant, Globex, holds `domain`.
    fn held_by_globex(domain: RegisteredDomain<ResolvedTenant>) -> FakeDomainStore {
        FakeDomainStore::holding(TenantId::new(), [domain])
    }

    /// A store in which Acme holds `parent`, delegated to us and verified.
    fn with_delegated_parent(parent: &str) -> FakeDomainStore {
        FakeDomainStore::holding(
            test_ctx().tenant_id(),
            [DomainSeed::verified(parent).delegated().build()],
        )
    }

    /// A stale availability read cannot override Globex's saved claim;
    /// registration conflicts without opening a zone or recording an event.
    #[test]
    fn a_name_taken_at_the_same_moment_is_a_conflict_and_opens_no_zone() {
        let f = fixture(Setup {
            domains: held_by_globex(DomainSeed::pending("acme.com").build()),
            delegation: delegation_available(),
            claims_as_read: Some(Arc::new(FakeDomainStore::empty())),
            ..Setup::default()
        });

        let result = add(&f, "acme.com", DomainConnection::Delegated);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(f.zones.opened().is_empty());
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A stale availability read cannot claim a child of Globex's saved
    /// domain; registration conflicts without a zone or audit event.
    #[test]
    fn a_name_above_taken_at_the_same_moment_is_a_conflict() {
        let f = fixture(Setup {
            domains: held_by_globex(DomainSeed::pending("acme.com").build()),
            delegation: delegation_available(),
            claims_as_read: Some(Arc::new(FakeDomainStore::empty())),
            ..Setup::default()
        });

        let result = add(&f, "login.acme.com", DomainConnection::Delegated);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(f.zones.opened().is_empty());
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A public suffix cannot be registered as a tenant domain; the
    /// validation failure records no registration event.
    #[test]
    fn a_public_suffix_is_refused() {
        let f = fixture(Setup::default());

        let result = add_own(&f, "co.uk");

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann registers `acme.com`. It waits for its proof, is saved for Acme,
    /// and the registration is recorded.
    #[test]
    fn a_new_domain_is_registered_pending() {
        let f = fixture(Setup::default());

        let domain = add_own(&f, "acme.com").unwrap();

        assert_eq!(domain.verification_status(), VerificationStatus::Pending);
        assert!(
            f.domains
                .domain_of(test_ctx().tenant_id(), domain.id())
                .is_some()
        );
        assert_eq!(
            f.audit.records.lock().unwrap()[0],
            "tenant.domain_registered"
        );
    }

    /// The operator vouches for `acme.internal`. Ann's `login.acme.internal`
    /// is verified on registration and its certificate is asked for.
    #[test]
    fn a_name_the_operator_vouches_for_is_verified_on_registration() {
        let f = fixture(Setup {
            trusted: trusting("acme.internal"),
            ..Setup::default()
        });

        let domain = add_own(&f, "login.acme.internal").unwrap();

        assert_eq!(domain.verification_status(), VerificationStatus::Verified);
        assert!(f.queue.holds(PROVISION_TLS_JOB));
    }

    /// The operator vouches for `acme.internal` only. Ann's `acme.com` still
    /// waits for its proof, and no certificate is asked for.
    #[test]
    fn a_name_outside_the_vouched_for_parents_still_waits_for_its_proof() {
        let f = fixture(Setup {
            trusted: trusting("acme.internal"),
            ..Setup::default()
        });

        let domain = add_own(&f, "acme.com").unwrap();

        assert_eq!(domain.verification_status(), VerificationStatus::Pending);
        assert_eq!(f.queue.count(), 0);
    }

    /// Globex holds a vouched-for name. Ann registering it too is refused:
    /// vouching proves the name, not that it is Acme's.
    #[test]
    fn a_vouched_for_name_is_still_claimed_only_once() {
        let f = fixture(Setup {
            domains: held_by_globex(DomainSeed::verified("login.acme.internal").build()),
            trusted: trusting("acme.internal"),
            ..Setup::default()
        });

        let result = add_own(&f, "login.acme.internal");

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Globex claimed `acme.com` yesterday. Ann registering it is refused.
    #[test]
    fn a_name_another_tenant_holds_is_refused() {
        let f = fixture(Setup {
            domains: held_by_globex(DomainSeed::pending("acme.com").build()),
            ..Setup::default()
        });

        let result = add_own(&f, "acme.com");

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Mallory claimed `acme.com` eight days ago and never proved it. Her
    /// claim gives way after a week, and Ann registers the name.
    #[test]
    fn an_unproved_claim_older_than_a_week_gives_way() {
        let stale = DomainSeed::pending("acme.com")
            .created_at(clock::now() - Duration::days(8))
            .build();
        let f = fixture(Setup {
            domains: held_by_globex(stale),
            ..Setup::default()
        });

        let domain = add_own(&f, "acme.com").unwrap();

        assert_eq!(f.domains.count(), 1);
        assert!(
            f.domains
                .domain_of(test_ctx().tenant_id(), domain.id())
                .is_some()
        );
    }

    /// Mallory claimed `acme.com` three days ago. Her claim still holds the
    /// name against Ann.
    #[test]
    fn an_unproved_claim_younger_than_a_week_still_holds_its_name() {
        let recent = DomainSeed::pending("acme.com")
            .created_at(clock::now() - Duration::days(3))
            .build();
        let f = fixture(Setup {
            domains: held_by_globex(recent),
            ..Setup::default()
        });

        let result = add_own(&f, "acme.com");

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Globex proved `acme.com` once, and the proof failed fifteen days ago.
    /// Its two weeks of grace are over, so the name was sold, and Ann
    /// registers it.
    #[test]
    fn a_claim_whose_proof_failed_past_its_grace_gives_way() {
        let sold = DomainSeed::verified("acme.com")
            .created_at(clock::now() - Duration::days(60))
            .lost_at(clock::now() - Duration::days(15))
            .build();
        let f = fixture(Setup {
            domains: held_by_globex(sold),
            ..Setup::default()
        });

        let domain = add_own(&f, "acme.com").unwrap();

        assert_eq!(f.domains.count(), 1);
        assert!(
            f.domains
                .domain_of(test_ctx().tenant_id(), domain.id())
                .is_some()
        );
    }

    /// Globex's proof of `acme.com` failed three days ago, maybe one bad DNS
    /// answer. Its grace still holds the name against Ann.
    #[test]
    fn a_claim_whose_proof_failed_recently_still_holds_its_name() {
        let shaky = DomainSeed::verified("acme.com")
            .created_at(clock::now() - Duration::days(60))
            .lost_at(clock::now() - Duration::days(3))
            .build();
        let f = fixture(Setup {
            domains: held_by_globex(shaky),
            ..Setup::default()
        });

        let result = add_own(&f, "acme.com");

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Acme cannot register a child of Globex's verified domain; the
    /// conflicting attempt leaves only Globex's registration stored.
    #[test]
    fn a_name_beneath_another_tenants_is_refused() {
        let f = fixture(Setup {
            domains: held_by_globex(DomainSeed::verified("acme.com").build()),
            ..Setup::default()
        });

        let result = add_own(&f, "login.acme.com");

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(f.domains.count(), 1);
    }

    /// Globex's pending child-domain claim prevents Acme from registering
    /// the enclosing parent name.
    #[test]
    fn a_name_above_another_tenants_is_refused() {
        let f = fixture(Setup {
            domains: held_by_globex(DomainSeed::pending("login.acme.com").build()),
            ..Setup::default()
        });

        let result = add_own(&f, "acme.com");

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Acme already holds `acme.com`. Ann registers `login.acme.com` beneath
    /// it: Acme's own names never stand in its way.
    #[test]
    fn a_name_beneath_the_tenants_own_is_registered() {
        let f = fixture(Setup {
            domains: FakeDomainStore::holding(
                test_ctx().tenant_id(),
                [DomainSeed::verified("acme.com").build()],
            ),
            ..Setup::default()
        });

        let result = add_own(&f, "login.acme.com");

        assert!(result.is_ok());
        assert_eq!(f.domains.count(), 2);
    }

    /// Globex claimed `acme.com` eight days ago and never proved it. Its
    /// lapsed claim holds nothing, so Ann registers `login.acme.com`.
    #[test]
    fn a_lapsed_claim_above_does_not_stand_in_the_way() {
        let stale = DomainSeed::pending("acme.com")
            .created_at(clock::now() - Duration::days(8))
            .build();
        let f = fixture(Setup {
            domains: held_by_globex(stale),
            ..Setup::default()
        });

        let result = add_own(&f, "login.acme.com");

        assert!(result.is_ok());
    }

    /// Acme holds `auth.acme.com` delegated and verified. Ann's wildcard over
    /// it is registered already proved, since holding the parent's zone is
    /// the proof.
    #[test]
    fn a_wildcard_over_a_delegated_parent_is_registered_and_already_proved() {
        let f = fixture(Setup {
            domains: with_delegated_parent("auth.acme.com"),
            ..Setup::default()
        });

        let domain = add_own(&f, "*.auth.acme.com").unwrap();

        assert_eq!(domain.connection(), DomainConnection::Delegated);
        assert_eq!(domain.verification_status(), VerificationStatus::Verified);
    }

    /// Ann's wildcard opens no zone of its own: it is a record inside its
    /// parent's.
    #[test]
    fn a_wildcard_opens_no_zone_of_its_own() {
        let f = fixture(Setup {
            domains: with_delegated_parent("auth.acme.com"),
            delegation: delegation_available(),
            ..Setup::default()
        });

        add(&f, "*.auth.acme.com", DomainConnection::Delegated).unwrap();

        assert!(f.zones.opened().is_empty());
    }

    /// Acme holds no `auth.acme.com`. A wildcard over it is refused, since no
    /// certificate could ever be issued for it.
    #[test]
    fn a_wildcard_without_its_parent_is_refused() {
        let f = fixture(Setup {
            delegation: delegation_available(),
            ..Setup::default()
        });

        let result = add(&f, "*.auth.acme.com", DomainConnection::Delegated);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(f.domains.count(), 0);
    }

    /// Acme runs `auth.acme.com` at its own provider. There is nowhere for us
    /// to publish a wildcard's proof, so the wildcard is refused.
    #[test]
    fn a_wildcard_over_a_self_managed_parent_is_refused() {
        let f = fixture(Setup {
            domains: FakeDomainStore::holding(
                test_ctx().tenant_id(),
                [DomainSeed::verified("auth.acme.com").build()],
            ),
            ..Setup::default()
        });

        let result = add_own(&f, "*.auth.acme.com");

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Acme's `auth.acme.com` is delegated but not verified yet. A wildcard
    /// over it is refused.
    #[test]
    fn a_wildcard_over_an_unverified_parent_is_refused() {
        let f = fixture(Setup {
            domains: FakeDomainStore::holding(
                test_ctx().tenant_id(),
                [DomainSeed::pending("auth.acme.com").delegated().build()],
            ),
            ..Setup::default()
        });

        let result = add_own(&f, "*.auth.acme.com");

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// A verified, delegated parent in Globex does not authorize Acme to
    /// register its wildcard.
    #[test]
    fn a_wildcard_over_another_tenants_parent_is_refused() {
        let f = fixture(Setup {
            domains: held_by_globex(DomainSeed::verified("auth.globex.com").delegated().build()),
            ..Setup::default()
        });

        let result = add_own(&f, "*.auth.globex.com");

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann delegates `auth.acme.com` to us. Its zone is opened and points at
    /// the proxy from the start, so the name answers as soon as the `NS`
    /// record lands.
    #[test]
    fn a_delegated_domain_opens_a_zone_pointing_at_the_proxy() {
        let f = fixture(Setup {
            delegation: delegation_available(),
            ..Setup::default()
        });

        let domain = add(&f, "auth.acme.com", DomainConnection::Delegated).unwrap();

        let written = f.zones.written();
        assert_eq!(domain.connection(), DomainConnection::Delegated);
        assert_eq!(f.zones.opened(), vec![nameserver("auth.acme.com")]);
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].1.kind(), RecordKind::A);
        assert_eq!(written[0].1.values()[0].as_presentation(), "203.0.113.10");
    }

    /// This deployment offers no delegation. Ann's request to delegate keeps
    /// the domain self-managed, since a name we cannot answer for would
    /// resolve to nothing.
    #[test]
    fn without_a_delegation_offer_a_domain_stays_self_managed() {
        let f = fixture(Setup::default());

        let domain = add(&f, "auth.acme.com", DomainConnection::Delegated).unwrap();

        assert_eq!(domain.connection(), DomainConnection::SelfManaged);
        assert!(f.zones.opened().is_empty());
    }

    /// Nameservers are configured but no address. That cannot serve the name
    /// either, so it is no delegation offer.
    #[test]
    fn nameservers_without_an_address_are_not_a_delegation_offer() {
        let f = fixture(Setup {
            delegation: DelegationOffer {
                nameservers: vec![nameserver("ns1.ianua.test")],
                proxy_address: None,
            },
            ..Setup::default()
        });

        let domain = add(&f, "auth.acme.com", DomainConnection::Delegated).unwrap();

        assert_eq!(domain.connection(), DomainConnection::SelfManaged);
    }

    /// Ann did not ask for delegation. Acme keeps its own DNS and no zone is
    /// opened.
    #[test]
    fn a_domain_that_did_not_ask_for_delegation_keeps_its_own_dns() {
        let f = fixture(Setup {
            delegation: delegation_available(),
            ..Setup::default()
        });

        let domain = add_own(&f, "auth.acme.com").unwrap();

        assert_eq!(domain.connection(), DomainConnection::SelfManaged);
        assert!(f.zones.opened().is_empty());
    }

    /// Globex already holds the zone for `auth.acme.com`. Ann's delegated
    /// registration is refused and not saved, so no domain is marked
    /// delegated with nothing behind it.
    #[test]
    fn a_domain_whose_zone_another_tenant_holds_is_not_registered() {
        let f = fixture(Setup {
            delegation: delegation_available(),
            ..Setup::default()
        });
        let label = DelegationLabel::for_registration(&DomainId::new());
        block_on(
            f.zones
                .create_zone(&TenantId::new(), &nameserver("auth.acme.com"), &label),
        )
        .unwrap();

        let result = add(&f, "auth.acme.com", DomainConnection::Delegated);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(f.domains.count(), 0);
    }

    /// Acme is at its plan's ceiling on domains. Ann's registration is
    /// refused before the name is claimed.
    #[test]
    fn a_registration_past_the_plan_ceiling_is_refused() {
        let f = fixture(Setup {
            limits: Arc::new(RejectingLimitEnforcer),
            ..Setup::default()
        });

        let result = add_own(&f, "acme.com");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.domains.count(), 0);
    }

    /// Update rights cannot register a lapsed name; the forbidden attempt
    /// leaves the existing claim stored and records no registration event.
    #[test]
    fn a_caller_who_may_not_add_domains_is_refused_before_anything_is_claimed() {
        let stale = DomainSeed::pending("acme.com")
            .created_at(clock::now() - Duration::days(8))
            .build();
        let f = fixture(Setup {
            domains: held_by_globex(stale),
            authorities: FakeTenantAuthorities::holding(&[SystemPermission::Domains(
                DomainAction::Update,
            )]),
            ..Setup::default()
        });

        let result = add_own(&f, "acme.com");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.domains.count(), 1);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot register a domain and leaves the store empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(Setup {
            authorities: FakeTenantAuthorities::refusing(Refusal::SignedOut),
            ..Setup::default()
        });

        let result = add_own(&f, "acme.com");

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(f.domains.count(), 0);
    }
}
