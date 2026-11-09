//! Decide access: whether one request through the gateway may pass, is
//! refused, or must show more first.
//!
//! The gateway's Policy stage calls this for every request, after the
//! Identity stage proved the credential. It holds no rule of its own: it
//! reads the route as stored now and the tenant's live policy, takes what
//! the credential check established about the caller, reads what the
//! person an agent acts for still holds, and the domain decides.
//!
//! What the caller holds is read once per request, by the credential check,
//! and handed over in its proof; it is not read again here. A proof older
//! than a request may take is refused rather than trusted.
//!
//! It denies by default: a route, record or policy that cannot be read is a
//! refusal, never a pass, and nothing here fails in a way the gateway could
//! mistake for one.

use std::sync::Arc;

use ianua_domain::domains::authorization::held::Held;
use ianua_domain::domains::authorization::policy::set::PolicySet;
use ianua_domain::domains::authorization::policy::time_window::{TimeOfDay, ZonedTime};
use ianua_domain::domains::proxy::access::decide;
use ianua_domain::domains::proxy::access::decision::AccessDecision;
use ianua_domain::domains::proxy::access::question::{
    AccessQuestion, Asked, Asker, Circumstances, Lookup, OnBehalf, Records, RouteTerms,
};
use ianua_domain::domains::proxy::request::context::{Caller, CallerClaims};
use ianua_domain::domains::routing::route::Route;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::types::{PrincipalRef, RouteId, Timezone};
use time::{Duration, OffsetDateTime};

use crate::ports::authorization::{AccessRecordStore, PolicyStore};
use crate::ports::organization::MemberStandings;
use crate::ports::routing::{PolicyDecisionPoint, RouteStore};
use crate::ports::scheduling::TimeZones;
use crate::services::authorization::held::{RecordSources, records_of};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::proxy::credentials::{Identification, Proven};

/// The longest a credential check's proof is decided on: more than any one
/// request takes between its two stages, so a proof kept from an earlier
/// request is refused.
const PROOF_LIFETIME: Duration = Duration::seconds(30);

/// One request the gateway asks about.
pub struct DecideAccessRequest {
    /// The route the request matched.
    pub route_id: RouteId,
    /// What the credential check established for this request: nobody, or
    /// the caller with what their credential carries and what they hold.
    pub identification: Identification,
    /// What the request asks for.
    pub asked: Asked,
    /// What the gateway knows around it.
    pub circumstances: Circumstances,
}

/// The ports [`DecideAccessUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DecideAccessPorts {
    /// The tenant's routes, as stored now.
    pub route_store: Arc<dyn RouteStore>,
    /// Whether the records know the one an agent acts for and let them act
    /// now.
    pub policy_decisions: Arc<dyn PolicyDecisionPoint>,
    /// What the one an agent acts for holds, from the tenant's records.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// The one an agent acts for, when an organization member, as the
    /// tenant reads them.
    pub member_standings: Arc<dyn MemberStandings>,
    /// The tenant's live access policy.
    pub policy_store: Arc<dyn PolicyStore>,
    /// The time of day in the zones the tenant's policy names.
    pub time_zones: Arc<dyn TimeZones>,
}

/// A proven caller, with what the decision reads of them.
struct Established {
    caller: Caller,
    credential: CallerClaims,
    records: Records,
    on_behalf: OnBehalf,
}

impl Established {
    /// The caller as the decision reads them.
    fn asker(&self) -> Asker<'_> {
        Asker::Identified {
            caller: &self.caller,
            credential: &self.credential,
            records: &self.records,
            on_behalf: &self.on_behalf,
        }
    }
}

/// Decides one request for the gateway.
pub struct DecideAccessUseCase {
    ports: DecideAccessPorts,
}

impl DecideAccessUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: DecideAccessPorts) -> Self {
        Self { ports }
    }

    /// The route `id` names, as stored now, or that it could not be read.
    async fn route(&self, tenant: &ScopedTenant, id: &RouteId) -> Lookup<Route<ResolvedTenant>> {
        match self.ports.route_store.find_by_id(tenant, id).await {
            Ok(Some(route)) => Lookup::Found(route),
            Ok(None) => Lookup::Missing,
            Err(error) => {
                tracing::warn!(route_id = %id, %error, "route unreadable; refusing");
                Lookup::Unreadable
            }
        }
    }

    /// The caller the credential check proved, with what it read of them
    /// while it is fresh, and what the records say of the one an agent
    /// acts for. Nobody when it proved nobody.
    async fn established(
        &self,
        tenant: &ScopedTenant,
        identification: Identification,
    ) -> Option<Established> {
        let Identification::Proven(proven) = identification else {
            return None;
        };
        let Proven {
            verified,
            claims,
            held,
            established_at,
            ..
        } = *proven;
        let on_behalf = self.on_behalf(tenant, &verified.caller).await;
        Some(Established {
            caller: verified.caller,
            credential: claims,
            records: fresh(held, established_at, clock::now()),
            on_behalf,
        })
    }

    /// Whose authority `caller` acts on beyond its own: for an agent acting
    /// for someone else, what the records say of them now.
    async fn on_behalf(&self, tenant: &ScopedTenant, caller: &Caller) -> OnBehalf {
        let Caller::Agent {
            agent_id,
            acting_for,
            ..
        } = caller
        else {
            return OnBehalf::Own;
        };
        if *acting_for == PrincipalRef::Agent(*agent_id) {
            return OnBehalf::Own;
        }
        let sources = RecordSources {
            decisions: self.ports.policy_decisions.as_ref(),
            access: self.ports.access_records.as_ref(),
            members: self.ports.member_standings.as_ref(),
        };
        OnBehalf::Of(records_of(sources, tenant, *acting_for).await)
    }

    /// The tenant's live policy, none, or that it could not be read.
    async fn live_policy(&self, tenant: &ScopedTenant) -> Lookup<PolicySet> {
        match self.ports.policy_store.find_active(tenant).await {
            Ok(Some(policy)) => Lookup::Found(policy),
            Ok(None) => Lookup::Missing,
            Err(error) => {
                tracing::warn!(%error, "tenant policy unreadable; refusing");
                Lookup::Unreadable
            }
        }
    }

    /// The time of day now in each zone `policy` names. A zone the
    /// timezone database does not hold is left out, so a rule on it reads
    /// a time nobody knows.
    fn local_times(&self, policy: Lookup<&PolicySet>, now: OffsetDateTime) -> Vec<ZonedTime> {
        let Lookup::Found(policy) = policy else {
            return Vec::new();
        };
        policy
            .timezones()
            .into_iter()
            .filter_map(|zone| self.local_time(zone, now))
            .collect()
    }

    /// The time of day `now` reads as in `zone`, when the zone is known.
    fn local_time(&self, zone: &Timezone, now: OffsetDateTime) -> Option<ZonedTime> {
        let local = self.ports.time_zones.local(zone, now).ok()?;
        let time = TimeOfDay::at(local.hour(), local.minute()).ok()?;
        Some(ZonedTime::new(zone.clone(), time))
    }
}

impl Query for DecideAccessUseCase {
    type Caller = ScopedTenant;
    type Input = DecideAccessRequest;
    type Output = AccessDecision;

    /// Whether `request` may pass in `tenant` now.
    ///
    /// It never fails: a route, record or policy that cannot be read, or
    /// does not answer in time, and a proof too old to trust, are refusals
    /// with their own reason codes.
    async fn execute(&self, tenant: &ScopedTenant, request: DecideAccessRequest) -> AccessDecision {
        let DecideAccessRequest {
            route_id,
            identification,
            asked,
            circumstances,
        } = request;
        let route = self.route(tenant, &route_id).await;
        let established = self.established(tenant, identification).await;
        let policy = self.live_policy(tenant).await;
        let local_times = self.local_times(policy.as_ref(), clock::now());
        decide(&AccessQuestion {
            route: route.as_ref().map(RouteTerms::of),
            asker: established
                .as_ref()
                .map_or(Asker::Anonymous, Established::asker),
            asked: &asked,
            circumstances: &circumstances,
            local_times: &local_times,
            tenant_policy: policy.as_ref(),
        })
    }
}

/// `held`, as read at `read_at`, while it may still decide a request at
/// `now`: a proof from the future or older than [`PROOF_LIFETIME`] is
/// stale.
fn fresh(held: Held, read_at: OffsetDateTime, now: OffsetDateTime) -> Records {
    let age = now - read_at;
    if age.is_negative() || age > PROOF_LIFETIME {
        return Records::Stale;
    }
    Records::Holds(held)
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::agents::authority::capability::{ActionApproval, McpGrant};
    use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::authorization::policy::action::PolicyAction;
    use ianua_domain::domains::authorization::policy::claims::{Claim, ClaimName, ClaimValue};
    use ianua_domain::domains::authorization::policy::condition::PolicyCondition;
    use ianua_domain::domains::authorization::policy::rule::PolicyRule;
    use ianua_domain::domains::authorization::policy::status::PolicyStatus;
    use ianua_domain::domains::authorization::stewardship::AdministratorCount;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::tenant_grant::{
        OrgTenantGrant, OrgTenantGrantRow,
    };
    use ianua_domain::domains::proxy::access::decision::{
        Challenge, DenyCode, Outcome, SettledBy, TenantRuling,
    };
    use ianua_domain::domains::proxy::access::question::{
        DpopBinding, MethodClaim, PostureFinding, Standing,
    };
    use ianua_domain::domains::proxy::request::context::{
        AgentLimits, ConsumerCredential, KeyBinding, Metering, UserSignIn, Verified,
    };
    use ianua_domain::domains::routing::matching::host::RouteHosts;
    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::domains::routing::route_status::RouteStatus;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::shared::model::restriction::Restriction;
    use ianua_domain::types::{
        ActedBy, AgentId, CanonicalPath, ConsumerId, DelegationId, Expiry, Fact, HttpMethod, Label,
        OrgUserId, OrganizationId, PathPrefix, PermissionName, PipelineId, RoleId, Text, UserId,
    };

    use super::*;
    use crate::listing::{Page, PageRequest, SortOrder};
    use crate::ports::TenantScoped;
    use crate::ports::authorization::{AccessRecords, HeldRecords, Holder, Holders};
    use crate::ports::organization::MemberStanding;
    use crate::ports::routing::RouteSortField;
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakePolicyStore, FakeRoleAssignmentStore,
        FakeRoleStore, policy_in, stored_assignment, stored_role,
    };
    use crate::test_support::organization::{FakeMemberStandings, test_org_owning, test_org_user};
    use crate::test_support::proxy::test_pipeline;
    use crate::test_support::routing::{
        FakePolicyDecisionPoint, FakeRouteStore, RouteShape, disabled, pinned_upstream, route_of,
        service_named,
    };
    use crate::test_support::scheduling::UtcTimeZones;
    use crate::test_support::{Fake, block_on, test_ctx};

    const VIEW_USERS: SystemPermission = SystemPermission::Users(UserAction::View);

    /// A store that cannot be reached: every read and write fails, as a
    /// database that is down or does not answer in time does.
    struct Unreachable;

    impl TenantScoped for Unreachable {}

    fn down() -> DomainError {
        DomainError::infra_msg("the store is unreachable")
    }

    #[async_trait]
    impl RouteStore for Unreachable {
        async fn find_by_id(
            &self,
            _tenant_id: &ScopedTenant,
            _id: &RouteId,
        ) -> Result<Option<Route<ResolvedTenant>>, DomainError> {
            Err(down())
        }

        async fn list_all(
            &self,
            _tenant_id: &ScopedTenant,
            _status: Option<RouteStatus>,
            _sort: &SortOrder<RouteSortField>,
            _page: &PageRequest,
        ) -> Result<Page<Route<ResolvedTenant>>, DomainError> {
            Err(down())
        }

        async fn list_by_pipeline(
            &self,
            _tenant_id: &ScopedTenant,
            _pipeline_id: &PipelineId,
        ) -> Result<Vec<Route<ResolvedTenant>>, DomainError> {
            Err(down())
        }

        async fn list_open_to_workflows(
            &self,
            _tenant_id: &ScopedTenant,
        ) -> Result<Vec<Route<ResolvedTenant>>, DomainError> {
            Err(down())
        }

        async fn save(
            &self,
            _tenant_id: &ScopedTenant,
            _route: &Route<ResolvedTenant>,
        ) -> Result<(), DomainError> {
            Err(down())
        }

        async fn delete(
            &self,
            _tenant_id: &ScopedTenant,
            _id: &RouteId,
        ) -> Result<(), DomainError> {
            Err(down())
        }
    }

    #[async_trait]
    impl PolicyStore for Unreachable {
        async fn find_versions(
            &self,
            _tenant_id: &ScopedTenant,
        ) -> Result<Vec<PolicySet>, DomainError> {
            Err(down())
        }

        async fn find_active(
            &self,
            _tenant_id: &ScopedTenant,
        ) -> Result<Option<PolicySet>, DomainError> {
            Err(down())
        }

        async fn save(
            &self,
            _tenant_id: &ScopedTenant,
            _policy: &PolicySet,
        ) -> Result<(), DomainError> {
            Err(down())
        }

        async fn save_activation(
            &self,
            _tenant_id: &ScopedTenant,
            _activated: &PolicySet,
            _replaced: Option<&PolicySet>,
        ) -> Result<(), DomainError> {
            Err(down())
        }
    }

    #[async_trait]
    impl AccessRecordStore for Unreachable {
        async fn load(&self, _tenant_id: &ScopedTenant) -> Result<AccessRecords, DomainError> {
            Err(down())
        }

        async fn load_held_by(
            &self,
            _tenant_id: &ScopedTenant,
            _holder: Holder<'_>,
        ) -> Result<HeldRecords, DomainError> {
            Err(down())
        }

        async fn load_held_by_all(
            &self,
            _tenant_id: &ScopedTenant,
            _holders: Holders<'_>,
        ) -> Result<HeldRecords, DomainError> {
            Err(down())
        }

        async fn count_administrators(
            &self,
            _tenant_id: &ScopedTenant,
        ) -> Result<AdministratorCount, DomainError> {
            Err(down())
        }

        async fn list_administrators(
            &self,
            _tenant_id: &ScopedTenant,
            _page: &PageRequest,
        ) -> Result<Page<UserId>, DomainError> {
            Err(down())
        }

        async fn list_holders_of(
            &self,
            _tenant_id: &ScopedTenant,
            _right: SystemPermission,
            _page: &PageRequest,
        ) -> Result<Page<UserId>, DomainError> {
            Err(down())
        }

        async fn hold_grants(&self, _tenant_id: &ScopedTenant) -> Result<(), DomainError> {
            Err(down())
        }
    }

    fn tenant() -> ScopedTenant {
        test_ctx().tenant()
    }

    /// A route on `/app` holding callers to `policy`.
    fn route(policy: RoutePolicy) -> Route<ResolvedTenant> {
        let service = service_named("app", pinned_upstream("https://backend:8080", "app"));
        route_of(
            RouteShape {
                name: "app",
                path: "/app",
                policy,
                hosts: RouteHosts::Any,
            },
            &service,
            &test_pipeline(),
        )
    }

    /// The stores a test decides through.
    struct Fixture {
        routes: Arc<dyn RouteStore>,
        decisions: Arc<dyn PolicyDecisionPoint>,
        records: Arc<dyn AccessRecordStore>,
        members: Arc<dyn MemberStandings>,
        policies: Arc<dyn PolicyStore>,
    }

    impl Fixture {
        /// Acme with `route` stored, anyone an agent acts for standing as
        /// `standing` and holding nothing, and no live policy.
        fn with(route: &Route<ResolvedTenant>, standing: Standing) -> Self {
            let routes = FakeRouteStore::empty();
            block_on(routes.save(&tenant(), route)).unwrap();
            Self {
                routes: Arc::new(routes),
                decisions: Arc::new(FakePolicyDecisionPoint::in_standing(standing)),
                records: Arc::new(FakeAccessRecordStore::empty()),
                members: Fake::fake(),
                policies: Arc::new(FakePolicyStore::empty()),
            }
        }

        /// Makes Sam a plain member of an organization, owning Acme when
        /// `owning` says, granted in Acme a role holding `permissions`, and
        /// answers his principal.
        fn member(
            self,
            owning: Owning,
            permissions: Vec<SystemPermission>,
        ) -> (Self, PrincipalRef) {
            let tenant_id = test_ctx().tenant_id();
            let organization_id = OrganizationId::new();
            let tenants = match owning {
                Owning::Acme => vec![tenant_id],
                Owning::Elsewhere => Vec::new(),
            };
            let sam = test_org_user(organization_id, "sam@acme.test", OrgRole::Member);
            let role = stored_role("granted", permissions, Vec::new());
            let grant = member_grant(*sam.id(), *role.id());
            let standing = MemberStanding {
                member: sam.reach(),
                organization: test_org_owning(organization_id, "acme", &tenants),
                grants: vec![grant],
            };
            let sources = AccessSources {
                roles: Arc::new(FakeRoleStore::holding(tenant_id, [role])),
                ..AccessSources::default()
            };
            let fixture = Self {
                records: Arc::new(FakeAccessRecordStore::reading(sources)),
                members: Arc::new(FakeMemberStandings::knowing(standing)),
                ..self
            };
            (fixture, PrincipalRef::OrgUser(*sam.id()))
        }

        /// Gives `principal`, in the records, a role holding `permissions`.
        fn grant(self, principal: PrincipalRef, permissions: Vec<SystemPermission>) -> Self {
            let tenant_id = test_ctx().tenant_id();
            let role = stored_role("granting", permissions, Vec::new());
            let given = stored_assignment(principal, *role.id());
            let sources = AccessSources {
                roles: Arc::new(FakeRoleStore::holding(tenant_id, [role])),
                assignments: Arc::new(FakeRoleAssignmentStore::holding(tenant_id, [given])),
                ..AccessSources::default()
            };
            Self {
                records: Arc::new(FakeAccessRecordStore::reading(sources)),
                ..self
            }
        }

        /// Makes `rules` Acme's live policy, allowing what they do not
        /// match.
        fn live(self, rules: Vec<PolicyRule>) -> Self {
            let policy = policy_in(PolicyStatus::Active, rules);
            Self {
                policies: Arc::new(FakePolicyStore::holding(test_ctx().tenant_id(), policy)),
                ..self
            }
        }

        fn decide(self, request: DecideAccessRequest) -> AccessDecision {
            let use_case = DecideAccessUseCase::new(DecideAccessPorts {
                route_store: self.routes,
                policy_decisions: self.decisions,
                access_records: self.records,
                member_standings: self.members,
                policy_store: self.policies,
                time_zones: Arc::new(UtcTimeZones),
            });
            block_on(use_case.execute(&tenant(), request))
        }
    }

    /// Whether a member's organization owns Acme.
    #[derive(Clone, Copy)]
    enum Owning {
        Acme,
        Elsewhere,
    }

    /// Grants the member a role in the tenant whose gateway request is decided.
    fn member_grant(member: OrgUserId, role: RoleId) -> OrgTenantGrant {
        OrgTenantGrant::reconstitute(OrgTenantGrantRow {
            org_user_id: member,
            tenant_id: test_ctx().tenant_id(),
            role_id: role,
            granted_by: ActedBy::Platform,
            granted_at: clock::now(),
        })
        .unwrap()
    }

    fn request(
        route: &Route<ResolvedTenant>,
        identification: Identification,
    ) -> DecideAccessRequest {
        DecideAccessRequest {
            route_id: *route.id(),
            identification,
            asked: Asked {
                method: Fact::Known(HttpMethod::Get),
                path: Fact::Known(CanonicalPath::new("/app/orders").unwrap()),
                method_claim: MethodClaim::AsSent,
                host: Fact::Unknown,
            },
            circumstances: Circumstances {
                country: Fact::Unknown,
                source_ip: Fact::Unknown,
                device: Fact::Unknown,
                risk: Fact::Unknown,
                sensitivity: Fact::Unknown,
                binding: DpopBinding::Unbound,
                posture: PostureFinding::NotAsked,
            },
        }
    }

    /// What the credential check established for `caller`, holding `held`
    /// and carrying `claims`, `age` ago.
    fn proven_ago(
        caller: Caller,
        held: Held,
        claims: CallerClaims,
        age: Duration,
    ) -> Identification {
        Identification::Proven(Box::new(Proven {
            verified: Verified {
                caller,
                expiry: Expiry::Never,
            },
            claims,
            held,
            established_at: clock::now() - age,
            binding: DpopBinding::Unbound,
        }))
    }

    fn proven(caller: Caller, held: Held) -> Identification {
        proven_ago(caller, held, CallerClaims::default(), Duration::ZERO)
    }

    fn a_person() -> Caller {
        Caller::User {
            user_id: UserId::new(),
            sign_in: UserSignIn::Token,
        }
    }

    fn holding(system: &[SystemPermission]) -> Held {
        Held::assumed(system, &[], &[], &[])
    }

    /// A person the credential check proved just now, holding `system`.
    fn person(system: &[SystemPermission]) -> Identification {
        proven(a_person(), holding(system))
    }

    /// An agent acting for `acting_for`, its token naming `token`.
    fn agent_for(agent_id: AgentId, acting_for: PrincipalRef, token: &[&str]) -> Identification {
        let caller = Caller::Agent {
            agent_id,
            delegation_id: DelegationId::new(),
            acting_for,
            limits: Box::new(AgentLimits {
                intent_envelope: Restriction::Unrestricted,
                mcp: McpGrant::default(),
                resource_scope: Restriction::Unrestricted,
                max_data_class: Restriction::Unrestricted,
                key_binding: KeyBinding::Bearer,
                approval: ActionApproval::NotRequired,
                metering: Metering::Unmetered,
            }),
        };
        let claims = CallerClaims {
            permissions: token
                .iter()
                .map(|name| PermissionName::new(*name).unwrap())
                .collect(),
            ..CallerClaims::default()
        };
        proven_ago(caller, Held::default(), claims, Duration::ZERO)
    }

    fn rule(name: &str, action: PolicyAction) -> PolicyRule {
        PolicyRule::new(
            Label::new("rule_name", name).unwrap(),
            vec![PolicyCondition::PathPrefix(
                PathPrefix::new("/app").unwrap(),
            )],
            action,
            10,
        )
        .unwrap()
    }

    fn deny(code: DenyCode) -> Outcome {
        Outcome::Deny(code)
    }

    /// Ann's role lets her view users, and the route asks for that. She is
    /// let through, and no tenant policy had a say.
    #[test]
    fn a_person_holding_the_routes_permission_is_permitted() {
        let route = route(RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]));
        let f = Fixture::with(&route, Standing::Good);

        let decision = f.decide(request(&route, person(&[VIEW_USERS])));

        assert_eq!(decision.outcome(), Outcome::Permit);
        assert_eq!(decision.ruling(), &TenantRuling::NoPolicy);
    }

    /// Token permission claims cannot replace missing grants in the proven
    /// records; access is denied for the missing permission.
    #[test]
    fn what_the_records_give_decides_not_the_token() {
        let route = route(RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]));
        let f = Fixture::with(&route, Standing::Good);
        let claiming = CallerClaims {
            permissions: vec![PermissionName::new("idp:users:view").unwrap()],
            ..CallerClaims::default()
        };
        let sam = proven_ago(a_person(), holding(&[]), claiming, Duration::ZERO);

        let decision = f.decide(request(&route, sam));

        assert_eq!(decision.outcome(), deny(DenyCode::PermissionMissing));
    }

    /// A consumer whose roles give it the route's permission is let
    /// through.
    #[test]
    fn a_consumer_is_decided_by_its_roles() {
        let route = route(RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]));
        let f = Fixture::with(&route, Standing::Good);
        let billing = Caller::Consumer {
            consumer_id: ConsumerId::new(),
            credential: ConsumerCredential::ApiKey,
        };

        let decision = f.decide(request(&route, proven(billing, holding(&[VIEW_USERS]))));

        assert_eq!(decision.outcome(), Outcome::Permit);
    }

    /// What the credential check read is not read again: with the records
    /// store down, Ann's proof still decides her request.
    #[test]
    fn the_callers_records_are_taken_from_the_proof() {
        let route = route(RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]));
        let f = Fixture {
            records: Arc::new(Unreachable),
            decisions: Arc::new(FakePolicyDecisionPoint::unreachable()),
            ..Fixture::with(&route, Standing::Good)
        };

        let decision = f.decide(request(&route, person(&[VIEW_USERS])));

        assert_eq!(decision.outcome(), Outcome::Permit);
    }

    /// A proof dated a minute ago or a minute ahead is refused as stale, even
    /// on a public route.
    #[test]
    fn a_stale_proof_is_refused() {
        let route = route(RoutePolicy::Public);
        let old = proven_ago(
            a_person(),
            holding(&[]),
            CallerClaims::default(),
            Duration::minutes(1),
        );
        let ahead = proven_ago(
            a_person(),
            holding(&[]),
            CallerClaims::default(),
            -Duration::minutes(1),
        );

        let from_old = Fixture::with(&route, Standing::Good).decide(request(&route, old));
        let from_ahead = Fixture::with(&route, Standing::Good).decide(request(&route, ahead));

        assert_eq!(from_old.outcome(), deny(DenyCode::RecordsStale));
        assert_eq!(from_ahead.outcome(), deny(DenyCode::RecordsStale));
    }

    /// An anonymous caller on an authenticated route is denied with sign-in
    /// required.
    #[test]
    fn a_missing_token_is_refused() {
        let route = route(RoutePolicy::Authenticated);
        let f = Fixture::with(&route, Standing::Good);

        let decision = f.decide(request(&route, Identification::Anonymous));

        assert_eq!(decision.outcome(), deny(DenyCode::SignInRequired));
    }

    /// Ann's agent acts for her, and she still holds what its token names.
    /// It is let through.
    #[test]
    fn an_agent_whose_delegator_still_holds_the_right_is_permitted() {
        let ann = UserId::new();
        let route = route(RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]));
        let f =
            Fixture::with(&route, Standing::Good).grant(PrincipalRef::User(ann), vec![VIEW_USERS]);
        let helper = agent_for(AgentId::new(), PrincipalRef::User(ann), &["idp:users:view"]);

        let decision = f.decide(request(&route, helper));

        assert_eq!(decision.outcome(), Outcome::Permit);
    }

    /// An agent's token permission does not grant access when its delegator
    /// holds no matching right in the current records.
    #[test]
    fn an_agent_whose_delegator_lost_the_right_is_refused() {
        let route = route(RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]));
        let f = Fixture::with(&route, Standing::Good);
        let helper = agent_for(
            AgentId::new(),
            PrincipalRef::User(UserId::new()),
            &["idp:users:view"],
        );

        let decision = f.decide(request(&route, helper));

        assert_eq!(decision.outcome(), deny(DenyCode::PermissionMissing));
    }

    /// A task token naming no permissions is refused as nothing delegated,
    /// even when its person holds a right and the route only requires sign-in.
    #[test]
    fn an_agent_whose_token_names_nothing_is_refused() {
        let ann = UserId::new();
        let route = route(RoutePolicy::Authenticated);
        let f =
            Fixture::with(&route, Standing::Good).grant(PrincipalRef::User(ann), vec![VIEW_USERS]);
        let reviewer = agent_for(AgentId::new(), PrincipalRef::User(ann), &[]);

        let decision = f.decide(request(&route, reviewer));

        assert_eq!(decision.outcome(), deny(DenyCode::NothingDelegated));
    }

    /// Unknown or barred delegators and unreadable standing or access records
    /// each deny the agent with the corresponding reason.
    #[test]
    fn an_agent_whose_delegator_may_not_act_is_refused() {
        let route = route(RoutePolicy::Authenticated);
        let ask = |f: Fixture| {
            let helper = agent_for(AgentId::new(), PrincipalRef::User(UserId::new()), &[]);
            f.decide(request(&route, helper)).outcome()
        };
        let unreachable = Fixture {
            decisions: Arc::new(FakePolicyDecisionPoint::unreachable()),
            ..Fixture::with(&route, Standing::Good)
        };
        let unreadable = Fixture {
            records: Arc::new(Unreachable),
            ..Fixture::with(&route, Standing::Good)
        };

        assert_eq!(
            ask(Fixture::with(&route, Standing::Unknown)),
            deny(DenyCode::DelegatorUnknown)
        );
        assert_eq!(
            ask(Fixture::with(&route, Standing::Barred)),
            deny(DenyCode::DelegatorBarred)
        );
        assert_eq!(ask(unreachable), deny(DenyCode::RecordsUnreadable));
        assert_eq!(ask(unreadable), deny(DenyCode::RecordsUnreadable));
    }

    /// Sam, a plain member of Acme's organization granted a role in Acme
    /// that lets him view users, delegates to his agent. The agent's request
    /// is judged on what Sam's grant gives, and let through.
    #[test]
    fn an_agent_acting_for_a_member_holding_the_right_is_permitted() {
        let route = route(RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]));
        let (f, sam) =
            Fixture::with(&route, Standing::Unknown).member(Owning::Acme, vec![VIEW_USERS]);
        let helper = agent_for(AgentId::new(), sam, &["idp:users:view"]);

        let decision = f.decide(request(&route, helper));

        assert_eq!(decision.outcome(), Outcome::Permit);
    }

    /// An organization member's agent is denied when the member's tenant
    /// grant lacks the required permission, despite the token claiming it.
    #[test]
    fn an_agent_acting_for_a_member_without_the_right_is_refused() {
        let route = route(RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]));
        let (f, sam) = Fixture::with(&route, Standing::Unknown).member(Owning::Acme, Vec::new());
        let helper = agent_for(AgentId::new(), sam, &["idp:users:view"]);

        let decision = f.decide(request(&route, helper));

        assert_eq!(decision.outcome(), deny(DenyCode::PermissionMissing));
    }

    /// An agent acting for a member of a non-owning organization is denied as
    /// barred; an absent member is denied as unknown.
    #[test]
    fn an_agent_acting_for_a_member_who_does_not_reach_the_tenant_is_refused() {
        let route = route(RoutePolicy::Authenticated);
        let (elsewhere, sam) =
            Fixture::with(&route, Standing::Good).member(Owning::Elsewhere, vec![VIEW_USERS]);
        let stranger = PrincipalRef::OrgUser(ianua_domain::types::OrgUserId::new());

        let barred = elsewhere.decide(request(
            &route,
            agent_for(AgentId::new(), sam, &["idp:users:view"]),
        ));
        let unknown = Fixture::with(&route, Standing::Good).decide(request(
            &route,
            agent_for(AgentId::new(), stranger, &["idp:users:view"]),
        ));

        assert_eq!(barred.outcome(), deny(DenyCode::DelegatorBarred));
        assert_eq!(unknown.outcome(), deny(DenyCode::DelegatorUnknown));
    }

    /// An agent acting for itself is held to its own grants, as the proof
    /// carries them, and nobody else's records are read.
    #[test]
    fn an_agent_acting_for_itself_is_held_to_its_own_grants() {
        let route = route(RoutePolicy::RequireSystemPermission(vec![VIEW_USERS]));
        let f = Fixture {
            decisions: Arc::new(FakePolicyDecisionPoint::unreachable()),
            ..Fixture::with(&route, Standing::Good)
        };
        let agent_id = AgentId::new();
        let Identification::Proven(mut itself) =
            agent_for(agent_id, PrincipalRef::Agent(agent_id), &["idp:users:view"])
        else {
            panic!("an agent is proven");
        };
        itself.held = holding(&[VIEW_USERS]);

        let decision = f.decide(request(&route, Identification::Proven(itself)));

        assert_eq!(decision.outcome(), Outcome::Permit);
    }

    /// Ann's token asserts she is in finance, and Acme's policy refuses
    /// finance under `/app`. The claim reaches the policy, which refuses.
    #[test]
    fn the_credentials_claims_reach_the_tenant_policy() {
        let route = route(RoutePolicy::Authenticated);
        let finance = PolicyRule::new(
            Label::new("rule_name", "no-finance").unwrap(),
            vec![PolicyCondition::ClaimEquals {
                name: ClaimName::new("department").unwrap(),
                value: ClaimValue::new("finance").unwrap(),
            }],
            PolicyAction::Deny {
                reason: Text::new("reason", "closed").unwrap(),
            },
            10,
        )
        .unwrap();
        let f = Fixture::with(&route, Standing::Good).live(vec![finance]);
        let asserting = CallerClaims {
            asserted: Fact::Known(vec![Claim::new(
                ClaimName::new("department").unwrap(),
                ClaimValue::new("finance").unwrap(),
            )]),
            ..CallerClaims::default()
        };
        let ann = proven_ago(a_person(), holding(&[]), asserting, Duration::ZERO);

        let decision = f.decide(request(&route, ann));

        assert_eq!(decision.outcome(), deny(DenyCode::TenantRule));
    }

    /// An unreadable route store denies an anonymous request even when its
    /// matched route was public.
    #[test]
    fn an_unreachable_route_store_refuses() {
        let route = route(RoutePolicy::Public);
        let f = Fixture {
            routes: Arc::new(Unreachable),
            ..Fixture::with(&route, Standing::Good)
        };

        let decision = f.decide(request(&route, Identification::Anonymous));

        assert_eq!(decision.outcome(), deny(DenyCode::RouteUnreadable));
    }

    /// A request naming a route absent from the store is denied as unknown.
    #[test]
    fn a_route_no_longer_stored_is_refused() {
        let stored = route(RoutePolicy::Public);
        let f = Fixture::with(&stored, Standing::Good);
        let mut gone = request(&stored, Identification::Anonymous);
        gone.route_id = RouteId::new();

        let decision = f.decide(gone);

        assert_eq!(decision.outcome(), deny(DenyCode::RouteUnknown));
    }

    /// A disabled public route denies the anonymous request as closed.
    #[test]
    fn a_disabled_route_is_refused() {
        let closed = disabled(route(RoutePolicy::Public));
        let f = Fixture::with(&closed, Standing::Good);

        let decision = f.decide(request(&closed, Identification::Anonymous));

        assert_eq!(decision.outcome(), deny(DenyCode::RouteClosed));
    }

    /// An unreadable tenant policy denies a public-route request and marks
    /// the tenant ruling unreadable.
    #[test]
    fn an_unreadable_tenant_policy_refuses() {
        let route = route(RoutePolicy::Public);
        let f = Fixture {
            policies: Arc::new(Unreachable),
            ..Fixture::with(&route, Standing::Good)
        };

        let decision = f.decide(request(&route, Identification::Anonymous));

        assert_eq!(decision.outcome(), deny(DenyCode::TenantPolicyUnreadable));
        assert_eq!(decision.ruling(), &TenantRuling::Unreadable);
    }

    /// A live tenant denial overrides an authenticated route's admission and
    /// identifies the rule that refused access.
    #[test]
    fn the_live_tenant_policy_refuses() {
        let route = route(RoutePolicy::Authenticated);
        let shut = rule(
            "shut-app",
            PolicyAction::Deny {
                reason: Text::new("reason", "closed").unwrap(),
            },
        );
        let f = Fixture::with(&route, Standing::Good).live(vec![shut]);

        let decision = f.decide(request(&route, person(&[])));

        assert_eq!(decision.outcome(), deny(DenyCode::TenantRule));
        let TenantRuling::Decided { settled_by, .. } = decision.ruling() else {
            panic!("the tenant policy decided");
        };
        assert_eq!(
            settled_by,
            &SettledBy::Rule(Label::new("rule_name", "shut-app").unwrap())
        );
    }

    /// Acme's policy asks for AAL2 under `/app`, and Ann's sign-in carries
    /// no level. She is asked to step up.
    #[test]
    fn the_live_tenant_policy_asks_for_a_stronger_sign_in() {
        let route = route(RoutePolicy::Authenticated);
        let mfa = rule("mfa", PolicyAction::RequireAal(AssuranceLevel::Aal2));
        let f = Fixture::with(&route, Standing::Good).live(vec![mfa]);

        let decision = f.decide(request(&route, person(&[])));

        assert_eq!(
            decision.outcome(),
            Outcome::Challenge(Challenge::StepUp(AssuranceLevel::Aal2))
        );
    }
}
