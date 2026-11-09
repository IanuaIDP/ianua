//! The gateway's access decision: whether one request may pass, refused
//! with a reason code, or asked for more first.
//!
//! The gateway authenticates the caller, gathers the facts around the
//! request and asks; it decides nothing itself. The rules, in the order
//! they are checked:
//!
//! 1. The route must be stored and in use.
//! 2. A signed-in caller must be one the tenant's records know and let act
//!    now. Nobody signed in passes only a public route.
//! 3. An agent whose task token is bound to a key must have proved
//!    possession of it, and may not ask to be read as another method.
//! 4. The route's policy must let the caller through: a person by what the
//!    records give them, a consumer by its roles or its credential's
//!    scopes, an agent by what its token names and the one it acts for
//!    still holds: a person it acts for whom the records do not let act
//!    stops it. An agent whose token names nothing at all reaches no
//!    route, not even one asking only for a signed-in caller.
//! 5. An agent's action must be inside its task's intent and its path
//!    inside its token's resource scope.
//! 6. A device that failed the route's posture check is refused.
//! 7. The tenant's live policy decides last. It may refuse, or ask for a
//!    stronger sign-in or a `DPoP` proof before letting the request
//!    through. A tenant with no live policy leaves the decision standing.
//!
//! Anything not read is not guessed at: a route, record or policy that
//! could not be read, or records read for another moment, refuse, and so
//! does a fact a refusing tenant rule
//! needs but nobody knows, such as the country of an address that could not
//! be placed.

mod assurance;
pub mod decision;
pub mod question;
mod requester;
mod tenant;

use crate::domains::authorization::permission::SystemPermission;
use crate::domains::proxy::access::decision::{AccessDecision, DenyCode};
use crate::domains::proxy::access::question::{
    AccessQuestion, Asker, Lookup, PostureFinding, RouteTerms,
};
use crate::domains::proxy::access::requester::Requester;
use crate::domains::proxy::stages::posture::PostureVerdict;
use crate::domains::routing::policy::RoutePolicy;

/// Decides one request.
#[must_use]
pub fn decide(question: &AccessQuestion<'_>) -> AccessDecision {
    match screened(question) {
        Ok(requester) => tenant::ruled(question, &requester),
        Err(code) => AccessDecision::refused(code),
    }
}

/// Whether `asker` holds `right`, as the gateway reads them: what a route
/// asking for that right alone would make of them. An agent holds it only
/// when its token names it and the one it acts for still holds it, and
/// nobody, or a caller the records do not let act, holds nothing.
#[must_use]
pub fn holds_right(asker: Asker<'_>, right: SystemPermission) -> bool {
    let policy = RoutePolicy::RequireSystemPermission(vec![right]);
    Requester::of(asker).is_ok_and(|requester| requester.ensure_meets(&policy).is_ok())
}

/// The caller, once every check before the tenant's policy has let it
/// through.
///
/// # Errors
///
/// - The [`DenyCode`] of the first check that refuses.
fn screened<'a>(question: &AccessQuestion<'a>) -> Result<Requester<'a>, DenyCode> {
    let route = open_route(question.route)?;
    let requester = Requester::of(question.asker)?;
    requester.ensure_key_proven(question.circumstances.binding)?;
    requester.ensure_sent_as(question.asked.method_claim)?;
    requester.ensure_meets(route.policy)?;
    requester.ensure_within_limits(question.asked, route.action)?;
    ensure_posture(question.circumstances.posture)?;
    Ok(requester)
}

/// The route, when it is stored and in use.
///
/// # Errors
///
/// - [`DenyCode::RouteUnknown`], [`DenyCode::RouteClosed`] or
///   [`DenyCode::RouteUnreadable`].
fn open_route(route: Lookup<RouteTerms<'_>>) -> Result<RouteTerms<'_>, DenyCode> {
    match route {
        Lookup::Found(terms) if terms.status.is_active() => Ok(terms),
        Lookup::Found(_) => Err(DenyCode::RouteClosed),
        Lookup::Missing => Err(DenyCode::RouteUnknown),
        Lookup::Unreadable => Err(DenyCode::RouteUnreadable),
    }
}

/// Refuses a device that failed the route's posture check.
///
/// # Errors
///
/// - [`DenyCode::PostureFailed`] when the check ran and failed.
fn ensure_posture(posture: PostureFinding) -> Result<(), DenyCode> {
    match posture {
        PostureFinding::NotAsked | PostureFinding::Checked(PostureVerdict::Meets) => Ok(()),
        PostureFinding::Checked(PostureVerdict::Fails(_)) => Err(DenyCode::PostureFailed),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::domains::agents::authority::capability::{
        ActionApproval, McpGrant, McpTool, McpToolPattern, ResourceScope,
    };
    use crate::domains::agents::authority::intent::IntentEnvelope;
    use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
    use crate::domains::authorization::held::Held;
    use crate::domains::authorization::permission::{
        CustomPermission, SystemPermission, UserAction,
    };
    use crate::domains::authorization::policy::action::PolicyAction;
    use crate::domains::authorization::policy::claims::{Claim, ClaimName, ClaimValue};
    use crate::domains::authorization::policy::condition::PolicyCondition;
    use crate::domains::authorization::policy::rule::PolicyRule;
    use crate::domains::authorization::policy::set::PolicySet;
    use crate::domains::authorization::policy::simulator::AuditMark;
    use crate::domains::crypto::jwk::JwkComponents;
    use crate::domains::proxy::access::decision::{Challenge, Outcome, SettledBy, TenantRuling};
    use crate::domains::proxy::access::question::{
        Asked, Asker, Circumstances, DpopBinding, MethodClaim, OnBehalf, Records,
    };
    use crate::domains::proxy::request::context::{
        AgentLimits, Caller, CallerClaims, ConsumerCredential, KeyBinding, Metering, UserSignIn,
    };
    use crate::domains::proxy::stages::posture::PostureGap;
    use crate::domains::routing::policy::RoutePolicy;
    use crate::domains::routing::route_status::RouteStatus;
    use crate::shared::model::restriction::Restriction;
    use crate::test_support::authority::anyone_holding;
    use crate::types::{
        ActionClass, AgentId, CanonicalPath, ConsumerId, CountryCode, DeclaredAction, DelegationId,
        Fact, HttpMethod, Label, PathPrefix, PermissionName, PrincipalRef, RoleId, Scope, Text,
        UserId,
    };

    const VIEW_USERS: SystemPermission = SystemPermission::Users(UserAction::View);
    const UPDATE_USERS: SystemPermission = SystemPermission::Users(UserAction::Update);

    /// A token naming one app permission, which no route below asks for.
    const READS_ORDERS: &[&str] = &["orders:read"];

    /// Who sends a test request, with what the records say of them.
    // A test fixture built once per test and never held in bulk, so the
    // size of its signed variant costs nothing; boxing it would only bury
    // the fields the table tests set.
    #[allow(clippy::large_enum_variant)]
    enum Sender {
        Nobody,
        Signed {
            caller: Caller,
            credential: CallerClaims,
            records: Records,
            on_behalf: OnBehalf,
        },
    }

    /// One request, owning everything its question lends out.
    struct Request {
        route: Lookup<RoutePolicy>,
        status: RouteStatus,
        sender: Sender,
        asked: Asked,
        around: Circumstances,
        tenant_policy: Lookup<PolicySet>,
    }

    impl Request {
        fn on(policy: RoutePolicy, sender: Sender) -> Self {
            Self {
                route: Lookup::Found(policy),
                status: RouteStatus::Active,
                sender,
                asked: Asked {
                    method: Fact::Known(HttpMethod::Get),
                    path: Fact::Known(path("/app/orders")),
                    method_claim: MethodClaim::AsSent,
                    host: Fact::Unknown,
                },
                around: Circumstances {
                    country: Fact::Unknown,
                    source_ip: Fact::Unknown,
                    device: Fact::Unknown,
                    risk: Fact::Unknown,
                    sensitivity: Fact::Unknown,
                    binding: DpopBinding::Unbound,
                    posture: PostureFinding::NotAsked,
                },
                tenant_policy: Lookup::Missing,
            }
        }

        fn route(self, route: Lookup<RoutePolicy>) -> Self {
            Self { route, ..self }
        }

        fn closed(self) -> Self {
            Self {
                status: RouteStatus::Disabled,
                ..self
            }
        }

        fn records(mut self, records: Records) -> Self {
            if let Sender::Signed { records: held, .. } = &mut self.sender {
                *held = records;
            }
            self
        }

        fn on_behalf(mut self, on_behalf: OnBehalf) -> Self {
            if let Sender::Signed { on_behalf: set, .. } = &mut self.sender {
                *set = on_behalf;
            }
            self
        }

        fn asserting(mut self, asserted: Fact<Vec<Claim>>) -> Self {
            if let Sender::Signed { credential, .. } = &mut self.sender {
                credential.asserted = asserted;
            }
            self
        }

        fn method(mut self, method: Fact<HttpMethod>) -> Self {
            self.asked.method = method;
            self
        }

        fn path(mut self, path: Fact<CanonicalPath>) -> Self {
            self.asked.path = path;
            self
        }

        fn overridden(mut self) -> Self {
            self.asked.method_claim = MethodClaim::Overridden;
            self
        }

        fn bound(mut self) -> Self {
            self.around.binding = DpopBinding::Bound;
            self
        }

        fn posture(mut self, verdict: PostureVerdict) -> Self {
            self.around.posture = PostureFinding::Checked(verdict);
            self
        }

        fn in_country(mut self, country: &str) -> Self {
            self.around.country = Fact::Known(CountryCode::new(country).unwrap());
            self
        }

        fn tenant(self, tenant_policy: Lookup<PolicySet>) -> Self {
            Self {
                tenant_policy,
                ..self
            }
        }

        fn decide(&self) -> AccessDecision {
            let asker = match &self.sender {
                Sender::Nobody => Asker::Anonymous,
                Sender::Signed {
                    caller,
                    credential,
                    records,
                    on_behalf,
                } => Asker::Identified {
                    caller,
                    credential,
                    records,
                    on_behalf,
                },
            };
            decide(&AccessQuestion {
                route: self.route.as_ref().map(|policy| RouteTerms {
                    policy,
                    action: DeclaredAction::Undeclared,
                    status: self.status,
                }),
                asker,
                asked: &self.asked,
                circumstances: &self.around,
                local_times: &[],
                tenant_policy: self.tenant_policy.as_ref(),
            })
        }

        fn outcome(&self) -> Outcome {
            self.decide().outcome()
        }
    }

    fn path(raw: &str) -> CanonicalPath {
        CanonicalPath::new(raw).unwrap()
    }

    fn names(names: &[&str]) -> Vec<PermissionName> {
        names
            .iter()
            .map(|name| PermissionName::new(*name).unwrap())
            .collect()
    }

    fn holding(system: &[SystemPermission]) -> Records {
        Records::Holds(Held::assumed(system, &[], &[], &[]))
    }

    fn user_at(assurance: Fact<AssuranceLevel>, records: Records) -> Sender {
        Sender::Signed {
            caller: Caller::User {
                user_id: UserId::new(),
                sign_in: UserSignIn::Token,
            },
            credential: CallerClaims {
                current_aal: assurance,
                ..CallerClaims::default()
            },
            records,
            on_behalf: OnBehalf::Own,
        }
    }

    fn user(records: Records) -> Sender {
        user_at(Fact::Known(AssuranceLevel::Aal1), records)
    }

    fn consumer(scopes: &[&str], records: Records) -> Sender {
        Sender::Signed {
            caller: Caller::Consumer {
                consumer_id: ConsumerId::new(),
                credential: ConsumerCredential::ApiKey,
            },
            credential: CallerClaims {
                scopes: scopes.iter().map(|s| Scope::new(*s).unwrap()).collect(),
                ..CallerClaims::default()
            },
            records,
            on_behalf: OnBehalf::Own,
        }
    }

    fn unlimited() -> AgentLimits {
        AgentLimits {
            intent_envelope: Restriction::Unrestricted,
            mcp: McpGrant::default(),
            resource_scope: Restriction::Unrestricted,
            max_data_class: Restriction::Unrestricted,
            key_binding: KeyBinding::Bearer,
            approval: ActionApproval::NotRequired,
            metering: Metering::Unmetered,
        }
    }

    /// An agent under `limits` with a token naming `token`, acting for a
    /// person who still holds every built-in right.
    fn agent_with(limits: AgentLimits, token: &[&str]) -> Sender {
        Sender::Signed {
            caller: Caller::Agent {
                agent_id: AgentId::new(),
                delegation_id: DelegationId::new(),
                acting_for: PrincipalRef::User(UserId::new()),
                limits: Box::new(limits),
            },
            credential: CallerClaims {
                permissions: names(token),
                ..CallerClaims::default()
            },
            records: Records::Holds(Held::default()),
            on_behalf: OnBehalf::Of(holding(SystemPermission::all())),
        }
    }

    fn agent(token: &[&str]) -> Sender {
        agent_with(unlimited(), token)
    }

    /// An agent with a token naming `token`, acting for itself, which the
    /// records give `own`.
    fn agent_for_itself(token: &[&str], own: Records) -> Sender {
        let agent_id = AgentId::new();
        Sender::Signed {
            caller: Caller::Agent {
                agent_id,
                delegation_id: DelegationId::new(),
                acting_for: PrincipalRef::Agent(agent_id),
                limits: Box::new(unlimited()),
            },
            credential: CallerClaims {
                permissions: names(token),
                ..CallerClaims::default()
            },
            records: own,
            on_behalf: OnBehalf::Own,
        }
    }

    fn department(value: &str) -> Claim {
        Claim::new(
            ClaimName::new("department").unwrap(),
            ClaimValue::new(value).unwrap(),
        )
    }

    fn of_department(value: &str) -> PolicyCondition {
        PolicyCondition::ClaimEquals {
            name: ClaimName::new("department").unwrap(),
            value: ClaimValue::new(value).unwrap(),
        }
    }

    fn read_only() -> AgentLimits {
        AgentLimits {
            intent_envelope: Restriction::To(IntentEnvelope::new([ActionClass::Read])),
            ..unlimited()
        }
    }

    fn scoped_to(prefix: &str) -> AgentLimits {
        AgentLimits {
            resource_scope: Restriction::To(ResourceScope::new([prefix.to_owned()]).unwrap()),
            ..unlimited()
        }
    }

    fn key_bound() -> AgentLimits {
        AgentLimits {
            key_binding: KeyBinding::Key(JwkComponents::Okp {
                kid: "agent-key".to_owned(),
                crv: "Ed25519".to_owned(),
                x: "x".to_owned(),
            }),
            ..unlimited()
        }
    }

    fn signed_in() -> RoutePolicy {
        RoutePolicy::Authenticated
    }

    fn needs(permission: SystemPermission) -> RoutePolicy {
        RoutePolicy::RequireSystemPermission(vec![permission])
    }

    fn rule(name: &str, conditions: Vec<PolicyCondition>, action: PolicyAction) -> PolicyRule {
        PolicyRule::new(
            Label::new("rule_name", name).unwrap(),
            conditions,
            action,
            10,
        )
        .unwrap()
    }

    fn refuse() -> PolicyAction {
        PolicyAction::Deny {
            reason: Text::new("reason", "refused").unwrap(),
        }
    }

    fn tenant_policy(default: PolicyAction, rules: Vec<PolicyRule>) -> Lookup<PolicySet> {
        let mut policy = PolicySet::new(default);
        for added in rules {
            policy
                .add_rule(added, anyone_holding(&[SystemPermission::ManagePolicy]))
                .unwrap();
        }
        Lookup::Found(policy)
    }

    fn tenant_rule(condition: PolicyCondition, action: PolicyAction) -> Lookup<PolicySet> {
        tenant_policy(
            PolicyAction::Allow,
            vec![rule("guard", vec![condition], action)],
        )
    }

    fn deny(code: DenyCode) -> Outcome {
        Outcome::Deny(code)
    }

    fn check(table: Vec<(&str, Request, Outcome)>) {
        for (case, request, expected) in table {
            assert_eq!(request.outcome(), expected, "{case}");
        }
    }

    /// Missing, unreadable and disabled routes refuse requests.
    #[test]
    fn the_route_and_the_caller_must_stand() {
        check(vec![
            (
                "route gone",
                Request::on(signed_in(), user(holding(&[]))).route(Lookup::Missing),
                deny(DenyCode::RouteUnknown),
            ),
            (
                "route store unreachable",
                Request::on(signed_in(), user(holding(&[]))).route(Lookup::Unreadable),
                deny(DenyCode::RouteUnreadable),
            ),
            (
                "route disabled",
                Request::on(RoutePolicy::Public, Sender::Nobody).closed(),
                deny(DenyCode::RouteClosed),
            ),
        ]);
    }

    /// Anonymous callers pass public routes and must sign in for other policies.
    #[test]
    fn anonymous_callers_need_a_public_route() {
        check(vec![
            (
                "nobody on a public route",
                Request::on(RoutePolicy::Public, Sender::Nobody),
                Outcome::Permit,
            ),
            (
                "missing token on a signed-in route",
                Request::on(signed_in(), Sender::Nobody),
                deny(DenyCode::SignInRequired),
            ),
            (
                "missing token on a permission route",
                Request::on(needs(VIEW_USERS), Sender::Nobody),
                deny(DenyCode::SignInRequired),
            ),
        ]);
    }

    /// Unknown, locked or unreadable user records refuse access, including public routes.
    #[test]
    fn user_records_must_allow_access() {
        check(vec![
            (
                "unknown subject",
                Request::on(signed_in(), user(Records::Unknown)),
                deny(DenyCode::CallerUnknown),
            ),
            (
                "unknown subject on a public route",
                Request::on(RoutePolicy::Public, user(Records::Unknown)),
                deny(DenyCode::CallerUnknown),
            ),
            (
                "locked account",
                Request::on(signed_in(), user(Records::Barred)),
                deny(DenyCode::CallerBarred),
            ),
            (
                "records unreachable",
                Request::on(signed_in(), user(Records::Unreadable)),
                deny(DenyCode::RecordsUnreadable),
            ),
        ]);
    }

    /// Unknown agents and disabled consumers are refused; a known person may sign in.
    #[test]
    fn each_caller_needs_current_records() {
        check(vec![
            (
                "unknown agent",
                Request::on(signed_in(), agent(&[])).records(Records::Unknown),
                deny(DenyCode::CallerUnknown),
            ),
            (
                "disabled consumer",
                Request::on(signed_in(), consumer(&[], Records::Barred)),
                deny(DenyCode::CallerBarred),
            ),
            (
                "signed-in person",
                Request::on(signed_in(), user(holding(&[]))),
                Outcome::Permit,
            ),
        ]);
    }

    /// User permission routes require the requested right and a nonempty requirement.
    #[test]
    fn the_route_policy_reads_what_each_kind_of_caller_holds() {
        check(vec![
            (
                "person holding the right",
                Request::on(needs(VIEW_USERS), user(holding(&[VIEW_USERS]))),
                Outcome::Permit,
            ),
            (
                "person without the right",
                Request::on(needs(UPDATE_USERS), user(holding(&[VIEW_USERS]))),
                deny(DenyCode::PermissionMissing),
            ),
            (
                "route listing nothing",
                Request::on(
                    RoutePolicy::RequireSystemPermission(Vec::new()),
                    user(holding(SystemPermission::all())),
                ),
                deny(DenyCode::NothingListed),
            ),
        ]);
    }

    /// A user's custom wildcard grants an app permission but supplies no OAuth scope.
    #[test]
    fn user_permissions_do_not_supply_scopes() {
        let orders_read = CustomPermission::parse("orders:read").unwrap();
        let wildcard = Records::Holds(Held::assumed(
            &[],
            &[CustomPermission::parse("orders:*").unwrap()],
            &[],
            &[],
        ));
        check(vec![
            (
                "person holding an app wildcard",
                Request::on(
                    RoutePolicy::RequireCustomPermission(vec![orders_read]),
                    user(wildcard),
                ),
                Outcome::Permit,
            ),
            (
                "person on a scope route",
                Request::on(
                    RoutePolicy::RequireScope(vec![Scope::new("orders:read").unwrap()]),
                    user(holding(SystemPermission::all())),
                ),
                deny(DenyCode::ScopeMissing),
            ),
        ]);
    }

    /// A consumer's scope must match the route's requested scope.
    #[test]
    fn consumers_need_the_requested_scope() {
        check(vec![
            (
                "consumer carrying the scope",
                Request::on(
                    RoutePolicy::RequireScope(vec![Scope::new("orders:read").unwrap()]),
                    consumer(&["orders:read"], holding(&[])),
                ),
                Outcome::Permit,
            ),
            (
                "consumer without the scope",
                Request::on(
                    RoutePolicy::RequireScope(vec![Scope::new("orders:read").unwrap()]),
                    consumer(&["orders:write"], holding(&[])),
                ),
                deny(DenyCode::ScopeMissing),
            ),
        ]);
    }

    /// Consumer roles and agent token permissions supply the right a route requests.
    #[test]
    fn machine_callers_need_the_requested_right() {
        check(vec![
            (
                "consumer holding the right through a role",
                Request::on(needs(VIEW_USERS), consumer(&[], holding(&[VIEW_USERS]))),
                Outcome::Permit,
            ),
            (
                "agent whose token names the right",
                Request::on(needs(VIEW_USERS), agent(&["idp:users:view"])),
                Outcome::Permit,
            ),
            (
                "agent whose token does not",
                Request::on(needs(UPDATE_USERS), agent(&["idp:users:view"])),
                deny(DenyCode::PermissionMissing),
            ),
        ]);
    }

    /// An agent cannot override its method and must prove its bound key.
    /// A person may override a method.
    #[test]
    fn an_agent_is_held_to_its_task_token() {
        check(vec![
            (
                "agent overriding its method",
                Request::on(signed_in(), agent(&[])).overridden(),
                deny(DenyCode::MethodOverridden),
            ),
            (
                "person overriding the method",
                Request::on(signed_in(), user(holding(&[]))).overridden(),
                Outcome::Permit,
            ),
            (
                "key-bound token without a proof",
                Request::on(signed_in(), agent_with(key_bound(), READS_ORDERS)),
                deny(DenyCode::KeyNotProven),
            ),
            (
                "key-bound token with a proof",
                Request::on(signed_in(), agent_with(key_bound(), READS_ORDERS)).bound(),
                Outcome::Permit,
            ),
        ]);
    }

    /// A read-only agent may read, but cannot delete or use an unknown method.
    #[test]
    fn agents_must_stay_within_intent() {
        check(vec![
            (
                "read-only agent deleting",
                Request::on(signed_in(), agent_with(read_only(), READS_ORDERS))
                    .method(Fact::Known(HttpMethod::Delete)),
                deny(DenyCode::OutsideIntent),
            ),
            (
                "read-only agent reading",
                Request::on(signed_in(), agent_with(read_only(), READS_ORDERS)),
                Outcome::Permit,
            ),
            (
                "agent with an intent and a method nobody knows",
                Request::on(signed_in(), agent_with(read_only(), READS_ORDERS))
                    .method(Fact::Unknown),
                deny(DenyCode::OutsideIntent),
            ),
        ]);
    }

    /// Resource scopes admit descendants and refuse sibling or unreadable paths.
    #[test]
    fn agents_must_stay_within_resource_scope() {
        check(vec![
            (
                "agent scoped to one account reaching another",
                Request::on(
                    signed_in(),
                    agent_with(scoped_to("/accounts/48"), READS_ORDERS),
                )
                .path(Fact::Known(path("/accounts/4821"))),
                deny(DenyCode::OutsideResourceScope),
            ),
            (
                "agent scoped to one account reaching it",
                Request::on(
                    signed_in(),
                    agent_with(scoped_to("/accounts/48"), READS_ORDERS),
                )
                .path(Fact::Known(path("/accounts/48/statements"))),
                Outcome::Permit,
            ),
            (
                "agent with a scope and a path nobody could read",
                Request::on(
                    signed_in(),
                    agent_with(scoped_to("/accounts/48"), READS_ORDERS),
                )
                .path(Fact::Unknown),
                deny(DenyCode::OutsideResourceScope),
            ),
        ]);
    }

    /// Public route policy does not remove the agent's read-only intent restriction.
    #[test]
    fn public_routes_still_enforce_agent_intent() {
        check(vec![(
            "agent limits on a public route",
            Request::on(RoutePolicy::Public, agent_with(read_only(), READS_ORDERS))
                .method(Fact::Known(HttpMethod::Delete)),
            deny(DenyCode::OutsideIntent),
        )]);
    }

    /// Empty tokens are refused on every route, even with a bound key or own rights.
    #[test]
    fn an_agent_whose_token_names_nothing_reaches_nothing() {
        check(vec![
            (
                "empty token on a signed-in route",
                Request::on(signed_in(), agent(&[])),
                deny(DenyCode::NothingDelegated),
            ),
            (
                "empty token on a public route",
                Request::on(RoutePolicy::Public, agent(&[])),
                deny(DenyCode::NothingDelegated),
            ),
            (
                "empty token on a permission route",
                Request::on(needs(VIEW_USERS), agent(&[])),
                deny(DenyCode::NothingDelegated),
            ),
            (
                "empty key-bound token with its proof",
                Request::on(signed_in(), agent_with(key_bound(), &[])).bound(),
                deny(DenyCode::NothingDelegated),
            ),
            (
                "empty token of an agent acting for itself",
                Request::on(signed_in(), agent_for_itself(&[], holding(&[VIEW_USERS]))),
                deny(DenyCode::NothingDelegated),
            ),
        ]);
    }

    /// An MCP tool grant counts as delegated authority on a signed-in route.
    #[test]
    fn mcp_grants_admit_signed_in_agents() {
        let tools_only = AgentLimits {
            mcp: McpGrant::new(
                vec![McpTool::new(
                    McpToolPattern::new("github_get_*").unwrap(),
                    ActionClass::Read,
                )],
                Vec::new(),
                Vec::new(),
            ),
            ..unlimited()
        };
        check(vec![(
            "token granting only MCP tools",
            Request::on(signed_in(), agent_with(tools_only, &[])),
            Outcome::Permit,
        )]);
    }

    /// A delegated right must appear both on the token and in the delegator's records.
    #[test]
    fn an_agent_is_held_to_what_its_delegator_holds_now() {
        let view = || needs(VIEW_USERS);
        check(vec![
            (
                "delegator still holds the right",
                Request::on(view(), agent(&["idp:users:view"])),
                Outcome::Permit,
            ),
            (
                "delegator lost the right since the token was minted",
                Request::on(view(), agent(&["idp:users:view"]))
                    .on_behalf(OnBehalf::Of(holding(&[]))),
                deny(DenyCode::PermissionMissing),
            ),
            (
                "delegator holds it, the token does not name it",
                Request::on(view(), agent(READS_ORDERS)),
                deny(DenyCode::PermissionMissing),
            ),
        ]);
    }

    /// Missing, barred, unreadable and stale delegator records refuse the agent.
    #[test]
    fn delegator_records_must_allow_access() {
        check(vec![
            (
                "delegator unknown",
                Request::on(signed_in(), agent(&[])).on_behalf(OnBehalf::Of(Records::Unknown)),
                deny(DenyCode::DelegatorUnknown),
            ),
            (
                "delegator locked",
                Request::on(signed_in(), agent(&[])).on_behalf(OnBehalf::Of(Records::Barred)),
                deny(DenyCode::DelegatorBarred),
            ),
            (
                "delegator records unreachable",
                Request::on(signed_in(), agent(&[])).on_behalf(OnBehalf::Of(Records::Unreadable)),
                deny(DenyCode::RecordsUnreadable),
            ),
            (
                "delegator records stale",
                Request::on(signed_in(), agent(&[])).on_behalf(OnBehalf::Of(Records::Stale)),
                deny(DenyCode::RecordsStale),
            ),
            (
                "nothing said of the delegator",
                Request::on(RoutePolicy::Public, agent(&[])).on_behalf(OnBehalf::Own),
                deny(DenyCode::DelegatorUnknown),
            ),
        ]);
    }

    /// An agent acting for itself needs its own grant; stale caller records refuse access.
    #[test]
    fn own_authority_needs_current_grants() {
        let view = || needs(VIEW_USERS);
        check(vec![
            (
                "agent for itself, holding the right of its own",
                Request::on(
                    view(),
                    agent_for_itself(&["idp:users:view"], holding(&[VIEW_USERS])),
                ),
                Outcome::Permit,
            ),
            (
                "agent for itself, without a grant of its own",
                Request::on(view(), agent_for_itself(&["idp:users:view"], holding(&[]))),
                deny(DenyCode::PermissionMissing),
            ),
            (
                "caller records stale",
                Request::on(signed_in(), user(Records::Stale)),
                deny(DenyCode::RecordsStale),
            ),
        ]);
    }

    /// Whether a caller holds one right reads as a route asking for it
    /// alone: an agent holds it while its token names it and its delegator
    /// holds it, and nobody holds nothing.
    #[test]
    fn holding_a_right_reads_as_the_route_rule() {
        let holds = |request: Request| {
            let asker = match &request.sender {
                Sender::Nobody => Asker::Anonymous,
                Sender::Signed {
                    caller,
                    credential,
                    records,
                    on_behalf,
                } => Asker::Identified {
                    caller,
                    credential,
                    records,
                    on_behalf,
                },
            };
            holds_right(asker, VIEW_USERS)
        };

        assert!(holds(Request::on(signed_in(), agent(&["idp:users:view"]))));
        assert!(!holds(
            Request::on(signed_in(), agent(&["idp:users:view"]))
                .on_behalf(OnBehalf::Of(holding(&[])))
        ));
        assert!(!holds(Request::on(signed_in(), agent(&[]))));
        assert!(!holds(Request::on(signed_in(), Sender::Nobody)));
        assert!(holds(Request::on(
            signed_in(),
            user(holding(&[VIEW_USERS]))
        )));
    }

    /// A refusing claim rule rejects its value and unknown claims, but permits another value.
    #[test]
    fn a_claim_rule_reads_what_the_credential_asserts() {
        let refuse_finance = || tenant_rule(of_department("finance"), refuse());
        let person = || Request::on(signed_in(), user(holding(&[])));
        let finance = || Fact::Known(vec![department("finance")]);
        let sales = || Fact::Known(vec![department("sales")]);
        check(vec![
            (
                "refusing rule, claim asserted",
                person().asserting(finance()).tenant(refuse_finance()),
                deny(DenyCode::TenantRule),
            ),
            (
                "refusing rule, another value asserted",
                person().asserting(sales()).tenant(refuse_finance()),
                Outcome::Permit,
            ),
            (
                "refusing rule, no claims carried",
                person().asserting(Fact::Unknown).tenant(refuse_finance()),
                deny(DenyCode::TenantRule),
            ),
        ]);
    }

    /// An allowing claim rule admits its value and refuses another or unknown value.
    #[test]
    fn allowing_claim_rules_need_known_matches() {
        let person = || Request::on(signed_in(), user(holding(&[])));
        let finance = || Fact::Known(vec![department("finance")]);
        let sales = || Fact::Known(vec![department("sales")]);
        check(vec![
            (
                "allowing rule, claim asserted",
                person().asserting(finance()).tenant(only_finance()),
                Outcome::Permit,
            ),
            (
                "allowing rule, another value asserted",
                person().asserting(sales()).tenant(only_finance()),
                deny(DenyCode::TenantRule),
            ),
            (
                "allowing rule, no claims carried",
                person().asserting(Fact::Unknown).tenant(only_finance()),
                deny(DenyCode::TenantRule),
            ),
        ]);
    }

    /// A claim refusal does not apply to an anonymous caller on a public route.
    #[test]
    fn anonymous_requests_carry_no_claim_identity() {
        check(vec![(
            "refusing rule, nobody signed in",
            Request::on(RoutePolicy::Public, Sender::Nobody)
                .tenant(tenant_rule(of_department("finance"), refuse())),
            Outcome::Permit,
        )]);
    }

    /// A policy that admits a known finance claim and refuses everything else.
    fn only_finance() -> Lookup<PolicySet> {
        tenant_policy(
            refuse(),
            vec![rule(
                "finance",
                vec![of_department("finance")],
                PolicyAction::Allow,
            )],
        )
    }

    /// A device that failed the route's posture check is refused; one that
    /// met it, or a route that asks for none, is not.
    #[test]
    fn a_failed_posture_check_refuses() {
        check(vec![
            (
                "posture failed",
                Request::on(signed_in(), user(holding(&[])))
                    .posture(PostureVerdict::Fails(PostureGap::NoReport)),
                deny(DenyCode::PostureFailed),
            ),
            (
                "posture met",
                Request::on(signed_in(), user(holding(&[]))).posture(PostureVerdict::Meets),
                Outcome::Permit,
            ),
        ]);
    }

    /// An unreadable tenant policy or a matching refusal blocks an otherwise valid caller.
    #[test]
    fn the_tenant_policy_decides_last() {
        check(vec![
            (
                "policy store unreachable",
                Request::on(signed_in(), user(holding(&[]))).tenant(Lookup::Unreadable),
                deny(DenyCode::TenantPolicyUnreadable),
            ),
            (
                "rule refusing the path",
                Request::on(signed_in(), user(holding(&[]))).tenant(tenant_rule(
                    PolicyCondition::PathPrefix(PathPrefix::new("/app").unwrap()),
                    refuse(),
                )),
                deny(DenyCode::TenantRule),
            ),
        ]);
    }

    /// AAL2 rules admit a person at AAL2 and challenge lower, unknown or absent sign-in.
    #[test]
    fn assurance_rules_require_the_requested_level() {
        let aal2 = || PolicyAction::RequireAal(AssuranceLevel::Aal2);
        let user_at_aal = |level| user_at(Fact::Known(level), holding(&[]));
        check(vec![
            (
                "AAL2 asked of a person at AAL1",
                Request::on(signed_in(), user_at_aal(AssuranceLevel::Aal1))
                    .tenant(tenant_rule(everywhere(), aal2())),
                Outcome::Challenge(Challenge::StepUp(AssuranceLevel::Aal2)),
            ),
            (
                "AAL2 asked of a person at AAL2",
                Request::on(signed_in(), user_at_aal(AssuranceLevel::Aal2))
                    .tenant(tenant_rule(everywhere(), aal2())),
                Outcome::Permit,
            ),
            (
                "AAL2 asked of a sign-in of no known level",
                Request::on(signed_in(), user_at(Fact::Unknown, holding(&[])))
                    .tenant(tenant_rule(everywhere(), aal2())),
                Outcome::Challenge(Challenge::StepUp(AssuranceLevel::Aal2)),
            ),
            (
                "AAL2 asked of nobody on a public route",
                Request::on(RoutePolicy::Public, Sender::Nobody)
                    .tenant(tenant_rule(everywhere(), aal2())),
                Outcome::Challenge(Challenge::StepUp(AssuranceLevel::Aal2)),
            ),
        ]);
    }

    /// Agents and consumers cannot satisfy a tenant rule requiring a person's AAL2 sign-in.
    #[test]
    fn machines_cannot_reach_person_assurance() {
        let aal2 = || PolicyAction::RequireAal(AssuranceLevel::Aal2);
        check(vec![
            (
                "AAL2 asked of an agent",
                Request::on(signed_in(), agent(READS_ORDERS))
                    .tenant(tenant_rule(everywhere(), aal2())),
                deny(DenyCode::AssuranceUnattainable),
            ),
            (
                "AAL2 asked of a consumer",
                Request::on(signed_in(), consumer(&[], holding(&[])))
                    .tenant(tenant_rule(everywhere(), aal2())),
                deny(DenyCode::AssuranceUnattainable),
            ),
        ]);
    }

    /// A DPoP rule challenges an unbound request and admits a bound one.
    #[test]
    fn dpop_rules_require_a_bound_request() {
        check(vec![
            (
                "DPoP asked of an unbound request",
                Request::on(signed_in(), user(holding(&[])))
                    .tenant(tenant_rule(everywhere(), PolicyAction::RequireDpop)),
                Outcome::Challenge(Challenge::DpopProof),
            ),
            (
                "DPoP asked of a bound request",
                Request::on(signed_in(), user(holding(&[])))
                    .bound()
                    .tenant(tenant_rule(everywhere(), PolicyAction::RequireDpop)),
                Outcome::Permit,
            ),
        ]);
    }

    /// A deny default stands without a matching allow, including when the path is unknown.
    #[test]
    fn unknown_paths_cannot_match_allow_rules() {
        check(vec![
            (
                "deny default, nothing allowing",
                Request::on(signed_in(), user(holding(&[])))
                    .tenant(tenant_policy(refuse(), Vec::new())),
                deny(DenyCode::TenantRule),
            ),
            (
                "allow on a path nobody could read",
                Request::on(signed_in(), user(holding(&[])))
                    .path(Fact::Unknown)
                    .tenant(tenant_policy(
                        refuse(),
                        vec![rule(
                            "let-in",
                            vec![PolicyCondition::PathPrefix(
                                PathPrefix::new("/app").unwrap(),
                            )],
                            PolicyAction::Allow,
                        )],
                    )),
                deny(DenyCode::TenantRule),
            ),
        ]);
    }

    /// A tenant condition covering every request path.
    fn everywhere() -> PolicyCondition {
        PolicyCondition::PathPrefix(PathPrefix::new("/").unwrap())
    }

    /// A country rule needs the country. Nobody placing the address is no
    /// proof the request is safe, so a refusal on everywhere but Germany
    /// refuses it; a refusal of one country lets a known other one through.
    #[test]
    fn a_geo_rule_refuses_a_country_nobody_knows() {
        let sanctioned = tenant_rule(
            PolicyCondition::CountryIn(vec![CountryCode::new("KP").unwrap()]),
            refuse(),
        );
        check(vec![
            (
                "country unknown",
                Request::on(signed_in(), user(holding(&[]))).tenant(only_germany()),
                deny(DenyCode::TenantRule),
            ),
            (
                "country known and allowed",
                Request::on(signed_in(), user(holding(&[])))
                    .in_country("DE")
                    .tenant(only_germany()),
                Outcome::Permit,
            ),
            (
                "another country than the one refused",
                Request::on(signed_in(), user(holding(&[])))
                    .in_country("DE")
                    .tenant(sanctioned),
                Outcome::Permit,
            ),
        ]);
    }

    /// A geographic refusal that allows only requests known to come from Germany.
    fn only_germany() -> Lookup<PolicySet> {
        tenant_rule(
            PolicyCondition::CountryNotIn(vec![CountryCode::new("DE").unwrap()]),
            refuse(),
        )
    }

    /// A tenant rule on a role matches a caller the records give that role,
    /// however the role is named on the token.
    #[test]
    fn a_tenant_role_rule_reads_the_roles_the_records_give() {
        let contractors = RoleId::new();
        let contractor = Records::Holds(Held::assumed(&[], &[], &[contractors], &[]));
        let request = Request::on(signed_in(), user(contractor))
            .tenant(tenant_rule(PolicyCondition::RoleIs(contractors), refuse()));

        assert_eq!(request.outcome(), deny(DenyCode::TenantRule));
    }

    /// The decision says which version and which rule of the tenant's
    /// policy settled it, and that an audit-only rule saw the request, so
    /// the request record can name them.
    #[test]
    fn the_decision_names_the_tenant_rule_behind_it() {
        let watched = Request::on(signed_in(), user(holding(&[]))).tenant(tenant_policy(
            PolicyAction::Allow,
            vec![
                rule("watch", Vec::new(), PolicyAction::AuditOnly),
                rule("shut", Vec::new(), refuse()),
            ],
        ));

        let decision = watched.decide();

        assert_eq!(decision.outcome(), deny(DenyCode::TenantRule));
        let TenantRuling::Decided {
            settled_by, audit, ..
        } = decision.ruling()
        else {
            panic!("the tenant policy decided");
        };
        assert_eq!(
            settled_by,
            &SettledBy::Rule(Label::new("rule_name", "shut").unwrap())
        );
        assert_eq!(*audit, AuditMark::Audited);
    }

    /// A tenant with no live policy leaves the route's decision standing,
    /// and says so; a refusal before the policy says it was not reached.
    #[test]
    fn the_ruling_says_how_far_the_tenant_policy_was_read() {
        let no_policy = Request::on(signed_in(), user(holding(&[])));
        let refused_early = Request::on(signed_in(), Sender::Nobody);

        assert_eq!(no_policy.decide().ruling(), &TenantRuling::NoPolicy);
        assert_eq!(refused_early.decide().ruling(), &TenantRuling::NotReached);
    }

    fn segment() -> impl Strategy<Value = String> {
        "[a-z0-9]{1,8}"
    }

    fn segments() -> impl Strategy<Value = Vec<String>> {
        prop::collection::vec(segment(), 1..4)
    }

    fn joined(segments: &[String]) -> String {
        format!("/{}", segments.join("/"))
    }

    /// Each kind of caller a request can come from.
    #[derive(Debug, Clone, Copy)]
    enum Kind {
        Nobody,
        Person,
        Consumer,
        Agent,
    }

    fn signed_in_kind() -> impl Strategy<Value = Kind> {
        prop_oneof![Just(Kind::Person), Just(Kind::Consumer), Just(Kind::Agent)]
    }

    fn any_kind() -> impl Strategy<Value = Kind> {
        prop_oneof![Just(Kind::Nobody), signed_in_kind()]
    }

    /// A caller of `kind` holding everything the route policies below ask
    /// for, so only what a test changes can refuse it.
    fn sender_of(kind: Kind) -> Sender {
        match kind {
            Kind::Nobody => Sender::Nobody,
            Kind::Person => user(holding(SystemPermission::all())),
            Kind::Consumer => consumer(&["orders:read"], holding(SystemPermission::all())),
            Kind::Agent => agent(&["idp:users:view"]),
        }
    }

    fn route_policy() -> impl Strategy<Value = RoutePolicy> {
        prop_oneof![
            Just(RoutePolicy::Public),
            Just(RoutePolicy::Authenticated),
            Just(needs(VIEW_USERS)),
            Just(RoutePolicy::RequireScope(vec![
                Scope::new("orders:read").unwrap()
            ])),
        ]
    }

    fn rights() -> impl Strategy<Value = Vec<SystemPermission>> {
        prop::sample::subsequence(SystemPermission::ALL_VARIANTS, 0..8)
    }

    proptest! {
        /// Whatever an agent's token names and whatever its delegator holds
        /// now, the agent passes a route asking for a right exactly when
        /// both carry it: what it may do is never more than either.
        #[test]
        fn an_agents_rights_are_within_its_token_and_its_delegator(
            token in rights(),
            delegator in rights(),
            wanted in prop::sample::select(SystemPermission::ALL_VARIANTS),
        ) {
            let carried = Held::assumed(&token, &[], &[], &[]).holdings().names();
            let named: Vec<&str> = carried.iter().map(PermissionName::as_str).collect();
            let request = Request::on(needs(wanted), agent(&named))
                .on_behalf(OnBehalf::Of(holding(&delegator)));

            let permitted = request.decide().permits();

            let in_token = wanted.held_in(&carried);
            let in_delegator = delegator.iter().any(|right| right.implies(&wanted));
            prop_assert_eq!(permitted, in_token && in_delegator);
            prop_assert!(!permitted || token.iter().any(|right| right.implies(&wanted)));
        }

        /// An agent scoped to a prefix reaches every path under it, on a
        /// segment boundary.
        #[test]
        fn an_agent_reaches_every_path_under_its_scope(
            prefix in segments(),
            below in prop::collection::vec(segment(), 0..4),
        ) {
            let scope = joined(&prefix);
            let mut full = prefix.clone();
            full.extend(below);
            let request = Request::on(signed_in(), agent_with(scoped_to(&scope), READS_ORDERS))
                .path(Fact::Known(path(&joined(&full))));

            prop_assert_eq!(request.outcome(), Outcome::Permit);
        }

        /// Appending characters to the final segment of an agent's allowed
        /// prefix produces a path denied as outside its resource scope.
        #[test]
        fn an_agent_never_reaches_a_sibling_sharing_its_letters(
            prefix in segments(),
            extra in segment(),
        ) {
            let scope = joined(&prefix);
            let sibling = format!("{scope}{extra}");
            let request = Request::on(signed_in(), agent_with(scoped_to(&scope), READS_ORDERS))
                .path(Fact::Known(path(&sibling)));

            prop_assert_eq!(request.outcome(), deny(DenyCode::OutsideResourceScope));
        }

        /// A tenant prefix refusal applies to generated descendant paths
        /// with repeated separators and to prefixes with an encoded first
        /// letter, while permitting a sibling sharing the prefix's letters.
        #[test]
        fn a_tenant_path_rule_holds_however_the_path_is_spelled(
            prefix in segments(),
            below in segments(),
            extra in segment(),
        ) {
            let rule_path = joined(&prefix);
            let refusing = || tenant_rule(
                PolicyCondition::PathPrefix(PathPrefix::new(&rule_path).unwrap()),
                refuse(),
            );
            let under = format!("/{}/{}/", prefix.join("//"), below.join("/"));
            let first = prefix[0].as_bytes()[0];
            let encoded = format!("/%{first:02X}{}", &joined(&prefix)[2..]);
            let sibling = format!("{rule_path}{extra}");
            let outcome_for = |raw: &str| {
                Request::on(signed_in(), user(holding(&[])))
                    .path(Fact::Known(path(raw)))
                    .tenant(refusing())
                    .outcome()
            };

            prop_assert_eq!(outcome_for(&under), deny(DenyCode::TenantRule));
            prop_assert_eq!(outcome_for(&encoded), deny(DenyCode::TenantRule));
            prop_assert_eq!(outcome_for(&sibling), Outcome::Permit);
        }

        /// Whatever the caller and the route's policy, a route that is gone
        /// or could not be read never lets a request through.
        #[test]
        fn a_route_not_read_never_permits(
            kind in any_kind(),
            route in prop_oneof![
                Just(Lookup::<RoutePolicy>::Missing),
                Just(Lookup::<RoutePolicy>::Unreadable),
            ],
        ) {
            let request = Request::on(RoutePolicy::Public, sender_of(kind)).route(route);

            prop_assert!(!request.decide().permits());
        }

        /// Whatever the route's policy, a signed-in caller the records do
        /// not know, bar, or could not be read for never gets through.
        #[test]
        fn a_caller_the_records_do_not_let_act_never_passes(
            kind in signed_in_kind(),
            policy in route_policy(),
            records in prop_oneof![
                Just(Records::Unknown),
                Just(Records::Barred),
                Just(Records::Unreadable),
            ],
        ) {
            let request = Request::on(policy, sender_of(kind)).records(records);

            prop_assert!(!request.decide().permits());
        }

        /// Whatever the route asks for and whatever the one it acts for
        /// holds, an agent whose token names nothing never gets through.
        #[test]
        fn an_agent_given_nothing_never_passes(
            policy in route_policy(),
            delegator in rights(),
        ) {
            let request = Request::on(policy, agent(&[]))
                .on_behalf(OnBehalf::Of(holding(&delegator)));

            prop_assert_eq!(request.outcome(), deny(DenyCode::NothingDelegated));
        }

        /// Whatever the caller and the route, a tenant policy that could not
        /// be read never lets a request through.
        #[test]
        fn an_unread_tenant_policy_never_permits(
            kind in any_kind(),
            policy in route_policy(),
        ) {
            let request = Request::on(policy, sender_of(kind)).tenant(Lookup::Unreadable);

            prop_assert!(!request.decide().permits());
        }
    }
}
