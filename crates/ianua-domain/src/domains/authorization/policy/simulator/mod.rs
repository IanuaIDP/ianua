//! The policy simulator: runs made-up requests against a policy without
//! sending them anywhere. It shows which rule would match and what the
//! outcome would be.
//!
//! Ann writes a policy and asks "what happens if Alice opens /admin from
//! Germany on a new device?". She sees the answer before the policy goes
//! live, so a mistake that locks everyone out is caught early.
//!
//! [`evaluate`] decides real requests the same way.

mod conditions;

use std::net::IpAddr;

use conditions::check_conditions;

use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::authentication::risk_engine::step_up::{Familiarity, Sensitivity};
use crate::domains::authorization::permission::CustomPermission;
use crate::domains::authorization::policy::action::PolicyAction;
use crate::domains::authorization::policy::claims::Claim;
use crate::domains::authorization::policy::condition::RiskThreshold;
use crate::domains::authorization::policy::rule::PolicyRule;
use crate::domains::authorization::policy::set::PolicySet;
use crate::domains::authorization::policy::time_window::ZonedTime;
use crate::domains::authorization::policy::version::PolicyVersion;
use crate::shared::model::two_cases::two_cases;
use crate::types::{
    CanonicalPath, CountryCode, Fact, GroupId, HostName, HttpMethod, Label, RoleId, Text, UrlPath,
};

/// A simulated request context for policy evaluation.
///
/// The admin fills in the fields that matter. A path, method or country left
/// unknown is read the way [`RequestFacts`] reads an unknown fact.
///
/// `current_aal` and `has_dpop` describe the caller but play no part in
/// choosing a rule. The result names the action, such as asking for a
/// stronger sign-in, without saying whether this caller would meet it.
#[derive(Debug, Clone)]
pub struct SimulationInput {
    /// The request path, such as `/admin/users`.
    pub path: Fact<CanonicalPath>,
    /// The HTTP method, such as `GET` or `DELETE`.
    pub method: Fact<HttpMethod>,
    /// The roles the user holds.
    pub roles: Vec<RoleId>,
    /// The user's country code.
    pub country: Fact<CountryCode>,
    /// Whether the device has been seen and trusted before.
    pub device: Familiarity,
    /// The current risk level.
    pub risk: RiskThreshold,
    /// The user's current assurance level.
    pub current_aal: AssuranceLevel,
    /// Whether this is a sensitive operation.
    pub sensitive_operation: Sensitivity,
    /// Whether the request includes a `DPoP` proof.
    pub has_dpop: DpopProof,
    /// The groups the user is in, with every group above them.
    pub groups: Vec<GroupId>,
    /// The permissions of the tenant's app the user holds, with what the
    /// ladders confer.
    pub permissions: Vec<CustomPermission>,
    /// The user's attributes and the claims of their sign-in.
    pub claims: Vec<Claim>,
    /// The address the request comes from.
    pub source_ip: Fact<IpAddr>,
    /// The time of day the request arrives, in each zone the admin tries.
    pub local_times: Vec<ZonedTime>,
    /// The host the request is for.
    pub host: Fact<HostName>,
}

impl SimulationInput {
    /// An input with nothing known about the path, method, country, address,
    /// time or host. The user holds no role, group, permission or claim. The
    /// device is known, the risk low, the sign-in at AAL1, the operation
    /// ordinary, and no `DPoP` proof is sent.
    #[must_use]
    pub fn new() -> Self {
        Self {
            path: Fact::Unknown,
            method: Fact::Unknown,
            roles: Vec::new(),
            country: Fact::Unknown,
            device: Familiarity::Known,
            risk: RiskThreshold::Low,
            current_aal: AssuranceLevel::Aal1,
            sensitive_operation: Sensitivity::Ordinary,
            has_dpop: DpopProof::Absent,
            groups: Vec::new(),
            permissions: Vec::new(),
            claims: Vec::new(),
            source_ip: Fact::Unknown,
            local_times: Vec::new(),
            host: Fact::Unknown,
        }
    }

    /// The path tried, as a simulation's record keeps it. A path the
    /// record's field cannot hold, such as one with letters outside ASCII,
    /// is left out rather than failing the run.
    pub(crate) fn recorded_path(&self) -> Option<UrlPath> {
        self.path
            .known()
            .and_then(|path| UrlPath::new(path.as_str()).ok())
    }
}

impl Default for SimulationInput {
    fn default() -> Self {
        Self::new()
    }
}

/// What a policy decides for a request.
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// The request is refused.
    Deny {
        /// Why, as the rule or default that refused it says.
        reason: Text,
    },
    /// The request goes through once the caller meets `step_up`.
    Allow {
        /// What the caller must also show. Nothing, for a plain allow.
        step_up: StepUp,
    },
}

two_cases! {
    /// Whether a request carries a `DPoP` proof.
    pub enum DpopProof {
        /// It does.
        Presented => true,
        /// It does not.
        Absent => false,
    }
}

two_cases! {
    /// Whether a matched rule asked for a `DPoP` proof.
    #[derive(Default)]
    pub enum DpopDemand {
        /// One did.
        Required => true,
        /// None did.
        #[default]
        NotRequired => false,
    }
}

two_cases! {
    /// Whether an audit-only rule, or an audit-only default, saw a request.
    #[derive(Default)]
    pub enum AuditMark {
        /// One did, so the request is recorded.
        Audited => true,
        /// None did.
        #[default]
        NotAudited => false,
    }
}

/// What an allowed request must also show before it goes through. That is
/// the strongest sign-in any matched rule asked for, and whether any asked
/// for a `DPoP` proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StepUp {
    aal: AalDemand,
    dpop: DpopDemand,
}

/// How strong a sign-in the matched rules ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AalDemand {
    /// No rule asked for more than the request has.
    #[default]
    Any,
    /// At least this level.
    AtLeast(AssuranceLevel),
}

impl AalDemand {
    /// Whether a sign-in at `level` meets the demand.
    #[must_use]
    pub fn is_met_by(self, level: AssuranceLevel) -> bool {
        match self {
            Self::Any => true,
            Self::AtLeast(required) => level >= required,
        }
    }

    fn and_at_least(self, level: AssuranceLevel) -> Self {
        match self {
            Self::Any => Self::AtLeast(level),
            Self::AtLeast(asked) => Self::AtLeast(asked.max(level)),
        }
    }
}

impl StepUp {
    /// The weakest sign-in the request may carry.
    #[must_use]
    pub fn required_aal(&self) -> AalDemand {
        self.aal
    }

    /// Whether the request must carry a `DPoP` proof.
    #[must_use]
    pub fn requires_dpop(&self) -> bool {
        self.dpop == DpopDemand::Required
    }

    /// Whether nothing more is asked.
    #[must_use]
    pub fn is_none(&self) -> bool {
        self.aal == AalDemand::Any && self.dpop == DpopDemand::NotRequired
    }

    fn with_aal(self, level: AssuranceLevel) -> Self {
        Self {
            aal: self.aal.and_at_least(level),
            ..self
        }
    }
}

/// The result of simulating a request against a policy set.
///
/// It names the version that decided and the rule that settled it, so a
/// request record says which rules a decision came from even after the
/// policy has moved on.
#[derive(Debug, Clone)]
pub struct SimulationResult {
    /// What the policy decides.
    decision: PolicyDecision,
    /// The version of the policy that decided.
    policy_version: PolicyVersion,
    /// Whether an audit-only rule, or an audit-only default, saw it.
    audited: AuditMark,
    /// The allow or deny rule that settled it. `None` when the default did.
    matched_rule: Option<Label>,
    /// All rules that were checked, in order.
    evaluated_rules: Vec<RuleEvaluation>,
}

/// How one rule was checked during simulation.
///
/// A rule matched exactly when none of its conditions failed, so that is
/// worked out from the failures rather than kept beside them.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RuleEvaluation {
    /// The rule name.
    name: Label,
    /// Which conditions failed. Empty when all matched.
    failed_conditions: Vec<String>,
}

impl SimulationResult {
    /// What the policy decides. Enforcement reads this. An allow carries
    /// every step-up the matched rules asked for.
    #[must_use]
    pub fn decision(&self) -> &PolicyDecision {
        &self.decision
    }

    /// The decision as one action, for showing to an admin.
    ///
    /// It is a refusal, the strongest step-up asked for, an audit or a plain
    /// allow. When both a stronger sign-in and a `DPoP` proof are asked for,
    /// it names only the sign-in. So enforcement reads
    /// [`decision`](Self::decision) instead.
    #[must_use]
    pub fn action(&self) -> PolicyAction {
        match &self.decision {
            PolicyDecision::Deny { reason } => PolicyAction::Deny {
                reason: reason.clone(),
            },
            PolicyDecision::Allow { step_up } => match (step_up.aal, step_up.dpop, self.audited) {
                (AalDemand::AtLeast(level), _, _) => PolicyAction::RequireAal(level),
                (AalDemand::Any, DpopDemand::Required, _) => PolicyAction::RequireDpop,
                (AalDemand::Any, DpopDemand::NotRequired, AuditMark::Audited) => {
                    PolicyAction::AuditOnly
                }
                (AalDemand::Any, DpopDemand::NotRequired, AuditMark::NotAudited) => {
                    PolicyAction::Allow
                }
            },
        }
    }

    /// Whether an audit-only rule, or an audit-only default, saw the request.
    #[must_use]
    pub fn audited(&self) -> bool {
        self.audited == AuditMark::Audited
    }

    /// The allow or deny rule that settled the request.
    #[must_use]
    pub fn matched_rule(&self) -> Option<&Label> {
        self.matched_rule.as_ref()
    }

    /// The version of the policy that decided.
    #[must_use]
    pub fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }

    /// Every rule checked, with how it matched.
    #[must_use]
    pub fn evaluated_rules(&self) -> &[RuleEvaluation] {
        &self.evaluated_rules
    }

    /// Whether the request would go through with nothing more asked.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(&self.decision, PolicyDecision::Allow { step_up } if step_up.is_none())
    }

    /// Whether the request would be denied.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self.decision, PolicyDecision::Deny { .. })
    }

    /// Whether the request would go through only after a step-up.
    #[must_use]
    pub fn requires_step_up(&self) -> bool {
        matches!(&self.decision, PolicyDecision::Allow { step_up } if !step_up.is_none())
    }
}

impl RuleEvaluation {
    /// The rule name.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// Whether the rule matched, meaning none of its conditions failed.
    #[must_use]
    pub fn matched(&self) -> bool {
        self.failed_conditions.is_empty()
    }

    /// The conditions that did not match, so an admin sees why.
    #[must_use]
    pub fn failed_conditions(&self) -> &[String] {
        &self.failed_conditions
    }
}

/// What is known about a request a policy decides.
///
/// A fact nobody knows is `Fact::Unknown`. The gateway knows a request's
/// path and the caller's roles, but not whether their device is trusted.
///
/// A condition on an unknown fact holds for a rule that refuses or asks for
/// more. It fails for a rule that allows or only records. So "deny unless
/// the device is trusted" refuses when nobody can say the device is trusted.
/// And "allow from Germany" grants nothing to a request whose country is
/// unknown. The path and method are read the same way, so a deny on
/// `/admin` refuses a request whose path nobody knows.
#[derive(Debug, Clone, Copy)]
pub struct RequestFacts<'a> {
    /// The request path in canonical form, the same form every path
    /// condition is written in, when it is known.
    pub path: Fact<&'a CanonicalPath>,
    /// The HTTP method, when it is known.
    pub method: Fact<&'a str>,
    /// The roles the caller holds.
    pub roles: &'a [RoleId],
    /// The caller's country, when it is known.
    pub country: Fact<&'a CountryCode>,
    /// Whether the device has been seen and trusted before, when it is known.
    pub device: Fact<Familiarity>,
    /// The risk of the request, when it is known.
    pub risk: Fact<RiskThreshold>,
    /// Whether the request is a sensitive operation, when it is known.
    pub sensitive_operation: Fact<Sensitivity>,
    /// The groups the caller is in, with every group above them, when they
    /// are known.
    pub groups: Fact<&'a [GroupId]>,
    /// The permissions of the tenant's app the caller holds, with what the
    /// ladders confer, when they are known.
    pub permissions: Fact<&'a [CustomPermission]>,
    /// The caller's attributes and the claims of their sign-in, when they
    /// are known. A claim missing from a known list is not held.
    pub claims: Fact<&'a [Claim]>,
    /// The address the request comes from, when it is known.
    pub source_ip: Fact<IpAddr>,
    /// The time of day the request arrived, in each zone the policy names.
    /// A zone missing from the list is a time nobody knows.
    pub local_times: &'a [ZonedTime],
    /// The host the request is for, when it is known.
    pub host: Fact<&'a HostName>,
}

/// Simulates a request against a policy set.
///
/// Decides the simulated request as [`evaluate`] decides a real one.
#[must_use]
pub fn simulate(policy: &PolicySet, input: &SimulationInput) -> SimulationResult {
    evaluate(
        policy,
        &RequestFacts {
            path: input.path.as_ref(),
            method: input.method.as_ref().map(HttpMethod::as_str),
            roles: &input.roles,
            country: input.country.as_ref(),
            device: Fact::Known(input.device),
            risk: Fact::Known(input.risk),
            sensitive_operation: Fact::Known(input.sensitive_operation),
            groups: Fact::Known(input.groups.as_slice()),
            permissions: Fact::Known(input.permissions.as_slice()),
            claims: Fact::Known(input.claims.as_slice()),
            source_ip: input.source_ip,
            local_times: &input.local_times,
            host: input.host.as_ref(),
        },
    )
}

/// Decides a request against a policy set.
///
/// Every enabled rule is read, in priority order. A deny whose conditions
/// all hold refuses the request, wherever it sits: an explicit refusal
/// always beats an allow, as cloud access policies treat it. Otherwise the
/// first allow whose conditions hold lets the request through. When no
/// allow or deny matches, the policy's default decides.
///
/// A matching step-up rule asks for more and grants nothing. It adds what
/// the caller must show to the allow. A matching audit-only rule records the
/// request and changes nothing. So a rule added to watch traffic never lets
/// through what another rule refuses.
#[must_use]
pub fn evaluate(policy: &PolicySet, facts: &RequestFacts<'_>) -> SimulationResult {
    let mut walk = Walk::of(policy.version());
    let mut first_allow = None;

    for rule in policy.rules().iter().filter(|rule| rule.enabled()) {
        if !walk.matches(rule, facts) {
            continue;
        }
        match walk.read(rule.action()) {
            Some(Settled::Deny(reason)) => {
                return walk.settled_by(Settled::Deny(reason), Some(rule.name().clone()));
            }
            Some(Settled::Allow) => {
                first_allow.get_or_insert_with(|| rule.name().clone());
            }
            None => {}
        }
    }

    if let Some(allowed_by) = first_allow {
        return walk.settled_by(Settled::Allow, Some(allowed_by));
    }
    let settled = walk.read(policy.default_action()).unwrap_or(Settled::Allow);
    walk.settled_by(settled, None)
}

/// What the rules of one version read so far have asked for.
struct Walk {
    version: PolicyVersion,
    step_up: StepUp,
    audited: AuditMark,
    evaluated: Vec<RuleEvaluation>,
}

/// An action that ends the reading.
enum Settled {
    Allow,
    Deny(Text),
}

impl Walk {
    /// A walk over the rules of `version`, nothing asked for yet.
    fn of(version: PolicyVersion) -> Self {
        Self {
            version,
            step_up: StepUp::default(),
            audited: AuditMark::default(),
            evaluated: Vec::new(),
        }
    }

    /// Whether all of `rule`'s conditions hold, recording the check.
    fn matches(&mut self, rule: &PolicyRule, facts: &RequestFacts<'_>) -> bool {
        let failed = check_conditions(rule.conditions(), facts, rule.action().on_unknown_fact());
        let evaluation = RuleEvaluation {
            name: rule.name().clone(),
            failed_conditions: failed,
        };
        let matched = evaluation.matched();
        self.evaluated.push(evaluation);
        matched
    }

    /// Records a matched action. Returns how it settles the request, if it
    /// does.
    fn read(&mut self, action: &PolicyAction) -> Option<Settled> {
        match action {
            PolicyAction::Allow => Some(Settled::Allow),
            PolicyAction::Deny { reason } => Some(Settled::Deny(reason.clone())),
            PolicyAction::RequireAal(level) => {
                self.step_up = self.step_up.with_aal(*level);
                None
            }
            PolicyAction::RequireDpop => {
                self.step_up.dpop = DpopDemand::Required;
                None
            }
            PolicyAction::AuditOnly => {
                self.audited = AuditMark::Audited;
                None
            }
        }
    }

    fn settled_by(self, settled: Settled, matched_rule: Option<Label>) -> SimulationResult {
        let decision = match settled {
            Settled::Allow => PolicyDecision::Allow {
                step_up: self.step_up,
            },
            Settled::Deny(reason) => PolicyDecision::Deny { reason },
        };
        SimulationResult {
            decision,
            policy_version: self.version,
            audited: self.audited,
            matched_rule,
            evaluated_rules: self.evaluated,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::hash::{DefaultHasher, Hash, Hasher};

    use super::*;
    use crate::domains::authorization::permission::SystemPermission;
    use crate::domains::authorization::policy::claims::{ClaimName, ClaimValue};
    use crate::domains::authorization::policy::condition::PolicyCondition;
    use crate::domains::authorization::policy::rule::PolicyRule;
    use crate::domains::authorization::policy::time_window::{TimeOfDay, TimeWindow};
    use crate::types::{CidrRange, Enablement, PathPrefix, Text, Timezone};

    /// The same id for the same name within a test, so a rule and the roles
    /// a caller holds can name one role.
    fn role(name: &str) -> RoleId {
        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        RoleId::from_uuid(uuid::Uuid::from_u64_pair(hasher.finish(), 0))
    }

    fn label(s: &str) -> Label {
        Label::new("rule_name", s).unwrap()
    }

    fn reason(s: &str) -> Text {
        Text::new("reason", s).unwrap()
    }

    fn add(policy: &mut PolicySet, rule: PolicyRule) {
        let author =
            crate::test_support::authority::anyone_holding(&[SystemPermission::ManagePolicy]);
        policy.add_rule(rule, author).unwrap();
    }

    /// A policy with no rules and an allow default is simulated. The request
    /// is allowed and no rule is named as the one that decided.
    #[test]
    fn empty_policy_returns_default() {
        let policy = PolicySet::permissive();
        let input = SimulationInput::new();
        let result = simulate(&policy, &input);

        assert!(result.is_allowed());
        assert!(result.matched_rule().is_none());
    }

    /// A rule denies `/admin` and the request is for `/admin/users`. It is
    /// denied, and "block-admin" is named as the deciding rule.
    #[test]
    fn matching_rule_fires() {
        let mut policy = PolicySet::permissive();
        add(
            &mut policy,
            PolicyRule::new(
                label("block-admin"),
                vec![PolicyCondition::PathPrefix(
                    PathPrefix::new("/admin").unwrap(),
                )],
                PolicyAction::Deny {
                    reason: reason("admin access blocked"),
                },
                10,
            )
            .unwrap(),
        );

        let mut input = SimulationInput::new();
        input.path = Fact::Known(CanonicalPath::new("/admin/users").unwrap());

        let result = simulate(&policy, &input);

        assert!(result.is_denied());
        assert_eq!(result.matched_rule().unwrap().as_str(), "block-admin");
    }

    /// A rule denies `/admin` and the request is for `/api/users`. The rule
    /// does not apply, so the allow default decides.
    #[test]
    fn non_matching_rule_skipped() {
        let mut policy = PolicySet::permissive();
        add(
            &mut policy,
            PolicyRule::new(
                label("block-admin"),
                vec![PolicyCondition::PathPrefix(
                    PathPrefix::new("/admin").unwrap(),
                )],
                PolicyAction::Deny {
                    reason: reason("no"),
                },
                10,
            )
            .unwrap(),
        );

        let mut input = SimulationInput::new();
        input.path = Fact::Known(CanonicalPath::new("/api/users").unwrap());

        let result = simulate(&policy, &input);
        assert!(result.is_allowed());
        assert!(result.matched_rule().is_none());
    }

    /// A super admin opens `/admin/settings`. The allow at priority 1 lets
    /// the request through, and the sign-in demand at priority 10 still
    /// applies: being allowed never skips a stronger sign-in a page asks
    /// for.
    #[test]
    fn an_allow_does_not_skip_a_later_step_up() {
        let mut policy = PolicySet::permissive();
        add(
            &mut policy,
            PolicyRule::new(
                label("allow-super-admin"),
                vec![PolicyCondition::RoleIs(role("super_admin"))],
                PolicyAction::Allow,
                1,
            )
            .unwrap(),
        );
        add(
            &mut policy,
            on_admin(
                "require-mfa",
                PolicyAction::RequireAal(AssuranceLevel::Aal2),
                10,
            ),
        );

        let mut input = SimulationInput::new();
        input.path = Fact::Known(CanonicalPath::new("/admin/settings").unwrap());
        input.roles = vec![role("super_admin")];

        let result = simulate(&policy, &input);
        assert!(!result.is_denied());
        assert_eq!(result.matched_rule().unwrap().as_str(), "allow-super-admin");
        assert!(matches!(
            result.decision(),
            PolicyDecision::Allow { step_up } if !step_up.required_aal().is_met_by(AssuranceLevel::Aal1)
        ));
    }

    /// A super admin requesting `/admin/settings` matches an allow at priority
    /// 1 and a path deny at priority 10. The result is denied and names the
    /// later deny as the deciding rule.
    #[test]
    fn a_later_deny_beats_an_earlier_allow() {
        let mut policy = PolicySet::permissive();
        add(
            &mut policy,
            PolicyRule::new(
                label("allow-super-admin"),
                vec![PolicyCondition::RoleIs(role("super_admin"))],
                PolicyAction::Allow,
                1,
            )
            .unwrap(),
        );
        add(
            &mut policy,
            on_admin(
                "deny-admin-path",
                PolicyAction::Deny {
                    reason: Text::new("reason", "closed for maintenance").unwrap(),
                },
                10,
            ),
        );
        let mut input = SimulationInput::new();
        input.path = Fact::Known(CanonicalPath::new("/admin/settings").unwrap());
        input.roles = vec![role("super_admin")];

        let result = simulate(&policy, &input);

        assert!(result.is_denied());
        assert_eq!(result.matched_rule().unwrap().as_str(), "deny-admin-path");
    }

    /// A rule denies `/admin` from a new device at medium risk. From a known
    /// device the request is allowed, and from a new one it is denied.
    #[test]
    fn all_conditions_must_match() {
        let mut policy = PolicySet::permissive();
        add(
            &mut policy,
            PolicyRule::new(
                label("risky-admin"),
                vec![
                    PolicyCondition::PathPrefix(PathPrefix::new("/admin").unwrap()),
                    PolicyCondition::DeviceUnknown,
                    PolicyCondition::RiskAtLeast(RiskThreshold::Medium),
                ],
                PolicyAction::Deny {
                    reason: reason("too risky"),
                },
                10,
            )
            .unwrap(),
        );

        let mut input = SimulationInput::new();
        input.path = Fact::Known(CanonicalPath::new("/admin/users").unwrap());
        input.device = Familiarity::Known;
        input.risk = RiskThreshold::Medium;

        let result = simulate(&policy, &input);
        assert!(result.is_allowed());

        input.device = Familiarity::New;
        let result = simulate(&policy, &input);
        assert!(result.is_denied());
    }

    /// A rule denies requests from KP and IR. A request from KP is denied,
    /// and one from DE is allowed.
    #[test]
    fn block_sanctioned_countries() {
        let mut policy = PolicySet::permissive();
        add(
            &mut policy,
            PolicyRule::new(
                label("sanctions"),
                vec![PolicyCondition::CountryIn(vec![
                    CountryCode::new("KP").unwrap(),
                    CountryCode::new("IR").unwrap(),
                ])],
                PolicyAction::Deny {
                    reason: reason("sanctioned country"),
                },
                1,
            )
            .unwrap(),
        );

        let mut input = SimulationInput::new();
        input.country = Fact::Known(CountryCode::new("KP").unwrap());

        assert!(simulate(&policy, &input).is_denied());

        input.country = Fact::Known(CountryCode::new("DE").unwrap());
        assert!(simulate(&policy, &input).is_allowed());
    }

    /// A rule asks for AAL2 under `/billing`. A request for
    /// `/billing/invoices` goes through only after a step-up.
    #[test]
    fn require_aal2_for_sensitive_path() {
        let mut policy = PolicySet::permissive();
        add(
            &mut policy,
            PolicyRule::new(
                label("billing-mfa"),
                vec![PolicyCondition::PathPrefix(
                    PathPrefix::new("/billing").unwrap(),
                )],
                PolicyAction::RequireAal(AssuranceLevel::Aal2),
                10,
            )
            .unwrap(),
        );

        let mut input = SimulationInput::new();
        input.path = Fact::Known(CanonicalPath::new("/billing/invoices").unwrap());

        let result = simulate(&policy, &input);
        assert!(result.requires_step_up());
    }

    /// A rule that denies everything is disabled. It is skipped, so the
    /// allow default decides.
    #[test]
    fn disabled_rules_are_skipped() {
        let mut policy = PolicySet::permissive();
        let mut rule = PolicyRule::new(
            label("block-all"),
            vec![],
            PolicyAction::Deny {
                reason: reason("blocked"),
            },
            1,
        )
        .unwrap();
        rule.switch(Enablement::Disabled);
        add(&mut policy, rule);

        let result = simulate(&policy, &SimulationInput::new());
        assert!(result.is_allowed());
    }

    /// Rules on `/a` and `/b` are checked for a request to `/b/data`. The
    /// result lists both, the first with its failed condition and the second
    /// as matched.
    #[test]
    fn result_includes_evaluation_trace() {
        let mut policy = PolicySet::permissive();
        add(
            &mut policy,
            PolicyRule::new(
                label("rule-a"),
                vec![PolicyCondition::PathPrefix(PathPrefix::new("/a").unwrap())],
                PolicyAction::Allow,
                1,
            )
            .unwrap(),
        );
        add(
            &mut policy,
            PolicyRule::new(
                label("rule-b"),
                vec![PolicyCondition::PathPrefix(PathPrefix::new("/b").unwrap())],
                PolicyAction::Allow,
                2,
            )
            .unwrap(),
        );

        let mut input = SimulationInput::new();
        input.path = Fact::Known(CanonicalPath::new("/b/data").unwrap());

        let result = simulate(&policy, &input);
        assert_eq!(result.evaluated_rules().len(), 2);
        assert!(!result.evaluated_rules()[0].matched());
        assert!(!result.evaluated_rules()[0].failed_conditions().is_empty());
        assert!(result.evaluated_rules()[1].matched());
    }

    /// Whether a rule with only `condition`, denying what it matches,
    /// refuses `input`.
    fn denies(condition: PolicyCondition, input: &SimulationInput) -> bool {
        let mut policy = PolicySet::permissive();
        add(
            &mut policy,
            PolicyRule::new(
                label("rule"),
                vec![condition],
                PolicyAction::Deny {
                    reason: reason("matched"),
                },
                10,
            )
            .unwrap(),
        );

        simulate(&policy, input).is_denied()
    }

    /// A deny on exactly `/admin` refuses a request to `/admin`. It does not
    /// refuse one to `/admin/users`.
    #[test]
    fn an_exact_path_condition_matches_that_path_and_nothing_else() {
        let mut asked_for = SimulationInput::new();
        asked_for.path = Fact::Known(CanonicalPath::new("/admin").unwrap());
        let mut something_else = SimulationInput::new();
        something_else.path = Fact::Known(CanonicalPath::new("/admin/users").unwrap());

        assert!(denies(
            PolicyCondition::PathExact(CanonicalPath::new("/admin").unwrap()),
            &asked_for
        ));
        assert!(!denies(
            PolicyCondition::PathExact(CanonicalPath::new("/admin").unwrap()),
            &something_else
        ));
    }

    /// A deny on holding the admin role refuses the holder and not a
    /// stranger. A deny on not holding it refuses the stranger and not the
    /// holder.
    #[test]
    fn a_role_condition_matches_the_holder_and_its_negation_matches_everyone_else() {
        let mut holder = SimulationInput::new();
        holder.roles = vec![role("admin")];
        let stranger = SimulationInput::new();

        assert!(denies(PolicyCondition::RoleIs(role("admin")), &holder));
        assert!(!denies(PolicyCondition::RoleIs(role("admin")), &stranger));

        assert!(denies(PolicyCondition::RoleIsNot(role("admin")), &stranger));
        assert!(!denies(PolicyCondition::RoleIsNot(role("admin")), &holder));
    }

    /// A deny on KP refuses a request from KP and not one from GB. A deny on
    /// everywhere but KP does the opposite.
    #[test]
    fn a_country_list_matches_the_countries_it_names() {
        let listed = CountryCode::new("KP").unwrap();
        let mut from_listed = SimulationInput::new();
        from_listed.country = Fact::Known(listed.clone());
        let mut from_elsewhere = SimulationInput::new();
        from_elsewhere.country = Fact::Known(CountryCode::new("GB").unwrap());

        assert!(denies(
            PolicyCondition::CountryIn(vec![listed.clone()]),
            &from_listed
        ));
        assert!(!denies(
            PolicyCondition::CountryIn(vec![listed.clone()]),
            &from_elsewhere
        ));

        assert!(!denies(
            PolicyCondition::CountryNotIn(vec![listed.clone()]),
            &from_listed
        ));
        assert!(denies(
            PolicyCondition::CountryNotIn(vec![listed]),
            &from_elsewhere
        ));
    }

    /// A deny on medium risk or above refuses medium and high risk requests.
    /// A low risk request goes through.
    #[test]
    fn a_risk_threshold_matches_risk_at_or_above_it() {
        let mut low = SimulationInput::new();
        low.risk = RiskThreshold::Low;
        let mut medium = SimulationInput::new();
        medium.risk = RiskThreshold::Medium;
        let mut high = SimulationInput::new();
        high.risk = RiskThreshold::High;

        assert!(!denies(
            PolicyCondition::RiskAtLeast(RiskThreshold::Medium),
            &low
        ));
        assert!(denies(
            PolicyCondition::RiskAtLeast(RiskThreshold::Medium),
            &medium
        ));
        assert!(denies(
            PolicyCondition::RiskAtLeast(RiskThreshold::Medium),
            &high
        ));
    }

    /// A deny on POST and DELETE refuses a POST. A GET goes through.
    #[test]
    fn a_method_condition_matches_the_methods_it_names() {
        let mut posting = SimulationInput::new();
        posting.method = Fact::from_option(HttpMethod::parse("POST"));
        let mut reading = SimulationInput::new();
        reading.method = Fact::from_option(HttpMethod::parse("GET"));

        assert!(denies(
            PolicyCondition::MethodIn(vec![HttpMethod::Post, HttpMethod::Delete]),
            &posting
        ));
        assert!(!denies(
            PolicyCondition::MethodIn(vec![HttpMethod::Post, HttpMethod::Delete]),
            &reading
        ));
    }

    /// A deny on sensitive operations refuses a sensitive request and not an
    /// ordinary one. Denies on known and on new devices each refuse only the
    /// device they name.
    #[test]
    fn the_flag_conditions_match_the_state_they_name() {
        let mut sensitive = SimulationInput::new();
        sensitive.sensitive_operation = Sensitivity::Sensitive;
        let ordinary = SimulationInput::new();

        assert!(denies(PolicyCondition::SensitiveOperation, &sensitive));
        assert!(!denies(PolicyCondition::SensitiveOperation, &ordinary));

        let mut known = SimulationInput::new();
        known.device = Familiarity::Known;
        let mut unknown = SimulationInput::new();
        unknown.device = Familiarity::New;

        assert!(denies(PolicyCondition::DeviceKnown, &known));
        assert!(!denies(PolicyCondition::DeviceKnown, &unknown));
        assert!(denies(PolicyCondition::DeviceUnknown, &unknown));
        assert!(!denies(PolicyCondition::DeviceUnknown, &known));
    }

    /// A request denied by "deny-admin" reads only as denied. A request the
    /// default allows reads only as allowed, with no step-up.
    #[test]
    fn a_result_answers_only_for_the_action_it_carries() {
        let mut policy = PolicySet::permissive();
        add(
            &mut policy,
            PolicyRule::new(
                label("deny-admin"),
                vec![PolicyCondition::PathPrefix(
                    PathPrefix::new("/admin").unwrap(),
                )],
                PolicyAction::Deny {
                    reason: reason("blocked"),
                },
                10,
            )
            .unwrap(),
        );

        let mut input = SimulationInput::new();
        input.path = Fact::Known(CanonicalPath::new("/admin").unwrap());
        let denied = simulate(&policy, &input);

        assert!(denied.is_denied());
        assert!(!denied.is_allowed());
        assert!(!denied.requires_step_up());

        let mut elsewhere = SimulationInput::new();
        elsewhere.path = Fact::Known(CanonicalPath::new("/home").unwrap());
        let allowed = simulate(&policy, &elsewhere);
        assert!(allowed.is_allowed());
        assert!(!allowed.is_denied());
        assert!(!allowed.requires_step_up());
    }

    /// "deny-admin" matches a request to `/admin`. Its trace lists no failed
    /// conditions, since there is nothing to explain to the admin.
    #[test]
    fn a_matched_rule_lists_no_failed_conditions() {
        let mut policy = PolicySet::permissive();
        add(
            &mut policy,
            PolicyRule::new(
                label("deny-admin"),
                vec![PolicyCondition::PathPrefix(
                    PathPrefix::new("/admin").unwrap(),
                )],
                PolicyAction::Deny {
                    reason: reason("blocked"),
                },
                10,
            )
            .unwrap(),
        );

        let mut input = SimulationInput::new();
        input.path = Fact::Known(CanonicalPath::new("/admin").unwrap());

        let result = simulate(&policy, &input);
        let evaluation = &result.evaluated_rules()[0];

        assert!(evaluation.matched());
        assert!(
            evaluation.failed_conditions().is_empty(),
            "{:?}",
            evaluation.failed_conditions()
        );
    }

    static ADMIN: std::sync::LazyLock<CanonicalPath> =
        std::sync::LazyLock::new(|| CanonicalPath::new("/admin").unwrap());

    fn facts<'a>(roles: &'a [RoleId]) -> RequestFacts<'a> {
        RequestFacts {
            path: Fact::Known(&ADMIN),
            method: Fact::Known("GET"),
            roles,
            country: Fact::Unknown,
            device: Fact::Unknown,
            risk: Fact::Unknown,
            sensitive_operation: Fact::Unknown,
            groups: Fact::Unknown,
            permissions: Fact::Unknown,
            claims: Fact::Unknown,
            source_ip: Fact::Unknown,
            local_times: &[],
            host: Fact::Unknown,
        }
    }

    fn deny_when(condition: PolicyCondition) -> PolicySet {
        let mut policy = PolicySet::permissive();
        add(
            &mut policy,
            PolicyRule::new(
                label("guard"),
                vec![condition],
                PolicyAction::Deny {
                    reason: reason("refused"),
                },
                10,
            )
            .unwrap(),
        );
        policy
    }

    fn unknown_fact_conditions() -> [PolicyCondition; 14] {
        let office = TimeWindow::new(
            TimeOfDay::at(8, 0).unwrap(),
            TimeOfDay::at(18, 0).unwrap(),
            Timezone::new("Europe/Berlin").unwrap(),
        )
        .unwrap();
        let ranges = || vec![CidrRange::new("10.0.0.0/8").unwrap()];
        [
            PolicyCondition::DeviceKnown,
            PolicyCondition::DeviceUnknown,
            PolicyCondition::RiskAtLeast(RiskThreshold::Low),
            PolicyCondition::SensitiveOperation,
            PolicyCondition::CountryIn(vec![CountryCode::new("DE").unwrap()]),
            PolicyCondition::CountryNotIn(vec![CountryCode::new("DE").unwrap()]),
            PolicyCondition::GroupIs(GroupId::new()),
            PolicyCondition::GroupIsNot(GroupId::new()),
            PolicyCondition::PermissionHeld(CustomPermission::new("billing", "read").unwrap()),
            PolicyCondition::ClaimEquals {
                name: ClaimName::new("department").unwrap(),
                value: ClaimValue::new("finance").unwrap(),
            },
            PolicyCondition::SourceIpIn(ranges()),
            PolicyCondition::SourceIpNotIn(ranges()),
            PolicyCondition::TimeWithin(office),
            PolicyCondition::HostIn(vec![HostName::new("billing.acme.test").unwrap()]),
        ]
    }

    fn with_action(condition: PolicyCondition, action: PolicyAction) -> PolicySet {
        let mut policy = PolicySet::new(PolicyAction::Deny {
            reason: reason("default"),
        });
        add(
            &mut policy,
            PolicyRule::new(label("guard"), vec![condition], action, 10).unwrap(),
        );
        policy
    }

    /// Deny conditions on unknown device, risk, sensitivity, country, group,
    /// permission, claim, address, time or host facts still deny the request.
    #[test]
    fn a_refusing_rule_fires_on_an_unknown_fact() {
        for condition in unknown_fact_conditions() {
            let result = evaluate(&deny_when(condition.clone()), &facts(&[]));

            assert!(result.is_denied(), "{condition:?} let an unknown fact pass");
        }
    }

    /// With device trust unknown, a rule for new devices still requires a
    /// step-up whether its action asks for AAL2 or a `DPoP` proof.
    #[test]
    fn a_rule_asking_for_more_fires_on_an_unknown_fact() {
        for action in [
            PolicyAction::RequireAal(AssuranceLevel::Aal2),
            PolicyAction::RequireDpop,
        ] {
            let mut policy = PolicySet::permissive();
            add(
                &mut policy,
                PolicyRule::new(
                    label("guard"),
                    vec![PolicyCondition::DeviceUnknown],
                    action,
                    10,
                )
                .unwrap(),
            );

            let result = evaluate(&policy, &facts(&[]));

            assert!(result.requires_step_up());
        }
    }

    /// Allow and audit-only conditions on unknown request facts name no
    /// deciding rule. The deny default refuses every such request.
    #[test]
    fn a_rule_letting_the_request_through_does_not_fire_on_an_unknown_fact() {
        for condition in unknown_fact_conditions() {
            for action in [PolicyAction::Allow, PolicyAction::AuditOnly] {
                let policy = with_action(condition.clone(), action);

                let result = evaluate(&policy, &facts(&[]));

                assert!(result.matched_rule().is_none(), "{condition:?}");
                assert!(result.is_denied());
            }
        }
    }

    /// Device trust is unknown. A deny that matched on it lists no failed
    /// condition, and an allow it stopped lists "device trust not known".
    #[test]
    fn an_unknown_fact_is_named_only_where_it_stopped_a_rule() {
        let refusing = evaluate(&deny_when(PolicyCondition::DeviceUnknown), &facts(&[]));
        let allowing = evaluate(
            &with_action(PolicyCondition::DeviceKnown, PolicyAction::Allow),
            &facts(&[]),
        );

        assert!(refusing.evaluated_rules()[0].failed_conditions().is_empty());
        assert_eq!(
            allowing.evaluated_rules()[0].failed_conditions(),
            ["device trust not known"]
        );
    }

    /// A deny on new devices meets a request from a device known to be
    /// trusted. It does not match, and the request is allowed.
    #[test]
    fn a_refusing_rule_does_not_fire_when_its_fact_is_known_and_does_not_hold() {
        let known = RequestFacts {
            device: Fact::Known(Familiarity::Known),
            ..facts(&[])
        };

        let result = evaluate(&deny_when(PolicyCondition::DeviceUnknown), &known);

        assert!(result.is_allowed());
    }

    /// An admin opens `/admin` through the gateway. A deny on `/admin`
    /// refuses them, and a deny on not being an admin lets them in.
    #[test]
    fn known_facts_decide_as_in_the_simulator() {
        let roles = vec![role("Admin")];

        let by_path = evaluate(
            &deny_when(PolicyCondition::PathPrefix(
                PathPrefix::new("/admin").unwrap(),
            )),
            &facts(&roles),
        );
        let by_role = evaluate(
            &deny_when(PolicyCondition::RoleIsNot(role("Admin"))),
            &facts(&roles),
        );

        assert!(by_path.is_denied());
        assert!(by_role.is_allowed());
    }

    /// An allow for the `/api/public` prefix admits `/api/public/docs`. The
    /// sibling paths `/api/public-admin` and `/api/publicx` are denied by default.
    #[test]
    fn an_allowed_prefix_does_not_reach_a_sibling_path() {
        let mut policy = PolicySet::new(PolicyAction::Deny {
            reason: reason("closed"),
        });
        add(
            &mut policy,
            PolicyRule::new(
                label("public"),
                vec![PolicyCondition::PathPrefix(
                    PathPrefix::new("/api/public").unwrap(),
                )],
                PolicyAction::Allow,
                10,
            )
            .unwrap(),
        );
        let decide = |raw: &str| {
            let path = CanonicalPath::new(raw).unwrap();
            evaluate(
                &policy,
                &RequestFacts {
                    path: Fact::Known(&path),
                    ..facts(&[])
                },
            )
        };

        assert!(decide("/api/public/docs").is_allowed());
        assert!(decide("/api/public-admin").is_denied());
        assert!(decide("/api/publicx").is_denied());
    }

    /// Exact-path denies written with a trailing slash, repeated slashes or
    /// an encoded letter all deny the canonical `/admin/delete` request.
    #[test]
    fn a_deny_fires_however_its_path_was_written() {
        let request = CanonicalPath::new("/admin/delete").unwrap();

        for written in ["/admin/delete/", "//admin//delete", "/admin/%64elete"] {
            let policy = deny_when(PolicyCondition::PathExact(
                CanonicalPath::new(written).unwrap(),
            ));

            let result = evaluate(
                &policy,
                &RequestFacts {
                    path: Fact::Known(&request),
                    ..facts(&[])
                },
            );

            assert!(result.is_denied(), "{written:?} did not fire");
        }
    }

    /// A deny for the `/admin` prefix refuses a request with an unknown path,
    /// even though the policy allows by default.
    #[test]
    fn a_deny_on_a_path_refuses_a_request_whose_path_is_unknown() {
        let policy = deny_when(PolicyCondition::PathPrefix(
            PathPrefix::new("/admin").unwrap(),
        ));

        let result = evaluate(
            &policy,
            &RequestFacts {
                path: Fact::Unknown,
                ..facts(&[])
            },
        );

        assert!(result.is_denied());
    }

    /// When both path and method are unknown, an exact `/admin` deny and a
    /// DELETE-method deny each refuse the request.
    #[test]
    fn a_path_or_method_condition_does_not_fail_on_an_unknown_fact() {
        let unknown = RequestFacts {
            path: Fact::Unknown,
            method: Fact::Unknown,
            ..facts(&[])
        };

        for condition in [
            PolicyCondition::PathExact(CanonicalPath::new("/admin").unwrap()),
            PolicyCondition::MethodIn(vec![HttpMethod::Delete]),
        ] {
            let result = evaluate(&deny_when(condition.clone()), &unknown);

            assert!(result.is_denied(), "{condition:?} let an unknown fact pass");
        }
    }

    /// With path and method unknown, neither an allow for `/public` nor an
    /// allow for GET names a deciding rule. Both requests are denied by default.
    #[test]
    fn an_allow_on_a_path_or_method_does_not_fire_on_an_unknown_fact() {
        let unknown = RequestFacts {
            path: Fact::Unknown,
            method: Fact::Unknown,
            ..facts(&[])
        };

        for condition in [
            PolicyCondition::PathPrefix(PathPrefix::new("/public").unwrap()),
            PolicyCondition::MethodIn(vec![HttpMethod::Get]),
        ] {
            let result = evaluate(
                &with_action(condition.clone(), PolicyAction::Allow),
                &unknown,
            );

            assert!(result.matched_rule().is_none(), "{condition:?}");
            assert!(result.is_denied());
        }
    }

    /// A simulation names no method. A deny on DELETE refuses it, as the
    /// gateway would refuse a request whose method nobody knows.
    #[test]
    fn a_simulation_without_a_method_meets_a_method_deny() {
        assert!(denies(
            PolicyCondition::MethodIn(vec![HttpMethod::Delete]),
            &SimulationInput::new()
        ));
    }

    /// A DELETE-method deny refuses both uppercase `DELETE` and lowercase
    /// `delete`, while GET is allowed by default.
    #[test]
    fn a_method_deny_catches_the_method_in_any_case() {
        let policy = deny_when(PolicyCondition::MethodIn(vec![HttpMethod::Delete]));
        let asking = |method| RequestFacts {
            method: Fact::Known(method),
            ..facts(&[])
        };

        assert!(evaluate(&policy, &asking("DELETE")).is_denied());
        assert!(evaluate(&policy, &asking("delete")).is_denied());
        assert!(evaluate(&policy, &asking("GET")).is_allowed());
    }

    /// A deny naming one role ID refuses its holder. A request holding a
    /// different role ID is allowed by default.
    #[test]
    fn a_role_rule_keeps_matching_the_role_it_named_whatever_it_is_called() {
        let auditors = RoleId::new();
        let renamed_impostor = RoleId::new();
        let policy = deny_when(PolicyCondition::RoleIs(auditors));

        assert!(evaluate(&policy, &facts(&[auditors])).is_denied());
        assert!(evaluate(&policy, &facts(&[renamed_impostor])).is_allowed());
    }

    fn on_admin(name: &str, action: PolicyAction, priority: u16) -> PolicyRule {
        PolicyRule::new(
            label(name),
            vec![PolicyCondition::PathPrefix(
                PathPrefix::new("/admin").unwrap(),
            )],
            action,
            priority,
        )
        .unwrap()
    }

    fn admin_request() -> SimulationInput {
        let mut input = SimulationInput::new();
        input.path = Fact::Known(CanonicalPath::new("/admin/users").unwrap());
        input
    }

    fn refuse() -> PolicyAction {
        PolicyAction::Deny {
            reason: reason("admins only"),
        }
    }

    /// An audit-only rule on `/admin` comes before a deny on `/admin`. The
    /// request is recorded and still denied, with the deny named.
    #[test]
    fn an_audit_only_rule_does_not_hide_a_later_deny() {
        let mut policy = PolicySet::permissive();
        add(&mut policy, on_admin("watch", PolicyAction::AuditOnly, 1));
        add(&mut policy, on_admin("shut", refuse(), 2));

        let result = simulate(&policy, &admin_request());

        assert!(result.is_denied());
        assert!(result.audited());
        assert_eq!(result.matched_rule().unwrap().as_str(), "shut");
    }

    /// An audit-only rule on `/admin` matches in a policy that denies by
    /// default. The default still denies, and no rule is named.
    #[test]
    fn an_audit_only_rule_does_not_hide_a_default_deny() {
        let mut policy = PolicySet::new(refuse());
        add(&mut policy, on_admin("watch", PolicyAction::AuditOnly, 1));

        let result = simulate(&policy, &admin_request());

        assert!(result.is_denied());
        assert!(result.matched_rule().is_none());
    }

    /// A matching AAL2 demand does not prevent a later matching deny from
    /// refusing an `/admin/users` request.
    #[test]
    fn a_step_up_rule_does_not_hide_a_later_deny() {
        let mut policy = PolicySet::permissive();
        add(
            &mut policy,
            on_admin("mfa", PolicyAction::RequireAal(AssuranceLevel::Aal2), 1),
        );
        add(&mut policy, on_admin("shut", refuse(), 2));

        assert!(simulate(&policy, &admin_request()).is_denied());
    }

    /// A matching AAL2 demand grants no access on its own. The deny default
    /// still refuses the `/admin/users` request.
    #[test]
    fn a_step_up_rule_does_not_hide_a_default_deny() {
        let mut policy = PolicySet::new(refuse());
        add(
            &mut policy,
            on_admin("mfa", PolicyAction::RequireAal(AssuranceLevel::Aal2), 1),
        );

        assert!(simulate(&policy, &admin_request()).is_denied());
    }

    /// Rules ask for AAL2, then a `DPoP` proof, then AAL3, then allow. The
    /// allow asks for AAL3 and the proof, and the request is not let through
    /// without them.
    #[test]
    fn an_allow_carries_every_step_up_matched_before_it() {
        let mut policy = PolicySet::new(refuse());
        add(
            &mut policy,
            on_admin("mfa", PolicyAction::RequireAal(AssuranceLevel::Aal2), 1),
        );
        add(&mut policy, on_admin("key", PolicyAction::RequireDpop, 2));
        add(
            &mut policy,
            on_admin(
                "hardware",
                PolicyAction::RequireAal(AssuranceLevel::Aal3),
                3,
            ),
        );
        add(&mut policy, on_admin("let-in", PolicyAction::Allow, 4));

        let result = simulate(&policy, &admin_request());

        let PolicyDecision::Allow { step_up } = result.decision() else {
            panic!("the allow rule settles it");
        };
        assert_eq!(
            step_up.required_aal(),
            AalDemand::AtLeast(AssuranceLevel::Aal3)
        );
        assert!(step_up.requires_dpop());
        assert!(result.requires_step_up());
        assert!(!result.is_allowed(), "not without the step-up");
    }

    /// A default that asks for a step-up allows once the step-up is met.
    /// A policy with no rules asks for AAL2 by default. The request goes
    /// through after the step-up, and the action shown is the AAL2 demand.
    #[test]
    fn a_step_up_default_allows_after_the_step_up() {
        let policy = PolicySet::new(PolicyAction::RequireAal(AssuranceLevel::Aal2));

        let result = simulate(&policy, &admin_request());

        assert!(result.requires_step_up());
        assert!(matches!(
            result.action(),
            PolicyAction::RequireAal(AssuranceLevel::Aal2)
        ));
    }

    /// A policy at version 1 decides a request. The result names version
    /// 1, so the request record says which rules decided.
    #[test]
    fn a_decision_names_the_version_that_made_it() {
        let result = simulate(&PolicySet::permissive(), &SimulationInput::new());

        assert_eq!(result.policy_version(), PolicyVersion::FIRST);
    }

    /// Ann is in Finance, holds `billing:read` and carries `department` as
    /// `finance`. A deny on each of those refuses her, and on another group,
    /// another permission or another value lets her through.
    #[test]
    fn group_permission_and_claim_conditions_read_what_the_caller_holds() {
        let finance = GroupId::new();
        let input = SimulationInput {
            groups: vec![finance],
            permissions: vec![CustomPermission::new("billing", "*").unwrap()],
            claims: vec![Claim::new(
                ClaimName::new("department").unwrap(),
                ClaimValue::new("finance").unwrap(),
            )],
            ..SimulationInput::new()
        };
        let claim = |value: &str| PolicyCondition::ClaimEquals {
            name: ClaimName::new("department").unwrap(),
            value: ClaimValue::new(value).unwrap(),
        };
        let permission =
            |text: &str| PolicyCondition::PermissionHeld(CustomPermission::parse(text).unwrap());

        assert!(denies(PolicyCondition::GroupIs(finance), &input));
        assert!(!denies(PolicyCondition::GroupIs(GroupId::new()), &input));
        assert!(!denies(PolicyCondition::GroupIsNot(finance), &input));
        assert!(denies(permission("billing:read"), &input));
        assert!(!denies(permission("orders:read"), &input));
        assert!(denies(claim("finance"), &input));
        assert!(!denies(claim("sales"), &input));
    }

    /// A deny from outside the office range refuses a request from
    /// 203.0.113.9 and lets one from 10.1.2.3 through. A deny on the
    /// billing host refuses `BILLING.acme.test`, whatever its case.
    #[test]
    fn address_and_host_conditions_read_the_request() {
        let office = vec![CidrRange::new("10.0.0.0/8").unwrap()];
        let from = |ip: &str| SimulationInput {
            source_ip: Fact::Known(ip.parse().unwrap()),
            host: Fact::Known(HostName::new("BILLING.acme.test").unwrap()),
            ..SimulationInput::new()
        };
        let outside = PolicyCondition::SourceIpNotIn(office.clone());
        let billing = PolicyCondition::HostIn(vec![HostName::new("billing.acme.test").unwrap()]);

        assert!(denies(outside.clone(), &from("203.0.113.9")));
        assert!(!denies(outside, &from("10.1.2.3")));
        assert!(denies(
            PolicyCondition::SourceIpIn(office),
            &from("10.1.2.3")
        ));
        assert!(denies(billing, &from("10.1.2.3")));
    }

    /// A deny outside office hours in Berlin refuses a request at 20:00
    /// Berlin time and lets one at 09:00 through. A rule naming Tokyo, a
    /// zone the gateway gave no time for, refuses: nobody knows the time
    /// there.
    #[test]
    fn a_time_condition_reads_the_time_in_its_own_zone() {
        let berlin = Timezone::new("Europe/Berlin").unwrap();
        let night = TimeWindow::new(
            TimeOfDay::at(18, 0).unwrap(),
            TimeOfDay::at(8, 0).unwrap(),
            berlin.clone(),
        )
        .unwrap();
        let at = |hour| SimulationInput {
            local_times: vec![ZonedTime::new(
                berlin.clone(),
                TimeOfDay::at(hour, 0).unwrap(),
            )],
            ..SimulationInput::new()
        };
        let tokyo_night = TimeWindow::new(
            TimeOfDay::at(18, 0).unwrap(),
            TimeOfDay::at(8, 0).unwrap(),
            Timezone::new("Asia/Tokyo").unwrap(),
        )
        .unwrap();

        assert!(denies(PolicyCondition::TimeWithin(night.clone()), &at(20)));
        assert!(!denies(PolicyCondition::TimeWithin(night), &at(9)));
        assert!(denies(PolicyCondition::TimeWithin(tokyo_night), &at(9)));
    }
}
