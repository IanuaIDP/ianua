//! A tenant's policy set: its rules in order, and where the policy is in
//! its life from draft through review and active to archived.

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::events::policies::{
    PolicyActivated, PolicyArchived, PolicyDefaultActionChanged, PolicyDraftStarted,
    PolicyRejected, PolicyRuleAdded, PolicyRuleChanged, PolicyRuleRemoved, PolicyRuleSwitched,
    PolicyRulesReordered, PolicySimulated, PolicySubmittedForReview,
};
use crate::domains::authorization::permission::{PolicySetAction, SystemPermission};
use crate::domains::authorization::policy::action::PolicyAction;
use crate::domains::authorization::policy::review::{
    PolicyApprover, Submission, ensure_second_person,
};
use crate::domains::authorization::policy::rule::PolicyRule;
use crate::domains::authorization::policy::rule_list::RuleList;
use crate::domains::authorization::policy::simulator::{self, SimulationInput, SimulationResult};
use crate::domains::authorization::policy::status::PolicyStatus;
use crate::domains::authorization::policy::version::{
    DraftStart, PolicyHistory, PolicyVersion, Replacing, StartingPoint, VersionBase,
};
use crate::isolation::scope::ResolvedTenant;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::{Enablement, Label, Timezone};

/// One version of a tenant's access policy.
///
/// Rules are checked lowest priority first. A deny whose conditions all
/// match refuses the request wherever it sits. Otherwise the first matching
/// allow lets it through. If no allow or deny matches, the default action
/// applies.
///
/// A version moves from `Draft` to `Review` to `Active` to `Archived`. A
/// tenant has at most one live version and at most one open draft beside
/// it, which [`PolicyHistory`] keeps: the live version goes on deciding
/// requests while the next is written and reviewed. A draft cannot skip
/// review, so a mistake that locks everyone out is caught before it goes
/// live.
///
/// Rules and the default action change only while the version is a draft.
/// So a version under review, live or archived is never rewritten in place.
/// The next one starts from [`start_draft`](Self::start_draft).
///
/// Writing a draft and sending it to review need the right to update the
/// policy. Approving, rejecting and taking a live policy out of use need
/// the right to activate it. Sam may view the policy. Without these checks,
/// he takes the rule that asks admins for a second factor out of a draft,
/// approves it himself and puts it live.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "PolicySetWire"))]
pub struct PolicySet {
    /// The policy rules, kept in priority order.
    rules: RuleList,
    /// The action to take when no rule matches.
    default_action: PolicyAction,
    /// Current deployment status.
    status: PolicyStatus,
    /// Which version of the tenant's policy this is.
    version: PolicyVersion,
    /// What this version was started from.
    based_on: VersionBase,
    /// Who sent it to review, so someone else approves it.
    #[cfg_attr(feature = "serde", serde(default))]
    submitted: Submission,
    /// What the policy raised since it was last saved. A policy is not typed
    /// by its tenant, so the scope here only marks the plane: each event
    /// takes the tenant it is saved for.
    #[cfg_attr(feature = "serde", serde(skip))]
    raised: Raised<ResolvedTenant>,
}

/// A policy set as it arrives, before its rules are put in priority order.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct PolicySetWire {
    rules: Vec<PolicyRule>,
    default_action: PolicyAction,
    status: PolicyStatus,
    version: PolicyVersion,
    based_on: VersionBase,
    #[serde(default)]
    submitted: Submission,
}

#[cfg(feature = "serde")]
impl TryFrom<PolicySetWire> for PolicySet {
    type Error = DomainError;

    /// Reads a policy written out whole through [`PolicySet::reconstitute`],
    /// so it is held to the same rules as a stored row.
    fn try_from(wire: PolicySetWire) -> Result<Self, Self::Error> {
        Self::reconstitute(PolicySetRow {
            rules: wire.rules,
            default_action: wire.default_action,
            status: wire.status,
            version: wire.version,
            based_on: wire.based_on,
            submitted: wire.submitted,
        })
    }
}

/// A [`PolicySet`] as storage holds it, read back through
/// [`PolicySet::reconstitute`].
pub struct PolicySetRow {
    /// The rules, in any order.
    pub rules: Vec<PolicyRule>,
    /// The action to take when no rule matches.
    pub default_action: PolicyAction,
    /// Where the version is in its life.
    pub status: PolicyStatus,
    /// Which version of the tenant's policy it is.
    pub version: PolicyVersion,
    /// What it was started from.
    pub based_on: VersionBase,
    /// Who sent it to review, or that nobody has.
    pub submitted: Submission,
}

impl PolicySet {
    /// Rebuilds a version from storage, its rules put in priority order
    /// whatever order they were written in. Rules of equal priority keep
    /// their written order.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when two rules share a name. Rules
    ///   are found, removed and audited by name.
    /// - [`DomainError::Infrastructure`] when it is in review and nobody
    ///   sent it.
    /// - [`DomainError::Infrastructure`] when it claims to start from
    ///   itself or a later version.
    pub fn reconstitute(row: PolicySetRow) -> Result<Self, DomainError> {
        RowCheck::of("policy set")
            .holds(
                row.status != PolicyStatus::Review || row.submitted != Submission::NotSubmitted,
                "in review with nobody who sent it",
            )
            .holds(
                row.based_on.comes_before(row.version),
                "started from itself or a later version",
            )
            .finish()?;
        Ok(Self {
            rules: RuleList::stored(row.rules)?,
            default_action: row.default_action,
            status: row.status,
            version: row.version,
            based_on: row.based_on,
            submitted: row.submitted,
            raised: Raised::default(),
        })
    }

    /// The first version of a policy, as an empty draft, for tests that
    /// build a policy rule by rule.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub(crate) fn new(default_action: PolicyAction) -> Self {
        Self::drafted(
            RuleList::default(),
            default_action,
            PolicyVersion::FIRST,
            VersionBase::Blank,
        )
    }

    /// A draft numbered `version`, started from `based_on`.
    fn drafted(
        rules: RuleList,
        default_action: PolicyAction,
        version: PolicyVersion,
        based_on: VersionBase,
    ) -> Self {
        Self {
            rules,
            default_action,
            status: PolicyStatus::Draft,
            version,
            based_on,
            submitted: Submission::NotSubmitted,
            raised: Raised::default(),
        }
    }

    /// A draft policy with no rules that allows by default.
    ///
    /// Only for tests. A test adds rules to it. Production code should never
    /// start from a policy that allows everything.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn permissive() -> Self {
        Self::new(PolicyAction::Allow)
    }

    /// The rules in priority order.
    #[must_use]
    pub fn rules(&self) -> &[PolicyRule] {
        self.rules.as_slice()
    }

    /// The fallback action when no rule matches.
    #[must_use]
    pub fn default_action(&self) -> &PolicyAction {
        &self.default_action
    }

    /// Current deployment status.
    #[must_use]
    pub fn status(&self) -> PolicyStatus {
        self.status
    }

    /// Which version of the tenant's policy this is.
    #[must_use]
    pub fn version(&self) -> PolicyVersion {
        self.version
    }

    /// What this version was started from.
    #[must_use]
    pub fn based_on(&self) -> VersionBase {
        self.based_on
    }

    /// Number of rules in the set.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.as_slice().len()
    }

    /// Finds a rule by name.
    #[must_use]
    pub fn find_rule(&self, name: &Label) -> Option<&PolicyRule> {
        self.rules.find(name)
    }

    /// Every timezone a rule reads the time in, each once. The gateway
    /// works out the request's local time in each, since the domain holds
    /// no timezone database.
    #[must_use]
    pub fn timezones(&self) -> Vec<&Timezone> {
        let mut zones: Vec<&Timezone> = self
            .rules()
            .iter()
            .flat_map(PolicyRule::conditions)
            .filter_map(|condition| condition.timezone())
            .collect();
        zones.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        zones.dedup();
        zones
    }

    /// Adds a rule among the rules of its priority, behind those already
    /// there. Raises `authorization.policy_rule_added`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if `editor` may not update the policy.
    /// - [`DomainError::Conflict`] if the policy is not a draft.
    /// - [`DomainError::Conflict`] if it already has a rule of that name.
    ///   Rules are found, removed and audited by name, so two alike could not
    ///   be told apart.
    /// - [`DomainError::Validation`] if it already holds a thousand rules.
    pub fn add_rule(
        &mut self,
        rule: PolicyRule,
        editor: &TenantAuthority,
    ) -> Result<(), DomainError> {
        self.ensure_editable_by(editor)?;
        let added = PolicyRuleAdded {
            rule_name: rule.name().clone(),
            priority: rule.priority(),
            occurred_at: crate::shared::clock::now(),
        };
        self.rules.add(rule)?;
        self.raised.raise(added);
        Ok(())
    }

    /// Removes a rule by name. Raises `authorization.policy_rule_removed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if `editor` may not update the policy.
    /// - [`DomainError::Conflict`] if the policy is not a draft.
    /// - [`DomainError::NotFound`] if it has no rule of that name. Removing
    ///   nothing and recording a removal would leave an audit trail that
    ///   lies about the policy.
    pub fn remove_rule(
        &mut self,
        name: &Label,
        editor: &TenantAuthority,
    ) -> Result<(), DomainError> {
        self.ensure_editable_by(editor)?;
        self.rules.remove(name)?;
        self.raised.raise(PolicyRuleRemoved {
            rule_name: name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Turns the rule named `name` on or off, where it stands. A disabled
    /// rule is skipped when requests are checked but kept for editing.
    /// Raises `authorization.policy_rule_switched`.
    ///
    /// The rule keeps its place among rules of the same priority. Taking it
    /// out and adding it back would move it behind them, and the first
    /// matching rule of a priority decides: a rule asking for a second
    /// factor could end up behind one that allows.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if `editor` may not update the policy.
    /// - [`DomainError::Conflict`] if the policy is not a draft.
    /// - [`DomainError::NotFound`] if it has no rule of that name.
    pub fn switch_rule(
        &mut self,
        name: &Label,
        to: Enablement,
        editor: &TenantAuthority,
    ) -> Result<(), DomainError> {
        self.ensure_editable_by(editor)?;
        self.rules.switch(name, to)?;
        self.raised.raise(PolicyRuleSwitched {
            rule_name: name.clone(),
            to,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Rewrites the rule named `name` as `rule`, where it stands and on or
    /// off as it was. Raises `authorization.policy_rule_changed` with the
    /// name before and after.
    ///
    /// Taking the rule out and adding it back would move it behind its
    /// equals, for the reason [`switch_rule`](Self::switch_rule) gives.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if `editor` may not update the policy.
    /// - [`DomainError::Conflict`] if the policy is not a draft.
    /// - [`DomainError::NotFound`] if it has no rule of that name.
    /// - [`DomainError::Conflict`] if `rule` takes another rule's name.
    pub fn change_rule(
        &mut self,
        name: &Label,
        rule: PolicyRule,
        editor: &TenantAuthority,
    ) -> Result<(), DomainError> {
        self.ensure_editable_by(editor)?;
        let changed = PolicyRuleChanged {
            previous_name: name.clone(),
            rule_name: rule.name().clone(),
            priority: rule.priority(),
            occurred_at: crate::shared::clock::now(),
        };
        self.rules.replace(name, rule)?;
        self.raised.raise(changed);
        Ok(())
    }

    /// Puts the rules in the order `order` names them, ten priority steps
    /// apart. Raises `authorization.policy_rules_reordered` with the order.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if `editor` may not update the policy.
    /// - [`DomainError::Conflict`] if the policy is not a draft.
    /// - [`DomainError::Validation`] if `order` does not name every rule
    ///   exactly once.
    pub fn reorder_rules(
        &mut self,
        order: &[Label],
        editor: &TenantAuthority,
    ) -> Result<(), DomainError> {
        self.ensure_editable_by(editor)?;
        self.rules.reorder(order)?;
        self.raised.raise(PolicyRulesReordered {
            order: order.to_vec(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Opens a new draft of the tenant's policy, for `editor`, numbered one
    /// past the highest version in `history`. Raises
    /// `authorization.policy_draft_started` on the draft.
    ///
    /// The live version, if any, goes on deciding requests until the draft
    /// is approved. Only one draft is open at a time: two drafts racing to
    /// replace one policy would each undo the other's review.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if `editor` may not update the policy.
    /// - [`DomainError::Conflict`] if a draft is open, being written or in
    ///   review.
    /// - The cases [`PolicyHistory`] lists for what `start` copies: nothing
    ///   live to copy, or a version to restore that is missing or in use.
    pub fn start_draft(
        history: &PolicyHistory<'_>,
        start: DraftStart,
        editor: &TenantAuthority,
    ) -> Result<Self, DomainError> {
        editor.ensure_holds(SystemPermission::PolicySet(PolicySetAction::Update))?;
        history.ensure_no_open_draft()?;
        let version = history.next_number()?;
        let mut draft = match history.starting_point(start)? {
            StartingPoint::Blank(action) => {
                Self::drafted(RuleList::default(), action, version, VersionBase::Blank)
            }
            StartingPoint::Copy(source, based_on) => Self::drafted(
                source.rules.clone(),
                source.default_action.clone(),
                version,
                based_on,
            ),
        };
        draft.raised.raise(PolicyDraftStarted {
            rule_count: draft.rule_count(),
            version,
            based_on: draft.based_on,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(draft)
    }

    /// Sets the default action. Raises
    /// `authorization.policy_default_action_changed` with the action before
    /// and after.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if `editor` may not update the policy.
    /// - [`DomainError::Conflict`] if the policy is not a draft.
    pub fn change_default_action(
        &mut self,
        action: PolicyAction,
        editor: &TenantAuthority,
    ) -> Result<(), DomainError> {
        self.ensure_editable_by(editor)?;
        let previous = std::mem::replace(&mut self.default_action, action);
        self.raised.raise(PolicyDefaultActionChanged {
            previous,
            current: self.default_action.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    fn ensure_editable_by(&self, editor: &TenantAuthority) -> Result<(), DomainError> {
        editor.ensure_holds(SystemPermission::PolicySet(PolicySetAction::Update))?;
        if !self.status.is_editable() {
            return Err(DomainError::conflict(message!(
                "authorization-this-policy-is-and-cannot-be",
                format!("this policy is {} and cannot be edited", self.status)
            )));
        }
        Ok(())
    }

    /// Submits the policy for review, for the person `by` names, who is
    /// recorded as its submitter. Raises
    /// `authorization.policy_submitted_for_review`.
    ///
    /// The submitter comes from who is signed in, never from the request.
    /// Sam writes a policy and names Bob as its submitter. He could then
    /// approve it himself, as the second person.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if `by` may not update the policy.
    /// - [`DomainError::InvalidTransition`] if the policy is not a draft.
    pub fn submit_for_review(&mut self, by: &TenantAuthority) -> Result<(), DomainError> {
        self.move_to(PolicyStatus::Review, by, PolicySetAction::Update)?;
        self.submitted = Submission::By(by.who().clone());
        self.raised.raise(PolicySubmittedForReview {
            rule_count: self.rule_count(),
            version: self.version,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Approves and activates the policy, for `approver`, in place of the
    /// version `replacing` names, which becomes a past version. Raises
    /// `authorization.policy_archived` for the version replaced, then
    /// `authorization.policy_activated`, both on this version: the approval
    /// is one change, recorded by the version that went live.
    ///
    /// Someone other than the person who sent it to review approves it,
    /// whenever the tenant has such a person. Another account of the same
    /// person is not someone else. A tenant with a single admin approves its
    /// own.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if `approver` may not activate the policy.
    /// - [`DomainError::Forbidden`] if `approver` sent it to review, through
    ///   any of their accounts, and someone else could approve it.
    /// - [`DomainError::InvalidTransition`] if the policy is not in review.
    /// - [`DomainError::Conflict`] if the version replaced is not live, or
    ///   is not older than this one.
    pub fn activate(
        &mut self,
        replacing: Replacing<'_>,
        approver: &PolicyApprover<'_>,
    ) -> Result<(), DomainError> {
        ensure_second_person(&self.submitted, approver)?;
        approver
            .authority()
            .ensure_holds(SystemPermission::PolicySet(PolicySetAction::Activate))?;
        let status = self.status.try_transition(PolicyStatus::Active)?;
        if let Replacing::Live(live) = replacing {
            live.supersede_with(self.version)?;
            self.raised.raise(PolicyArchived {
                version: live.version,
                occurred_at: crate::shared::clock::now(),
            });
        }
        self.status = status;
        self.raised.raise(PolicyActivated {
            rule_count: self.rule_count(),
            version: self.version,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Moves this live version out of use for `newer`, which goes live in
    /// its place and records the move.
    fn supersede_with(&mut self, newer: PolicyVersion) -> Result<(), DomainError> {
        if !self.status.is_active() || self.version >= newer {
            return Err(DomainError::conflict(message!(
                "authorization-version-is-and-is-not-replaced",
                format!(
                    "version {} is {} and is not replaced by version {newer}",
                    self.version, self.status
                )
            )));
        }
        self.status = self.status.try_transition(PolicyStatus::Archived)?;
        Ok(())
    }

    /// Who sent the policy to review, or that nobody has yet.
    #[must_use]
    pub fn submitted(&self) -> &Submission {
        &self.submitted
    }

    /// Rejects the policy and sends it back to draft, for `approver`. Raises
    /// `authorization.policy_rejected`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if `approver` may not activate the policy.
    /// - [`DomainError::InvalidTransition`] if the policy is not in review.
    pub fn reject(&mut self, approver: &TenantAuthority) -> Result<(), DomainError> {
        self.move_to(PolicyStatus::Draft, approver, PolicySetAction::Activate)?;
        self.submitted = Submission::NotSubmitted;
        self.raised.raise(PolicyRejected {
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Archives the policy, because it is taken out of use or abandoned as a
    /// draft. Raises `authorization.policy_archived`.
    ///
    /// Archiving the live policy stops it deciding requests, so it needs the
    /// right to activate. Abandoning a draft needs the right to update.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if `by` lacks the right this needs.
    /// - [`DomainError::InvalidTransition`] if the policy is in review or
    ///   already archived.
    pub fn archive(&mut self, by: &TenantAuthority) -> Result<(), DomainError> {
        let needed = match self.status {
            PolicyStatus::Active => PolicySetAction::Activate,
            PolicyStatus::Draft | PolicyStatus::Review | PolicyStatus::Archived => {
                PolicySetAction::Update
            }
        };
        self.move_to(PolicyStatus::Archived, by, needed)?;
        self.raised.raise(PolicyArchived {
            version: self.version,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// How this policy decides `input`, a request that is never made, for
    /// `viewer`. Raises `authorization.policy_simulated` with what was tried
    /// and how it was decided; the policy itself does not change.
    ///
    /// Any version is simulated, whatever its status: a draft and one in
    /// review are what an admin most wants to try before they go live.
    ///
    /// Every run is recorded: many in a row can be someone probing for a
    /// way past the policy.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] if `viewer` may not view the policy.
    pub fn simulate(
        &mut self,
        input: &SimulationInput,
        viewer: &TenantAuthority,
    ) -> Result<SimulationResult, DomainError> {
        viewer.ensure_holds(SystemPermission::PolicySet(PolicySetAction::View))?;
        let result = simulator::simulate(self, input);
        self.raised.raise(PolicySimulated {
            simulated_path: input.recorded_path(),
            result_allowed: result.is_allowed().into(),
            matched_rule: result.matched_rule().cloned(),
            version: self.version,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(result)
    }

    /// Moves to `to` for `by`, who must hold the policy right `needed`,
    /// through their roles or an active break-glass grant.
    fn move_to(
        &mut self,
        to: PolicyStatus,
        by: &TenantAuthority,
        needed: PolicySetAction,
    ) -> Result<(), DomainError> {
        by.ensure_holds(SystemPermission::PolicySet(needed))?;
        self.status = self.status.try_transition(to)?;
        Ok(())
    }
}

impl Raises for PolicySet {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::policy::condition::PolicyCondition;
    use crate::domains::authorization::policy::review::OtherApprovers;
    use crate::domains::authorization::policy::time_window::{TimeOfDay, TimeWindow};
    use crate::shared::events::data::FieldValue;
    use crate::test_support::authority::{anyone_holding, assumed_authority};
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{Human, HumanAccount, OrgUserId, PathPrefix, PersonKey, TenantId, UserId};

    fn label(name: &str) -> Label {
        Label::new("rule_name", name).unwrap()
    }

    fn rule(name: &str, priority: u16) -> PolicyRule {
        PolicyRule::new(
            label(name),
            vec![PolicyCondition::PathPrefix(
                PathPrefix::new("/admin").unwrap(),
            )],
            PolicyAction::Deny {
                reason: crate::types::Text::new("reason", "blocked").unwrap(),
            },
            priority,
        )
        .unwrap()
    }

    fn deny_all() -> PolicyAction {
        PolicyAction::Deny {
            reason: crate::types::Text::new("reason", "closed by default").unwrap(),
        }
    }

    /// The tenant user numbered `n`.
    fn user(n: u128) -> UserId {
        UserId::from_uuid(uuid::Uuid::from_u128(n))
    }

    /// The person who writes and submits the test policies, through their
    /// tenant account.
    fn author() -> Human {
        Human::new(
            HumanAccount::User(user(21)),
            PersonKey::new("user21@acme.test").unwrap(),
        )
    }

    /// The author, signed in, holding `system`.
    fn submitting(system: &[SystemPermission]) -> &'static TenantAuthority {
        assumed_authority(&author(), TenantId::new(), system, &[])
    }

    /// User `n` approving with `system`, while others could too.
    fn approving_as(n: u128, system: &[SystemPermission]) -> PolicyApprover<'static> {
        let who = Human::new(
            HumanAccount::User(user(n)),
            PersonKey::new(format!("user{n}@acme.test")).unwrap(),
        );
        let authority = assumed_authority(&who, TenantId::new(), system, &[]);
        PolicyApprover::assumed(authority, OtherApprovers::Exist)
    }

    /// A second person approving with `system`, while others could too.
    fn reviewer(system: &[SystemPermission]) -> PolicyApprover<'static> {
        approving_as(22, system)
    }

    const MANAGES: &[SystemPermission] = &[SystemPermission::ManagePolicy];

    /// Ann, who may manage the policy.
    fn ann() -> &'static TenantAuthority {
        anyone_holding(MANAGES)
    }

    fn in_review() -> PolicySet {
        let mut policy = PolicySet::permissive();
        policy.add_rule(rule("block-admin", 10), ann()).unwrap();
        policy.submit_for_review(submitting(MANAGES)).unwrap();
        policy
    }

    fn active() -> PolicySet {
        let mut policy = in_review();
        policy
            .activate(Replacing::NothingLive, &reviewer(MANAGES))
            .unwrap();
        policy
    }

    fn history(versions: &[PolicySet]) -> PolicyHistory<'_> {
        PolicyHistory::of(versions).unwrap()
    }

    /// The draft that follows the live version in `versions`, sent to
    /// review.
    fn next_in_review(versions: &[PolicySet]) -> PolicySet {
        let mut next =
            PolicySet::start_draft(&history(versions), DraftStart::FromLive, ann()).unwrap();
        next.submit_for_review(submitting(MANAGES)).unwrap();
        next
    }

    fn rule_names(policy: &PolicySet) -> Vec<&str> {
        policy.rules().iter().map(|r| r.name().as_str()).collect()
    }

    /// Viewing authority cannot remove a draft rule, submit a draft or approve
    /// a policy in review. Each attempt is forbidden; the draft retains its
    /// rule and the policy awaiting approval stays in review.
    #[test]
    fn changing_a_policy_needs_the_policy_rights() {
        let viewing = [SystemPermission::PolicySet(PolicySetAction::View)];
        let mut draft = PolicySet::permissive();
        draft.add_rule(rule("block-admin", 10), ann()).unwrap();
        let mut reviewed = in_review();

        let removed = draft.remove_rule(&label("block-admin"), anyone_holding(&viewing));
        let submitted = draft.submit_for_review(submitting(&viewing));
        let approved = reviewed.activate(Replacing::NothingLive, &reviewer(&viewing));

        for refused in [removed, submitted, approved] {
            assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        }
        assert_eq!(rule_names(&draft), ["block-admin"]);
        assert_eq!(reviewed.status(), PolicyStatus::Review);
    }

    /// Update authority cannot activate a policy in review or archive a live
    /// one. The live version stays active, while archiving a draft succeeds.
    #[test]
    fn putting_a_policy_live_or_out_of_use_needs_the_right_to_activate() {
        let writing = [SystemPermission::PolicySet(PolicySetAction::Update)];
        let bob = anyone_holding(&writing);
        let mut reviewed = in_review();
        let mut live = active();
        let mut draft = PolicySet::permissive();

        let approved = reviewed.activate(Replacing::NothingLive, &reviewer(&writing));
        let switched_off = live.archive(bob);

        assert!(matches!(approved, Err(DomainError::Forbidden(_))));
        assert!(matches!(switched_off, Err(DomainError::Forbidden(_))));
        assert_eq!(live.status(), PolicyStatus::Active);
        assert!(draft.archive(bob).is_ok());
    }

    /// Ann holds "manage policy" only through a break-glass grant during an
    /// incident. Changing a policy needs only the right, not handing it
    /// out. So she adds a rule to a draft, approves it once its author sent
    /// it to review, and archives the old policy.
    #[test]
    fn a_break_glass_grant_counts_for_changing_a_policy() {
        let incident = TenantAuthority::in_emergency(MANAGES);
        let mut draft = PolicySet::permissive();
        let mut old = active();

        draft.add_rule(rule("block-admin", 10), incident).unwrap();
        draft.submit_for_review(submitting(MANAGES)).unwrap();
        draft
            .activate(
                Replacing::NothingLive,
                &PolicyApprover::assumed(incident, OtherApprovers::Exist),
            )
            .unwrap();
        old.archive(incident).unwrap();

        assert_eq!(draft.status(), PolicyStatus::Active);
        assert_eq!(old.status(), PolicyStatus::Archived);
    }

    /// An emergency grant limited to viewing cannot reject a policy in review.
    /// The refusal leaves that policy in review.
    #[test]
    fn a_break_glass_grant_gives_only_the_rights_it_names() {
        let viewing = [SystemPermission::PolicySet(PolicySetAction::View)];
        let mut reviewed = in_review();

        let rejected = reviewed.reject(TenantAuthority::in_emergency(&viewing));

        assert!(matches!(rejected, Err(DomainError::Forbidden(_))));
        assert_eq!(reviewed.status(), PolicyStatus::Review);
    }

    /// Ann opens a draft while the tenant has no policy. It is version 1,
    /// started blank.
    #[test]
    fn the_first_draft_is_version_one() {
        let draft =
            PolicySet::start_draft(&history(&[]), DraftStart::Blank(PolicyAction::Allow), ann())
                .unwrap();

        assert_eq!(draft.status(), PolicyStatus::Draft);
        assert_eq!(draft.version(), PolicyVersion::FIRST);
        assert_eq!(draft.based_on(), VersionBase::Blank);
    }

    /// Version 1 is live. Ann opens the next draft from it: version 2, with
    /// its rules, while version 1 stays live and keeps deciding requests.
    #[test]
    fn a_draft_opens_beside_the_live_version() {
        let versions = [active()];

        let draft =
            PolicySet::start_draft(&history(&versions), DraftStart::FromLive, ann()).unwrap();

        assert_eq!(draft.version().number(), 2);
        assert_eq!(draft.based_on(), VersionBase::CopyOf(PolicyVersion::FIRST));
        assert_eq!(rule_names(&draft), ["block-admin"]);
        assert_eq!(versions[0].status(), PolicyStatus::Active);
    }

    /// A reviewer approves version 2 in place of live version 1. Version 2
    /// goes live and version 1 becomes a past version. Version 2 records
    /// both, version 1's archiving first; version 1 records nothing of its
    /// own.
    #[test]
    fn approving_the_draft_makes_the_live_version_a_past_one() {
        let mut live = active();
        raised_names(&mut live);
        let mut next = next_in_review(std::slice::from_ref(&live));
        raised_names(&mut next);

        next.activate(Replacing::Live(&mut live), &reviewer(MANAGES))
            .unwrap();

        assert_eq!(next.status(), PolicyStatus::Active);
        assert_eq!(live.status(), PolicyStatus::Archived);
        let recorded = raised(&mut next);
        let names: Vec<String> = recorded
            .iter()
            .map(|event| event.event_type().to_string())
            .collect();
        assert_eq!(
            names,
            [
                "authorization.policy_archived",
                "authorization.policy_activated"
            ]
        );
        assert_eq!(recorded[0].payload().get("version"), Some("1"));
        assert!(raised_names(&mut live).is_empty());
    }

    /// Activation cannot replace an archived version. It returns a conflict,
    /// leaving the proposed policy in review and the archived version archived.
    #[test]
    fn a_draft_replaces_only_an_older_live_version() {
        let mut past = active();
        past.archive(ann()).unwrap();
        let mut draft = in_review();

        let refused = draft.activate(Replacing::Live(&mut past), &reviewer(MANAGES));

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert_eq!(draft.status(), PolicyStatus::Review);
        assert_eq!(past.status(), PolicyStatus::Archived);
    }

    /// With a live version and a second version in review, opening another
    /// draft from the live version returns a conflict.
    #[test]
    fn a_second_open_draft_is_refused() {
        let live = active();
        let open = next_in_review(std::slice::from_ref(&live));
        let versions = [live, open];

        let refused = PolicySet::start_draft(&history(&versions), DraftStart::FromLive, ann());

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
    }

    /// Version 1 was replaced by version 2. Ann restores version 1: a new
    /// draft, version 3, with version 1's rules, recorded as restored from
    /// it.
    #[test]
    fn a_past_version_is_restored_as_a_new_draft() {
        let mut first = active();
        let mut second = next_in_review(std::slice::from_ref(&first));
        second
            .activate(Replacing::Live(&mut first), &reviewer(MANAGES))
            .unwrap();
        let versions = [first, second];

        let restored = PolicySet::start_draft(
            &history(&versions),
            DraftStart::Restore(PolicyVersion::FIRST),
            ann(),
        )
        .unwrap();

        assert_eq!(restored.version().number(), 3);
        assert_eq!(
            restored.based_on(),
            VersionBase::RestoredFrom(PolicyVersion::FIRST)
        );
        assert_eq!(rule_names(&restored), ["block-admin"]);
    }

    /// Ann restores the live version, and a version the tenant never had.
    /// The first is in use already and the second is not found.
    #[test]
    fn only_a_past_version_is_restored() {
        let versions = [active()];
        let tenant = history(&versions);

        let live =
            PolicySet::start_draft(&tenant, DraftStart::Restore(PolicyVersion::FIRST), ann());
        let missing = PolicySet::start_draft(
            &tenant,
            DraftStart::Restore(PolicyVersion::parse(9).unwrap()),
            ann(),
        );

        assert!(matches!(live, Err(DomainError::Conflict(_))));
        assert!(matches!(missing, Err(DomainError::NotFound)));
    }

    /// Nothing is live, so there is nothing to copy the next draft from.
    #[test]
    fn copying_the_live_version_needs_one() {
        let refused = PolicySet::start_draft(&history(&[]), DraftStart::FromLive, ann());

        assert!(matches!(refused, Err(DomainError::NotFound)));
    }

    /// Reading policy history containing two active versions returns an
    /// infrastructure error.
    #[test]
    fn a_history_with_two_live_versions_is_refused() {
        let mut second = active();
        let mut versions = vec![active()];
        second.version = PolicyVersion::parse(2).unwrap();
        versions.push(second);

        assert!(matches!(
            PolicyHistory::of(&versions),
            Err(DomainError::Infrastructure(_))
        ));
    }

    /// Viewing authority cannot open a blank draft, even when the tenant has
    /// no policy history.
    #[test]
    fn opening_a_draft_needs_the_right_to_update_the_policy() {
        let viewing = [SystemPermission::PolicySet(PolicySetAction::View)];

        let refused = PolicySet::start_draft(
            &history(&[]),
            DraftStart::Blank(PolicyAction::Allow),
            anyone_holding(&viewing),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Ann tries her draft and the version in review before either goes
    /// live. Both are simulated, and the result names the version tried.
    #[test]
    fn a_draft_and_a_version_in_review_are_simulated() {
        let mut draft = PolicySet::permissive();
        draft.add_rule(rule("block-admin", 10), ann()).unwrap();
        let mut reviewed = in_review();
        let input = SimulationInput {
            path: crate::types::Fact::Known(crate::types::CanonicalPath::new("/admin").unwrap()),
            ..SimulationInput::new()
        };

        let tried = draft.simulate(&input, ann()).unwrap();
        let reviewing = reviewed.simulate(&input, ann()).unwrap();

        assert!(tried.is_denied());
        assert!(reviewing.is_denied());
        assert_eq!(tried.policy_version(), PolicyVersion::FIRST);
    }

    /// Removing the misspelled rule name "block-admni" returns not found and
    /// leaves the existing "block-admin" rule in the draft.
    #[test]
    fn removing_a_rule_that_is_not_there_is_refused() {
        let mut policy = PolicySet::permissive();
        policy.add_rule(rule("block-admin", 10), ann()).unwrap();

        let refused = policy.remove_rule(&label("block-admni"), ann());

        assert!(matches!(refused, Err(DomainError::NotFound)));
        assert_eq!(rule_names(&policy), ["block-admin"]);
    }

    /// Ann turns "require-mfa" off and on again. It stays ahead of the
    /// "allow-office" rule of the same priority throughout, so switching it
    /// never lets the allow decide first.
    #[test]
    fn switching_a_rule_keeps_its_place_among_equals() {
        let mut policy = PolicySet::permissive();
        policy.add_rule(rule("require-mfa", 10), ann()).unwrap();
        policy.add_rule(rule("allow-office", 10), ann()).unwrap();

        policy
            .switch_rule(&label("require-mfa"), Enablement::Disabled, ann())
            .unwrap();
        assert!(!policy.find_rule(&label("require-mfa")).unwrap().enabled());
        policy
            .switch_rule(&label("require-mfa"), Enablement::Enabled, ann())
            .unwrap();

        assert!(policy.find_rule(&label("require-mfa")).unwrap().enabled());
        assert_eq!(rule_names(&policy), ["require-mfa", "allow-office"]);
    }

    /// Switching a live policy's rule returns a conflict. Switching a name
    /// absent from a draft returns not found.
    #[test]
    fn a_rule_is_switched_only_in_a_draft_and_only_if_it_exists() {
        let mut live = active();
        let mut draft = PolicySet::permissive();

        let on_live = live.switch_rule(&label("block-admin"), Enablement::Disabled, ann());
        let unknown = draft.switch_rule(&label("nothing"), Enablement::Disabled, ann());

        assert!(matches!(on_live, Err(DomainError::Conflict(_))));
        assert!(matches!(unknown, Err(DomainError::NotFound)));
    }

    /// Ann rewrites "block-admin" in place as "block-admin-pages" and puts
    /// the rules in a new order. Each change is raised.
    #[test]
    fn a_draft_rule_is_rewritten_and_the_rules_reordered() {
        let mut draft = PolicySet::permissive();
        draft.add_rule(rule("block-admin", 10), ann()).unwrap();
        draft.add_rule(rule("block-billing", 20), ann()).unwrap();
        raised_names(&mut draft);

        draft
            .change_rule(&label("block-admin"), rule("block-admin-pages", 10), ann())
            .unwrap();
        draft
            .reorder_rules(&[label("block-billing"), label("block-admin-pages")], ann())
            .unwrap();

        assert_eq!(rule_names(&draft), ["block-billing", "block-admin-pages"]);
        assert_eq!(
            raised_names(&mut draft),
            [
                "authorization.policy_rule_changed",
                "authorization.policy_rules_reordered",
            ]
        );
    }

    /// Rewriting or reordering live policy rules returns a conflict. The same
    /// operations on a draft are forbidden when the caller can only view policies.
    #[test]
    fn rules_are_rewritten_and_reordered_only_in_a_draft_by_an_editor() {
        let mut live = active();
        let mut draft = PolicySet::permissive();
        draft.add_rule(rule("block-admin", 10), ann()).unwrap();
        let viewer = anyone_holding(&[SystemPermission::PolicySet(PolicySetAction::View)]);

        let rewritten = live.change_rule(&label("block-admin"), rule("block-admin", 1), ann());
        let reordered = live.reorder_rules(&[label("block-admin")], ann());
        let by_viewer = draft.change_rule(&label("block-admin"), rule("block-admin", 1), viewer);
        let reordered_by_viewer = draft.reorder_rules(&[label("block-admin")], viewer);

        assert!(matches!(rewritten, Err(DomainError::Conflict(_))));
        assert!(matches!(reordered, Err(DomainError::Conflict(_))));
        assert!(matches!(by_viewer, Err(DomainError::Forbidden(_))));
        assert!(matches!(
            reordered_by_viewer,
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A rule reads the time in Berlin and another in Tokyo. The policy
    /// names both zones once each, for the gateway to read the clock in.
    #[test]
    fn a_policy_names_each_timezone_its_rules_read() {
        let window = |zone: &str| {
            PolicyCondition::TimeWithin(
                TimeWindow::new(
                    TimeOfDay::at(8, 0).unwrap(),
                    TimeOfDay::at(18, 0).unwrap(),
                    Timezone::new(zone).unwrap(),
                )
                .unwrap(),
            )
        };
        let mut policy = PolicySet::permissive();
        for (name, zone) in [
            ("a", "Europe/Berlin"),
            ("b", "Asia/Tokyo"),
            ("c", "Europe/Berlin"),
        ] {
            let timed =
                PolicyRule::new(label(name), vec![window(zone)], PolicyAction::Allow, 1).unwrap();
            policy.add_rule(timed, ann()).unwrap();
        }

        let zones: Vec<&str> = policy.timezones().iter().map(|z| z.as_str()).collect();

        assert_eq!(zones, ["Asia/Tokyo", "Europe/Berlin"]);
    }

    /// An admin adds a rule at priority 30, then two at priority 10. They are
    /// kept lowest first, with the two ties in the order added.
    #[test]
    fn rules_are_kept_in_priority_order_whatever_order_they_are_added_in() {
        let mut policy = PolicySet::permissive();
        policy.add_rule(rule("late", 30), ann()).unwrap();
        policy.add_rule(rule("first-tie", 10), ann()).unwrap();
        policy.add_rule(rule("second-tie", 10), ann()).unwrap();

        assert_eq!(rule_names(&policy), ["first-tie", "second-tie", "late"]);
    }

    /// A tenant changes a draft's default from allow to deny. The policy then
    /// denies every request no rule matches.
    #[test]
    fn changing_the_default_action_takes_effect() {
        let mut policy = PolicySet::permissive();
        assert!(policy.default_action().is_allow());

        policy.change_default_action(deny_all(), ann()).unwrap();

        assert!(policy.default_action().is_deny());
    }

    /// Adding a rule to a policy in review or active use returns a conflict. Both
    /// policies retain only their existing "block-admin" rule.
    #[test]
    fn a_rule_cannot_be_added_to_a_policy_in_review_or_live() {
        for mut policy in [in_review(), active()] {
            let refused = policy.add_rule(rule("sneaked-in", 1), ann());

            assert!(matches!(refused, Err(DomainError::Conflict(_))));
            assert_eq!(rule_names(&policy), ["block-admin"]);
        }
    }

    /// Removing "block-admin" from an active policy returns a conflict and
    /// leaves the rule in place.
    #[test]
    fn a_rule_cannot_be_removed_from_an_active_policy() {
        let mut policy = active();

        let refused = policy.remove_rule(&label("block-admin"), ann());

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert_eq!(rule_names(&policy), ["block-admin"]);
    }

    /// An admin changes the default of a policy in review, then of a live
    /// one. Both are refused and the default stays allow, so no unmatched
    /// request changes outcome without a review.
    #[test]
    fn the_default_action_cannot_change_in_review_or_while_active() {
        for mut policy in [in_review(), active()] {
            let refused = policy.change_default_action(deny_all(), ann());

            assert!(matches!(refused, Err(DomainError::Conflict(_))));
            assert!(policy.default_action().is_allow());
        }
    }

    /// A stored policy lists its rules in reverse priority order. It reads
    /// back lowest priority first, so a deny never lands behind the allow it
    /// overrides.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_policy_reads_back_with_its_rules_in_priority_order() {
        let mut policy = PolicySet::permissive();
        policy.add_rule(rule("first", 1), ann()).unwrap();
        policy.add_rule(rule("second", 2), ann()).unwrap();
        let mut json = serde_json::to_value(&policy).unwrap();
        json["rules"].as_array_mut().unwrap().reverse();

        let read: PolicySet = serde_json::from_value(json).unwrap();

        assert_eq!(rule_names(&read), ["first", "second"]);
    }

    /// Adding a second "block-admin" rule at another priority returns a
    /// conflict and leaves the draft with one rule.
    #[test]
    fn a_second_rule_of_the_same_name_is_refused() {
        let mut policy = PolicySet::permissive();
        policy.add_rule(rule("block-admin", 10), ann()).unwrap();

        let result = policy.add_rule(rule("block-admin", 50), ann());

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert_eq!(policy.rule_count(), 1);
    }

    /// A stored policy holds "block-admin" twice, and another claims to be
    /// restored from its own version. Reading either is refused.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_policy_that_breaks_its_rules_is_refused() {
        let mut policy = PolicySet::permissive();
        policy.add_rule(rule("block-admin", 10), ann()).unwrap();
        let mut twice = serde_json::to_value(&policy).unwrap();
        let copy = twice["rules"][0].clone();
        twice["rules"].as_array_mut().unwrap().push(copy);
        let mut from_itself = serde_json::to_value(&policy).unwrap();
        from_itself["based_on"] = serde_json::json!({ "RestoredFrom": 1 });

        assert!(serde_json::from_value::<PolicySet>(twice).is_err());
        assert!(serde_json::from_value::<PolicySet>(from_itself).is_err());
    }

    /// A live policy is written to JSON and read back. It keeps its rules,
    /// its allow default, its live status and its version.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_policy_round_trips() {
        let policy = active();

        let read: PolicySet =
            serde_json::from_value(serde_json::to_value(&policy).unwrap()).unwrap();

        assert_eq!(rule_names(&read), ["block-admin"]);
        assert_eq!(read.status(), PolicyStatus::Active);
        assert!(read.default_action().is_allow());
        assert_eq!(read.version(), PolicyVersion::FIRST);
    }

    /// A new draft cannot be activated. Once submitted it is in review, and
    /// only then does activating make it live.
    #[test]
    fn a_policy_reaches_active_only_through_review() {
        let mut policy = PolicySet::permissive();

        assert!(
            policy
                .activate(Replacing::NothingLive, &reviewer(MANAGES))
                .is_err(),
            "a draft must not go live unreviewed"
        );

        policy.submit_for_review(submitting(MANAGES)).unwrap();
        policy
            .activate(Replacing::NothingLive, &reviewer(MANAGES))
            .unwrap();
        assert_eq!(policy.status(), PolicyStatus::Active);
    }

    /// A reviewer rejects a policy and it returns to draft. An abandoned
    /// draft is archived, and archiving it again is refused.
    #[test]
    fn a_rejected_policy_returns_to_draft_and_an_archived_one_stays_archived() {
        let mut rejected = PolicySet::permissive();
        rejected.submit_for_review(submitting(MANAGES)).unwrap();
        rejected.reject(ann()).unwrap();
        assert_eq!(rejected.status(), PolicyStatus::Draft);

        let mut archived = PolicySet::permissive();
        archived.archive(ann()).unwrap();
        assert_eq!(archived.status(), PolicyStatus::Archived);
        assert!(archived.archive(ann()).is_err());
    }

    /// When another approver exists, the submitter cannot activate their own
    /// policy. It stays in review and retains the submitter's identity.
    #[test]
    fn the_author_does_not_approve_their_own_policy() {
        let mut policy = in_review();

        let own = policy.activate(Replacing::NothingLive, &approving_as(21, MANAGES));

        assert!(matches!(own, Err(DomainError::Forbidden(_))));
        assert_eq!(policy.status(), PolicyStatus::Review);
        assert_eq!(policy.submitted(), &Submission::By(author()));
    }

    /// When another approver exists, using an organization account for the same
    /// person does not permit self-approval. The proposed version stays in
    /// review and the version it would replace stays active.
    #[test]
    fn the_author_does_not_approve_their_own_policy_from_another_account() {
        let mut live = active();
        let mut policy = next_in_review(std::slice::from_ref(&live));
        let anns_org_account = Human::new(
            HumanAccount::OrgUser(OrgUserId::new()),
            PersonKey::new("user21@acme.test").unwrap(),
        );
        let authority = assumed_authority(&anns_org_account, TenantId::new(), MANAGES, &[]);

        let own = policy.activate(
            Replacing::Live(&mut live),
            &PolicyApprover::assumed(authority, OtherApprovers::Exist),
        );

        assert!(matches!(own, Err(DomainError::Forbidden(_))));
        assert_eq!(policy.status(), PolicyStatus::Review);
        assert_eq!(live.status(), PolicyStatus::Active);
    }

    /// Ann opens a draft, writes two rules, switches one off, removes the
    /// other and changes the fallback. Each step is raised, in order.
    #[test]
    fn editing_a_draft_raises_each_step_in_order() {
        let mut draft =
            PolicySet::start_draft(&history(&[]), DraftStart::Blank(deny_all()), ann()).unwrap();

        draft.add_rule(rule("block-admin", 10), ann()).unwrap();
        draft.add_rule(rule("block-billing", 20), ann()).unwrap();
        draft
            .switch_rule(&label("block-admin"), Enablement::Disabled, ann())
            .unwrap();
        draft.remove_rule(&label("block-billing"), ann()).unwrap();
        draft
            .change_default_action(PolicyAction::Allow, ann())
            .unwrap();

        assert_eq!(
            raised_names(&mut draft),
            [
                "authorization.policy_draft_started",
                "authorization.policy_rule_added",
                "authorization.policy_rule_added",
                "authorization.policy_rule_switched",
                "authorization.policy_rule_removed",
                "authorization.policy_default_action_changed",
            ]
        );
    }

    /// Ann moves the fallback from deny to allow. The record keeps both.
    #[test]
    fn a_default_action_change_raises_the_action_before_and_after() {
        let mut draft = PolicySet::new(deny_all());

        draft
            .change_default_action(PolicyAction::Allow, ann())
            .unwrap();

        let payload = raised(&mut draft)[0].payload();
        let Some(FieldValue::Change(change)) = payload.value("default_action") else {
            panic!("the default action is recorded as a change");
        };
        assert_eq!((change.from(), change.to()), (Some("deny"), Some("allow")));
    }

    /// Ann's policy goes to review and is approved by a second admin, then
    /// archived. A draft goes to review and is rejected. Each move is
    /// raised.
    #[test]
    fn moving_a_policy_through_its_life_raises_each_move() {
        let mut policy = PolicySet::permissive();
        policy.submit_for_review(submitting(MANAGES)).unwrap();
        policy
            .activate(Replacing::NothingLive, &reviewer(MANAGES))
            .unwrap();
        policy.archive(ann()).unwrap();
        let mut next = PolicySet::permissive();
        next.submit_for_review(submitting(MANAGES)).unwrap();
        next.reject(ann()).unwrap();

        assert_eq!(
            raised_names(&mut policy),
            [
                "authorization.policy_submitted_for_review",
                "authorization.policy_activated",
                "authorization.policy_archived",
            ]
        );
        assert_eq!(
            raised_names(&mut next),
            [
                "authorization.policy_submitted_for_review",
                "authorization.policy_rejected",
            ]
        );
    }

    /// Ann tries the live policy against `/admin`. The run is raised with
    /// the path, the denial, the rule that matched and the version; the
    /// policy is as it was.
    #[test]
    fn a_simulation_is_raised_with_what_was_tried_and_decided() {
        let mut policy = active();
        raised_names(&mut policy);
        let input = SimulationInput {
            path: crate::types::Fact::Known(crate::types::CanonicalPath::new("/admin").unwrap()),
            ..SimulationInput::new()
        };

        let result = policy.simulate(&input, ann()).unwrap();

        let events = raised(&mut policy);
        let payload = events[0].payload();
        assert!(!result.is_allowed());
        assert_eq!(payload.get("simulated_path"), Some("/admin"));
        assert_eq!(payload.get("result_allowed"), Some("false"));
        assert_eq!(payload.get("matched_rule"), Some("block-admin"));
        assert_eq!(payload.get("version"), Some("1"));
        assert_eq!(policy.status(), PolicyStatus::Active);
    }

    /// Viewing authority cannot add a rule or reject a policy in review, and
    /// a caller with no policy rights cannot simulate it. All three refusals
    /// leave the policy without new events.
    #[test]
    fn a_refused_policy_change_raises_nothing() {
        let mut policy = in_review();
        raised_names(&mut policy);
        let viewing = anyone_holding(&[SystemPermission::PolicySet(PolicySetAction::View)]);

        let added = policy.add_rule(rule("block-billing", 20), viewing);
        let rejected = policy.reject(viewing);
        let simulated = policy.simulate(&SimulationInput::new(), anyone_holding(&[]));

        assert!(added.is_err());
        assert!(rejected.is_err());
        assert!(simulated.is_err());
        assert!(raised_names(&mut policy).is_empty());
    }

    /// A stored policy is read back. Nothing is raised: reading changes
    /// nothing.
    #[cfg(feature = "serde")]
    #[test]
    fn a_policy_read_back_from_storage_has_raised_nothing() {
        let policy = active();
        let mut read: PolicySet =
            serde_json::from_value(serde_json::to_value(&policy).unwrap()).unwrap();

        assert!(raised_names(&mut read).is_empty());
    }
}
