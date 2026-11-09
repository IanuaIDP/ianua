//! The limits a delegation puts on using its capabilities, such as lifetime,
//! task, budget and approval.

use crate::domains::agents::authority::capability::{AgentBudget, AppReach, ResourceScope};
use crate::domains::agents::authority::intent::IntentBinding;
use crate::domains::data_classification::level::DataClassLevel;
use crate::shared::errors::DomainError;
use crate::shared::model::restriction::Restriction;
use crate::shared::validation::numeric::validate_range;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{Seconds, Setting, TaskTemplateId};

text_value! {
    /// The task a delegation is for, in words a person can read, such as
    /// "close the Q1 books".
    pub struct TaskBinding;
}

impl TextValue for TaskBinding {
    const FIELD: &'static str = "task";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.free_text(Self::MAX_LEN)
    }
}

impl TaskBinding {
    /// The longest task text accepted.
    const MAX_LEN: usize = 500;
}

/// Which apps an agent may call through the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum AppAccess {
    /// No app that requires sign-in.
    NoApps,
    /// The listed apps and no others.
    Listed(AppReach),
}

/// Whether each action under a delegation waits for a person to approve it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ActionApproval {
    /// Actions go ahead within the delegation's other bounds.
    NotRequired,
    /// Every action waits for a person.
    PerAction,
}

/// What a task token issued under a delegation proves on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum TokenBinding {
    /// Whoever holds the token may use it.
    Bearer,
    /// Every request must also carry a `DPoP` proof made with the agent's
    /// credential key. A stolen token is useless without that key.
    ProofOfPossession,
}

/// The limits on using a delegation.
///
/// They are its lifetime, how deep it may be passed on, its task, a request
/// budget, an intent, the paths and apps it reaches, the most sensitive data
/// it may touch, and the template it came from. They also say whether each
/// action needs a person's approval and whether its token is bound to a key.
///
/// These say how a delegation may be used, not what it grants. What it grants
/// lives in
/// [`CapabilitySet`](crate::domains::agents::authority::capability::CapabilitySet).
///
/// Every limit is a [`Restriction`] or a two-way choice, never a missing
/// value. Stored constraints that lack one do not load. So a lost field never
/// reads as "no limit".
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "DelegationConstraintsWire"))]
pub struct DelegationConstraints {
    ttl_seconds: Seconds,
    max_depth: u8,
    task: Setting<TaskBinding>,
    budget: Restriction<AgentBudget>,
    intent: Restriction<IntentBinding>,
    resource_scope: Restriction<ResourceScope>,
    apps: AppAccess,
    approval: ActionApproval,
    binding: TokenBinding,
    max_data_class: Restriction<DataClassLevel>,
    template: Restriction<TaskTemplateId>,
}

/// [`DelegationConstraints`] as stored, before its checks run.
///
/// Loading goes through [`DelegationConstraints::new`]. So a stored lifetime
/// of zero seconds is refused, as it is when building one.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct DelegationConstraintsWire {
    ttl_seconds: Seconds,
    max_depth: u8,
    task: Option<TaskBinding>,
    budget: Restriction<AgentBudget>,
    intent: Restriction<IntentBinding>,
    resource_scope: Restriction<ResourceScope>,
    apps: AppAccess,
    approval: ActionApproval,
    binding: TokenBinding,
    max_data_class: Restriction<DataClassLevel>,
    template: Restriction<TaskTemplateId>,
}

#[cfg(feature = "serde")]
impl TryFrom<DelegationConstraintsWire> for DelegationConstraints {
    type Error = DomainError;

    fn try_from(wire: DelegationConstraintsWire) -> Result<Self, Self::Error> {
        let mut constraints = Self::new(wire.ttl_seconds, wire.max_depth)?;
        constraints.task = Setting::from_stored(wire.task);
        constraints.budget = wire.budget;
        constraints.intent = wire.intent;
        constraints.resource_scope = wire.resource_scope;
        constraints.apps = wire.apps;
        constraints.approval = wire.approval;
        constraints.binding = wire.binding;
        constraints.max_data_class = wire.max_data_class;
        constraints.template = wire.template;
        Ok(constraints)
    }
}

/// The longest a delegation may live: 30 days. An agent that needs longer
/// is given a new delegation, so a person looks at it again.
pub(crate) const MAX_DELEGATION_SECONDS: u32 = 30 * 24 * 3600;

impl DelegationConstraints {
    /// Creates constraints with a lifetime and a limit on how deep the
    /// delegation may be passed on.
    ///
    /// Every other limit starts unrestricted. It reaches no apps, needs no
    /// approval and issues bearer tokens. Under a parent, a limit left
    /// unrestricted takes the parent's limit when the delegation is narrowed.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `ttl_seconds` is zero or longer
    ///   than `MAX_DELEGATION_SECONDS`.
    pub fn new(ttl_seconds: Seconds, max_depth: u8) -> Result<Self, DomainError> {
        validate_range("ttl_seconds", ttl_seconds.get(), 1..=MAX_DELEGATION_SECONDS)?;
        Ok(Self {
            ttl_seconds,
            max_depth,
            task: Setting::Unset,
            budget: Restriction::Unrestricted,
            intent: Restriction::Unrestricted,
            resource_scope: Restriction::Unrestricted,
            apps: AppAccess::NoApps,
            approval: ActionApproval::NotRequired,
            binding: TokenBinding::Bearer,
            max_data_class: Restriction::Unrestricted,
            template: Restriction::Unrestricted,
        })
    }

    /// Names the apps the agent may call through the gateway.
    #[must_use]
    pub fn with_apps(mut self, apps: AppReach) -> Self {
        self.apps = AppAccess::Listed(apps);
        self
    }

    /// The apps the agent may call through the gateway.
    #[must_use]
    pub fn apps(&self) -> &AppAccess {
        &self.apps
    }

    /// Names the task this delegation is for.
    #[must_use]
    pub fn with_task(mut self, task: TaskBinding) -> Self {
        self.task = Setting::Set(task);
        self
    }

    /// Caps how many requests the agent may make per window.
    #[must_use]
    pub fn with_budget(mut self, budget: AgentBudget) -> Self {
        self.budget = Restriction::To(budget);
        self
    }

    /// Ties the delegation to what the person said the agent is for.
    #[must_use]
    pub fn with_intent(mut self, intent: IntentBinding) -> Self {
        self.intent = Restriction::To(intent);
        self
    }

    /// Limits the agent to requests under the given URL path prefixes.
    #[must_use]
    pub fn with_resource_scope(mut self, scope: ResourceScope) -> Self {
        self.resource_scope = Restriction::To(scope);
        self
    }

    /// Binds the token to the agent's credential key. The proxy then asks for
    /// a `DPoP` proof made with that key on every request.
    #[must_use]
    pub fn sender_constrained(mut self) -> Self {
        self.binding = TokenBinding::ProofOfPossession;
        self
    }

    /// Makes each action under this delegation wait for a person to approve it.
    #[must_use]
    pub fn requiring_approval(mut self) -> Self {
        self.approval = ActionApproval::PerAction;
        self
    }

    /// Caps the data the agent may reach under this delegation at `class`.
    #[must_use]
    pub fn with_max_data_class(mut self, class: DataClassLevel) -> Self {
        self.max_data_class = Restriction::To(class);
        self
    }

    /// Records the task template the delegation was granted under.
    #[must_use]
    pub fn under_template(mut self, template: TaskTemplateId) -> Self {
        self.template = Restriction::To(template);
        self
    }

    /// Replaces the narrowable limits with those a parent allows.
    pub(crate) fn with_limits(mut self, limits: Limits) -> Self {
        self.budget = limits.budget;
        self.intent = limits.intent;
        self.resource_scope = limits.resource_scope;
        self.apps = limits.apps;
        self.max_data_class = limits.max_data_class;
        self.template = limits.template;
        self
    }

    /// The lifetime in seconds.
    #[must_use]
    pub fn ttl_seconds(&self) -> Seconds {
        self.ttl_seconds
    }

    /// How deep the delegation may be passed on to further agents.
    #[must_use]
    pub fn max_depth(&self) -> u8 {
        self.max_depth
    }

    /// These constraints for a link sitting at `depth`: a chain's limit is
    /// never below the link it sits on, which would make a stored link
    /// contradict itself. At the limit the link hands nothing further on.
    #[must_use]
    pub(crate) fn deep_enough_for(mut self, depth: u8) -> Self {
        self.max_depth = self.max_depth.max(depth);
        self
    }

    /// The task this delegation is for, if one was named.
    #[must_use]
    pub fn task(&self) -> Option<&TaskBinding> {
        self.task.value()
    }

    /// The request budget.
    #[must_use]
    pub fn budget(&self) -> &Restriction<AgentBudget> {
        &self.budget
    }

    /// The intent the delegation is tied to.
    #[must_use]
    pub fn intent(&self) -> &Restriction<IntentBinding> {
        &self.intent
    }

    /// The URL path prefixes the agent is limited to.
    #[must_use]
    pub fn resource_scope(&self) -> &Restriction<ResourceScope> {
        &self.resource_scope
    }

    /// What a task token issued under this delegation proves on its own.
    #[must_use]
    pub fn binding(&self) -> TokenBinding {
        self.binding
    }

    /// Whether the token is bound to the agent's key and needs a `DPoP` proof.
    #[must_use]
    pub fn is_sender_constrained(&self) -> bool {
        self.binding == TokenBinding::ProofOfPossession
    }

    /// Whether each action waits for a person to approve it.
    #[must_use]
    pub fn approval(&self) -> ActionApproval {
        self.approval
    }

    /// Whether every action needs a person's approval first.
    #[must_use]
    pub fn requires_approval(&self) -> bool {
        self.approval == ActionApproval::PerAction
    }

    /// The most sensitive data the agent may reach.
    #[must_use]
    pub fn max_data_class(&self) -> Restriction<DataClassLevel> {
        self.max_data_class
    }

    /// The task template the delegation was granted under.
    #[must_use]
    pub fn template(&self) -> &Restriction<TaskTemplateId> {
        &self.template
    }

    /// The limits a sub-delegation may tighten, copied out together.
    pub(crate) fn limits(&self) -> Limits {
        Limits {
            budget: self.budget.clone(),
            intent: self.intent.clone(),
            resource_scope: self.resource_scope.clone(),
            apps: self.apps.clone(),
            max_data_class: self.max_data_class,
            template: self.template,
        }
    }
}

/// The limits on a delegation that a sub-delegation may tighten but never
/// loosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Limits {
    pub(crate) budget: Restriction<AgentBudget>,
    pub(crate) intent: Restriction<IntentBinding>,
    pub(crate) resource_scope: Restriction<ResourceScope>,
    pub(crate) apps: AppAccess,
    pub(crate) max_data_class: Restriction<DataClassLevel>,
    pub(crate) template: Restriction<TaskTemplateId>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::authority::intent::{
        DriftPolicy, IntentBinding, IntentDigest, IntentStatement,
    };
    use crate::types::Seconds;

    /// Constraints with a lifetime of zero seconds are refused. Ten minutes
    /// is accepted.
    #[test]
    fn constraints_reject_zero_ttl() {
        assert!(DelegationConstraints::new(Seconds::new(0), 1).is_err());
        assert!(DelegationConstraints::new(Seconds::new(600), 1).is_ok());
    }

    /// Delegation lifetimes of `u32::MAX` seconds and one second above the
    /// limit are refused. A lifetime exactly at the limit is accepted.
    #[test]
    fn a_lifetime_past_the_ceiling_is_refused() {
        let longest = Seconds::new(MAX_DELEGATION_SECONDS);

        assert!(DelegationConstraints::new(Seconds::new(u32::MAX), 1).is_err());
        assert!(DelegationConstraints::new(Seconds::new(MAX_DELEGATION_SECONDS + 1), 1).is_err());
        assert!(DelegationConstraints::new(longest, 1).is_ok());
    }

    /// Plain constraints have no intent and need no approval. Constraints
    /// given the intent "book a flight" and per-action approval report both.
    #[test]
    fn constraints_carry_intent_and_approval_gate() {
        let plain = DelegationConstraints::new(Seconds::new(600), 1).unwrap();
        assert!(!plain.intent().is_restricted());
        assert!(!plain.requires_approval());

        let binding = IntentBinding::new(
            IntentStatement::new("book a flight").unwrap(),
            IntentDigest::new([1u8; 32]),
            DriftPolicy::Off,
            crate::domains::agents::authority::intent::IntentEnvelope::default(),
        );
        let gated = DelegationConstraints::new(Seconds::new(600), 1)
            .unwrap()
            .with_intent(binding)
            .requiring_approval();
        assert!(gated.requires_approval());
        assert_eq!(
            gated.intent().limit().map(|i| i.statement().as_str()),
            Some("book a flight")
        );
    }

    /// Constraints given the task "close the Q1 books" report that task.
    /// Constraints given none report no task.
    #[test]
    fn constraints_report_the_task_they_were_given() {
        let task = TaskBinding::new("close the Q1 books").unwrap();

        let bound = DelegationConstraints::new(Seconds::new(600), 1)
            .unwrap()
            .with_task(task.clone());

        assert_eq!(bound.task(), Some(&task));

        let plain = DelegationConstraints::new(Seconds::new(600), 1).unwrap();
        assert_eq!(plain.task(), None);
    }

    /// A delegation bound to the agent's key reports itself as bound, and a
    /// plain one does not. The server cannot make a `DPoP` proof for an
    /// agent, so this decides whether a server run may act under it.
    #[test]
    fn only_a_sender_constrained_delegation_reports_itself_as_one() {
        let plain = DelegationConstraints::new(Seconds::new(600), 1).unwrap();
        let bound = DelegationConstraints::new(Seconds::new(600), 1)
            .unwrap()
            .sender_constrained();

        assert!(!plain.is_sender_constrained());
        assert!(bound.is_sender_constrained());
    }

    /// Stored constraints with a zero-second lifetime cannot deserialize.
    /// The same limits with a ten-minute lifetime load and retain that lifetime.
    #[cfg(feature = "serde")]
    #[test]
    fn a_zero_lifetime_delegation_constraint_is_refused() {
        let limits = r#""budget":"unrestricted","intent":"unrestricted","resource_scope":"unrestricted","apps":"no_apps","approval":"not_required","binding":"bearer","max_data_class":"unrestricted","template":"unrestricted""#;
        let zero = format!(r#"{{"ttl_seconds":0,"max_depth":1,"task":null,{limits}}}"#);
        let ok = format!(r#"{{"ttl_seconds":600,"max_depth":1,"task":null,{limits}}}"#);

        assert!(serde_json::from_str::<DelegationConstraints>(&zero).is_err());
        let parsed: DelegationConstraints = serde_json::from_str(&ok).unwrap();
        assert_eq!(parsed.ttl_seconds(), Seconds::new(600));
    }

    /// Stored constraints containing only lifetime, depth and task cannot
    /// deserialize when the remaining limits are missing.
    #[cfg(feature = "serde")]
    #[test]
    fn stored_constraints_missing_a_limit_do_not_load() {
        let missing = r#"{"ttl_seconds":600,"max_depth":1,"task":null}"#;

        assert!(serde_json::from_str::<DelegationConstraints>(missing).is_err());
    }

    /// Constraints with a data class cap, per-action approval and a bound
    /// token are saved as JSON and loaded again. They come back equal.
    #[cfg(feature = "serde")]
    #[test]
    fn constraints_read_back_as_written() {
        let constraints = DelegationConstraints::new(Seconds::new(600), 1)
            .unwrap()
            .with_max_data_class(DataClassLevel::Internal)
            .requiring_approval()
            .sender_constrained();

        let json = serde_json::to_string(&constraints).unwrap();

        assert_eq!(
            serde_json::from_str::<DelegationConstraints>(&json).unwrap(),
            constraints
        );
    }

    /// A stored task that is empty, or holds a NUL character, fails to load.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_task_binding_that_is_empty_is_refused() {
        assert!(serde_json::from_str::<TaskBinding>(r#""""#).is_err());
        assert!(serde_json::from_str::<TaskBinding>(r#""a\u0000b""#).is_err());
    }

    /// The task "reconcile the March ledger" is saved as JSON and loaded
    /// again. It comes back with the same text.
    #[cfg(feature = "serde")]
    #[test]
    fn a_task_binding_reads_back_what_it_writes() {
        let task = TaskBinding::new("reconcile the March ledger").unwrap();

        let json = serde_json::to_string(&task).unwrap();

        assert_eq!(serde_json::from_str::<TaskBinding>(&json).unwrap(), task);
    }
}
