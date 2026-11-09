//! Policy rules: a set of conditions paired with an action.

use crate::domains::authorization::policy::action::PolicyAction;
use crate::domains::authorization::policy::condition::PolicyCondition;
use crate::shared::validation::ValidationError;
use crate::types::{Enablement, Label};

/// A single policy rule within a tenant's policy set.
///
/// When all its conditions match, the rule's action applies. Rules are
/// checked in priority order. A matching deny always wins; otherwise the
/// first matching allow does.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "PolicyRuleWire"))]
pub struct PolicyRule {
    /// The rule's name, shown in simulation results and the audit trail.
    name: Label,
    /// Conditions that must all hold for this rule to apply.
    conditions: Vec<PolicyCondition>,
    /// What to do when the rule matches.
    action: PolicyAction,
    /// Lower numbers are checked first. Rules of equal priority are checked
    /// in the order they were added.
    priority: u16,
    /// Whether this rule is in use. A disabled rule is skipped when checking
    /// but kept for editing.
    enabled: Enablement,
}

/// A rule as it is stored, before [`PolicyRule::new`] has checked its
/// conditions.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct PolicyRuleWire {
    name: Label,
    conditions: Vec<PolicyCondition>,
    action: PolicyAction,
    priority: u16,
    enabled: Enablement,
}

#[cfg(feature = "serde")]
impl TryFrom<PolicyRuleWire> for PolicyRule {
    type Error = ValidationError;

    fn try_from(wire: PolicyRuleWire) -> Result<Self, Self::Error> {
        let mut rule = Self::new(wire.name, wire.conditions, wire.action, wire.priority)?;
        rule.enabled = wire.enabled;
        Ok(rule)
    }
}

impl PolicyRule {
    /// Creates a new enabled policy rule.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] from the first condition that cannot mean what
    ///   it says. [`PolicyCondition::check`] lists the cases.
    pub fn new(
        name: Label,
        conditions: Vec<PolicyCondition>,
        action: PolicyAction,
        priority: u16,
    ) -> Result<Self, ValidationError> {
        conditions.iter().try_for_each(PolicyCondition::check)?;
        Ok(Self {
            name,
            conditions,
            action,
            priority,
            enabled: Enablement::Enabled,
        })
    }

    /// This rule with `conditions` in place of its own, on or off as it
    /// was: how a rule is carried into another tenant, whose roles and
    /// groups go by ids of their own.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] from the first condition that cannot mean what
    ///   it says, as [`PolicyRule::new`] checks.
    pub fn with_conditions(
        &self,
        conditions: Vec<PolicyCondition>,
    ) -> Result<Self, ValidationError> {
        let mut rule = Self::new(
            self.name.clone(),
            conditions,
            self.action.clone(),
            self.priority,
        )?;
        rule.enabled = self.enabled;
        Ok(rule)
    }

    /// The rule's name.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// The conditions that must all match.
    #[must_use]
    pub fn conditions(&self) -> &[PolicyCondition] {
        &self.conditions
    }

    /// The action to take when matched.
    #[must_use]
    pub fn action(&self) -> &PolicyAction {
        &self.action
    }

    /// Where the rule is checked. Lower numbers come first.
    #[must_use]
    pub fn priority(&self) -> u16 {
        self.priority
    }

    /// Whether this rule is in use.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled == Enablement::Enabled
    }

    /// Turns the rule on or off. Only its policy does this, through
    /// [`PolicySet::switch_rule`](crate::domains::authorization::policy::set::PolicySet::switch_rule),
    /// which checks who edits and that the policy is a draft.
    pub(crate) fn switch(&mut self, to: Enablement) {
        self.enabled = to;
    }

    /// Moves the rule to `priority`. Only its policy does this, when the
    /// rules are put in a new order, after checking who edits.
    pub(crate) fn move_to(&mut self, priority: u16) {
        self.priority = priority;
    }

    /// Whether this rule is on or off.
    #[must_use]
    pub fn enablement(&self) -> Enablement {
        self.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(priority: u16) -> PolicyRule {
        PolicyRule::new(
            Label::new("rule_name", "block-admin").unwrap(),
            vec![PolicyCondition::PathPrefix(
                crate::types::PathPrefix::new("/admin").unwrap(),
            )],
            PolicyAction::Deny {
                reason: crate::types::Text::new("reason", "blocked").unwrap(),
            },
            priority,
        )
        .unwrap()
    }

    /// Rules built with priority 10 and 0 report 10 and 0. A wrong number
    /// would put a deny behind the allow it was meant to override.
    #[test]
    fn a_rule_reports_the_priority_it_was_given() {
        assert_eq!(rule(10).priority(), 10);
        assert_eq!(rule(0).priority(), 0);
    }

    /// A new rule is enabled. An admin disables it and then enables it
    /// again, and each change shows.
    #[test]
    fn a_rule_can_be_turned_off_and_back_on() {
        let mut rule = rule(10);
        assert!(rule.enabled());

        rule.switch(Enablement::Disabled);
        assert!(!rule.enabled());

        rule.switch(Enablement::Enabled);
        assert!(rule.enabled());
    }

    /// Replacing a disabled rule's conditions preserves its name, priority and
    /// disabled state while applying the new condition.
    #[test]
    fn a_rule_given_new_conditions_stays_as_it_was() {
        let mut off = rule(10);
        off.switch(Enablement::Disabled);

        let carried = off
            .with_conditions(vec![PolicyCondition::DeviceUnknown])
            .unwrap();

        assert!(!carried.enabled());
        assert_eq!(carried.priority(), 10);
        assert_eq!(carried.name(), off.name());
        assert!(matches!(
            carried.conditions(),
            [PolicyCondition::DeviceUnknown]
        ));
    }

    /// An admin builds a rule on an empty country list, an empty excluded
    /// country list, an empty method list, an empty address range list, an
    /// empty excluded range list or an empty host list. Each is refused,
    /// since an excluded list alone would match every request.
    #[test]
    fn a_rule_over_an_empty_list_is_refused() {
        for condition in [
            PolicyCondition::CountryIn(vec![]),
            PolicyCondition::CountryNotIn(vec![]),
            PolicyCondition::MethodIn(vec![]),
            PolicyCondition::SourceIpIn(vec![]),
            PolicyCondition::SourceIpNotIn(vec![]),
            PolicyCondition::HostIn(vec![]),
        ] {
            let built = PolicyRule::new(
                Label::new("rule_name", "empty").unwrap(),
                vec![condition],
                PolicyAction::Allow,
                1,
            );
            assert!(built.is_err());
        }
    }

    /// A stored rule excludes an empty list of countries. Reading it is
    /// refused, so it is never evaluated.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_rule_over_an_empty_list_is_refused() {
        let stored = r#"{"name":"r","conditions":[{"CountryNotIn":[]}],"action":"Allow","priority":1,"enabled":true}"#;

        assert!(serde_json::from_str::<PolicyRule>(stored).is_err());
    }

    /// A stored rule is disabled. It reads back disabled, not as a new
    /// enabled rule.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_rule_keeps_its_enabled_flag() {
        let stored =
            r#"{"name":"r","conditions":[],"action":"Allow","priority":1,"enabled":false}"#;

        let rule: PolicyRule = serde_json::from_str(stored).unwrap();

        assert!(!rule.enabled());
    }
}
