//! A policy's rules, kept in the order they are checked.
//!
//! Rules are found, changed and audited by name, so no two share one. They
//! are kept lowest priority first, and rules of equal priority keep the
//! order they were written in: the first matching allow of a priority
//! decides, so moving a rule behind its equals can change what a request
//! gets.

use crate::domains::authorization::policy::rule::PolicyRule;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::ValidationError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::types::{Enablement, Label};

/// The most rules one policy holds. A policy past it is no longer one a
/// reviewer can read, and reordering gives each rule a priority ten apart,
/// which must stay inside a `u16`.
pub(crate) const MAX_RULES: usize = 1000;

/// The gap between two rules' priorities after a reorder, leaving room to
/// add a rule between any two later.
const PRIORITY_STEP: usize = 10;

/// A policy's rules, lowest priority first, each name once.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub(crate) struct RuleList(Vec<PolicyRule>);

impl RuleList {
    /// Rules read back from storage, put in priority order whatever order
    /// they were written in.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when two rules share a name.
    pub(crate) fn stored(mut rules: Vec<PolicyRule>) -> Result<Self, DomainError> {
        if first_repeat(rules.iter().map(PolicyRule::name)).is_some() {
            return Err(DomainError::corrupt_row(
                "policy set",
                "two rules with one name",
            ));
        }
        rules.sort_by_key(PolicyRule::priority);
        Ok(Self(rules))
    }

    /// The rules in the order they are checked.
    pub(crate) fn as_slice(&self) -> &[PolicyRule] {
        &self.0
    }

    /// The rule named `name`.
    pub(crate) fn find(&self, name: &Label) -> Option<&PolicyRule> {
        self.0.iter().find(|rule| rule.name() == name)
    }

    /// Adds `rule` among the rules of its priority, behind those already
    /// there.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when a rule already has its name.
    /// - [`ValidationError::Count`] when the policy already holds
    ///   [`MAX_RULES`].
    pub(crate) fn add(&mut self, rule: PolicyRule) -> Result<(), DomainError> {
        self.ensure_name_free(rule.name())?;
        validate_count("rules", self.0.len().saturating_add(1), 0..=MAX_RULES)?;
        self.0.push(rule);
        self.0.sort_by_key(PolicyRule::priority);
        Ok(())
    }

    /// Takes out the rule named `name`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when no rule has that name.
    pub(crate) fn remove(&mut self, name: &Label) -> Result<PolicyRule, DomainError> {
        let at = self.position(name)?;
        Ok(self.0.remove(at))
    }

    /// Turns the rule named `name` on or off where it stands.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when no rule has that name.
    pub(crate) fn switch(&mut self, name: &Label, to: Enablement) -> Result<(), DomainError> {
        self.named_mut(name)?.switch(to);
        Ok(())
    }

    /// Puts `rule` where the rule named `name` stands, keeping that rule's
    /// on or off state, and gives back the rule it replaced.
    ///
    /// A rule whose priority stays the same keeps its place among its
    /// equals. One given a new priority moves to it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when no rule has that name.
    /// - [`DomainError::Conflict`] when `rule` takes the name of another
    ///   rule.
    pub(crate) fn replace(
        &mut self,
        name: &Label,
        mut rule: PolicyRule,
    ) -> Result<PolicyRule, DomainError> {
        if rule.name() != name {
            self.ensure_name_free(rule.name())?;
        }
        let current = self.named_mut(name)?;
        rule.switch(current.enablement());
        let replaced = std::mem::replace(current, rule);
        self.0.sort_by_key(PolicyRule::priority);
        Ok(replaced)
    }

    /// Puts the rules in the order `order` names them, each ten priority
    /// steps after the one before.
    ///
    /// # Errors
    ///
    /// - [`ValidationError::Count`] when `order` names more or fewer rules
    ///   than the policy has.
    /// - [`DomainError::Validation`] when it names a rule twice, or one the
    ///   policy does not have. A list that left a rule out or named one
    ///   twice would drop a rule nobody chose to drop.
    pub(crate) fn reorder(&mut self, order: &[Label]) -> Result<(), DomainError> {
        validate_count("rules", order.len(), self.0.len()..=self.0.len())?;
        if first_repeat(order).is_some() {
            return Err(DomainError::invalid(message!(
                "authorization-the-new-order-names-a-rule",
                "the new order names a rule twice"
            )));
        }
        let mut reordered = Vec::with_capacity(order.len());
        for (index, name) in order.iter().enumerate() {
            let mut rule = self.find(name).cloned().ok_or_else(|| {
                DomainError::invalid(message!(
                    "authorization-the-policy-has-no-rule",
                    format!("the policy has no rule '{name}'")
                ))
            })?;
            rule.move_to(priority_at(index)?);
            reordered.push(rule);
        }
        self.0 = reordered;
        Ok(())
    }

    /// Where the rule named `name` stands.
    fn position(&self, name: &Label) -> Result<usize, DomainError> {
        self.0
            .iter()
            .position(|rule| rule.name() == name)
            .ok_or(DomainError::NotFound)
    }

    /// The rule named `name`, to change where it stands.
    fn named_mut(&mut self, name: &Label) -> Result<&mut PolicyRule, DomainError> {
        self.0
            .iter_mut()
            .find(|rule| rule.name() == name)
            .ok_or(DomainError::NotFound)
    }

    /// Refuses `name` when a rule already has it.
    fn ensure_name_free(&self, name: &Label) -> Result<(), DomainError> {
        if self.find(name).is_some() {
            return Err(DomainError::conflict(message!(
                "authorization-the-policy-already-has-a-rule",
                "the policy already has a rule of that name"
            )));
        }
        Ok(())
    }
}

/// The priority of the rule at `index` after a reorder.
fn priority_at(index: usize) -> Result<u16, ValidationError> {
    let step = index.saturating_add(1).saturating_mul(PRIORITY_STEP);
    u16::try_from(step).map_err(|_| ValidationError::Count {
        field: "rules",
        min: 0,
        max: MAX_RULES,
        actual: index.saturating_add(1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::policy::action::PolicyAction;

    fn label(name: &str) -> Label {
        Label::new("rule_name", name).unwrap()
    }

    fn rule(name: &str, priority: u16) -> PolicyRule {
        PolicyRule::new(label(name), Vec::new(), PolicyAction::Allow, priority).unwrap()
    }

    fn names(list: &RuleList) -> Vec<&str> {
        list.as_slice().iter().map(|r| r.name().as_str()).collect()
    }

    fn list(rules: &[(&str, u16)]) -> RuleList {
        let mut list = RuleList::default();
        for (name, priority) in rules {
            list.add(rule(name, *priority)).unwrap();
        }
        list
    }

    /// Ann rewrites "require-mfa" at the same priority. It keeps its place
    /// ahead of "allow-office", and stays switched off as it was.
    #[test]
    fn a_rule_rewritten_at_its_priority_keeps_its_place_and_state() {
        let mut rules = list(&[("require-mfa", 10), ("allow-office", 10)]);
        rules
            .switch(&label("require-mfa"), Enablement::Disabled)
            .unwrap();

        rules
            .replace(&label("require-mfa"), rule("require-mfa", 10))
            .unwrap();

        assert_eq!(names(&rules), ["require-mfa", "allow-office"]);
        assert!(!rules.find(&label("require-mfa")).unwrap().enabled());
    }

    /// Ann rewrites "late" with priority 1. It moves to the front.
    #[test]
    fn a_rule_given_a_new_priority_moves_to_it() {
        let mut rules = list(&[("first", 10), ("late", 30)]);

        rules.replace(&label("late"), rule("late", 1)).unwrap();

        assert_eq!(names(&rules), ["late", "first"]);
    }

    /// Renaming a rule to another rule's name is refused, preserving both names
    /// and their order.
    #[test]
    fn a_rule_cannot_be_renamed_onto_another() {
        let mut rules = list(&[("block-admin", 10), ("allow-office", 20)]);

        let refused = rules.replace(&label("block-admin"), rule("allow-office", 10));

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert_eq!(names(&rules), ["block-admin", "allow-office"]);
    }

    /// Ann puts three rules in a new order. Each takes a priority ten
    /// apart, in the order she named them.
    #[test]
    fn reordering_spaces_the_rules_in_the_order_named() {
        let mut rules = list(&[("a", 1), ("b", 2), ("c", 3)]);

        rules
            .reorder(&[label("c"), label("a"), label("b")])
            .unwrap();

        assert_eq!(names(&rules), ["c", "a", "b"]);
        let priorities: Vec<u16> = rules.as_slice().iter().map(PolicyRule::priority).collect();
        assert_eq!(priorities, [10, 20, 30]);
    }

    /// Reordering with missing, repeated or unknown rule names is rejected, and
    /// the existing rule order remains intact.
    #[test]
    fn a_reorder_must_name_every_rule_once() {
        let mut rules = list(&[("block-admin", 1), ("allow", 2)]);

        let short = rules.reorder(&[label("allow")]);
        let twice = rules.reorder(&[label("allow"), label("allow")]);
        let unknown = rules.reorder(&[label("allow"), label("nothing")]);

        for refused in [short, twice, unknown] {
            assert!(matches!(refused, Err(DomainError::Validation(_))));
        }
        assert_eq!(names(&rules), ["block-admin", "allow"]);
    }

    /// Stored policy rules sharing a name are rejected as corrupt.
    #[test]
    fn stored_rules_with_one_name_twice_are_refused() {
        let stored = RuleList::stored(vec![rule("block-admin", 1), rule("block-admin", 2)]);

        assert!(matches!(stored, Err(DomainError::Infrastructure(_))));
    }

    /// The thousand-and-first rule is refused, so a reorder always fits
    /// every priority in a `u16`.
    #[test]
    fn a_policy_holds_at_most_a_thousand_rules() {
        let mut rules = RuleList::default();
        for n in 0..MAX_RULES {
            rules.add(rule(&format!("r{n}"), 1)).unwrap();
        }

        let refused = rules.add(rule("one-more", 1));

        assert!(matches!(refused, Err(DomainError::Validation(_))));
        assert!(priority_at(MAX_RULES - 1).is_ok());
    }
}
