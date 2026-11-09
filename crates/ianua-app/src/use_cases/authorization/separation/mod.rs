//! Separation of duties: the pairs of roles nobody in a tenant holds
//! together, checked whenever a role or a group is given.

pub(crate) mod add_rule;
pub(crate) mod list_rules;
pub(crate) mod remove_rule;

pub use add_rule::{AddRulePorts, AddRuleRequest, AddRuleUseCase};
pub use list_rules::{ListRulesPorts, ListRulesUseCase};
pub use remove_rule::{RemoveRulePorts, RemoveRuleUseCase};
