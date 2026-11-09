//! The rules of a draft: added, changed, reordered, switched.

pub(crate) mod add;
pub(crate) mod change;
pub(crate) mod change_default_action;
pub(crate) mod remove;
pub(crate) mod reorder;
pub(crate) mod switch;

pub use add::{AddRulePorts, AddRuleUseCase};
pub use change::{ChangeRulePorts, ChangeRuleRequest, ChangeRuleUseCase};
pub use change_default_action::{ChangeDefaultActionPorts, ChangeDefaultActionUseCase};
pub use remove::{RemoveRulePorts, RemoveRuleUseCase};
pub use reorder::{ReorderRulesPorts, ReorderRulesUseCase};
pub use switch::{SwitchRulePorts, SwitchRuleRequest, SwitchRuleUseCase};
