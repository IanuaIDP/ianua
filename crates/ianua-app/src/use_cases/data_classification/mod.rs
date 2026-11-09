//! Data classification use cases: which response fields are sensitive.

pub(crate) mod add_classification_rule;
pub(crate) mod change_classification_rule;
pub(crate) mod get_classification;
mod lookup;
pub(crate) mod remove_classification_rule;

pub use add_classification_rule::{
    AddClassificationRulePorts, AddClassificationRuleRequest, AddClassificationRuleUseCase,
};
pub use change_classification_rule::{
    ChangeClassificationRulePorts, ChangeClassificationRuleRequest, ChangeClassificationRuleUseCase,
};
pub use get_classification::{GetClassificationPorts, GetClassificationUseCase};
pub use remove_classification_rule::{
    RemoveClassificationRulePorts, RemoveClassificationRuleUseCase,
};
