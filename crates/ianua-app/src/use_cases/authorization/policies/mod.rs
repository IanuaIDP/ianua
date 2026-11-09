//! Access policies: opening a draft beside the live version, changing it
//! one step at a time, moving it through review, reading the history, and
//! trying any version out.

pub(crate) mod get;
/// The rules of a draft: added, changed, reordered, switched.
pub(crate) mod rules;
pub(crate) mod simulate;
/// A policy's versions: drafted, reviewed, activated, read.
pub(crate) mod versions;

pub use get::{GetPorts, GetUseCase, Overview};
pub use rules::{
    AddRulePorts, AddRuleUseCase, ChangeDefaultActionPorts, ChangeDefaultActionUseCase,
    ChangeRulePorts, ChangeRuleRequest, ChangeRuleUseCase, RemoveRulePorts, RemoveRuleUseCase,
    ReorderRulesPorts, ReorderRulesUseCase, SwitchRulePorts, SwitchRuleRequest, SwitchRuleUseCase,
};
pub use simulate::{SimulatePorts, SimulateRequest, SimulateUseCase, SimulatedVersion};
pub use versions::{
    ChangeStatusPorts, ChangeStatusUseCase, GetVersionPorts, GetVersionUseCase, ListVersionsPorts,
    ListVersionsUseCase, StartDraftPorts, StartDraftUseCase, Transition,
};
