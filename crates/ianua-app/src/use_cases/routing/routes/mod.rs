//! HTTP routes: what the proxy answers, and where it forwards.

pub(crate) mod activate;
pub(crate) mod change_conditions;
pub(crate) mod create;
pub(crate) mod delete;
pub(crate) mod disable;
pub(crate) mod get;
pub(crate) mod get_traffic;
pub(crate) mod list;
pub(crate) mod openable;
pub(crate) mod retarget;
pub(crate) mod set_attack_mode;
pub(crate) mod set_workflow_use;
pub(crate) mod update;

pub use activate::{ActivatePorts, ActivateUseCase};
pub use change_conditions::{
    ChangeConditionsPorts, ChangeConditionsRequest, ChangeConditionsUseCase,
};
pub use create::{CreatePorts, CreateRequest, CreateUseCase};
pub use delete::{DeletePorts, DeleteUseCase};
pub use disable::{DisablePorts, DisableUseCase};
pub use get::{GetPorts, GetUseCase};
pub use get_traffic::{GetTrafficPorts, GetTrafficRequest, GetTrafficUseCase};
pub use list::{ListPorts, ListRequest, ListUseCase, RouteFilter};
pub use openable::{ListOpenablePorts, ListOpenableUseCase, OpenableApp, Opening};
pub use set_attack_mode::{
    AttackChange, SetAttackModePorts, SetAttackModeRequest, SetAttackModeUseCase,
};
pub use set_workflow_use::{SetWorkflowUsePorts, SetWorkflowUseRequest, SetWorkflowUseUseCase};
pub use update::{UpdatePorts, UpdateRequest, UpdateUseCase};
