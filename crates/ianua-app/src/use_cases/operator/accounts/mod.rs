//! Platform operators: installing the first, creating, reading, enabling and
//! disabling them, and moving one's address.

pub(crate) mod change_email;
pub(crate) mod create;
pub(crate) mod disable;
pub(crate) mod enable;
pub(crate) mod get;
pub(crate) mod install_first;
pub(crate) mod list_operators;

pub use change_email::{
    ChangeOperatorEmailPorts, ChangeOperatorEmailRequest, ChangeOperatorEmailUseCase,
};
pub use create::{CreateOperatorPorts, CreateOperatorRequest, CreateOperatorUseCase};
pub use disable::{DisableOperatorPorts, DisableOperatorUseCase};
pub use enable::{EnableOperatorPorts, EnableOperatorUseCase};
pub use get::{GetOperatorPorts, GetOperatorUseCase};
pub use install_first::{
    FirstOperator, InstallFirstOperatorPorts, InstallFirstOperatorRequest,
    InstallFirstOperatorUseCase,
};
pub use list_operators::{ListOperatorsPorts, ListOperatorsRequest, ListOperatorsUseCase};
