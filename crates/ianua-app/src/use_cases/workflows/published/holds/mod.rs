//! Holding versions in service that can no longer use an account they act
//! through: an account's change planned into a check, and the check that
//! holds each version the account no longer serves. A start finds and
//! holds such a version too, through [`holds`](crate::services::holds).

pub(crate) mod check;
pub(crate) mod plan;

pub use check::{CheckAccountHandler, CheckAccountPorts, CheckAccountUseCase};
pub use plan::{AccountChecks, PlanAccountChecksPorts, PlanAccountChecksUseCase};
