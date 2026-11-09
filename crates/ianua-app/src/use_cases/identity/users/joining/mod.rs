//! How accounts come to be: registered by an admin or signed up. Imported
//! accounts come through `identity::imports`, worked through by the worker.

pub(crate) mod register;
pub(in crate::use_cases::identity) mod room;
pub(crate) mod sign_up;
pub(crate) mod sign_up_rules;

pub use register::{New, RegisterPorts, RegisterResult, RegisterUseCase};
pub use sign_up::{SignUp, SignUpOutcome, SignUpPorts, SignUpRequest, SignUpUseCase};
pub use sign_up_rules::{SignUpRulesPorts, SignUpRulesUseCase};
