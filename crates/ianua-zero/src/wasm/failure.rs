//! Why a guest call reached no verdict of its own. Every one is a denial.

use std::error::Error;

use ianua_domain::shared::errors::DomainError;

use super::abi::MalformedAnswer;

/// Why a call to a tenant's module was refused.
///
/// The kind is for the operator's log and the request record; the client
/// is told only that the stage denied the request.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Failure {
    /// No module is stored under the stage's reference.
    #[error("no module is stored under the stage's reference")]
    NotFound,
    /// The module store failed.
    #[error("the module store failed")]
    Store(#[source] DomainError),
    /// The module store did not answer in time.
    #[error("the module store did not answer in time")]
    StoreTimedOut,
    /// The bytes are not a module this engine compiles.
    #[error("the module did not compile")]
    Compile(#[source] Box<dyn Error + Send + Sync>),
    /// Compiling took longer than allowed.
    #[error("the module took too long to compile")]
    CompileTimedOut,
    /// Every sandbox stayed busy for the stage's whole time limit.
    #[error("no sandbox was free within the stage's time limit")]
    Busy,
    /// The call's store could not be set up.
    #[error("the sandbox could not be set up")]
    Setup(#[source] Box<dyn Error + Send + Sync>),
    /// The module could not be instantiated: an import it needs is not
    /// offered, WASI among them, or it asks for more memory than allowed.
    #[error("the module could not be instantiated")]
    Instantiate(#[source] Box<dyn Error + Send + Sync>),
    /// The module lacks an export the ABI requires.
    #[error("the module does not export {0}")]
    MissingExport(&'static str),
    /// The module used its whole fuel budget.
    #[error("the module used all its fuel")]
    OutOfFuel,
    /// The module ran past the stage's time limit.
    #[error("the module ran past its time limit")]
    TimedOut,
    /// The module trapped, a memory growth past its limit included.
    #[error("the module trapped")]
    Trap(#[source] Box<dyn Error + Send + Sync>),
    /// The module's answer does not fit the ABI.
    #[error("the module's answer is malformed")]
    Malformed(#[source] MalformedAnswer),
}

impl Failure {
    /// A short, stable kind for the request record.
    #[must_use]
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::NotFound => "module_not_found",
            Self::Store(_) => "module_store_failed",
            Self::StoreTimedOut => "module_store_timed_out",
            Self::Compile(_) => "compile_failed",
            Self::CompileTimedOut => "compile_timed_out",
            Self::Busy => "sandbox_busy",
            Self::Setup(_) => "setup_failed",
            Self::Instantiate(_) => "instantiate_failed",
            Self::MissingExport(_) => "missing_export",
            Self::OutOfFuel => "out_of_fuel",
            Self::TimedOut => "timed_out",
            Self::Trap(_) => "trapped",
            Self::Malformed(_) => "malformed_answer",
        }
    }

    /// The failure a guest's run ended in: its fuel spent, its time up, or
    /// any other trap, sorted by what wasmtime reports.
    pub(super) fn trapped(error: wasmtime::Error) -> Self {
        match error.downcast_ref::<wasmtime::Trap>() {
            Some(wasmtime::Trap::OutOfFuel) => Self::OutOfFuel,
            Some(wasmtime::Trap::Interrupt) => Self::TimedOut,
            Some(_) | None => Self::Trap(error.into()),
        }
    }

    /// The failure an instantiation ended in: a trap in the module's start
    /// function, or a module that could not be instantiated at all.
    pub(super) fn instantiating(error: wasmtime::Error) -> Self {
        if error.downcast_ref::<wasmtime::Trap>().is_some() {
            return Self::trapped(error);
        }
        Self::Instantiate(error.into())
    }
}
