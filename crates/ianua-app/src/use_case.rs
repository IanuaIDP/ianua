//! The one shape every use case has.
//!
//! A use case is one operation the application offers. It runs through a
//! single `execute`: who is asking, and what they asked for, already parsed
//! into domain types. Operations that change state and leave an audit record
//! are [`Command`]s and receive the request's [`RequestAuditor`]; operations
//! that only read are [`Query`]s and receive none.
//!
//! The same operation for different kinds of owner is still one use case: the
//! owner goes in `Input` as an enum. Different operations are different use
//! cases, each with its own `execute`.
//!
//! Inputs are owned values: a request struct, an id, never a borrow. That keeps
//! every implementation naming its real input type in the signature.

use std::future::Future;

use crate::auditor::RequestAuditor;

/// An operation that changes state and records what it did.
pub trait Command {
    /// Who is asking: a resolved caller, a tenant, or `()` for public flows.
    type Caller: ?Sized;
    /// What the operation needs, already parsed into domain types.
    type Input;
    /// What it gives back, usually `Result<_, AppError>`.
    type Output;

    /// Runs the operation and dispatches its audit events through `auditor`.
    fn execute(
        &self,
        caller: &Self::Caller,
        auditor: &RequestAuditor,
        input: Self::Input,
    ) -> impl Future<Output = Self::Output> + Send;
}

/// An operation that only reads.
pub trait Query {
    /// Who is asking: a resolved caller, a tenant, or `()` for public flows.
    type Caller: ?Sized;
    /// What the operation needs, already parsed into domain types.
    type Input;
    /// What it gives back, usually `Result<_, AppError>`.
    type Output;

    /// Runs the operation.
    fn execute(
        &self,
        caller: &Self::Caller,
        input: Self::Input,
    ) -> impl Future<Output = Self::Output> + Send;
}
