//! The mark that keeps the signals context's rule traits to this crate.

/// Marks a type of this crate that may answer one of the signals context's
/// rules.
///
/// The module holding it is private to the crate, so no caller outside can
/// implement a rule with an answer that always agrees.
pub trait Sealed {}
