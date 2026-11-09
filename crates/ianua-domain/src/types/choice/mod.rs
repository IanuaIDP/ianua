//! Ways to say a value outright, or that there is none.
//!
//! Each names its cases: known or unknown, set or unset, on or off.

/// Who did something: a named account, or the platform itself.
pub mod acted_by;
/// Whether something configured is switched on.
pub mod enablement;
/// Something observed about a request or a sign-in, or that it was not.
pub mod fact;
/// Something's own value, or that it follows a default set elsewhere.
pub mod preference;
/// A configuration value that is off until someone sets it.
pub mod setting;
