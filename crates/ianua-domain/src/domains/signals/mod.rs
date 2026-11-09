//! Security signals (CAEP/SSE) pushed to relying parties as they happen.
//!
//! A relying party learns of a revoked session or a locked account right
//! away, instead of when its token expires.

pub mod control;
pub mod delivery;
pub mod events;
pub mod receiver;
pub mod report;
pub(crate) mod sealed;
pub mod set;
pub mod signal;
pub mod stream;
pub mod subjects;
pub mod verification;
