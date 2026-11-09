//! The stages, by group. Each group is a struct holding what its stages
//! need, with one method per stage kind it runs; the dispatcher that fills
//! the application's stage ports matches each `StageKind` to its group.

pub mod checks;
pub mod counters;
pub mod identity;
pub mod policy;
pub mod response;
