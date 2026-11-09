//! Assertion keys: signing the identity the gateway hands an upstream as
//! `X-Ianua-Assertion`, publishing the keys upstreams check it with, and
//! the sweeps that rotate them by age and retire them after the overlap.
//!
//! A tenant's first key is made at its setup, by
//! [`RunStepUseCase`](crate::use_cases::tenant::setup::RunStepUseCase). It
//! cannot be made on first need: the gateway, the one that needs it, has no
//! right to write keys, so a gateway broken into cannot plant one of its
//! own. A tenant whose keys were all retired by hand gets a new one from
//! the next rotation sweep, which treats a set where nothing signs as due.

pub(crate) mod get_published;
pub(crate) mod retire_after_overlap;
pub(crate) mod rotate_by_age;
pub(crate) mod sign;

pub use get_published::{GetPublishedPorts, GetPublishedUseCase};
pub use retire_after_overlap::{RetireAfterOverlapPorts, RetireAfterOverlapUseCase};
pub use rotate_by_age::{RotateByAgePorts, RotateByAgeUseCase};
pub use sign::{SignPorts, SignUseCase};
