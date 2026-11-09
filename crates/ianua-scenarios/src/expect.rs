//! The checks every step of a scenario uses: waiting for what happens
//! later, one call as every actor, nothing secret in what came back, the
//! audit trail, the gateway's request records, and a tenant's
//! signature checked against its published keys.

mod eventually;
mod matrix;
mod records;
mod refusal;
mod secrets;
mod signed;
mod trail;

pub use eventually::{Waiting, eventually, eventually_paced, eventually_within};
pub use matrix::{Matrix, Outcome};
pub use records::Records;
pub use refusal::assert_clean_refusal;
pub use secrets::no_secret_leaked;
pub use signed::{standard_webhook_signed_by, verified_rs256};
pub use trail::Trail;
