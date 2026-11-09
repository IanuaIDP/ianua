//! Credentials at the gateway: who a request comes from, proven from the
//! credential it presents.
//!
//! The gateway extracts the credential, hands it over as it arrived, and
//! enforces the answer. It never parses a token, digests a key or decides
//! who a caller is on its own: [`AuthenticateUseCase`] does, through the
//! readers in [`crate::ports::authentication`] and the stored records.

mod agent;
mod authenticate;
mod checking;
mod consumer;
pub(crate) mod held;
pub(crate) mod outcome;
mod person;
mod presented;
mod run_pass;

pub use agent::AgentPorts;
pub use authenticate::{AuthenticatePorts, AuthenticateRequest, AuthenticateUseCase};
pub use consumer::ConsumerPorts;
pub use outcome::{Identification, KeyMismatch, Proven, Refusal};
pub use person::PersonPorts;
pub use presented::{AppSessionCookie, Presented, RequestTarget};
