//! Who is calling, where, and with what credential.
//!
//! `CallerContext` is what the API layer hands every use case once it knows
//! who sent the request: their identity, the organization and tenant they
//! target, the credential they came with, and the request's address and
//! client. It claims no permission. A use case that changes something asks
//! [`acting`](crate::acting) to work out, from the stored records, what the
//! credential lets its holder do, and passes that proof to the domain.

mod agent;
mod consumer;
mod directory;
mod operator;
mod organization;
mod scim;
mod tenant;

pub use agent::*;
pub use consumer::*;
pub use directory::*;
pub use operator::*;
pub use organization::*;
pub use scim::*;
pub use tenant::*;
