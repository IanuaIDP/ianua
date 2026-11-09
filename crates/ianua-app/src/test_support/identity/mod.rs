//! Fakes for the identity ports, by topic: users and their passwords,
//! invitations, mailed links, privacy requests, metadata and declared
//! attributes, and pending email changes; and the identity helpers and use
//! cases other use cases are built over.

mod access;
mod attributes;
mod credentials;
mod email_change;
mod exports;
mod held;
mod impersonations;
mod imports;
mod invitations;
mod links;
mod privacy;
mod removal;
mod tokens;
#[cfg(any(test, feature = "test-support"))]
mod use_cases;
mod users;

pub use access::*;
pub use attributes::*;
pub use credentials::*;
pub use email_change::*;
pub use exports::*;
pub use impersonations::*;
pub use imports::*;
pub use invitations::*;
pub use links::*;
pub use privacy::*;
pub use removal::*;
pub use tokens::*;
pub use users::*;
