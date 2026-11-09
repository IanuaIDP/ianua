//! Fakes for the organization ports: organizations and members as tests
//! need them, and in-memory stores that keep what is saved, organization by
//! organization.
//!
//! Who acts on an organization is not faked here. Use cases ask `acting`
//! for it, and its fakes live in `test_support::acting`.

mod billing;
mod branding;
mod cloud;
mod grants;
mod identities;
mod identity_providers;
mod invitations;
mod lifecycle;
mod members;
mod passkeys;
mod privacy;
mod sessions;
mod signups;
mod tokens;

pub use billing::*;
pub use branding::*;
pub use cloud::*;
pub use grants::*;
pub use identities::*;
pub use identity_providers::*;
pub use invitations::*;
pub use lifecycle::*;
pub use members::*;
pub use passkeys::*;
pub use privacy::*;
pub use sessions::*;
pub use signups::*;
pub use tokens::*;
