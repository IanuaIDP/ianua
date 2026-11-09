//! Who acts: each actor owns its own [`Client`](crate::net::Client) and
//! its own credentials, and signs in through the API's real flows.
//!
//! - [`Founder`]: someone signing a company up, before there is a world.
//! - [`Member`]: an organization member at the dashboard, such as its
//!   owner, a tenant administrator, a member without rights, or a stranger
//!   administering another organization's tenant.
//! - [`Person`]: a tenant user with their own devices: password, an
//!   authenticator app, a passkey, recovery codes.
//! - [`KeyHolder`]: a program calling with one of the tenant's API keys.
//! - [`Anonymous`]: nobody signed in.
//!
//! Each also makes its own spoiled variants for a matrix, through real
//! actions: a client signed out, one whose session an administrator ended,
//! one holding a revoked key, a person suspended.

mod anonymous;
mod founder;
mod key_holder;
pub(crate) mod mailed;
mod member;
mod person;

pub use anonymous::Anonymous;
pub use founder::{FOUNDER_PASSWORD, Founder};
pub use key_holder::{KeyHolder, KeyRequest};
pub use member::{Member, MemberAccount};
pub use person::{Person, PersonAccount, SignedInWith};
