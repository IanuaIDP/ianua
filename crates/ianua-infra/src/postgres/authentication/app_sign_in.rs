//! The second-factor challenges and the session passes of signing in on an
//! app's own host: the stores of `ports/authentication/app_sign_in.rs`.
//!
//! The check that an app session is still live reads the `sessions` table,
//! so it sits beside the session store in `postgres::shared::sessions`,
//! sharing its mapping.

mod handoffs;
mod mfa_challenges;

pub use handoffs::PgHandoffStore;
pub use mfa_challenges::PgMfaChallengeStore;
