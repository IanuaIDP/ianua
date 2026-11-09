//! The checks the proxy makes on every agent request: whether the
//! delegation behind the token still stands, whether the agent may act
//! now, and whether the data it has touched lets it reach the route.
//! Each reads one row, and each answers deny for a row that is gone.

mod exposure;
mod revocation;
mod status;

pub use exposure::PgAgentExposureGate;
pub use revocation::PgDelegationRevocationCheck;
pub use status::PgAgentStandingCheck;
