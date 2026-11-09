//! Access requests and the limit a tenant sets on them: the stores of
//! `ports/authorization/access_requests.rs`.

mod asks;
mod limits;

pub use asks::PgAccessRequestStore;
pub use limits::PgAccessRequestPolicyStore;
