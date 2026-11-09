//! Consumers: the non-human callers a tenant lets through the gateway.
//!
//! A consumer is a partner integration, a backend worker or a cron job. It
//! signs in with an API key, a client certificate or its own JWT. It has no
//! password and no second factor.
//!
//! A consumer holds no permissions of its own. It is a
//! [`PrincipalRef`](crate::types::PrincipalRef), so what it may reach comes
//! from the roles it is given. A person gets their rights the same way. So
//! "what may this caller reach" has one answer for every kind of caller.

pub mod authority;
pub mod consumer;
pub mod control;
pub mod credential;
pub mod credentials;
pub mod events;
pub mod quota;
pub mod sign_in;
pub mod takeover;

#[cfg(test)]
pub(crate) mod fixtures;
