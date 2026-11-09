//! Everything a REST service needs to become an integration, so a new one
//! is mostly a description:
//!
//! - [`operation`]: each step described once, as data, from which its spec,
//!   its guide and its request are made.
//! - [`access`]: how an account reaches the service and signs its calls,
//!   with a token alone, an organization's token, or a site of its own
//!   held to the sites the deployment allows; [`grant`]: a lasting grant
//!   exchanged for a token first, keeping a refresh token the service
//!   replaced.
//! - [`service`]: the whole integration made from a profile, the steps, the
//!   access, the headers, the request that proves a credential, and how the
//!   service says yes.
//! - [`request`] and [`names`]: a step's call, every part of its address
//!   checked and escaped, and a whole mail message as its body where the
//!   service takes one.
//! - [`event`]: each event the service sends described once, beside what
//!   registers workflows for them and reads what the service sends.
//! - [`watch`]: the calls that register, renew and remove those
//!   registrations, through the steps' own access.
//! - [`sign_in`]: signing in at the service to connect an account, through
//!   OAuth 2.0's authorization code flow with PKCE.
//! - [`checks`]: the rules every set of steps keeps, for a service's tests.
//! - [`openapi`] (with the `test-support` feature): checking the steps
//!   against the service's own published API description.

pub mod access;
pub mod checks;
pub mod event;
pub mod grant;
mod mail;
pub mod names;
#[cfg(any(test, feature = "test-support"))]
pub mod openapi;
pub mod operation;
pub mod request;
pub mod service;
pub mod sign_in;
pub mod watch;
