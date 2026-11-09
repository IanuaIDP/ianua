#![cfg_attr(not(test), warn(clippy::too_many_lines))]
// Test fixtures stop on invalid setup; production builds still check panic shortcuts.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! The HTTP API: handlers, request and response bodies, middleware and
//! routing over the app's use cases.
//!
//! It depends on `ianua-app` (use cases and ports) and `ianua-domain`
//! (types), never on an infrastructure crate. It says who is calling; the
//! app decides what they may do.

pub(crate) mod codec;
pub mod credential_use;
pub mod dto;
pub mod error;
pub mod extractors;
pub mod handlers;
pub(crate) mod method;
pub mod middleware;
pub mod openapi;
pub(crate) mod patch;
pub mod response;
pub mod router;
pub mod routes;
pub mod state;
#[cfg(any(test, feature = "test-support"))]
// These fixtures are only used by tests and stop when their setup fails.
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod test_support;
pub(crate) mod ws;
pub mod ws_limits;
