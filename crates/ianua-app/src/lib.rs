//! Application layer: the use cases, the ports they need from the outside,
//! and the services and fakes they share.
// Tests stop immediately when a fixture or an asserted result is invalid.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![cfg_attr(not(test), warn(clippy::too_many_lines))]
#![warn(unreachable_pub)]
#![warn(missing_docs)]
// Test setups end in `..Ports::fakes()` even while they name every port, so
// adding a port to a use case leaves its existing tests compiling.
#![cfg_attr(test, allow(clippy::needless_update))]

pub mod acting;
pub mod auditor;
pub mod context;
pub mod email;
pub mod error;
pub mod input;
pub mod listing;
pub mod ports;
pub mod services;
pub mod tenancy;
#[cfg(any(test, feature = "test-support"))]
// These fakes and fixtures are compiled only for tests or the test-support feature.
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod test_support;
pub mod use_case;
pub mod use_cases;
