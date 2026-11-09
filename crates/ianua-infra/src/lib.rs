//! Concrete implementations of the ports the domain and the application
//! define: Postgres stores, the cache, the message bus, mail, crypto,
//! outbound HTTP, and what runs inside the process itself.
//!
//! Rebuilt from scratch against the current ports. The previous crate is
//! in git history (`legacy/ianua-infra` at fad68319); a piece taken from it
//! is rewritten to the new ports, never copied as is.
//!
//! Adapters face the outside world, so the crate holds itself to the
//! domain's strictest lints: nothing that can panic, no match that quietly
//! takes in a case added later, and no cast that can lose a value.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]
#![warn(unreachable_pub)]
#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::wildcard_enum_match_arm,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::dbg_macro,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss
    )
)]

pub mod billing;
pub mod bundled;
pub mod bus;
pub mod cache;
pub mod cloud;
pub mod crypto;
pub mod css;
pub mod dns;
pub mod files;
pub mod geo;
pub mod http;
pub mod inbox;
pub mod integrations;
pub mod language;
pub mod mail;
pub mod namespace;
pub mod outbox;
pub mod packages;
pub mod pages;
pub mod postgres;
pub mod proofs;
pub mod reading;
pub mod runtime;
pub mod saml;
pub mod sandbox;
pub mod sms;
#[cfg(feature = "test-support")]
// The test harness stops the run when its database cannot be made: no test
// could go on without it.
#[allow(clippy::expect_used)]
pub mod test_support;
pub mod tls;
pub mod vectors;
