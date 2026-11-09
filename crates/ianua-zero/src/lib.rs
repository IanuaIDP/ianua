//! The gateway: the zero-trust proxy every request to a tenant's apps
//! passes through.
//!
//! It ends the connection, reads the credential, asks the application who
//! the caller is and whether the request may pass, enforces the answer, and
//! forwards or refuses. It decides nothing itself: every decision is a use
//! case or a domain rule, and a decision that is missing, ambiguous or
//! failed is a refusal.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

pub mod app_sign_in;
pub mod boot;
pub mod config;
pub mod connectors;
pub mod error;
pub mod fleet;
pub mod follow;
pub mod forward;
pub mod handler;
pub mod listen;
pub mod observability;
pub mod pipeline;
pub mod request;
pub mod resolve;
pub mod respond;
pub mod runtime;
pub mod serve;
pub mod stream;
pub mod wasm;
