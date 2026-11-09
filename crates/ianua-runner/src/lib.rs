//! `ianua-runner`: the runner beside an agent's sandbox, the agent's only
//! way out.
//!
//! An agent runs where nothing routes anywhere but its runner, on the
//! address the runner listens on. The runner holds the agent's key and its
//! task tokens; the agent holds nothing worth taking. For every request the
//! agent sends, the runner drops every header that could carry an identity
//! or a credential, attaches the task token the destination takes, and for
//! the gateway a proof of possession made with the agent's key for that
//! request alone, then streams it on: to the gateway, which decides it as it
//! decides any agent's request, or for `/_ianua/messages/{topic}` to the
//! message relay. Its answer comes back without a session the agent could
//! keep.
//!
//! The key is made in the runner's memory and enrolled by attesting the
//! runner's workload with its SPIFFE SVID, signing the binding of the
//! platform's nonce and that key, or mounted for clusters without SPIRE.
//! What a request carries is the app's `agents::runner` use cases; the
//! rules are the domain's `agents::runner`; the key, the tokens and the
//! proofs are infra's adapters. This crate reads the settings, builds them,
//! and runs the listener.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(unreachable_pub)]

pub mod config;
pub mod error;
pub mod handler;
pub mod listen;
pub mod outbound;
mod parts;
pub mod serve;

pub use serve::{run, serving};
