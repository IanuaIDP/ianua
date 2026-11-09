//! `ianua-egress`: the egress gateway, the only way out for the services
//! agents can reach.
//!
//! A service an agent may call could be made to fetch anything, and the
//! request would leave from the service, not the agent. Such services have
//! no route out of their network but this gateway. Each connects with its
//! client certificate, which names it by its SPIFFE ID or its fingerprint;
//! the gateway reads where it wants to go from a `CONNECT` or a plain HTTP
//! request in absolute form, without decrypting anything, and lets it out
//! only to a host and port the one tenant policy written for that service
//! lists. It resolves names itself and never dials an internal address
//! unless told to.
//!
//! When the call carries the assertion the gateway signed onto the agent's
//! request that caused it (`X-Ianua-Assertion`), the agent's data mark is
//! held to what the policy lets out, and a refusal is recorded against the
//! agent as `agents.egress_denied` in the data plane's sealed inbox, which
//! the worker moves onto the audit trail and the agent's drift.
//!
//! The decision is the app's `routing::egress::DecideUseCase`; the rules
//! are the domain's `routing::egress`; the policies, the assertion keys,
//! the marks and the inbox are infra's adapters, read under the data
//! plane's database role. This crate reads the settings, builds them, and
//! runs the listeners.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(unreachable_pub)]

pub mod config;
pub mod dial;
pub mod error;
pub mod handler;
pub mod listen;
mod parts;
pub mod serve;
pub mod status;
pub mod target;
pub mod tls;

pub use serve::{Serving, run, serving};
