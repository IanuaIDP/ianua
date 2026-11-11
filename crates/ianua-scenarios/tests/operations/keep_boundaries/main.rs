//! The public and internal doors, TLS, host names and tenant boundaries
//! refuse callers without the required proof. Refused probes disclose no
//! secrets and leave the intended users, credentials and records usable.
//!
//! - `agent_network`: what an agent and its runner reach on the cluster.
//! - `front_door`: internal endpoints, relay seals, bodies and foreign origins.
//! - `fuzzing`: hostile bodies and ids sent to every endpoint the API
//!   description lists break nothing and keep nobody waiting.
//! - `gateway_door`: obsolete TLS, plaintext, slow headers and SNI boundaries.
//! - `headers`: security headers and responses that cannot be cached.
//! - `hosts`: mailed links use the configured address.
//! - `injection`: SQL, templates and scripts are kept as written and never
//!   run, unkeepable text is a bad request, wildcards search for
//!   themselves, and fields a request does not offer change nothing.
//! - `probing`: unusual paths, methods, scripts and private error details.
//! - `stranger`: cross-tenant reads and writes leave victims unchanged.

#![cfg(test)]

mod agent_network;
mod front_door;
mod fuzzing;
mod gateway_door;
mod headers;
mod hosts;
mod injection;
mod probing;
mod stranger;
