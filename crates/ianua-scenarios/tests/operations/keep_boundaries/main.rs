//! The public and internal doors, TLS, host names and tenant boundaries
//! refuse callers without the required proof. Refused probes disclose no
//! secrets and leave the intended users, credentials and records usable.
//!
//! - `agent_network`: what an agent and its runner reach on the cluster.
//! - `front_door`: internal endpoints, relay seals, bodies and foreign origins.
//! - `gateway_door`: obsolete TLS, plaintext, slow headers and SNI boundaries.
//! - `headers`: security headers and responses that cannot be cached.
//! - `hosts`: mailed links use the configured address.
//! - `probing`: unusual paths, methods, scripts and private error details.
//! - `stranger`: cross-tenant reads and writes leave victims unchanged.

#![cfg(test)]

mod agent_network;
mod front_door;
mod gateway_door;
mod headers;
mod hosts;
mod probing;
mod stranger;
