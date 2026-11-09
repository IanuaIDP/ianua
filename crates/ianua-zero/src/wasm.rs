//! The sandbox a `Custom` stage runs a tenant's WASM module in.
//!
//! One [`WasmEngine`] serves the whole process; every call gets a fresh
//! store, so nothing one call does reaches the next. Modules are read
//! through the application's `WasmModuleStore` and compiled once per
//! version into a bounded cache, keyed by tenant and content-addressed
//! reference, so a reference always names the same bytes.
//!
//! Each call is held to the stage's time and memory limits and to a fuel
//! budget, and only so many run at once. The guest sees one import,
//! `env.get_request`, which hands it the input the stage built, and must
//! export `memory` and `evaluate`. No WASI is linked, so a module built
//! for it fails to instantiate.
//!
//! Deny by default: a module that is missing, does not compile, does not
//! instantiate, traps, runs out of fuel or time, grows past its memory or
//! answers with anything malformed comes to [`Verdict::Refused`], never to
//! a pass. The guest may pass, deny, challenge or add headers; it cannot
//! choose where a request goes.
//!
//! [`WasmRuntime::run`] is what the `Custom` stage calls.

mod abi;
mod cache;
mod engine;
mod failure;
mod runtime;

pub(crate) use abi::{GuestInput, MAX_INPUT_BYTES, Verdict};
pub(crate) use engine::WasmEngine;
#[cfg(test)]
pub(crate) use failure::Failure;
pub(crate) use runtime::{WasmBounds, WasmRuntime};
