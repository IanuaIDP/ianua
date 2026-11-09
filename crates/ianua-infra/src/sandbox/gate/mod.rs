//! Code runs through a gate: on a single server, where handing the worker
//! the container engine's socket would hand it the whole machine.
//!
//! The gate is a process of its own, the only one holding the engine's
//! socket. The worker reaches it over a socket of the gate's, shared with
//! nothing else, and can only ask for a run: the runtime, the exact image
//! and the version's limits, then the run itself. The gate decides the
//! container's lockdown alone ([`SandboxGate`]); the worker's side is
//! [`GateCodeRunner`]. A run the gate refuses or cannot start is reported
//! as no sandbox being free, so it is tried again.

mod client;
mod engine;
mod serving;
mod wire;

pub use client::{GateCodeRunner, GateSettings};
pub use serving::{GateServing, SandboxGate};
