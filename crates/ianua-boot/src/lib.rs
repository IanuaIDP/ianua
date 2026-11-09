//! What every composition root starts from: the environment and its
//! readers, the environment kind, the logs, the one stop signal, the
//! network settings both roots read alike, and the readers of the
//! foundation every process is built on (the database, the keys, the bus,
//! the shared state and the file store).
//!
//! The server and the gateway are both outermost, so they share this
//! crate rather than each other: neither depends on the other, and both
//! read a setting the same way. The foundation readers are split by role,
//! so a process reads what it holds and nothing more: the gateway reads
//! the shared root and the sealing keys and never the control plane's
//! root, and each process names the database role it signs in as.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(unreachable_pub)]

pub mod env;
pub mod environment;
pub mod foundation;
pub mod hosts;
pub mod internal_link;
pub mod logging;
pub mod network;
pub mod shutdown;
pub mod tunnel;
