//! The gateway's composition root: every adapter, use case and table it
//! runs on, built once from its configuration, and its listeners opened.
//!
//! [`foundation`] reaches the database as the gateway's own role, holds the
//! keys made from the shared root (never the control plane's), and
//! connects the bus and the cache. [`stores`] builds every store under
//! that role, [`use_cases`] every application use case the stages and the
//! handler call, [`stages`] the five stage groups and their dispatcher,
//! and [`tables`] what the follower fills. [`start`] wires them together,
//! starts what runs beside the requests (the config follower, the stream
//! listeners, the fleet, the health probes, the name lookups, the record
//! batches) and opens the public, status, ACME and runner listeners.

pub mod foundation;
pub mod stage_ports;
pub mod stages;
pub mod start;
pub mod stores;
pub mod tables;
pub mod use_cases;
