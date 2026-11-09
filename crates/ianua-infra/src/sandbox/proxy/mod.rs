//! The network filter a version's code reaches its allowed hosts through,
//! and nothing else: the filter itself ([`SandboxProxy`]), the signed
//! ticket each run shows it, and how a runner gives a run its ticket
//! ([`ProxyAccess`]).
//!
//! A sandbox that may reach the network still has no route of its own: it
//! reaches only the filter, which opens an encrypted tunnel to a host the
//! ticket names, on port 443, when that host's name leads somewhere public.

mod access;
mod serving;
mod ticket;

pub use access::ProxyAccess;
pub(super) use access::{RunNetwork, run_network};
pub use serving::{ProxyServing, SandboxProxy, Upstreams};
pub use ticket::TicketKey;
