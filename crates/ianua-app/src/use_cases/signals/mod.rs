//! Signals use cases: CAEP/SSE signal streams, their endpoints and the
//! signals pushed to them or held for them to poll.

pub mod caller;
pub mod delivery;
mod lookup;
pub mod reports;
pub mod streams;
pub mod transmit;
