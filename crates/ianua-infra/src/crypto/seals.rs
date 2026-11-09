//! Keyed seals and digests: the keyed digest every handed-out secret is
//! kept as, the seals on sealed requests, receipts and the audit chain, and
//! the seals events, live updates and the gateway's shared verdicts carry
//! on the bus.

pub(crate) mod broadcasts;
pub(crate) mod digests;
pub(crate) mod events;
pub(crate) mod fleet;
