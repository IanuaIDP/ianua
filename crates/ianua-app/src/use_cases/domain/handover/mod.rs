//! Handing a domain from one tenant to another of the same organization:
//! an admin of the giving tenant offers it, and an admin of the receiving
//! tenant accepts it. Neither can push or pull a domain alone.

pub(crate) mod accept;
pub(crate) mod offer;

pub use accept::{AcceptDomainPorts, AcceptDomainRequest, AcceptDomainUseCase};
pub use offer::{OfferDomainPorts, OfferDomainRequest, OfferDomainUseCase};
