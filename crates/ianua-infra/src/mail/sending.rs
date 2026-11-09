//! How a rendered mail leaves: the accounts it goes out through, the
//! message as the provider is handed it, and the providers themselves,
//! SMTP or a provider's own API.

pub(in crate::mail) mod accounts;
pub(in crate::mail) mod apis;
pub(in crate::mail) mod delivery;
pub(in crate::mail) mod message;
pub(in crate::mail) mod smtp;
pub(in crate::mail) mod transport;
