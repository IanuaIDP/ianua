//! A tenant's connections to outside identity providers, the connections
//! that follow a metadata address, the accounts linked through them, and
//! what their group mappings gave each person: the stores of
//! `ports/federation/connections.rs`.
//!
//! How a connection's settings are kept, and the words of its choices, are
//! written once here, in `config` and `words`, and shared with the
//! organization's own identity provider.

pub(crate) mod config;
mod followers;
mod holdings;
mod links;
mod providers;
mod words;

pub use followers::PgMetadataFollowers;
pub use holdings::PgMappedHoldingsStore;
pub use links::PgFederatedLinkStore;
pub use providers::PgConnectionStore;
