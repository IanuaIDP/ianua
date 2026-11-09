//! The tenants' memories, each table row under row-level security, and the
//! texts they keep with their vectors, in pgvector beside them.

mod entries;
mod store;

pub use entries::{PgMemoryEntries, PgTenantMemoryPurger};
pub use store::{PgCrossTenantMemories, PgMemoryStore};
