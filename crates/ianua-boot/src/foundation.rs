//! What every process is built from: the database, the keys, the bus, the
//! shared state and the file store, each read by the role the process
//! plays, and the namespace the bus's and the cache's names sit under.

pub mod bus;
pub mod cache;
pub mod crypto;
pub mod database;
pub mod files;
pub mod namespace;

pub use bus::{BusConfig, BusPlace};
pub use cache::{CacheConfig, CachePlace};
pub use crypto::{CryptoConfig, HashSettings, SharedKeys, control_root};
pub use database::{
    AppDatabaseSettings, ControlPlaneLogins, DatabaseConfig, DatabaseLogin, DatabaseRole,
};
pub use files::FilesConfig;
