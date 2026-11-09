//! Postgres: where every tenant's records are kept.
//!
//! The machinery every store shares is in [`foundation`]. The stores of
//! each context sit in a folder named after the app's ports of that
//! context, one file per store.
//!
//! What the composition root needs to start the database is named here:
//! the databases, the unit of work, the migrations and the roles the app
//! and the audit purge sign in as.

pub mod activity;
pub mod agents;
pub mod audit;
pub mod authentication;
pub mod authorization;
pub mod branding;
pub mod cloud;
pub mod consumers;
pub mod crypto;
pub mod data_classification;
pub mod directory;
pub mod domain;
pub mod federation;
pub mod foundation;
pub mod identity;
pub mod limits;
pub mod messaging;
pub mod metrics;
pub mod notifications;
pub mod oauth;
pub mod operator;
pub mod organization;
pub mod proxy;
pub mod routing;
pub mod runtime;
pub mod scheduling;
pub mod shared;
pub mod signals;
pub mod tenant;
pub mod webhooks;
pub mod workflows;

pub use foundation::migrations::{migrate_platform, schema_is_current};
pub use foundation::pool::{Databases, DedicatedDatabase, PoolLimits};
pub use foundation::roles::{LoginRole, PlatformRoles, audit_sealed_from, ensure_roles};
pub use foundation::unit::PgUnitOfWork;
