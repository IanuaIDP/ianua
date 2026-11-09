//! The LDAP server: the tenant directory for clients that speak only LDAP,
//! such as `ldapsearch`, SSSD, Jira or GitLab.
//!
//! People bind with their password over the client certificate their
//! connection presents; applications bind as their service account with
//! its secret. A bound connection searches the tenant it bound to, and a
//! person writes users and groups with their own rights. Every one of
//! these is a directory use case's decision: this crate reads LDAP, asks
//! the use case, and encodes its answer, refusing wherever an answer is
//! missing or failed.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

pub mod config;
pub mod dit;
pub mod error;
mod ip_throttle;
mod ops;
pub mod ports;
mod server;
mod session;
pub mod tls;

pub use config::{LdapConfig, LdapLimits, LdapTls};
pub use error::LdapError;
pub use ports::{GroupWrites, LdapPorts, Targets, UserWrites};
pub use server::LdapServer;
pub use tls::ReloadableAcceptor;
