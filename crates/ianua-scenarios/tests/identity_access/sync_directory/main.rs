//! A company's directory keeping the tenant's people and groups over
//! SCIM 2.0, and what that changes for who signs in and what they may do,
//! on the platform and through its LDAP directory.
//!
//! - `discovery`: the directory reads the endpoint's abilities, record
//!   kinds and schemas before any token, then provisions where they
//!   point; `/Me` is not offered.
//! - `people`: the directory renames and readdresses Pat without proving
//!   her new mailbox, finds her by its search, may not make a second Pat,
//!   deactivates and reactivates her, and removes people as Tess set it.
//! - `groups`: Pat holds what her directory group's role allows only while
//!   the directory keeps her in it.
//! - `ldap`: an LDAP app finds Pat and her group as the directory keeps
//!   them, Pat binds with her own password, and once deactivated binds no
//!   more.
//! - `users`: a person's whole record read back, every patch form, finding
//!   and paging people, clashing records, the accounts it may never move,
//!   and the tenant's user limit.
//! - `memberships`: a group's whole life, the group writes refused, the
//!   groups a person keeps out of its reach, whose access its replaced
//!   lists move, and the tenant's group limit.
//! - `link`: the token that opens one tenant's directory, a link paused
//!   and switched back on, and what the endpoint does with the people it
//!   makes.
//! - `ldap_apps`: what a service account reaches and how it is ended, the
//!   binds that reach nothing, the writes a person may make, and SCIM's
//!   changes as an LDAP app reads them.

#![cfg(test)]

mod discovery;
mod groups;
mod ldap;
mod ldap_apps;
mod link;
mod memberships;
mod people;
mod support;
mod users;
