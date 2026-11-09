//! The groups a directory keeps, record by record: what it writes and
//! reads back, the writes it cannot make, the groups a person keeps that
//! it cannot reach, whose access its replaced lists move, and the room the
//! tenant has for them.
//!
//! - `records`: Finance made, read back with its version, found by name,
//!   renamed, its members added, replaced and removed, replaced whole, and
//!   deleted, each change recorded.
//! - `refusals`: a taken name, members who are nobody, too many members in
//!   one write, a `sortBy` on groups and unreadable member paths refused
//!   in SCIM's terms; a group the directory does not keep not found.
//! - `dashboard`: the group Tess keeps is out of the directory's sight and
//!   reach, but its name is still taken.
//! - `access`: a list the directory replaces moves the group's access from
//!   Pat to Uma.
//! - `limits`: no group is made past the tenant's group limit.

mod access;
mod dashboard;
mod limits;
mod records;
mod refusals;
