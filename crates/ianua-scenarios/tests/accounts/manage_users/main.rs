//! Tess runs her tenant's users: she gives and takes back roles, puts
//! people in groups and takes them out, renames, locks, lets back in and
//! removes them. Every change shows at once on the session the person
//! already holds, and whoever lacks the right is refused with nothing
//! changed and nothing recorded, as is a change the trail cannot record.
//!
//! - `attributes`: the fields the tenant declares and the values its
//!   people hold under them: a field its holder keeps, one only staff keep,
//!   a sensitive one, a required one, withdrawn and discarded.
//! - `details`: a person's own details and the company's records about
//!   them, each replaced as a whole.
//! - `imports`: a batch of accounts opened by a worker, the set-aside
//!   lines named without an address, and an imported password signing in.
//! - `erasure`: staff calling off a person's erasure.
//! - `credentials`: a mailed reset link, a welcome, a lost authenticator
//!   cleared, the sign-in history read and an account switched off, none
//!   of them for someone without the right.
//! - `roles`: a role given and taken back, its permissions changed, a
//!   revocation the trail cannot record, and who may give a role.
//! - `groups`: a group's role reaches its members and leaves them as
//!   they leave it, and who may take someone out of a group.
//! - `standing`: a rename, a lock, a release and a removal each felt at
//!   once, who may change a standing, and a lock the trail cannot record.

#![cfg(test)]

mod attributes;
mod credentials;
mod details;
mod erasure;
mod groups;
mod imports;
mod roles;
mod standing;
mod support;
