//! The names a tenant's apps answer on: Tess puts Wiki on the tenant's
//! random platform label, flat or nested under the apps domain, where it
//! answers on that label and on no other tenant's; Pat signs in to Wiki
//! there; and a readable name answers only once Tess opts the tenant in,
//! stopping again when she opts out. Every choice is in the audit trail.
//!
//! - `flat`: Wiki on the tenant's flat random label, reached by everyone
//!   and on no other label; Pat signs in there and is stopped after
//!   signing out.
//! - `nested`: Wiki on the nested random label, served over TLS from the
//!   certificates the worker orders; a readable name follows Tess's
//!   consent.
//! - `domains`: a domain of the tenant's own held against everyone else,
//!   refused at the handshake once removed, and carrying nothing of its
//!   old routes to its next owner.

mod domains;
mod flat;
mod nested;
