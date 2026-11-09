//! The tenant signing people in through an outside SAML provider, Acme's,
//! and keeping that link working as the provider changes: Pat signs in on
//! the dashboard through it, and the provider checks the platform's
//! messages with its own code.
//!
//! - `details`: which addresses are sent to the provider, switching a
//!   connection off and on and deleting it, mapping the provider's groups
//!   to roles, requiring sealed assertions and removing a user's link.
//! - `rollover`: the provider rolls its signing key over; while both keys
//!   stand either signs Pat in, and once Tess rolls the connection over
//!   the old one signs nobody in.
//! - `requests`: once Tess asks, the requests the platform sends the
//!   provider carry a signature the connection's published certificate
//!   made, and a changed one fails the check.
//! - `metadata`: a connection following the provider's published
//!   metadata takes its next key, and drops the old one, without Tess.
//! - `logout`: single logout with the provider either way. Its request
//!   ends Pat's session and is answered signed; Pat signing out at the
//!   platform sends the provider a signed request for her session, whose
//!   answer is taken.

#![cfg(test)]

mod details;
mod logout;
mod metadata;
mod requests;
mod rollover;
mod support;
