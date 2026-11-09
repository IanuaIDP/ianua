//! Services outside the platform that people sign in to through it, each
//! checking what the platform hands it with code of its own:
//!
//! - [`saml`]: a SAML app taking a tenant as its identity provider.

pub mod saml;
