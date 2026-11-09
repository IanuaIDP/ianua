//! Connection handlers, by app area: a connection's life, its SAML
//! specifics, its group mapping, and home realm discovery.

pub mod discover;
pub mod groups;
pub mod lifecycle;
pub mod saml;
