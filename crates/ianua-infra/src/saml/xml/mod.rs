//! The XML under every SAML adapter: reading a document safely, its
//! exclusive canonical form, the algorithms and keys signatures use, and
//! enveloped signatures themselves.

pub(crate) mod canonical;
pub(crate) mod document;
pub(crate) mod keys;
pub(crate) mod signature;
