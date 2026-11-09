//! SAML: requests, assertions and metadata.

pub mod assertion;
pub mod assertion_builder;
pub mod authn_request;
pub mod idp_metadata_builder;
/// Single logout, both ways: requests, answers and the requests sent.
pub mod logout;
/// The single logout messages this platform writes.
pub mod logout_builder;
/// The `NameID` a person is named by to a SAML app.
pub mod name_id;
pub mod response_builder;
/// What SAML exchanges with peers leave on the record.
pub mod trail;
mod xml;
