//! SAML as a service provider: the sign-in requests a tenant's connections
//! sent and keep until they are answered, and the assertions they spent.
//! The stores of `ports/federation/saml.rs`.

mod assertions;
mod requests;

pub use assertions::PgSamlAssertionLedger;
pub use requests::PgSamlRequestStore;
