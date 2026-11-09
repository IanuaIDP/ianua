//! Ids SAML messages carry, and of the apps signed in to over SAML.

/// Id of a SAML sign-in request held on the server since it arrived.
pub(crate) mod arrival;
/// The `ID` of a SAML assertion, used to spot replays.
pub(crate) mod assertion;
/// The `ID` of a SAML `AuthnRequest`.
pub(crate) mod request;
/// The `ID` of a SAML response this platform sends.
pub(crate) mod response;
/// Id of an app a tenant signs people in to over SAML.
pub(crate) mod service_provider;
/// A SAML assertion's session index.
pub(crate) mod session_index;

pub use arrival::SamlArrivalId;
pub use assertion::SamlAssertionId;
pub use request::SamlRequestId;
pub use response::SamlResponseId;
pub use service_provider::SamlServiceProviderId;
pub use session_index::SessionIndex;
