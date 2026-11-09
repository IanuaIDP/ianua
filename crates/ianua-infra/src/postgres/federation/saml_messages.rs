//! Single logout: the logout requests a tenant sent and keeps until they
//! are answered, the ones its peers sent that were taken, and the provider
//! sessions a logout names. The stores of
//! `ports/federation/saml_messages.rs`.

mod logout_requests;
mod provider_sessions;
mod taken_logouts;

pub use logout_requests::PgSentLogoutRequestStore;
pub use provider_sessions::PgProviderSessionStore;
pub use taken_logouts::PgSamlLogoutLedger;
