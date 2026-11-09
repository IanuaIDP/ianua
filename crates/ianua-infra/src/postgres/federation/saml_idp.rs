//! SAML as an identity provider: the tenant's SAML apps, the apps each
//! session signed in to, and the sign-in requests held until they are
//! answered. The stores of `ports/federation/saml_idp.rs`.

mod app_sessions;
mod apps;
mod held_sign_ins;

pub use app_sessions::PgSamlAppSessionStore;
pub use apps::PgSamlServiceProviderStore;
pub use held_sign_ins::PgHeldSamlSignInStore;
