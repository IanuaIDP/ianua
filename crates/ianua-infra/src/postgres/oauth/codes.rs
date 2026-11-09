//! Authorization codes and the consents people give clients: the stores of
//! `ports/oauth/codes.rs`.

mod authorizations;
mod consents;

pub use authorizations::PgAuthCodeStore;
pub use consents::PgOAuthConsentStore;
