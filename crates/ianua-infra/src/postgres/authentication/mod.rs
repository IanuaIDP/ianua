//! The stores of the authentication context: a tenant's passwords, second
//! factors, passkeys, sign-in codes, trusted devices, sign-in history and
//! break-glass grants, each table under row-level security.
//!
//! A ports file holding one store has it here; one holding several has a
//! folder of the same name, so the context reads as the app's ports do.
//! Tenant sessions, and the check of an app session against them, are in
//! `postgres::shared::sessions`.

mod app_sign_in;
mod credentials;
mod passkeys;
mod sent_codes;
pub(crate) mod sign_in;

pub use app_sign_in::{PgHandoffStore, PgMfaChallengeStore};
pub use credentials::{
    PgCredentialStore, PgFactorStanding, PgMfaEnrollmentStore, PgPasswordHistory,
    PgRecoveryCodeStore, PgResetRequestStore,
};
pub use passkeys::{PgPasskeyCeremonyStore, PgPasskeyStore};
pub use sent_codes::PgSentCodeStore;
pub use sign_in::{
    PgBreakGlassStore, PgDeviceStandings, PgSignInCodeStore, PgSignInHistoryStore,
    PgTrustedDeviceStore, PgUserLookup,
};
