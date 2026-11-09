//! Passkeys and the ceremonies that register and use them: the stores of
//! `ports/authentication/passkeys.rs`.

mod ceremonies;
mod credentials;

pub use ceremonies::PgPasskeyCeremonyStore;
pub use credentials::PgPasskeyStore;
