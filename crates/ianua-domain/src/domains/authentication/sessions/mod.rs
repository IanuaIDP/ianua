/// What a session is held to besides itself: its account, as it stands now,
/// and the idle timeout.
pub mod account_check;
pub mod channel;
pub mod fresh_sign_in;
pub mod handoff;
pub mod last_use;
pub mod mfa_challenge;
pub mod mfa_factor;
/// A second factor proved just now, and the account it was proved for.
pub mod proved_factor;
pub mod retention;
/// The tenant session aggregate and its lifecycle.
pub mod session;
pub mod sign_in_code;
pub mod sign_in_progress;
/// Authentication session lifecycle: active, suspended, revoked.
pub mod status;
pub mod timeout;
pub mod way_in;
