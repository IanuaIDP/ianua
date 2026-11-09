/// The purpose type for email verification tokens.
pub mod email_verification;
/// The purpose type for an installation's owner setup token.
pub mod installation_setup;
/// The purpose type for magic link sign-in tokens.
pub mod magic_link;
/// The purpose type for password reset tokens.
pub mod password_reset;
/// How long each kind of link may live, and what following it does.
pub mod purpose;
/// The new link an offer gets when its old one ran out.
pub mod renewal;
/// One-time, time-limited tokens stored only as a hash.
pub mod secure;
/// The purpose type for the link that confirms a sign-in by email.
pub mod sign_in_confirmation;
/// The rules every emailed single-use token keeps.
pub(crate) mod single_use;
