/// Marks a [`SecureToken`](crate::domains::identity::tokens::secure::SecureToken) as a password
/// reset token.
///
/// The compiler then refuses a reset token where an email verification or
/// magic link token is expected.
#[derive(Debug)]
pub struct PasswordReset;
