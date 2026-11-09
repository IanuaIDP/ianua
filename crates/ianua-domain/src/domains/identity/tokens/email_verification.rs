/// Marks a [`SecureToken`](crate::domains::identity::tokens::secure::SecureToken) as an email
/// verification token.
///
/// The compiler then refuses it where a password reset or magic link token
/// is expected.
#[derive(Debug)]
pub struct EmailVerification;
