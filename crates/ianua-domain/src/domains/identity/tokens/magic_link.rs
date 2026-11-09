/// Marks a [`SecureToken`](crate::domains::identity::tokens::secure::SecureToken) as a magic link
/// token, for signing in without a password.
///
/// The compiler then refuses it where an email verification or password
/// reset token is expected.
#[derive(Debug)]
pub struct MagicLink;
