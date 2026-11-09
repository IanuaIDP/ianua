//! Browser single sign-on: what the OIDC and SAML ways in share.
//!
//! Going out, the browser is handed a secret, kept in a cookie, whose hash is
//! stored with the request. Coming back, the answer is accepted only from the
//! browser holding it, so nobody can finish in someone else's browser a
//! sign-in they started themselves. The session that results never travels
//! in an address: the browser comes back with a one-time code, and the
//! dashboard swaps the code for the session behind the scenes.

use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::message;
use ianua_domain::shared::config::DisplayNameLimits;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{HttpsUrl, Lifetime, TokenHash, UserId};

use crate::error::{AppError, OrInternal};
use crate::ports::oauth::CodeHasher;

/// A single sign-on on its way to the identity provider.
pub struct SsoStart {
    /// Where to send the browser.
    pub url: HttpsUrl,
    /// The secret the browser keeps until it comes back. Never stored here,
    /// only its hash.
    pub binding: Secret,
}

/// A single sign-on the identity provider vouched for.
pub struct SsoSignIn {
    /// The one-time code the browser carries back to the dashboard.
    pub code: Secret,
    /// Who signed in.
    pub user_id: UserId,
    /// Whether their account was created by this sign-in.
    pub jit_provisioned: bool,
    /// Whether the session still waits on a second factor, or on one being
    /// set up.
    pub second_factor: SecondFactor,
}

/// How single sign-on hands sessions back and makes accounts.
#[derive(Debug, Clone)]
pub struct SsoPolicy {
    /// How long the one-time code standing in for a session can be swapped.
    pub code_lifetime: Lifetime,
    /// How long the name of an account made on first sign-in may be.
    pub display_names: DisplayNameLimits,
}

/// A secret for the browser and its hash for the request.
///
/// # Errors
///
/// Returns `AppError::Internal` when no secret can be made.
pub(crate) async fn bind_browser(hasher: &dyn CodeHasher) -> Result<(Secret, TokenHash), AppError> {
    hasher.generate_code().await.or_internal()
}

/// Refuses an answer brought back by a browser other than the one that
/// started the sign-in.
///
/// # Errors
///
/// - `AppError::Forbidden` when `presented` is not the secret whose hash
///   the request kept.
/// - `AppError::Internal` when the secret cannot be hashed.
pub(crate) async fn ensure_same_browser(
    hasher: &dyn CodeHasher,
    presented: &Secret,
    expected: &TokenHash,
) -> Result<(), AppError> {
    let presented_hash = hasher.hash_code(presented).await.or_internal()?;
    if presented_hash != *expected {
        return Err(AppError::Forbidden(message!(
            "authentication-this-sign-in-was-started-in",
            "this sign-in was started in another browser"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::block_on;
    use crate::test_support::oauth::FakeCodeHasher;

    /// Ann's browser started the sign-in and brings the answer back with
    /// the secret it was given. The answer is accepted.
    #[test]
    fn an_answer_from_the_starting_browser_is_accepted() {
        let hasher = FakeCodeHasher::new();
        let (binding, binding_hash) = block_on(bind_browser(&hasher)).unwrap();

        let result = block_on(ensure_same_browser(&hasher, &binding, &binding_hash));

        assert!(result.is_ok());
    }

    /// An answer carrying another browser's secret fails the sign-in binding check.
    #[test]
    fn an_answer_from_another_browser_is_refused() {
        let hasher = FakeCodeHasher::new();
        let (_, binding_hash) = block_on(bind_browser(&hasher)).unwrap();

        let result = block_on(ensure_same_browser(
            &hasher,
            &Secret::new("another-browser"),
            &binding_hash,
        ));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
