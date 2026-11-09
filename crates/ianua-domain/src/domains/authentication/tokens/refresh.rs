//! Refresh tokens: an opaque random token and its one-way hash.
//!
//! A session gets a random refresh token when it opens. The session keeps
//! only the hash, and the client gets the raw token. On refresh, the client
//! presents the raw token. The system hashes it and looks up the session
//! with that hash.

use crate::shared::errors::DomainError;
use crate::shared::security::secret::Secret;
use crate::types::TokenHash;

/// A generated refresh token: the raw value and its one-way hash.
pub struct RefreshToken {
    /// The raw opaque token sent to the client.
    raw: Secret,
    /// The one-way hash stored in the session.
    hash: TokenHash,
}

impl RefreshToken {
    /// A refresh token from its raw value and the hash of that value.
    #[must_use]
    pub fn new(raw: Secret, hash: TokenHash) -> Self {
        Self { raw, hash }
    }

    /// The raw opaque token. It goes to the client and is never stored.
    #[must_use]
    pub fn raw(&self) -> &Secret {
        &self.raw
    }

    /// The one-way hash, stored in the session.
    #[must_use]
    pub fn hash(&self) -> &TokenHash {
        &self.hash
    }

    /// The raw token and the hash, in that order.
    #[must_use]
    pub fn into_parts(self) -> (Secret, TokenHash) {
        (self.raw, self.hash)
    }
}

/// Makes opaque refresh tokens.
///
/// Infrastructure implements it with a secure random source, such as
/// `rand::rngs::OsRng`, and a one-way hash such as SHA-256.
///
/// # Implementors
///
/// - **Infrastructure:** `TokenGenerator`, using random bytes and SHA-256.
/// - **Tests:** `test_support::fakes::FakeRefreshTokenGenerator`, behind the
///   `test-support` feature. It returns predictable values.
pub trait RefreshTokenGenerator: Send + Sync {
    /// A new opaque refresh token and its hash.
    ///
    /// # Errors
    ///
    /// - [`DomainError`] when the random source or the hash fails.
    fn generate(&self) -> Result<RefreshToken, DomainError>;

    /// The hash of a raw token, used to look up its session on refresh.
    ///
    /// It must give the same hash that `generate()` gave for the same token.
    fn hash_raw(&self, raw: &str) -> TokenHash;
}

impl<T: RefreshTokenGenerator + ?Sized> RefreshTokenGenerator for std::sync::Arc<T> {
    fn generate(&self) -> Result<RefreshToken, DomainError> {
        (**self).generate()
    }

    fn hash_raw(&self, raw: &str) -> TokenHash {
        (**self).hash_raw(raw)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// A generator whose hash depends on the input, so a forwarded call can
    /// be told apart from a stubbed one.
    struct Reversing;

    impl RefreshTokenGenerator for Reversing {
        fn generate(&self) -> Result<RefreshToken, DomainError> {
            Ok(RefreshToken::new(
                Secret::new("raw-token"),
                TokenHash::from_stored("nekot-war".to_owned()),
            ))
        }

        fn hash_raw(&self, raw: &str) -> TokenHash {
            TokenHash::from_stored(raw.chars().rev().collect())
        }
    }

    /// Through the shared `Arc` handle the app layer holds, "raw-token" and
    /// "other-token" hash to different values from the inner generator. A
    /// fixed answer would map every token to the same session.
    #[test]
    fn a_shared_generator_hashes_the_token_it_was_given() {
        let shared: Arc<Reversing> = Arc::new(Reversing);

        assert_eq!(shared.hash_raw("raw-token").as_str(), "nekot-war");
        assert_eq!(
            shared.hash_raw("other-token").as_str(),
            "nekot-rehto",
            "two tokens must not hash alike"
        );
        assert_eq!(shared.generate().unwrap().hash().as_str(), "nekot-war");
    }

    /// A token hands back its raw value and its hash unswapped, both through
    /// the getters and through `into_parts`. The raw value goes to the client
    /// and the hash to the session row.
    #[test]
    fn a_token_keeps_its_raw_value_and_hash_apart() {
        let token = RefreshToken::new(
            Secret::new("raw-token"),
            TokenHash::from_stored("nekot-war".to_owned()),
        );

        assert_eq!(token.raw().expose(), "raw-token");
        assert_eq!(token.hash().as_str(), "nekot-war");
        let (raw, hash) = token.into_parts();
        assert_eq!(raw.expose(), "raw-token");
        assert_eq!(hash, TokenHash::from_stored("nekot-war".to_owned()));
    }
}
