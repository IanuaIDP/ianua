use crate::shared::security::constant_time::same_secret;

/// A one-way digest of a high-entropy secret.
///
/// The secret may be a session or reset token, an authorization or device
/// code, a recovery code, a client secret or an API key. Its owner gets it
/// once and it is never kept. This digest is kept instead, and a presented
/// secret is looked up and compared by it. It is its own type, so a raw
/// token is never stored, compared or bound where its digest was meant, nor
/// the other way round.
///
/// It has no `Display`, and its `Debug` output is redacted. A digest is a
/// lookup key, and one that reaches a log is one more copy to guard. Two
/// digests compare in a time that does not show where they differ, so a
/// presented token cannot be found a byte at a time.
#[derive(Clone, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenHash(String);

impl PartialEq for TokenHash {
    fn eq(&self, other: &Self) -> bool {
        same_secret(self.0.as_bytes(), other.0.as_bytes())
    }
}

impl std::hash::Hash for TokenHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl std::fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TokenHash").field(&"<redacted>").finish()
    }
}

impl TokenHash {
    /// Wraps a digest made by the token hasher or read from storage.
    ///
    /// It is not checked, since a trusted hasher made it and it was stored
    /// as is.
    #[must_use]
    pub fn from_stored(hash: String) -> Self {
        Self(hash)
    }

    /// The digest, for storage and lookup.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session token's digest printed in a debug log shows the type name
    /// but not the digest, so the log holds no copy of the lookup key.
    #[test]
    fn debug_does_not_print_the_digest() {
        let hash = TokenHash::from_stored("distinctivedigest".to_owned());

        let rendered = format!("{hash:?}");

        assert!(!rendered.contains("distinctivedigest"), "{rendered}");
        assert!(rendered.contains("TokenHash"), "{rendered}");
    }

    /// A digest read from storage as `abc123` gives back `abc123` for
    /// lookup.
    #[test]
    fn a_stored_digest_reads_back_as_written() {
        let hash = TokenHash::from_stored("abc123".to_owned());

        assert_eq!(hash.as_str(), "abc123");
    }
}
