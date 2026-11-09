use crate::shared::security::constant_time::same_secret;

/// An opaque password hash made by a `PasswordHasher`.
///
/// The raw password is never stored and cannot be recovered from it. The
/// string holds the algorithm, salt and hash in a self-describing form, such
/// as an Argon2 PHC string.
///
/// It has no `Display`, and its `Debug` output is redacted, so a hash is not
/// logged by accident. A leaked PHC string can be cracked offline. Two
/// hashes compare in a time that does not show where they differ.
#[derive(Clone, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PasswordHash(String);

impl PartialEq for PasswordHash {
    fn eq(&self, other: &Self) -> bool {
        same_secret(self.0.as_bytes(), other.0.as_bytes())
    }
}

impl std::fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PasswordHash").field(&"<redacted>").finish()
    }
}

impl PasswordHash {
    /// Wraps a hash string read from storage or made by a hasher.
    ///
    /// It is not checked, since a trusted `PasswordHasher` made it and it
    /// was stored as is.
    #[must_use]
    pub fn from_stored(hash: String) -> Self {
        Self(hash)
    }

    /// The hash string, for storage.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Debug output identifies a password hash by its type while withholding
    /// the stored hash material from log readers.
    #[test]
    fn debug_does_not_print_the_hash() {
        let hash = PasswordHash::from_stored("$argon2id$v=19$m=19456$distinctivehash".to_owned());

        let rendered = format!("{hash:?}");

        assert!(
            !rendered.contains("distinctivehash"),
            "the hash appears in Debug output: {rendered}"
        );
        assert!(rendered.contains("PasswordHash"), "{rendered}");
    }
}
