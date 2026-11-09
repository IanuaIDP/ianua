use crate::shared::errors::DomainError;
use crate::types::PasswordHash;

/// Hashes passwords and checks them against stored hashes.
///
/// Infrastructure implements it, for example with argon2.
///
/// # Security contract
///
/// Implementors must:
/// - Use a memory-hard algorithm. Argon2id is recommended.
/// - Generate a unique random salt per hash.
/// - Produce a self-describing output in PHC string format.
/// - Compare in constant time during verification.
///
/// # Implementors
///
/// - **Infrastructure:** `Argon2Hasher` using the `argon2` crate.
/// - **Tests:** `FakeHasher`, which is fast and never used in production.
pub trait PasswordHasher: Send + Sync {
    /// Hashes a raw password into a form that is safe to store.
    ///
    /// # Errors
    ///
    /// - [`DomainError`] when the hashing algorithm fails, for example when
    ///   argon2 runs out of memory.
    fn hash(&self, raw_password: &str) -> Result<PasswordHash, DomainError>;

    /// Whether a raw password matches a stored hash.
    ///
    /// The comparison must run in constant time. Otherwise the time it takes
    /// tells an attacker how much of a guess was right.
    ///
    /// # Errors
    ///
    /// - [`DomainError`] when the stored hash is malformed.
    /// - [`DomainError`] when the verification algorithm fails.
    fn verify(&self, raw_password: &str, hash: &PasswordHash) -> Result<bool, DomainError>;
}

impl<T: PasswordHasher + ?Sized> PasswordHasher for std::sync::Arc<T> {
    fn hash(&self, raw_password: &str) -> Result<PasswordHash, DomainError> {
        (**self).hash(raw_password)
    }

    fn verify(&self, raw_password: &str, hash: &PasswordHash) -> Result<bool, DomainError> {
        (**self).verify(raw_password, hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An argon2 hash loaded from the database reads back as the same text,
    /// so the hasher can parse its parameters.
    #[test]
    fn from_stored_preserves_value() {
        let hash = PasswordHash::from_stored("$argon2id$v=19$m=65536,t=3,p=4$salt$hash".to_owned());
        assert_eq!(hash.as_str(), "$argon2id$v=19$m=65536,t=3,p=4$salt$hash");
    }

    /// `PasswordHash` has no `Display`, so the hash cannot end up in logs or
    /// error messages. This test marks the rule. Adding `Display` is the
    /// change to avoid.
    #[test]
    fn password_hash_does_not_implement_display() {
        let hash = PasswordHash::from_stored("secret_hash".to_owned());
        let _ = hash;
    }

    /// A hasher that answers on the password, so a forwarded call can be
    /// told apart from a stubbed one.
    struct Prefixing;

    impl PasswordHasher for Prefixing {
        fn hash(&self, raw_password: &str) -> Result<PasswordHash, DomainError> {
            Ok(PasswordHash::from_stored(format!("fake${raw_password}")))
        }

        fn verify(&self, raw_password: &str, hash: &PasswordHash) -> Result<bool, DomainError> {
            Ok(hash.as_str() == format!("fake${raw_password}"))
        }
    }

    /// Every password login uses this port behind an `Arc`. Ann's right
    /// password must pass and a wrong one must fail through the shared
    /// handle, so the forward really reaches the inner hasher.
    #[test]
    fn a_shared_hasher_checks_the_password_against_the_stored_hash() {
        let shared: std::sync::Arc<Prefixing> = std::sync::Arc::new(Prefixing);
        let stored = shared.hash("correct horse").unwrap();

        assert_eq!(stored.as_str(), "fake$correct horse");
        assert!(shared.verify("correct horse", &stored).unwrap());
        assert!(
            !shared.verify("wrong horse", &stored).unwrap(),
            "a wrong password must stay wrong through the shared handle"
        );
    }
}
