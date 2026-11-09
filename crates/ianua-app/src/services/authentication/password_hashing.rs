//! Hashing and checking passwords under the node's cap on how many run at
//! once.
//!
//! A use case never holds the password hasher itself. It holds a
//! [`PasswordHashing`], which hands out a hasher only together with a
//! permit, and the permit goes back when the hasher is dropped. So there is
//! no path that hashes without a permit, and no fallback that hashes when
//! none is free: the caller is told the node is busy instead.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::password::PasswordHasher;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::PasswordHash;

use crate::error::AppError;
use crate::ports::authentication::{HashPermit, PasswordHashPermits};

/// The password hasher, reachable only through a permit.
#[derive(Clone, ianua_macros::Fakes)]
pub struct PasswordHashing {
    hasher: Arc<dyn PasswordHasher>,
    permits: Arc<dyn PasswordHashPermits>,
}

impl PasswordHashing {
    /// Hashing with `hasher`, each hash taking one of `permits` first.
    #[must_use]
    pub fn new(hasher: Arc<dyn PasswordHasher>, permits: Arc<dyn PasswordHashPermits>) -> Self {
        Self { hasher, permits }
    }

    /// The hasher, holding a permit until it is dropped. Drop it as soon as
    /// the hash is done, so the permit is not held across other work.
    ///
    /// # Errors
    ///
    /// - `AppError::Busy` when every permit stayed taken for the whole
    ///   wait. Nothing was hashed.
    pub async fn permitted(&self) -> Result<PermittedHasher<'_>, AppError> {
        let permit = self.permits.take().await.map_err(|_| AppError::Busy)?;
        Ok(PermittedHasher {
            hasher: self.hasher.as_ref(),
            _permit: permit,
        })
    }
}

/// The password hasher while it holds a permit.
pub struct PermittedHasher<'a> {
    hasher: &'a dyn PasswordHasher,
    _permit: HashPermit,
}

impl PasswordHasher for PermittedHasher<'_> {
    fn hash(&self, raw_password: &str) -> Result<PasswordHash, DomainError> {
        self.hasher.hash(raw_password)
    }

    fn verify(&self, raw_password: &str, hash: &PasswordHash) -> Result<bool, DomainError> {
        self.hasher.verify(raw_password, hash)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::test_support::fakes::FakeHasher;

    use super::*;
    use crate::test_support::authentication::{BusyHashPermits, CountingHasher, FakeHashPermits};
    use crate::test_support::block_on;

    /// A hash taken through a permit runs, and the permit is back once the
    /// hasher is dropped.
    #[test]
    fn a_permitted_hash_runs_and_hands_its_permit_back() {
        let permits = Arc::new(FakeHashPermits::default());
        let hashing = PasswordHashing::new(Arc::new(FakeHasher), permits.clone());

        let hasher = block_on(hashing.permitted()).unwrap();
        let held = permits.held();
        let hashed = hasher.hash("correct horse");
        drop(hasher);

        assert!(hashed.is_ok());
        assert_eq!(held, 1);
        assert_eq!(permits.held(), 0);
    }

    /// When the permit provider reports busy, obtaining a hasher returns
    /// busy and the underlying hasher records no work.
    #[test]
    fn a_busy_node_refuses_before_any_hash_runs() {
        let hasher = Arc::new(CountingHasher::default());
        let hashing = PasswordHashing::new(hasher.clone(), Arc::new(BusyHashPermits));

        let result = block_on(hashing.permitted());

        assert!(matches!(result, Err(AppError::Busy)));
        assert_eq!(hasher.hashed(), 0);
    }
}
