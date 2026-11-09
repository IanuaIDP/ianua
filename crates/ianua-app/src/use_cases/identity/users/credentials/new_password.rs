//! Settling the password an account is given when an admin creates or resets
//! it: the one supplied, or one generated to the same rules.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::random::RandomSource;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{PasswordHash, PasswordPolicy};

use crate::error::{AppError, OrInternal};
use crate::ports::runtime::SecureRandom;
use crate::services::authentication::password_hashing::PasswordHashing;

/// Makes the passwords an admin hands out: checks a supplied one against the
/// tenant's rules, or draws one that meets them, and hashes it.
pub struct PasswordMaker {
    hashing: PasswordHashing,
    random: Arc<dyn SecureRandom>,
}

/// A password made for an account, kept apart from its hash.
pub(crate) struct MadePassword {
    /// The password, shown once to whoever asked for it.
    pub(crate) secret: Secret,
    /// What is stored.
    pub(crate) hash: PasswordHash,
    /// Whether it was drawn rather than supplied.
    origin: PasswordOrigin,
}

/// Where a made password came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PasswordOrigin {
    /// The admin supplied it.
    Supplied,
    /// It was drawn from the random source.
    Generated,
}

impl MadePassword {
    /// The password, when it was drawn rather than supplied: the only one
    /// whoever asked does not know yet.
    pub(crate) fn generated(self) -> Option<Secret> {
        (self.origin == PasswordOrigin::Generated).then_some(self.secret)
    }
}

impl PasswordMaker {
    /// Passwords hashed through `hashing`, drawn from `random` when none is
    /// given.
    #[must_use]
    pub fn new(hashing: PasswordHashing, random: Arc<dyn SecureRandom>) -> Self {
        Self { hashing, random }
    }

    /// The supplied password once it meets `policy`, or a fresh one drawn to
    /// `policy` when none was given, with its hash.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the supplied password violates `policy`.
    /// - `AppError::Busy` if no hash could start on this node in time.
    /// - `AppError::Internal` if drawing or hashing fails.
    pub(crate) async fn made(
        &self,
        policy: &PasswordPolicy,
        supplied: Option<String>,
    ) -> Result<MadePassword, AppError> {
        let (secret, origin) = match supplied {
            Some(password) => (checked(policy, password)?, PasswordOrigin::Supplied),
            None => (self.drawn(policy)?, PasswordOrigin::Generated),
        };
        let hasher = self.hashing.permitted().await?;
        let hash = hasher.hash(secret.expose()).or_internal()?;
        Ok(MadePassword {
            secret,
            hash,
            origin,
        })
    }

    /// A password drawn to `policy`.
    fn drawn(&self, policy: &PasswordPolicy) -> Result<Secret, AppError> {
        policy
            .generate(&mut Drawn(self.random.as_ref()))
            .map_err(AppError::from_domain)
    }
}

/// `password` once it meets `policy`.
fn checked(policy: &PasswordPolicy, password: String) -> Result<Secret, AppError> {
    policy
        .validate(&password)
        .map_err(|e| AppError::Domain(DomainError::Validation(e)))?;
    Ok(Secret::new(password))
}

/// The maker's secure source, lent to the domain's password rules.
struct Drawn<'a>(&'a dyn SecureRandom);

impl RandomSource for Drawn<'_> {
    fn index_below(&mut self, upper: usize) -> usize {
        self.0.index_below(upper)
    }
}
