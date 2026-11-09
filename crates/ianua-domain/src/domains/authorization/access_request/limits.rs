//! The longest a tenant lets its people ask for access.

use std::num::NonZeroU32;

use crate::domains::authorization::access_request::MAX_ACCESS_LENGTH;
use crate::shared::errors::DomainError;
use crate::types::Lifetime;

/// The longest a tenant lets its people ask for access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessRequestLimits {
    longest: Lifetime,
}

impl AccessRequestLimits {
    /// Requests of up to `MAX_ACCESS_LENGTH`: what a tenant allows until
    /// it sets a shorter limit.
    pub const WIDEST: Self = Self {
        longest: Lifetime::from_secs(NonZeroU32::new(2_592_000).unwrap()),
    };

    /// Requests of at most `longest`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `longest` is past
    ///   `MAX_ACCESS_LENGTH`.
    pub fn new(longest: Lifetime) -> Result<Self, DomainError> {
        longest.ensure_at_most(MAX_ACCESS_LENGTH, "access asked for")?;
        Ok(Self { longest })
    }

    /// The longest a request may ask for.
    #[must_use]
    pub fn longest(&self) -> Lifetime {
        self.longest
    }
}
