//! Where a memory's vectors come from, and how long each is.
//!
//! A vector only means something beside vectors the same embedding model
//! made, so a memory keeps the model that filled it and the length of its
//! vectors from the day it was made, and every text it keeps or is
//! searched with goes through that model.

use crate::domains::agents::execution::model_provider::ModelName;
use crate::shared::validation::ValidationError;
use crate::shared::validation::numeric::validate_range;
use crate::types::ModelProviderId;

/// The longest vector a memory keeps: past every common embedding model's.
pub(crate) const MAX_VECTOR_SIZE: u16 = 4096;

/// Where a memory's vectors come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbeddingSource {
    /// The platform's own embedding server, with the model it served when
    /// the memory was made.
    Platform(ModelName),
    /// One of the tenant's model providers, with the embedding model it
    /// offered when the memory was made.
    Provider {
        /// The tenant connection supplying vectors for this collection.
        provider_id: ModelProviderId,
        /// Its embedding model.
        model: ModelName,
    },
}

impl EmbeddingSource {
    /// The embedding model that fills the memory.
    #[must_use]
    pub fn model(&self) -> &ModelName {
        match self {
            Self::Platform(model) | Self::Provider { model, .. } => model,
        }
    }

    /// The stored kind, `platform` or `provider`.
    #[must_use]
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::Platform(_) => "platform",
            Self::Provider { .. } => "provider",
        }
    }
}

/// How many numbers each of a memory's vectors holds, as its embedding
/// model makes them, such as 1,536 for OpenAI's `text-embedding-3-small`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VectorSize(u16);

impl VectorSize {
    /// A length of `size` numbers.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::OutOfRange`] outside 1 to
    /// `MAX_VECTOR_SIZE`.
    pub fn new(size: u16) -> Result<Self, ValidationError> {
        validate_range("vector_size", size, 1..=MAX_VECTOR_SIZE)?;
        Ok(Self(size))
    }

    /// The length.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }

    /// The length as an index.
    #[must_use]
    pub fn as_usize(self) -> usize {
        usize::from(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A vector of 1,536 numbers, as OpenAI's small model makes, is a size.
    #[test]
    fn a_common_size_is_taken() {
        assert_eq!(VectorSize::new(1536).unwrap().as_usize(), 1536);
    }

    /// Vector sizes reject zero and a length above the supported maximum.
    #[test]
    fn sizes_past_the_bounds_are_refused() {
        assert!(VectorSize::new(0).is_err());
        assert!(VectorSize::new(MAX_VECTOR_SIZE + 1).is_err());
    }
}
