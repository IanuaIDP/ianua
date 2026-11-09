//! One text a memory keeps, with its vector, and what a search for the
//! most similar finds.

use time::OffsetDateTime;

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::memory::source::VectorSize;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;
use crate::shared::validation::{TextValue, ValidationError, Validator, text_value};
use crate::types::MemoryEntryId;

/// The most characters one kept text holds: a support ticket or a page of
/// notes fits, a whole document is split before it is kept.
pub(crate) const MAX_TEXT_CHARS: usize = 8_000;

/// The most entries one search finds.
pub const MAX_FOUND: u8 = 20;

text_value! {
    /// A text a memory keeps, such as one support ticket.
    pub struct MemoryText;
}

impl TextValue for MemoryText {
    const FIELD: &'static str = "text";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_blank()
            .char_length(1..=MAX_TEXT_CHARS)
            .no_control_chars_but_line_breaks()
    }
}

/// The vector an embedding model made for a text: as many numbers as the
/// memory's vectors hold, each a finite number.
#[derive(Debug, Clone, PartialEq)]
pub struct Embedding(Vec<f32>);

impl Embedding {
    /// `values` as a vector of a memory whose vectors are `size` long.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] when the vector is of another
    /// length, as one from another embedding model would be, or holds a
    /// number that is not finite.
    pub fn new(values: Vec<f32>, size: VectorSize) -> Result<Self, DomainError> {
        if values.len() != size.as_usize() {
            let made = values.len();
            let kept = size.get();
            return Err(DomainError::invalid(message!(
                "workflows-the-vector-is-of-another-length",
                format!(
                    "the embedding model made a vector of {made} numbers, and this memory keeps vectors of {kept}"
                )
            )));
        }
        if values.iter().any(|value| !value.is_finite()) {
            return Err(DomainError::invalid(message!(
                "workflows-the-vector-holds-no-number",
                "the embedding model made a vector holding something that is not a number"
            )));
        }
        Ok(Self(values))
    }

    /// The numbers.
    #[must_use]
    pub fn values(&self) -> &[f32] {
        &self.0
    }
}

/// How many entries a search finds, at most [`MAX_FOUND`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundCount(u8);

impl FoundCount {
    /// The three most similar, when a step names no count.
    pub const DEFAULT: Self = Self(3);

    /// At most `count` entries.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::OutOfRange`] outside 1 to [`MAX_FOUND`].
    pub fn new(count: u8) -> Result<Self, ValidationError> {
        validate_range("count", count, 1..=MAX_FOUND)?;
        Ok(Self(count))
    }

    /// The count.
    #[must_use]
    pub fn get(self) -> u8 {
        self.0
    }
}

/// One text a memory keeps.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryEntry {
    id: MemoryEntryId,
    text: MemoryText,
    embedding: Embedding,
    exposure: DataClassLevel,
    created_at: OffsetDateTime,
}

/// The values an entry is kept with.
pub struct MemoryEntryParams {
    /// The passage retained for later semantic retrieval.
    pub text: MemoryText,
    /// Its vector.
    pub embedding: Embedding,
    /// The most sensitive data the text may hold, as the step that kept it
    /// was exposed to.
    pub exposure: DataClassLevel,
}

impl MemoryEntry {
    /// A new entry for `params`.
    #[must_use]
    pub fn new(params: MemoryEntryParams) -> Self {
        Self {
            id: MemoryEntryId::new(),
            text: params.text,
            embedding: params.embedding,
            exposure: params.exposure,
            created_at: crate::shared::clock::now(),
        }
    }

    /// The stable identity used to retrieve or remove this retained passage.
    #[must_use]
    pub fn id(&self) -> &MemoryEntryId {
        &self.id
    }

    /// The retained passage from which this entry's embedding was derived.
    #[must_use]
    pub fn text(&self) -> &MemoryText {
        &self.text
    }

    /// Its vector.
    #[must_use]
    pub fn embedding(&self) -> &Embedding {
        &self.embedding
    }

    /// The most sensitive data the text may hold.
    #[must_use]
    pub fn exposure(&self) -> DataClassLevel {
        self.exposure
    }

    /// When it was kept.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }
}

/// An entry a search found, and how alike it is to what was searched for.
#[derive(Debug, Clone, PartialEq)]
pub struct FoundEntry {
    /// The entry.
    pub id: MemoryEntryId,
    /// The matching passage returned with its sensitivity and similarity score.
    pub text: MemoryText,
    /// The most sensitive data the text may hold.
    pub exposure: DataClassLevel,
    /// How alike: the cosine of the angle between the two vectors, from -1
    /// for opposite to 1 for the same direction.
    pub similarity: f32,
    /// When it was kept.
    pub kept_at: OffsetDateTime,
}

/// One text a memory keeps, as an export reads it back: without its
/// vector, which means nothing outside the memory's embedding model.
#[derive(Debug, Clone, PartialEq)]
pub struct KeptEntry {
    /// The entry.
    pub id: MemoryEntryId,
    /// The retained passage exported without its model-specific vector.
    pub text: MemoryText,
    /// The most sensitive data the text may hold.
    pub exposure: DataClassLevel,
    /// When it was kept.
    pub kept_at: OffsetDateTime,
}

/// Where a page of a memory's texts starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageStart {
    /// At the oldest text.
    First,
    /// At this text, as the page before named it.
    At(MemoryEntryId),
}

/// Whether more texts follow a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextPage {
    /// None: the page holds the newest text.
    Done,
    /// The next page starts at this text.
    At(MemoryEntryId),
}

/// One page of a memory's texts, oldest first.
#[derive(Debug, Clone, PartialEq)]
pub struct EntryPage {
    /// The texts.
    pub entries: Vec<KeptEntry>,
    /// Where the next page starts, if one follows.
    pub next: NextPage,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn three() -> VectorSize {
        VectorSize::new(3).unwrap()
    }

    /// A vector as long as the memory's, of finite numbers, is taken.
    #[test]
    fn a_vector_of_the_memory_s_length_is_taken() {
        assert!(Embedding::new(vec![0.1, -0.2, 0.3], three()).is_ok());
    }

    /// Embeddings reject a mismatched vector length and values containing NaN
    /// or infinity.
    #[test]
    fn vectors_that_do_not_fit_are_refused() {
        assert!(Embedding::new(vec![0.1, 0.2], three()).is_err());
        assert!(Embedding::new(vec![0.1, f32::NAN, 0.3], three()).is_err());
        assert!(Embedding::new(vec![0.1, f32::INFINITY, 0.3], three()).is_err());
    }

    /// Memory text rejects whitespace-only and oversized input while accepting
    /// a short nonblank passage.
    #[test]
    fn texts_past_the_bounds_are_refused() {
        assert!(MemoryText::new("   ").is_err());
        assert!(MemoryText::new("x".repeat(MAX_TEXT_CHARS + 1)).is_err());
        assert!(MemoryText::new("I want my money back").is_ok());
    }

    /// A search finds between one and twenty entries.
    #[test]
    fn a_search_finds_one_to_twenty() {
        assert!(FoundCount::new(0).is_err());
        assert!(FoundCount::new(MAX_FOUND + 1).is_err());
        assert_eq!(FoundCount::new(5).unwrap().get(), 5);
    }
}
