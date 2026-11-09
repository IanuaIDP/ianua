//! A memory's text as a search reads it back, and a vector in the text
//! form pgvector reads and writes.

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::memory::entry::{
    Embedding, EntryPage, FoundEntry, KeptEntry, MemoryText, NextPage,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::MemoryEntryId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const ENTRY: Stored = Stored("memory entry");

/// A found text as it is read.
pub(super) struct FoundRecord {
    pub(super) id: Uuid,
    pub(super) text: String,
    pub(super) exposure: String,
    pub(super) similarity: f32,
    pub(super) kept_at: OffsetDateTime,
}

impl FoundRecord {
    /// The entry the record holds, its values checked again.
    pub(super) fn into_found(self) -> Result<FoundEntry, DomainError> {
        Ok(FoundEntry {
            id: MemoryEntryId::from_uuid(self.id),
            text: ENTRY.value("text", MemoryText::new(self.text))?,
            exposure: DataClassLevel::from_stored(&self.exposure)?,
            similarity: self.similarity,
            kept_at: self.kept_at,
        })
    }
}

/// A kept text as an export reads it.
pub(super) struct KeptRecord {
    pub(super) id: Uuid,
    pub(super) text: String,
    pub(super) exposure: String,
    pub(super) kept_at: OffsetDateTime,
}

impl KeptRecord {
    /// The entry the record holds, its values checked again.
    fn into_kept(self) -> Result<KeptEntry, DomainError> {
        Ok(KeptEntry {
            id: MemoryEntryId::from_uuid(self.id),
            text: ENTRY.value("text", MemoryText::new(self.text))?,
            exposure: DataClassLevel::from_stored(&self.exposure)?,
            kept_at: self.kept_at,
        })
    }
}

/// The page `records` hold, read with one row more than `limit`: that row,
/// when there, is where the next page starts.
pub(super) fn paged(mut records: Vec<KeptRecord>, limit: u8) -> Result<EntryPage, DomainError> {
    let following = records.split_off(usize::from(limit).min(records.len()));
    let next = following.first().map_or(NextPage::Done, |record| {
        NextPage::At(MemoryEntryId::from_uuid(record.id))
    });
    let entries = records
        .into_iter()
        .map(KeptRecord::into_kept)
        .collect::<Result<_, _>>()?;
    Ok(EntryPage { entries, next })
}

/// `embedding` in pgvector's text form.
pub(super) fn vector_text(embedding: &Embedding) -> String {
    let numbers: Vec<String> = embedding.values().iter().map(f32::to_string).collect();
    format!("[{}]", numbers.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A vector is written as pgvector reads it: its numbers in brackets,
    /// comma-separated.
    #[test]
    fn a_vector_is_written_in_pgvector_s_text_form() {
        let size = ianua_domain::domains::workflows::memory::source::VectorSize::new(3).unwrap();
        let embedding = Embedding::new(vec![0.5, -1.0, 0.25], size).unwrap();

        assert_eq!(vector_text(&embedding), "[0.5,-1,0.25]");
    }

    fn kept(id: u128) -> KeptRecord {
        KeptRecord {
            id: Uuid::from_u128(id),
            text: format!("ticket {id}"),
            exposure: "internal".to_owned(),
            kept_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// Three rows read for a page of two: the page holds the first two and
    /// the third is where the next starts.
    #[test]
    fn the_extra_row_names_the_next_page() {
        let page = paged(vec![kept(1), kept(2), kept(3)], 2).unwrap();

        assert_eq!(page.entries.len(), 2);
        assert_eq!(
            page.next,
            NextPage::At(MemoryEntryId::from_uuid(Uuid::from_u128(3)))
        );
    }

    /// Fewer rows than a page: the page is the last.
    #[test]
    fn a_short_page_is_the_last() {
        let page = paged(vec![kept(1)], 2).unwrap();

        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.next, NextPage::Done);
    }

    /// Reading a found entry with an unknown exposure returns an
    /// infrastructure error.
    #[test]
    fn a_found_row_with_an_unknown_exposure_is_corrupt() {
        let read = FoundRecord {
            id: Uuid::nil(),
            text: "I want my money back".to_owned(),
            exposure: "secretish".to_owned(),
            similarity: 0.9,
            kept_at: OffsetDateTime::UNIX_EPOCH,
        }
        .into_found();

        assert!(
            matches!(read, Err(DomainError::Infrastructure(_))),
            "{read:?}"
        );
    }
}
