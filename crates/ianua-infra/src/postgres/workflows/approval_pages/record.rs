//! A page of a loop's items a person opened, as its row holds it: read back
//! into the page the domain counts, and written out from it.

use ianua_domain::domains::workflows::execution::SeenPage;
use ianua_domain::shared::errors::DomainError;
use time::OffsetDateTime;

use crate::postgres::foundation::stored::Stored;

const PAGE: Stored = Stored("workflow approval page");

/// A page as it is read. The store's checked query fills it.
pub(super) struct PageRecord {
    pub(super) opening: OffsetDateTime,
    pub(super) first_item: i32,
    pub(super) item_count: i32,
    pub(super) opened_at: OffsetDateTime,
}

impl PageRecord {
    /// The page the record holds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its first item or its
    /// count is negative.
    pub(super) fn into_page(self) -> Result<SeenPage, DomainError> {
        Ok(SeenPage {
            opening: self.opening,
            first: u32::try_from(self.first_item)
                .map_err(|_| DomainError::corrupt_row(PAGE.0, "a negative first item"))?,
            count: u32::try_from(self.item_count)
                .map_err(|_| DomainError::corrupt_row(PAGE.0, "a negative item count"))?,
            at: self.opened_at,
        })
    }
}

/// A page's numbers, as they are written.
pub(super) struct PageColumns {
    pub(super) first_item: i32,
    pub(super) item_count: i32,
}

impl PageColumns {
    /// The numbers `page` is written as.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` for a position or a count past
    /// what a column holds, which no loop of at most a thousand items makes.
    pub(super) fn of(page: &SeenPage) -> Result<Self, DomainError> {
        Ok(Self {
            first_item: i32::try_from(page.first).map_err(DomainError::infra)?,
            item_count: i32::try_from(page.count).map_err(DomainError::infra)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A row whose count went negative is refused as corrupt rather than
    /// read as a page of nothing.
    #[test]
    fn a_negative_count_is_refused() {
        let record = PageRecord {
            opening: OffsetDateTime::UNIX_EPOCH,
            first_item: 0,
            item_count: -1,
            opened_at: OffsetDateTime::UNIX_EPOCH,
        };

        assert!(matches!(
            record.into_page(),
            Err(DomainError::Infrastructure(_))
        ));
    }
}
