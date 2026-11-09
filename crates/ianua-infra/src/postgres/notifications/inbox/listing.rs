//! How an inbox list is read: the column each sort field orders by, and
//! the condition the read filter adds.

use ianua_app::ports::notifications::{NotificationSortField, ReadFilter};

use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns};

impl SortColumns for NotificationSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::Severity => "severity",
            Self::Category => "category",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

/// `listed` narrowed to what `reads` asks for: every notification, or only
/// those not yet read.
pub(super) fn in_reads(listed: PageQuery<'static>, reads: ReadFilter) -> PageQuery<'static> {
    match reads {
        ReadFilter::All => listed,
        ReadFilter::UnreadOnly => listed.keep("NOT read"),
    }
}
