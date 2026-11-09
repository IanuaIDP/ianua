//! The words an export request's choices are stored as.

use ianua_domain::domains::identity::privacy::export::{ExportAskedBy, ExportScope};
use ianua_domain::domains::identity::privacy::export_state::ExportStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    ExportStatus as "export status" {
        Requested => "requested",
        Ready => "ready",
        Expired => "expired",
    }
}

stored_words! {
    ExportScope as "export scope" {
        Access => "access",
        Portability => "portability",
    }
}

stored_words! {
    ExportAskedBy as "export asker" {
        Holder => "holder",
        Staff => "staff",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Each status and scope is stored as the name the domain gives it, so
    /// a row reads the same to every reader of it.
    #[test]
    fn every_word_is_the_domains_own_name() {
        for status in [
            ExportStatus::Requested,
            ExportStatus::Ready,
            ExportStatus::Expired,
        ] {
            assert_eq!(status.word(), status.as_str());
        }
        for scope in [ExportScope::Access, ExportScope::Portability] {
            assert_eq!(scope.word(), scope.as_str());
        }
    }
}
