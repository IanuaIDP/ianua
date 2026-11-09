//! The words an audit log export's choices are stored as.

use ianua_domain::domains::audit::export::filter::AuditExportFormat;
use ianua_domain::domains::audit::export::state::AuditExportStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    AuditExportFormat as "audit export format" {
        Csv => "csv",
        Json => "json",
    }
}

stored_words! {
    AuditExportStatus as "audit export status" {
        Pending => "pending",
        Ready => "ready",
        Failed => "failed",
        Expired => "expired",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every format and status reads back from the word it is written as,
    /// the word the domain names it by.
    #[test]
    fn every_format_and_status_reads_back_from_its_word() {
        for format in [AuditExportFormat::Csv, AuditExportFormat::Json] {
            assert_eq!(AuditExportFormat::from_word(format.word()), Some(format));
            assert_eq!(format.word(), format.as_str());
        }
        for status in [
            AuditExportStatus::Pending,
            AuditExportStatus::Ready,
            AuditExportStatus::Failed,
            AuditExportStatus::Expired,
        ] {
            assert_eq!(AuditExportStatus::from_word(status.word()), Some(status));
            assert_eq!(status.word(), status.as_str());
        }
    }
}
