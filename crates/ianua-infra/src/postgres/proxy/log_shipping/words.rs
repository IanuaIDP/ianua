//! The words a log shipping target's choices are stored as.

use ianua_domain::domains::proxy::log_shipping::{LogFormat, LogTargetStatus};

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    LogFormat as "log format" {
        JsonLines => "json_lines",
        OpenTelemetry => "open_telemetry",
    }
}

stored_words! {
    LogTargetStatus as "log target status" {
        Active => "active",
        Paused => "paused",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every format and status reads back from the word it is written as,
    /// so a paused target is never read as one shipping records.
    #[test]
    fn every_format_and_status_reads_back_from_its_word() {
        for format in [LogFormat::JsonLines, LogFormat::OpenTelemetry] {
            assert_eq!(LogFormat::from_word(format.word()), Some(format));
        }
        for status in [LogTargetStatus::Active, LogTargetStatus::Paused] {
            assert_eq!(LogTargetStatus::from_word(status.word()), Some(status));
        }
    }
}
