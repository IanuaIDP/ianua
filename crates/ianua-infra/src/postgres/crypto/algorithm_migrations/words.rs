//! The words an algorithm migration's choices are stored as.

use ianua_domain::domains::crypto::migration_status::MigrationStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    MigrationStatus as "migration status" {
        Planned => "planned",
        InProgress => "in_progress",
        Validating => "validating",
        Completed => "completed",
        RolledBack => "rolled_back",
        Cancelled => "cancelled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every status reads back from its word, so a finished migration is
    /// never read as one still running.
    #[test]
    fn every_status_reads_back_from_its_word() {
        for status in [
            MigrationStatus::Planned,
            MigrationStatus::InProgress,
            MigrationStatus::Validating,
            MigrationStatus::Completed,
            MigrationStatus::RolledBack,
            MigrationStatus::Cancelled,
        ] {
            assert_eq!(MigrationStatus::from_word(status.word()), Some(status));
        }
    }
}
