//! The words a pipeline's choices are stored as.

use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    PipelineStatus as "pipeline status" {
        Draft => "draft",
        Active => "active",
        Disabled => "disabled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every status reads back from the word it is written as, so a
    /// disabled pipeline is never read as one running traffic.
    #[test]
    fn every_status_reads_back_from_its_word() {
        for status in [
            PipelineStatus::Draft,
            PipelineStatus::Active,
            PipelineStatus::Disabled,
        ] {
            assert_eq!(PipelineStatus::from_word(status.word()), Some(status));
        }
    }
}
