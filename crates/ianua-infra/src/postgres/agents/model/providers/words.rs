//! The words a model provider's choices are stored as.

use ianua_domain::domains::agents::execution::model_provider::{
    ModelProviderKind, ModelProviderStatus, ModelProviderTestStatus,
};

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    ModelProviderKind as "model provider kind" {
        SelfHosted => "self_hosted",
        OpenAi => "openai",
        Anthropic => "anthropic",
    }
}

stored_words! {
    ModelProviderStatus as "model provider status" {
        Active => "active",
        Disabled => "disabled",
    }
}

stored_words! {
    ModelProviderTestStatus as "model provider test outcome" {
        Passed => "passed",
        Failed => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every kind reads back from its word, so a provider is never called
    /// in another backend's wire format.
    #[test]
    fn every_kind_reads_back_from_its_word() {
        for kind in [
            ModelProviderKind::SelfHosted,
            ModelProviderKind::OpenAi,
            ModelProviderKind::Anthropic,
        ] {
            assert_eq!(ModelProviderKind::from_word(kind.word()), Some(kind));
        }
    }

    /// Every status and test outcome reads back from its word, so a
    /// disabled provider is never read as one a run may pick.
    #[test]
    fn every_status_and_outcome_reads_back_from_its_word() {
        for status in [ModelProviderStatus::Active, ModelProviderStatus::Disabled] {
            assert_eq!(ModelProviderStatus::from_word(status.word()), Some(status));
        }
        for outcome in [
            ModelProviderTestStatus::Passed,
            ModelProviderTestStatus::Failed,
        ] {
            assert_eq!(
                ModelProviderTestStatus::from_word(outcome.word()),
                Some(outcome)
            );
        }
    }
}
