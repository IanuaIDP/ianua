//! The words a signal stream's choices, and its deliveries', are stored
//! as.

use ianua_domain::domains::signals::delivery::SignalDeliveryStatus;
use ianua_domain::domains::signals::signal::SecuritySignalType;
use ianua_domain::domains::signals::stream::{DeliveryMethod, StreamStatus};
use ianua_domain::domains::signals::subjects::DefaultSubjects;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    StreamStatus as "stream status" {
        Active => "active",
        Paused => "paused",
        Disabled => "disabled",
    }
}

stored_words! {
    DeliveryMethod as "signal delivery method" {
        Push => "push",
        Poll => "poll",
    }
}

stored_words! {
    DefaultSubjects as "subject list" {
        All => "all",
        None => "none",
    }
}

stored_words! {
    SecuritySignalType as "signal type" {
        SessionRevoked => "session_revoked",
        SessionSuspended => "session_suspended",
        CredentialChanged => "credential_changed",
        AccountLocked => "account_locked",
        AccountDisabled => "account_disabled",
        PermissionsChanged => "permissions_changed",
        DeviceCompromised => "device_compromised",
        TokenCompromised => "token_compromised",
        RiskLevelChanged => "risk_level_changed",
        AssuranceChanged => "assurance_changed",
        CredentialCompromised => "credential_compromised",
        IdentifierChanged => "identifier_changed",
        AccountPurged => "account_purged",
    }
}

stored_words! {
    SignalDeliveryStatus as "signal delivery status" {
        Success => "success",
        Failed => "failed",
        Timeout => "timeout",
        Unreachable => "unreachable",
        Queued => "queued",
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{SortKey, SortKeys};
    use ianua_app::ports::signals::StreamSortField;
    use ianua_domain::domains::signals::stream::{SignalStream, SignalStreamRow};
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::postgres::foundation::stored::StoredWord;
    use crate::test_support::rows::signals::stream_row;

    /// A list sorted by status seeks past the cursor's word in the column,
    /// so the word a status is stored as must be the word it sorts by.
    #[test]
    fn every_status_is_stored_as_the_word_it_sorts_by() {
        for status in [
            StreamStatus::Active,
            StreamStatus::Paused,
            StreamStatus::Disabled,
        ] {
            let stream: SignalStream<ResolvedTenant> =
                SignalStream::reconstitute(SignalStreamRow {
                    status,
                    ..stream_row("https://app.acme.com/sse")
                })
                .unwrap();

            assert_eq!(
                stream.sort_key(StreamSortField::Status),
                SortKey::Text(status.word().to_owned())
            );
            assert_eq!(StreamStatus::from_word(status.word()), Some(status));
        }
    }

    /// Every signal type reads back from the word it is written as, so a
    /// stream never hears of a signal it did not ask for.
    #[test]
    fn every_signal_type_reads_back_from_its_word() {
        for signal in [
            SecuritySignalType::SessionRevoked,
            SecuritySignalType::SessionSuspended,
            SecuritySignalType::CredentialChanged,
            SecuritySignalType::AccountLocked,
            SecuritySignalType::AccountDisabled,
            SecuritySignalType::PermissionsChanged,
            SecuritySignalType::DeviceCompromised,
            SecuritySignalType::TokenCompromised,
            SecuritySignalType::RiskLevelChanged,
            SecuritySignalType::AssuranceChanged,
            SecuritySignalType::CredentialCompromised,
            SecuritySignalType::IdentifierChanged,
            SecuritySignalType::AccountPurged,
        ] {
            assert_eq!(SecuritySignalType::from_word(signal.word()), Some(signal));
        }
    }

    /// Every delivery status reads back from the word it is written as, so
    /// a push the receiver refused is never read as one it took.
    #[test]
    fn every_delivery_status_reads_back_from_its_word() {
        for status in [
            SignalDeliveryStatus::Success,
            SignalDeliveryStatus::Failed,
            SignalDeliveryStatus::Timeout,
            SignalDeliveryStatus::Unreachable,
            SignalDeliveryStatus::Queued,
        ] {
            assert_eq!(SignalDeliveryStatus::from_word(status.word()), Some(status));
        }
    }

    /// Every delivery method and subject list reads back from its word.
    #[test]
    fn every_method_and_subject_list_reads_back_from_its_word() {
        for method in [DeliveryMethod::Push, DeliveryMethod::Poll] {
            assert_eq!(DeliveryMethod::from_word(method.word()), Some(method));
        }
        for subjects in [DefaultSubjects::All, DefaultSubjects::None] {
            assert_eq!(DefaultSubjects::from_word(subjects.word()), Some(subjects));
        }
    }
}
