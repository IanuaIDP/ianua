//! The words a webhook's choices, and its deliveries', are stored as.

use ianua_domain::domains::webhooks::delivery::WebhookDeliveryStatus;
use ianua_domain::domains::webhooks::retry_policy::RetryPreset;
use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    WebhookSubscriptionStatus as "webhook status" {
        Active => "active",
        Paused => "paused",
        Disabled => "disabled",
    }
}

stored_words! {
    RetryPreset as "retry policy" {
        Standard => "standard",
        Aggressive => "aggressive",
        Patient => "patient",
    }
}

stored_words! {
    WebhookDeliveryStatus as "webhook delivery status" {
        Success => "success",
        Failed => "failed",
        Timeout => "timeout",
        Unreachable => "unreachable",
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{SortKey, SortKeys};
    use ianua_app::ports::webhooks::WebhookSubscriptionSortField;
    use ianua_domain::domains::webhooks::subscription::{
        WebhookSubscription, WebhookSubscriptionRow,
    };
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::postgres::foundation::stored::StoredWord;
    use crate::test_support::rows::webhooks::webhook_row;

    /// A list sorted by status seeks past the cursor's word in the column,
    /// so the word a status is stored as must be the word it sorts by.
    #[test]
    fn every_status_is_stored_as_the_word_it_sorts_by() {
        for status in [
            WebhookSubscriptionStatus::Active,
            WebhookSubscriptionStatus::Paused,
            WebhookSubscriptionStatus::Disabled,
        ] {
            let webhook: WebhookSubscription<ResolvedTenant> =
                WebhookSubscription::reconstitute(WebhookSubscriptionRow {
                    status,
                    ..webhook_row("https://hooks.acme.com/in")
                })
                .unwrap();

            assert_eq!(
                webhook.sort_key(WebhookSubscriptionSortField::Status),
                SortKey::Text(status.word().to_owned())
            );
            assert_eq!(
                WebhookSubscriptionStatus::from_word(status.word()),
                Some(status)
            );
        }
    }

    /// Every retry policy is stored as the name it is shown under, and
    /// reads back from it.
    #[test]
    fn every_retry_policy_is_stored_as_its_name() {
        for preset in [
            RetryPreset::Standard,
            RetryPreset::Aggressive,
            RetryPreset::Patient,
        ] {
            assert_eq!(preset.word(), preset.as_str());
            assert_eq!(RetryPreset::from_word(preset.word()), Some(preset));
        }
    }

    /// Every delivery status reads back from the word it is written as, so
    /// a try the endpoint refused is never read as one it took.
    #[test]
    fn every_delivery_status_reads_back_from_its_word() {
        for status in [
            WebhookDeliveryStatus::Success,
            WebhookDeliveryStatus::Failed,
            WebhookDeliveryStatus::Timeout,
            WebhookDeliveryStatus::Unreachable,
        ] {
            assert_eq!(
                WebhookDeliveryStatus::from_word(status.word()),
                Some(status)
            );
        }
    }
}
