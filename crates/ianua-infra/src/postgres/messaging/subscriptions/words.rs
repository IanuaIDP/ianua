//! The words a subscription's choices are stored as.

use ianua_domain::domains::messaging::subscription::{DeliveryMode, SubscriptionStatus};

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    SubscriptionStatus as "subscription status" {
        Active => "active",
        Paused => "paused",
    }
}

stored_words! {
    DeliveryMode as "delivery mode" {
        Pull => "pull",
        Push => "push",
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{SortKey, SortKeys};
    use ianua_app::ports::messaging::SubscriptionSortField;
    use ianua_domain::domains::messaging::subscription::{Subscription, SubscriptionRow};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::ConsumerId;

    use super::*;
    use crate::postgres::foundation::stored::StoredWord;
    use crate::test_support::rows::messaging::subscription_row;

    /// A list sorted by status seeks past the cursor's word in the column,
    /// so the word a status is stored as must be the word it sorts by.
    #[test]
    fn every_status_is_stored_as_the_word_it_sorts_by() {
        for status in [SubscriptionStatus::Active, SubscriptionStatus::Paused] {
            let subscription: Subscription<ResolvedTenant> =
                Subscription::reconstitute(SubscriptionRow {
                    status,
                    ..subscription_row("orders.created", ConsumerId::new())
                })
                .unwrap();

            assert_eq!(
                subscription.sort_key(SubscriptionSortField::Status),
                SortKey::Text(status.word().to_owned())
            );
            assert_eq!(SubscriptionStatus::from_word(status.word()), Some(status));
        }
    }

    /// Every delivery mode reads back from the word it is written as, so a
    /// pushed subscription is never read as a pulled one.
    #[test]
    fn every_delivery_mode_reads_back_from_its_word() {
        for mode in [DeliveryMode::Pull, DeliveryMode::Push] {
            assert_eq!(DeliveryMode::from_word(mode.word()), Some(mode));
        }
    }
}
