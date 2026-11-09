//! The words a destination's kind and state are stored as.

use ianua_domain::domains::notifications::destination::{DestinationKind, DestinationState};

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    DestinationKind as "destination kind" {
        Slack => "slack",
        Teams => "teams",
        Webhook => "webhook",
    }
}

stored_words! {
    DestinationState as "destination state" {
        Active => "active",
        Paused => "paused",
    }
}
