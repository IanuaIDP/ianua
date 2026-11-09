//! The words how a notification reaches its reader is stored as.

use ianua_domain::domains::notifications::reach::NotificationReach;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    NotificationReach as "notification reach" {
        ByRights => "by_rights",
        OwnAccount => "own_account",
        Addressed => "addressed",
    }
}
