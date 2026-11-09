//! The words a chosen channel is stored as.

use ianua_domain::domains::notifications::channel::NotificationChannel;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    NotificationChannel as "notification channel" {
        InApp => "in_app",
        InAppAndEmail => "in_app_and_email",
        Disabled => "disabled",
    }
}
