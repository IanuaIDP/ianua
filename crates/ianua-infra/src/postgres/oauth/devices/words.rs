//! The words a device authorization's status is stored as.

use ianua_domain::domains::oauth::grants::device_auth_status::DeviceAuthStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    DeviceAuthStatus as "device authorization status" {
        Pending => "pending",
        Approved => "approved",
        Denied => "denied",
        Expired => "expired",
        Redeemed => "redeemed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every status reads back from the word it is written as, so a denied
    /// request is never read as an approved one.
    #[test]
    fn every_status_reads_back_from_its_word() {
        for status in [
            DeviceAuthStatus::Pending,
            DeviceAuthStatus::Approved,
            DeviceAuthStatus::Denied,
            DeviceAuthStatus::Expired,
            DeviceAuthStatus::Redeemed,
        ] {
            assert_eq!(DeviceAuthStatus::from_word(status.word()), Some(status));
        }
    }
}
