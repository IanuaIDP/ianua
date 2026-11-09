//! The words a trusted device's choices are stored as.

use ianua_domain::domains::authentication::device_status::DeviceStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    DeviceStatus as "device status" {
        Trusted => "trusted",
        Revoked => "revoked",
    }
}
