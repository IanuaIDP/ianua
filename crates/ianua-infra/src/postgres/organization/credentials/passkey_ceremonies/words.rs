//! The words a passkey ceremony's purpose is stored as.

use ianua_domain::domains::authentication::credentials::passkey_ceremony::CeremonyPurpose;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    CeremonyPurpose as "ceremony purpose" {
        Registration => "registration",
        Authentication => "authentication",
        DiscoverableAuthentication => "discoverable_authentication",
    }
}
