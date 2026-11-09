//! The words a SAML app's choices are stored as, inside its settings. Its
//! status is a connection status, stored as a connection's is.

use ianua_domain::domains::federation::service_provider::{
    AccountAttribute, AttributeNameFormat, SignedParts,
};

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    AccountAttribute as "account attribute" {
        Email => "email",
        DisplayName => "display_name",
        Locale => "locale",
        Timezone => "timezone",
        AccountId => "account_id",
        Roles => "roles",
        Groups => "groups",
    }
}

stored_words! {
    AttributeNameFormat as "attribute name format" {
        Unspecified => "unspecified",
        Basic => "basic",
        Uri => "uri",
    }
}

stored_words! {
    SignedParts as "signed parts" {
        Assertion => "assertion",
        AssertionAndResponse => "assertion_and_response",
    }
}
