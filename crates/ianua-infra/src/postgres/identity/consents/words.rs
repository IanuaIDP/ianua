//! The words a consent record's type is stored as.

use ianua_domain::domains::identity::privacy::consent::ConsentType;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    ConsentType as "consent type" {
        DataProcessing => "data_processing",
        Marketing => "marketing",
        TermsOfService => "terms_of_service",
        PrivacyPolicy => "privacy_policy",
        HealthDataSharing => "health_data_sharing",
        Cookies => "cookies",
    }
}
