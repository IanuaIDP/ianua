//! The words a teardown's steps are stored as.

use ianua_domain::domains::tenant::teardown::TeardownStep;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    TeardownStep as "teardown step" {
        Data => "data",
        AuditTrail => "audit_trail",
        Database => "database",
    }
}
