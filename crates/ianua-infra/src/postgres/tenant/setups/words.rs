//! The words a setup's steps are stored as.

use ianua_domain::domains::tenant::setup::SetupStep;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    SetupStep as "setup step" {
        Database => "database",
        SigningKey => "signing_key",
        AssertionKey => "assertion_key",
        StartingRoles => "starting_roles",
        Activate => "activate",
    }
}
