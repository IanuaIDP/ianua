//! The words a clone's parts and failures are stored as.

use ianua_domain::domains::tenant::clone::{CloneFailure, ClonePart};

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    ClonePart as "clone part" {
        Settings => "settings",
        Branding => "branding",
        RolesAndPolicies => "roles_and_policies",
        Routes => "routes",
        OAuthApplications => "oauth_applications",
    }
}

stored_words! {
    CloneFailure as "clone failure" {
        SourceGone => "source_gone",
        TargetGone => "target_gone",
        CopyFailed => "copy_failed",
    }
}
