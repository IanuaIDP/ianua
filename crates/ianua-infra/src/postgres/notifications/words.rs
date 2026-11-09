//! The words the choices every notification store shares are stored as.
//!
//! A list sorted by category reads its cursor from the domain's own word
//! for it, so the stored word is that word exactly. A notification's
//! severity is stored as its rank, so a list by severity runs by urgency;
//! its word is how a destination's lowest severity is kept.

use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::severity::NotificationSeverity;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    NotificationCategory as "notification category" {
        Identity => "identity",
        Crypto => "crypto",
        OAuth => "oauth",
        Authorization => "authorization",
        Federation => "federation",
        Routing => "routing",
        Pipeline => "pipeline",
        Signals => "signals",
        Webhooks => "webhooks",
        Branding => "branding",
        Authentication => "authentication",
        Organization => "organization",
        Tenant => "tenant",
        Agents => "agents",
        Consumers => "consumers",
        Messaging => "messaging",
        Domains => "domains",
        Mtls => "mtls",
        Scim => "scim",
        Classification => "classification",
        Policy => "policy",
        Audit => "audit",
        Workflows => "workflows",
    }
}

stored_words! {
    NotificationSeverity as "notification severity" {
        Info => "info",
        Warning => "warning",
        Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord as _;

    /// Every category's stored word matches the domain word used in
    /// pagination cursors.
    #[test]
    fn every_category_is_stored_as_the_word_its_cursor_holds() {
        for category in NotificationCategory::all() {
            assert_eq!(category.word(), category.as_str());
        }
    }

    /// Every severity is stored under the domain's own word for it.
    #[test]
    fn every_severity_is_stored_as_the_domains_word() {
        for severity in [
            NotificationSeverity::Info,
            NotificationSeverity::Warning,
            NotificationSeverity::Critical,
        ] {
            assert_eq!(severity.word(), severity.as_str());
        }
    }
}
