//! Which store caches each event touches, decided once per event type.
//!
//! One `match` over every [`EventType`], and inside it one over every event
//! of each context, with no catch-all anywhere: a new event does not
//! compile until someone decides what it drops. An event touches a cache
//! when the change it records can make an entry of that cache wrong:
//!
//! - **Callers**: anything that ends, suspends, rotates, revokes or
//!   expires a session or a key, or changes the standing of who it names,
//!   so a bearer that stopped answering is not resolved from the cache.
//! - **Holdings**: anything that changes a role, a role's rights, a group,
//!   the group tree, an assignment, a membership, a resource type or a
//!   break-glass grant, or removes a principal whose records cascade away.
//! - **Signing keys**: anything that adds, rotates, revokes or promotes a
//!   tenant's signing key, so a revoked key is not believed from the cache.
//! - **Classifications**: any change to a tenant's classification rules.
//! - **Assertion keys**: only a tenant's deletion. Their rotation is a
//!   sweep that records nothing; a rotated key stays published for a day,
//!   far longer than an entry lives, so signing with it a little longer
//!   is still believed.
//!
//! A tenant's deletion touches everything, since its data is purged by
//! plain deletes no cache sees. Touching a cache drops the owner's entries
//! on this node and raises the owner's version for every node. Touching
//! too much costs store reads; touching too little serves a stale answer
//! until the entry lapses, so a doubtful event touches.

mod access;
mod people;
mod platform;
mod work;

use ianua_domain::types::EventType;

use crate::cache::stores::versions::Cached;

/// No store cache.
const NOTHING: &[Cached] = &[];

/// The callers bearers resolve to.
const CALLERS: &[Cached] = &[Cached::Callers];

/// What decides holders' holdings.
const HOLDINGS: &[Cached] = &[Cached::Holdings];

/// The public halves of a tenant's signing keys.
const SIGNING_KEYS: &[Cached] = &[Cached::SigningKeys];

/// The opened key that signs a tenant's assertions.
const ASSERTION_KEYS: &[Cached] = &[Cached::AssertionKeys];

/// A tenant's classification rule set.
const CLASSIFICATIONS: &[Cached] = &[Cached::Classifications];

/// Every store cache.
const EVERYTHING: &[Cached] = Cached::ALL;

/// The store caches an event of `event` type touches.
pub(crate) fn touched_by(event: EventType) -> &'static [Cached] {
    match event {
        EventType::Agents(event) => work::agents(event),
        EventType::Authentication(event) => people::authentication(event),
        EventType::Authorization(event) => access::authorization(event),
        EventType::Branding(event) => platform::branding(event),
        EventType::Crypto(event) => platform::crypto(event),
        EventType::Federation(event) => access::federation(event),
        EventType::Identity(event) => people::identity(event),
        EventType::OAuth(event) => access::oauth(event),
        EventType::Operator(event) => platform::operator(event),
        EventType::Organization(event) => platform::organization(event),
        EventType::Proxy(event) => work::proxy(event),
        EventType::Routing(event) => work::routing(event),
        EventType::Signals(event) => work::signals(event),
        EventType::Tenant(event) => platform::tenant(event),
        EventType::Notifications(event) => work::notifications(event),
        EventType::Messaging(event) => work::messaging(event),
        EventType::Consumers(event) => access::consumers(event),
        EventType::Webhooks(event) => work::webhooks(event),
        EventType::Workflows(event) => work::workflows(event),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(name: &str) -> &'static [Cached] {
        touched_by(EventType::parse(name).expect("a known event type"))
    }

    /// Every event type there is has its decision, and the decisions name
    /// each cache at most once.
    #[test]
    fn every_event_type_is_decided() {
        let decided: Vec<(EventType, &[Cached])> = EventType::all()
            .map(|event| (event, touched_by(event)))
            .collect();

        assert_eq!(decided.len(), EventType::all().count());
        for (event, touched) in decided {
            let mut seen = touched.to_vec();
            seen.dedup();
            assert_eq!(seen.len(), touched.len(), "{event} names a cache twice");
        }
    }

    /// Tenant-deletion events are classified as affecting every cache family.
    #[test]
    fn a_tenants_deletion_touches_everything() {
        for name in ["tenant.deleted", "tenant.deleted_early", "tenant.torn_down"] {
            assert_eq!(named(name), Cached::ALL, "{name}");
        }
    }

    /// Each listed credential-revocation event selects the caller cache for invalidation.
    #[test]
    fn every_revocation_of_a_credential_touches_the_callers() {
        for name in [
            "authentication.session_revoked",
            "authentication.token_refreshed",
            "authentication.password_changed",
            "oauth.api_key_revoked",
            "oauth.api_key_expired",
            "organization.org_session_revoked",
            "organization.org_api_key_revoked",
            "organization.org_user_deleted",
            "operator.operator_api_key_revoked",
            "operator.operator_disabled",
            "identity.user_deleted",
            "tenant.status_changed",
        ] {
            assert!(named(name).contains(&Cached::Callers), "{name}");
        }
    }

    /// Authorization link-change events select the holdings cache for invalidation.
    #[test]
    fn every_change_to_a_link_touches_the_holdings() {
        for name in [
            "authorization.role_revoked",
            "authorization.role_assigned",
            "authorization.permission_revoked",
            "authorization.group_member_removed",
            "authorization.group_moved",
            "authorization.group_role_unassigned",
            "authorization.role_assignment_expired",
            "authorization.resource_type_updated",
            "authentication.break_glass_revoked",
            "identity.user_deleted",
            "agents.agent_deleted",
            "consumers.consumer_deleted",
        ] {
            assert!(named(name).contains(&Cached::Holdings), "{name}");
        }
    }

    /// Each listed signing-key change selects the signing-key cache for invalidation.
    #[test]
    fn every_change_to_a_signing_key_touches_the_signing_keys() {
        for name in [
            "crypto.key_created",
            "crypto.key_rotated",
            "crypto.key_revoked",
            "crypto.migration_started",
            "crypto.migration_promoted",
            "crypto.migration_completed",
            "crypto.migration_rolled_back",
        ] {
            assert!(named(name).contains(&Cached::SigningKeys), "{name}");
        }
    }

    /// Every assertion key made, rotated or retired drops the opened key
    /// the gateway signs with, so its next assertion is signed with the
    /// key that signs now.
    #[test]
    fn every_change_to_an_assertion_key_touches_the_assertion_keys() {
        for name in [
            "crypto.assertion_key_created",
            "crypto.assertion_key_rotated",
            "crypto.assertion_key_retired",
        ] {
            assert!(named(name).contains(&Cached::AssertionKeys), "{name}");
        }
    }

    /// Classification-rule changes select the classification cache for invalidation.
    #[test]
    fn every_change_to_a_rule_touches_the_classifications() {
        for name in [
            "proxy.classification_rule_added",
            "proxy.classification_rule_removed",
            "proxy.classification_rule_changed",
        ] {
            assert!(named(name).contains(&Cached::Classifications), "{name}");
        }
    }

    /// An event that changes nothing a cache holds drops nothing, so a busy
    /// tenant's sign-ins do not empty its caches.
    #[test]
    fn an_unrelated_event_touches_nothing() {
        for name in [
            "authentication.login_succeeded",
            "messaging.message_published",
            "workflows.step_succeeded",
            "proxy.honeypot_hit",
        ] {
            assert!(named(name).is_empty(), "{name}");
        }
    }
}
