//! What each step of Pat's life leaves behind: the audit records it
//! raised, told from those there before, and the secrets in play, which
//! appear nowhere outside the fields made to carry them.

use std::collections::HashSet;

use ianua_scenarios::actors::Person;
use ianua_scenarios::expect::{Trail, no_secret_leaked};
use ianua_scenarios::wire::Exchange;
use ianua_scenarios::wire::audit::AuditEntry;
use ianua_scenarios::world::World;

/// The audit records the steps raised, read from the first organization's
/// trail, each record counted once.
pub(super) struct Witness<'w> {
    trail: Trail<'w>,
    seen: HashSet<String>,
}

impl<'w> Witness<'w> {
    /// A witness reading `world`'s trail as its owner, every record made
    /// before now already seen.
    pub(super) async fn of(world: &'w World<'_>) -> Self {
        let trail = world.trail();
        let seen = trail.ids().await;
        Self { trail, seen }
    }

    /// The record of `event_type` this step raised, once the trail holds
    /// one not seen before.
    pub(super) async fn recorded(&mut self, event_type: &str) -> AuditEntry {
        let entry = self.trail.recorded_after(&self.seen, event_type).await;
        self.seen.insert(entry.id.clone());
        entry
    }

    /// Fails when the trail holds a record of `event_type` not seen before:
    /// a refused step records nothing it refused.
    pub(super) async fn nothing_new(&self, event_type: &str) {
        self.trail.nothing_after(&self.seen, event_type).await;
    }
}

/// Fails when any of `secrets` appears in `exchanges` or `records` outside
/// the fields made to carry them, which the exchanges print redacted.
pub(super) fn nothing_leaked(exchanges: &[Exchange], records: &[&AuditEntry], secrets: &[String]) {
    let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
    for exchange in exchanges {
        no_secret_leaked(&exchange.to_string(), &secrets);
    }
    for record in records {
        no_secret_leaked(&record.details.to_string(), &secrets);
    }
}

/// Every secret in play: Pat's and the cast's.
pub(super) fn secrets_in_play(world: &World<'_>, pat: &Person) -> Vec<String> {
    let mut secrets = pat.secrets();
    secrets.extend(world.cast_secrets());
    secrets
}
