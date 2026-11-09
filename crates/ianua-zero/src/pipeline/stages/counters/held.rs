//! This instance's copy of the blocks and flags the fleet holds: the ones
//! raised here, and the ones the other instances broadcast.
//!
//! Read on every request, so it answers from memory before the shared
//! counter is asked. It is bounded: the other instances' verdicts arrive
//! from the bus, so a flood of addresses must cost a full table rather than
//! the process. When full of verdicts still in force, a new one is not held
//! here, and the shared counter still answers for it.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{PoisonError, RwLock};
use std::time::{Duration, Instant};

use ianua_domain::types::TenantId;

use crate::fleet::{ThreatVerdict, VerdictSink};

/// The blocks and flags this instance holds.
#[derive(Debug)]
pub(crate) struct HeldVerdicts {
    blocked: Holding<(TenantId, IpAddr)>,
    flagged: Holding<IpAddr>,
}

impl HeldVerdicts {
    /// An empty table holding at most `room` blocks and `room` flags.
    #[must_use]
    pub(crate) fn new(room: usize) -> Self {
        Self {
            blocked: Holding::new(room),
            flagged: Holding::new(room),
        }
    }

    /// Blocks `client` from `tenant` for `lasts`, or longer when it already
    /// is.
    pub(super) fn block(&self, tenant: TenantId, client: IpAddr, lasts: Duration) {
        let now = Instant::now();
        self.blocked.hold((tenant, client), now + lasts, now);
    }

    /// Flags `client` for every tenant for `lasts`, or longer when it
    /// already is.
    pub(super) fn flag(&self, client: IpAddr, lasts: Duration) {
        let now = Instant::now();
        self.flagged.hold(client, now + lasts, now);
    }

    /// Whether `client` is blocked from `tenant` now.
    pub(super) fn is_blocked(&self, tenant: TenantId, client: IpAddr) -> bool {
        self.blocked.holds(&(tenant, client), Instant::now())
    }

    /// Whether `client` is flagged now.
    pub(super) fn is_flagged(&self, client: IpAddr) -> bool {
        self.flagged.holds(&client, Instant::now())
    }
}

impl VerdictSink for HeldVerdicts {
    fn apply(&self, verdict: ThreatVerdict) {
        match verdict {
            ThreatVerdict::ClientBlocked {
                tenant,
                client,
                lasts,
            } => self.block(tenant, client, lasts.get()),
            ThreatVerdict::ClientFlagged { client, lasts } => self.flag(client, lasts.get()),
        }
    }
}

/// Keys held until a moment each.
#[derive(Debug)]
struct Holding<K> {
    until: RwLock<HashMap<K, Instant>>,
    room: usize,
}

impl<K: Eq + Hash> Holding<K> {
    fn new(room: usize) -> Self {
        Self {
            until: RwLock::new(HashMap::new()),
            room,
        }
    }

    /// Holds `key` until `until`. A key already held keeps the later of its
    /// two ends; a new key past the room is not held.
    fn hold(&self, key: K, until: Instant, now: Instant) {
        let mut held = self.until.write().unwrap_or_else(PoisonError::into_inner);
        if !held.contains_key(&key) && !has_room(&mut held, self.room, now) {
            tracing::warn!("the gateway's verdict table is full; a new verdict is not held");
            return;
        }
        let end = held.entry(key).or_insert(until);
        *end = (*end).max(until);
    }

    fn holds(&self, key: &K, now: Instant) -> bool {
        self.until
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .is_some_and(|end| *end > now)
    }
}

/// Whether `held` has room for one more, once what ended by `now` is
/// dropped.
fn has_room<K>(held: &mut HashMap<K, Instant>, room: usize, now: Instant) -> bool {
    if held.len() < room {
        return true;
    }
    held.retain(|_, end| *end > now);
    held.len() < room
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(last: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, last])
    }

    /// A block holds until its end and not after.
    #[test]
    fn a_block_ends_when_it_lasts() {
        let holding = Holding::new(10);
        let now = Instant::now();
        holding.hold(address(7), now + Duration::from_secs(60), now);

        assert!(holding.holds(&address(7), now + Duration::from_secs(59)));
        assert!(!holding.holds(&address(7), now + Duration::from_secs(60)));
    }

    /// Applying a one-minute hold to an address already held for ten minutes
    /// leaves it blocked five minutes later.
    #[test]
    fn a_shorter_verdict_never_shortens_a_block() {
        let holding = Holding::new(10);
        let now = Instant::now();
        holding.hold(address(7), now + Duration::from_secs(600), now);

        holding.hold(address(7), now + Duration::from_secs(60), now);

        assert!(holding.holds(&address(7), now + Duration::from_secs(300)));
    }

    /// A full one-entry table rejects a second address while still extending
    /// the first address's hold.
    #[test]
    fn a_full_table_holds_no_new_key() {
        let holding = Holding::new(1);
        let now = Instant::now();
        holding.hold(address(1), now + Duration::from_secs(60), now);

        holding.hold(address(2), now + Duration::from_secs(60), now);
        holding.hold(address(1), now + Duration::from_secs(120), now);

        assert!(!holding.holds(&address(2), now));
        assert!(holding.holds(&address(1), now + Duration::from_secs(90)));
    }

    /// A key whose hold has ended makes room for a new one.
    #[test]
    fn an_ended_hold_makes_room() {
        let holding = Holding::new(1);
        let now = Instant::now();
        holding.hold(address(1), now + Duration::from_secs(1), now);
        let later = now + Duration::from_secs(2);

        holding.hold(address(2), later + Duration::from_secs(60), later);

        assert!(holding.holds(&address(2), later));
    }

    /// A block another instance broadcast is held here for its tenant only.
    #[test]
    fn a_broadcast_block_is_held_for_its_tenant() {
        let held = HeldVerdicts::new(10);
        let (tenant, other) = (TenantId::new(), TenantId::new());

        held.apply(ThreatVerdict::ClientBlocked {
            tenant,
            client: address(7),
            lasts: crate::fleet::VerdictLifetime::capped(Duration::from_secs(60)),
        });

        assert!(held.is_blocked(tenant, address(7)));
        assert!(!held.is_blocked(other, address(7)));
    }
}
