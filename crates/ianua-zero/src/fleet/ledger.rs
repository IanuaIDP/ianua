//! The nonces of the verdicts applied of late, so none is applied twice.
//!
//! A nonce is remembered for as long as a verdict carrying it could still
//! pass the age check; after that the age check refuses its replay alone.
//! The ledger holds a bounded number of nonces, and when it is full of ones
//! it must still remember, a new verdict is refused rather than an old
//! nonce forgotten: a lost verdict weakens a defence, a replayed one is a
//! verdict nobody raised.

use std::collections::{HashSet, VecDeque};
use std::sync::{Mutex, PoisonError};

use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::wire::Refusal;

#[derive(Debug, Default)]
struct Spent {
    nonces: HashSet<Uuid>,
    until: VecDeque<(OffsetDateTime, Uuid)>,
}

/// The nonces spent of late.
#[derive(Debug)]
pub(super) struct NonceLedger {
    spent: Mutex<Spent>,
    room: usize,
    remember: Duration,
}

impl NonceLedger {
    /// A ledger of at most `room` nonces, each remembered for `remember`.
    pub(super) fn new(room: usize, remember: Duration) -> Self {
        Self {
            spent: Mutex::new(Spent::default()),
            room,
            remember,
        }
    }

    /// Spends `nonce` at `now`.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal::Replayed`] when it was spent already, and
    /// [`Refusal::LedgerFull`] when no room is left to remember it.
    pub(super) fn spend(&self, nonce: Uuid, now: OffsetDateTime) -> Result<(), Refusal> {
        let mut spent = self.spent.lock().unwrap_or_else(PoisonError::into_inner);
        forget_before(&mut spent, now);
        if spent.nonces.contains(&nonce) {
            return Err(Refusal::Replayed);
        }
        if spent.nonces.len() >= self.room {
            return Err(Refusal::LedgerFull);
        }
        spent.nonces.insert(nonce);
        spent.until.push_back((now + self.remember, nonce));
        Ok(())
    }
}

/// Forgets every nonce remembered until `now` or earlier.
fn forget_before(spent: &mut Spent, now: OffsetDateTime) {
    while let Some((until, nonce)) = spent.until.front().copied() {
        if until > now {
            return;
        }
        spent.until.pop_front();
        spent.nonces.remove(&nonce);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000 + seconds).unwrap()
    }

    /// Spending a nonce succeeds once and rejects its reuse one second later.
    #[test]
    fn a_nonce_is_spent_once() {
        let ledger = NonceLedger::new(10, Duration::seconds(60));
        let nonce = Uuid::now_v7();

        let first = ledger.spend(nonce, at(0));
        let again = ledger.spend(nonce, at(1));

        assert_eq!((first, again), (Ok(()), Err(Refusal::Replayed)));
    }

    /// A full ledger rejects a new nonce while retaining replay protection
    /// for the nonce it already holds.
    #[test]
    fn a_full_ledger_refuses_rather_than_forgets() {
        let ledger = NonceLedger::new(1, Duration::seconds(60));
        let first = Uuid::now_v7();
        ledger.spend(first, at(0)).unwrap();

        let second = ledger.spend(Uuid::now_v7(), at(1));

        assert_eq!(second, Err(Refusal::LedgerFull));
        assert_eq!(ledger.spend(first, at(2)), Err(Refusal::Replayed));
    }

    #[test]
    fn a_nonce_past_its_time_makes_room() {
        let ledger = NonceLedger::new(1, Duration::seconds(60));
        ledger.spend(Uuid::now_v7(), at(0)).unwrap();

        let later = ledger.spend(Uuid::now_v7(), at(61));

        assert_eq!(later, Ok(()));
    }
}
