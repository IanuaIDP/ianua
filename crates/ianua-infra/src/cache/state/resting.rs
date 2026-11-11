//! Resting a cache server that stopped answering, so callers are not held
//! by it one after another.
//!
//! When the server is down, every call waits its whole deadline before it
//! fails, and a request that makes several cached reads waits that many
//! deadlines: past the gateway's limit on the whole request, so every
//! request is refused late, and held all that time, even though each read
//! could have asked its store at once. So once a call finds the server
//! unreachable or silent, the server rests for a moment: calls fail at once
//! instead of waiting. When the rest is over one call alone tries the
//! server again; the others go on failing at once until it has answered.
//! An answer ends the rest, a failure starts another. A trying call its
//! caller gave up on counts as a failure, so the server is tried again
//! after the next rest instead of never.
//!
//! Failing at once changes nothing a call promises: a store cache that
//! cannot read its versions still asks its store, and a counter that cannot
//! count still refuses.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::cache::state::CacheError;

/// The cache server stopped answering moments ago and rests.
#[derive(Debug, thiserror::Error)]
#[error("the cache stopped answering moments ago and is not asked until it rests")]
pub(super) struct Resting;

/// Whether the cache server answers, as its last calls found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Standing {
    /// It answered its last call.
    Answering,
    /// It failed, and is not asked until this instant.
    RestingUntil(Instant),
    /// Its rest is over and one call is trying it.
    Tried,
}

/// How a call may go to the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Admission {
    /// As usual: the server answered its last call.
    Usual,
    /// As the one call trying the server after its rest.
    Trying,
}

/// What a call found of the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Found {
    /// It answered, even if only to refuse the command.
    Answering,
    /// It could not be reached, or did not answer in time.
    Silent,
}

/// The rest a cache server takes after it stops answering.
#[derive(Debug)]
pub(super) struct Rests {
    standing: Mutex<Standing>,
    rest: Duration,
}

impl Rests {
    /// Answering, resting for `rest` after each failure.
    pub(super) fn after_each_failure(rest: Duration) -> Self {
        Self {
            standing: Mutex::new(Standing::Answering),
            rest,
        }
    }

    /// How a call made at `now` may go to the server.
    ///
    /// # Errors
    ///
    /// [`CacheError::Unreachable`] while the server rests, or while another
    /// call is trying it.
    pub(super) fn admission(&self, now: Instant) -> Result<Admission, CacheError> {
        let mut standing = self.standing();
        match *standing {
            Standing::Answering => Ok(Admission::Usual),
            Standing::RestingUntil(until) if now >= until => {
                *standing = Standing::Tried;
                Ok(Admission::Trying)
            }
            Standing::RestingUntil(_) | Standing::Tried => {
                Err(CacheError::Unreachable(Box::new(Resting)))
            }
        }
    }

    /// Takes in what a call `found` of the server at `now`: an answer ends
    /// the rest, silence starts one.
    pub(super) fn settle(&self, found: Found, now: Instant) {
        *self.standing() = match found {
            Found::Answering => Standing::Answering,
            Found::Silent => Standing::RestingUntil(now.checked_add(self.rest).unwrap_or(now)),
        };
    }

    /// The trying call admitted at `admission` was given up on at `now`
    /// before it settled: the server rests again rather than stay tried.
    pub(super) fn abandon(&self, admission: Admission, now: Instant) {
        if admission == Admission::Trying {
            *self.standing() = Standing::RestingUntil(now.checked_add(self.rest).unwrap_or(now));
        }
    }

    /// The standing, even after a panic while it was held: it is a plain
    /// value, never left half-changed.
    fn standing(&self) -> std::sync::MutexGuard<'_, Standing> {
        self.standing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// One call let through to the server: what it found is taken in when it
/// settles, and a call dropped before it settled counts as given up.
pub(super) struct Attempt<'a> {
    rests: &'a Rests,
    admission: Admission,
    settled: Settled,
}

/// Whether an attempt's finding was taken in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Settled {
    /// Not yet: dropping it now gives it up.
    Open,
    /// Its finding was taken in.
    Done,
}

impl<'a> Attempt<'a> {
    /// A call let through by `rests` now.
    ///
    /// # Errors
    ///
    /// [`CacheError::Unreachable`] while the server rests.
    pub(super) fn admitted(rests: &'a Rests) -> Result<Self, CacheError> {
        let admission = rests.admission(Instant::now())?;
        Ok(Self {
            rests,
            admission,
            settled: Settled::Open,
        })
    }

    /// Takes in what the call `found` of the server.
    pub(super) fn settle(mut self, found: Found) {
        self.rests.settle(found, Instant::now());
        self.settled = Settled::Done;
    }
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if self.settled == Settled::Open {
            self.rests.abandon(self.admission, Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How long the server rests in these tests.
    const REST: Duration = Duration::from_secs(1);

    /// A server that answers is asked as usual.
    #[test]
    fn an_answering_server_is_asked_as_usual() {
        let rests = Rests::after_each_failure(REST);

        let admission = rests.admission(Instant::now()).unwrap();

        assert_eq!(admission, Admission::Usual);
    }

    /// A call that times out rests the server: a call during the rest fails
    /// at once without asking it.
    #[test]
    fn a_failed_call_rests_the_server_and_calls_fail_at_once() {
        let rests = Rests::after_each_failure(REST);
        let start = Instant::now();
        rests.settle(Found::Silent, start);

        let during = rests.admission(start + REST / 2);

        assert!(matches!(during, Err(CacheError::Unreachable(_))));
    }

    /// Once the rest is over one call tries the server while the others
    /// still fail at once; its answer puts the server back in use.
    #[test]
    fn after_the_rest_one_call_tries_and_its_answer_ends_the_rest() {
        let rests = Rests::after_each_failure(REST);
        let start = Instant::now();
        rests.settle(Found::Silent, start);
        let later = start + REST;

        let trying = rests.admission(later).unwrap();
        let other = rests.admission(later);
        rests.settle(Found::Answering, later);
        let after = rests.admission(later).unwrap();

        assert_eq!(trying, Admission::Trying);
        assert!(other.is_err(), "only one call tries the server");
        assert_eq!(after, Admission::Usual);
    }

    /// A trying call that fails starts another rest.
    #[test]
    fn a_trying_call_that_fails_rests_the_server_again() {
        let rests = Rests::after_each_failure(REST);
        let start = Instant::now();
        rests.settle(Found::Silent, start);
        let later = start + REST;
        rests.admission(later).unwrap();

        rests.settle(Found::Silent, later);

        assert!(rests.admission(later + REST / 2).is_err());
        assert_eq!(rests.admission(later + REST).unwrap(), Admission::Trying);
    }

    /// A trying call its caller gave up on leaves the server resting, to be
    /// tried again after the next rest rather than never.
    #[test]
    fn a_trying_call_given_up_on_is_tried_again_after_the_next_rest() {
        let rests = Rests::after_each_failure(REST);
        let start = Instant::now();
        rests.settle(Found::Silent, start);
        let later = start + REST;
        let trying = rests.admission(later).unwrap();

        rests.abandon(trying, later);

        assert!(rests.admission(later).is_err());
        assert_eq!(rests.admission(later + REST).unwrap(), Admission::Trying);
    }

    /// A server that refused a command still answered: it is not rested.
    #[test]
    fn a_refused_command_does_not_rest_the_server() {
        let rests = Rests::after_each_failure(REST);

        rests.settle(Found::Answering, Instant::now());

        assert_eq!(rests.admission(Instant::now()).unwrap(), Admission::Usual);
    }
}
