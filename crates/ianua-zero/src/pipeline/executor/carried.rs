//! What one stage of a request finds for a later one: the caller the
//! Identity stage proved, what a device check found, and the tokens a
//! token limit set aside.
//!
//! It lives in the request's run and dies with it, so nothing one request
//! found reaches another, and its lock is never held across a call out of
//! the gateway.

use std::sync::{Mutex, MutexGuard, PoisonError};

use ianua_app::use_cases::proxy::credentials::Identification;
use ianua_domain::domains::proxy::access::question::PostureFinding;
use ianua_domain::domains::proxy::stages::token_budget::{Reservation, TokenRateLimitConfig};
use ianua_domain::types::StageId;

use crate::pipeline::stages::policy::EarlierFindings;

/// Tokens a token limit set aside for this request, until its answer
/// settles them or the request ends without one.
pub(super) struct HeldTokens {
    /// The stage that set them aside.
    pub(super) stage: StageId,
    /// Its limit, which the counter they were set aside in is keyed by.
    pub(super) config: TokenRateLimitConfig,
    /// What was set aside, and in which window.
    pub(super) reservation: Reservation,
}

/// What earlier stages found, as the stages after them read it.
struct Found {
    identification: Option<Identification>,
    posture: PostureFinding,
    held: Vec<HeldTokens>,
}

/// One request's findings.
pub(super) struct Carried {
    found: Mutex<Found>,
}

impl Carried {
    /// Nothing found yet: nobody proven, no device asked about, no tokens
    /// set aside.
    pub(super) fn new() -> Self {
        Self {
            found: Mutex::new(Found {
                identification: None,
                posture: PostureFinding::NotAsked,
                held: Vec::new(),
            }),
        }
    }

    /// Keeps whom the Identity stage proved, for the Policy stage.
    pub(super) fn record_identity(&self, identification: Identification) {
        self.found().identification = Some(identification);
    }

    /// Keeps what the device check found, for the Policy stage.
    pub(super) fn posture_checked(&self, finding: PostureFinding) {
        self.found().posture = finding;
    }

    /// What the Policy stage decides on, handed over once. `None` when no
    /// Identity stage proved anyone before it, or Policy already took it.
    pub(super) fn earlier(&self) -> Option<EarlierFindings> {
        let mut found = self.found();
        let identification = found.identification.take()?;
        Some(EarlierFindings {
            identification,
            posture: found.posture,
        })
    }

    /// What a device check found, for an open connection to be checked
    /// against later as the request was.
    pub(super) fn posture(&self) -> PostureFinding {
        self.found().posture
    }

    /// Keeps the tokens a limit set aside, for its answer to settle.
    pub(super) fn record_reservation(&self, held: HeldTokens) {
        self.found().held.push(held);
    }

    /// The tokens the limit `stage` set aside, handed over to settle once.
    pub(super) fn reservation_of(&self, stage: &StageId) -> Option<Reservation> {
        let mut found = self.found();
        let index = found.held.iter().position(|held| held.stage == *stage)?;
        Some(found.held.remove(index).reservation)
    }

    /// Every set of tokens no answer settled, handed over to release.
    pub(super) fn unspent(&self) -> Vec<HeldTokens> {
        std::mem::take(&mut self.found().held)
    }

    /// The findings, still readable after a panic elsewhere left the lock
    /// poisoned: they belong to this request alone, so nothing else can
    /// have left them half written.
    fn found(&self) -> MutexGuard<'_, Found> {
        self.found.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
