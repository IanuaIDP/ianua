//! Signed-in people the gateway turned away, recorded for workflows to
//! start from.
//!
//! Pat's browser retries the payroll app a hundred times a minute. Each
//! refusal stays in the request records; the audit trail gets one
//! `proxy.person_turned_away` for Pat on that app in each quiet period, so
//! it does not fill with his retries. The memory of what was recorded is
//! bounded: once full of refusals still in their quiet period, a new one
//! goes unrecorded rather than growing it. The person is refused either
//! way.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ianua_app::auditor::RequestAuditor;
use ianua_app::ports::shared::EventDispatcher;
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::proxy::RecordTurnedAwayUseCase;
use ianua_domain::domains::proxy::access::decision::Outcome;
use ianua_domain::domains::proxy::events::Refused;
use ianua_domain::domains::proxy::request::context::{Caller, PipelineContext};
use ianua_domain::types::{EventLabel, RouteId, TenantId, UserId};

use crate::pipeline::facts::RequestFacts;

/// How long after recording a person turned away from an app the next
/// refusal of them there goes unrecorded.
const QUIET: Duration = Duration::from_secs(600);

/// The most refusals remembered at once.
const MOST_REMEMBERED: usize = 10_000;

/// One person refused by one app.
type Seen = (TenantId, UserId, RouteId);

/// Records people turned away, once per person and app in each quiet
/// period.
pub(super) struct TurnedAway {
    events: Arc<dyn EventDispatcher>,
    recent: Mutex<HashMap<Seen, Instant>>,
    call_timeout: Duration,
}

impl TurnedAway {
    /// Records through `events`, each record held to `call_timeout`.
    pub(super) fn new(events: Arc<dyn EventDispatcher>, call_timeout: Duration) -> Self {
        Self {
            events,
            recent: Mutex::new(HashMap::new()),
            call_timeout,
        }
    }

    /// Records that the request `facts` describe was denied, when the
    /// access decision `outcome` denied it, `ctx` names a signed-in person,
    /// and they were not recorded on that app in the quiet period. A
    /// decision that never came, or asked for more, is not a denial.
    pub(super) async fn record(
        &self,
        ctx: &PipelineContext,
        facts: &RequestFacts,
        outcome: Option<Outcome>,
    ) {
        let Some(Outcome::Deny(code)) = outcome else {
            return;
        };
        let Some(Caller::User { user_id, .. }) = ctx.authentication().caller() else {
            return;
        };
        let reason = code.as_str();
        let route_id = *facts.route.id();
        if !self.is_due((ctx.tenant_id, *user_id, route_id), Instant::now()) {
            return;
        }
        let refused = Refused {
            user_id: *user_id,
            route_id,
            route_label: EventLabel::of(facts.route.name().as_str()),
            reason,
            correlation_id: ctx.correlation_id,
        };
        let auditor = RequestAuditor::system(Arc::clone(&self.events)).with_tenant(ctx.tenant_id);
        let recorded = RecordTurnedAwayUseCase.execute(&facts.tenant, &auditor, refused);
        match tokio::time::timeout(self.call_timeout, recorded).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(%error, "a refusal was not recorded"),
            Err(_) => tracing::warn!("recording a refusal timed out"),
        }
    }

    /// Whether `seen` is due a record at `now`, noting it when it is.
    fn is_due(&self, seen: Seen, now: Instant) -> bool {
        let Ok(mut recent) = self.recent.lock() else {
            return false;
        };
        recent.retain(|_, at| now.duration_since(*at) < QUIET);
        if recent.contains_key(&seen) || recent.len() >= MOST_REMEMBERED {
            return false;
        }
        recent.insert(seen, now);
        true
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::FakeEventDispatcher;

    use super::*;

    fn turned_away() -> TurnedAway {
        TurnedAway::new(Arc::new(FakeEventDispatcher::new()), Duration::from_secs(1))
    }

    fn seen() -> Seen {
        (TenantId::new(), UserId::new(), RouteId::new())
    }

    /// Pat is refused the payroll app twice in a minute: the first is
    /// recorded, the second is not. Ten minutes on, it is again.
    #[test]
    fn one_refusal_is_recorded_in_each_quiet_period() {
        let refusals = turned_away();
        let pat = seen();
        let now = Instant::now();

        let first = refusals.is_due(pat, now);
        let again = refusals.is_due(pat, now + Duration::from_secs(60));
        let later = refusals.is_due(pat, now + QUIET + Duration::from_secs(1));

        assert!(first);
        assert!(!again);
        assert!(later);
    }

    /// Ann, refused at the same time as Pat, is recorded too: the quiet
    /// period is per person and app.
    #[test]
    fn another_person_is_recorded_alongside() {
        let refusals = turned_away();
        let now = Instant::now();

        let pat = refusals.is_due(seen(), now);
        let ann = refusals.is_due(seen(), now);

        assert!(pat && ann);
    }
}
