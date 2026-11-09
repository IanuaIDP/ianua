//! Detect convergence: agents meeting at a place ianua cannot close.
//!
//! A worker over `AgentActionAuthorized` events. Every allowed request is a
//! touch on a path. When a request makes an agent meet another there for the
//! first time in the window, one writing and the other reading, it is
//! recorded as [`AgentsConverged`]. Under an `Enforce` drift policy the
//! platform's monitor suspends the agent whose request completed the
//! meeting, the same response as a high-risk drift; otherwise the meeting is
//! an alert for a person to look at.

use std::sync::Arc;

use ianua_domain::domains::agents::events::execution::AgentsConverged;
use ianua_domain::domains::agents::execution::convergence::{
    Touch, TouchKind, newly_met, places_met, places_touched,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::{
    ActingFor, ActionClass, ActorRef, AgentId, CanonicalPath, DelegationId, HttpMethod,
};
use time::{Duration, OffsetDateTime};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, DelegationStore, TouchEntry, TouchLedger};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::lifecycle::containment::suspension::{
    EnforcementStores, suspension_if_enforced,
};

/// One allowed agent request, as the proxy recorded it.
pub struct DetectConvergenceRequest {
    /// The acting agent.
    pub agent_id: AgentId,
    /// The delegation the request was allowed under.
    pub delegation_id: DelegationId,
    /// The request as `"METHOD /path"`.
    pub action: String,
    /// The class the proxy judged the request as.
    pub action_class: ActionClass,
    /// When the proxy allowed it.
    pub at: OffsetDateTime,
}

/// What the detector concluded.
#[derive(Debug, PartialEq, Eq)]
pub enum ConvergenceOutcome {
    /// The request met nobody new.
    NoMeeting,
    /// The request met these agents for the first time in the window.
    Met {
        /// The agents met.
        met: Vec<AgentId>,
        /// Whether the acting agent was suspended for it.
        suspended: bool,
    },
}

/// The ports [`DetectConvergenceUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DetectConvergencePorts {
    /// Recent touches per path.
    pub ledger: Arc<dyn TouchLedger>,
    /// Loads the delegation, to read its drift policy.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// Suspends the agent under `Enforce`.
    pub agent_store: Arc<dyn AgentStore>,
}

/// Detects agents meeting at one path.
pub struct DetectConvergenceUseCase {
    window: Duration,
    ports: DetectConvergencePorts,
}

impl DetectConvergenceUseCase {
    /// A use case working through `ports`. `window` is how far back two
    /// touches on one place still count as a meeting; long, on purpose,
    /// since agents taking turns at a message board can wait between them.
    #[must_use]
    pub fn new(window: Duration, ports: DetectConvergencePorts) -> Self {
        Self { window, ports }
    }
}

impl Command for DetectConvergenceUseCase {
    type Caller = ScopedTenant;
    type Input = DetectConvergenceRequest;
    type Output = Result<ConvergenceOutcome, AppError>;

    /// Reports any new meeting the touch makes, then records the touch, so
    /// a report that could not be kept leaves the touch unrecorded and the
    /// same request, handed over again, finds the same meeting.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the request's path cannot be read as a
    ///   canonical path, or the monitor may not suspend the agent.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: DetectConvergenceRequest,
    ) -> Result<ConvergenceOutcome, AppError> {
        let request = TouchedPath::of(&req)?;
        let window_start = request.at - self.window;
        let met = meetings_made(self.ports.ledger.as_ref(), tenant, &request, window_start).await?;
        let heard = Heard {
            req: &req,
            request: &request,
        };
        let outcome = reported(&self.ports, tenant, auditor, &heard, met).await?;
        touch_recorded(self.ports.ledger.as_ref(), tenant, &request, window_start).await?;
        Ok(outcome)
    }
}

/// One request as a touch on a canonical path, and when it was made.
struct TouchedPath {
    path: CanonicalPath,
    touch: Touch,
    at: OffsetDateTime,
}

impl TouchedPath {
    /// The touch `req` makes. A method the proxy does not know counts as a
    /// write, since it may change what the next reader sees.
    fn of(req: &DetectConvergenceRequest) -> Result<Self, AppError> {
        let (method, path) = req
            .action
            .split_once(' ')
            .map_or((None, req.action.as_str()), |(method, path)| {
                (HttpMethod::parse(method), path)
            });
        let path = CanonicalPath::new(path)
            .map_err(|error| AppError::from_domain(DomainError::from(error)))?;
        let kind = method.map_or(TouchKind::Write, |method| {
            TouchKind::of_action(method, req.action_class)
        });
        Ok(Self {
            path,
            touch: Touch {
                agent: req.agent_id,
                kind,
            },
            at: req.at,
        })
    }
}

/// The agents `request` meets for the first time since `window_start`.
async fn meetings_made(
    ledger: &dyn TouchLedger,
    tenant: &ScopedTenant,
    request: &TouchedPath,
    window_start: OffsetDateTime,
) -> Result<Vec<AgentId>, AppError> {
    let earlier = touches_met(ledger, tenant, &request.path, window_start).await?;
    Ok(newly_met(&earlier, &request.touch))
}

/// The request a meeting is judged for, as asked and as a touch.
struct Heard<'a> {
    req: &'a DetectConvergenceRequest,
    request: &'a TouchedPath,
}

/// The outcome of `met`, recorded, the acting agent suspended first when
/// its delegation enforces its intent.
async fn reported(
    ports: &DetectConvergencePorts,
    tenant: &ScopedTenant,
    auditor: &RequestAuditor,
    heard: &Heard<'_>,
    met: Vec<AgentId>,
) -> Result<ConvergenceOutcome, AppError> {
    let Heard { req, request } = heard;
    if met.is_empty() {
        return Ok(ConvergenceOutcome::NoMeeting);
    }
    let suspension = enforced_suspension(ports, tenant, req).await?;
    let suspended = suspension.is_some();
    let meeting = AgentsConverged::observed(
        **tenant,
        req.delegation_id,
        met.clone(),
        &request.path,
        req.at,
    )
    .with_actor(ActorRef::Agent {
        id: req.agent_id,
        on_behalf_of: ActingFor::Itself,
    });
    let events: Vec<DomainEvent> = std::iter::once(meeting).chain(suspension).collect();
    auditor.dispatch(&events).await.or_internal()?;
    Ok(ConvergenceOutcome::Met { met, suspended })
}

/// Records `request`'s touch on every place it reaches.
async fn touch_recorded(
    ledger: &dyn TouchLedger,
    tenant: &ScopedTenant,
    request: &TouchedPath,
    window_start: OffsetDateTime,
) -> Result<(), AppError> {
    for place in places_touched(&request.path) {
        let entry = TouchEntry {
            path: &place,
            touch: &request.touch,
            at: request.at,
            forget_before: window_start,
        };
        ledger.record(tenant, &entry).await.or_internal()?;
    }
    Ok(())
}

/// The touches since `window_start` on every place a request to `path`
/// meets.
async fn touches_met(
    ledger: &dyn TouchLedger,
    tenant: &ScopedTenant,
    path: &CanonicalPath,
    window_start: OffsetDateTime,
) -> Result<Vec<Touch>, AppError> {
    let mut earlier = Vec::new();
    for place in places_met(path) {
        earlier.extend(
            ledger
                .since(tenant, &place, window_start)
                .await
                .or_internal()?,
        );
    }
    Ok(earlier)
}

/// The acting agent's suspension, when its delegation enforces its intent
/// and the agent was still running; `None` otherwise.
async fn enforced_suspension(
    ports: &DetectConvergencePorts,
    tenant: &ScopedTenant,
    req: &DetectConvergenceRequest,
) -> Result<Option<DomainEvent>, AppError> {
    suspension_if_enforced(
        EnforcementStores {
            delegation_store: ports.delegation_store.as_ref(),
            agent_store: ports.agent_store.as_ref(),
        },
        tenant,
        &req.agent_id,
        &req.delegation_id,
    )
    .await
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::intent::{
        DriftPolicy, DriftThreshold, IntentBinding, IntentDigest, IntentEnvelope, IntentStatement,
    };
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::shared::clock;

    use super::*;
    use crate::test_support::agents::{
        FakeAgentStore, FakeDelegationStore, FakeTouchLedger, grant_to,
    };
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, block_on, test_auditor, test_ctx,
    };

    const WINDOW: Duration = Duration::hours(24);

    /// The agents of the test tenant, their delegations and touches, and
    /// what the detector records.
    struct Fixture {
        agents: Arc<FakeAgentStore>,
        delegations: Arc<FakeDelegationStore>,
        ledger: Arc<FakeTouchLedger>,
        sink: Arc<FakeEventDispatcher>,
    }

    fn fixture() -> Fixture {
        Fixture {
            agents: Arc::new(FakeAgentStore::empty()),
            delegations: Arc::new(FakeDelegationStore::empty()),
            ledger: Arc::new(FakeTouchLedger::default()),
            sink: Arc::new(FakeEventDispatcher::new()),
        }
    }

    impl Fixture {
        /// The detector shares this fixture's activity ledger and authority stores.
        fn detector(&self) -> DetectConvergenceUseCase {
            DetectConvergenceUseCase::new(
                WINDOW,
                DetectConvergencePorts {
                    ledger: self.ledger.clone(),
                    delegation_store: self.delegations.clone(),
                    agent_store: self.agents.clone(),
                },
            )
        }

        /// A running agent and its delegation, watched under `policy`.
        fn agent(&self, policy: Option<DriftPolicy>) -> (AgentId, DelegationId) {
            let agent = AgentId::new();
            self.agents.add_active(agent);
            let binding = policy.map(|policy| {
                IntentBinding::new(
                    IntentStatement::new("watch the queue").unwrap(),
                    IntentDigest::new([1u8; 32]),
                    policy,
                    IntentEnvelope::new([ActionClass::Read, ActionClass::Write]),
                )
            });
            let granted = grant_to(agent, binding, None);
            block_on(self.delegations.save(&test_ctx().tenant(), &granted)).unwrap();
            (agent, *granted.id())
        }

        fn act(
            &self,
            (agent, delegation): (AgentId, DelegationId),
            action: &str,
            at: OffsetDateTime,
        ) -> Result<ConvergenceOutcome, AppError> {
            let use_case = self.detector();
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                DetectConvergenceRequest {
                    agent_id: agent,
                    delegation_id: delegation,
                    action: action.to_owned(),
                    action_class: class_of(action),
                    at,
                },
            ))
        }

        fn status_of(&self, agent: AgentId) -> AgentStatus {
            self.agents.find_by_id_direct(&agent).unwrap().status()
        }

        fn recorded(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// The class the proxy would judge `action` as.
    fn class_of(action: &str) -> ActionClass {
        let (method, path) = action.split_once(' ').unwrap();
        HttpMethod::parse(method).map_or(ActionClass::Write, |method| {
            ActionClass::classify(method, path)
        })
    }

    fn now() -> OffsetDateTime {
        clock::now()
    }

    fn threshold() -> DriftThreshold {
        DriftThreshold::from_basis_points(5000).unwrap()
    }

    fn met(writer: AgentId, suspended: bool) -> ConvergenceOutcome {
        ConvergenceOutcome::Met {
            met: vec![writer],
            suspended,
        }
    }

    /// One agent writes `/board/1`, and another reads it. They met, and
    /// the meeting is recorded.
    #[test]
    fn a_reader_after_a_writer_on_one_path_is_a_meeting_on_record() {
        let f = fixture();
        let (writer, reader) = (f.agent(None), f.agent(None));

        f.act(writer, "PUT /board/1", now()).unwrap();
        let outcome = f.act(reader, "GET /board/1", now()).unwrap();

        assert_eq!(outcome, met(writer.0, false));
        assert_eq!(f.recorded(), ["agents.converged"]);
    }

    /// A message board: one agent posts an item, the other lists the
    /// collection. They met, though their paths differ.
    #[test]
    fn listing_a_collection_meets_the_agent_that_wrote_into_it() {
        let f = fixture();
        let (writer, reader) = (f.agent(None), f.agent(None));

        f.act(writer, "POST /board/42", now()).unwrap();
        let outcome = f.act(reader, "GET /board/", now()).unwrap();

        assert_eq!(outcome, met(writer.0, false));
    }

    /// The writer posted three hours before the reader looked. Taking
    /// turns still counts as meeting.
    #[test]
    fn turns_hours_apart_still_meet() {
        let f = fixture();
        let (writer, reader) = (f.agent(None), f.agent(None));

        f.act(writer, "PUT /board/1", now() - Duration::hours(3))
            .unwrap();
        let outcome = f.act(reader, "GET /board/1", now()).unwrap();

        assert!(matches!(outcome, ConvergenceOutcome::Met { .. }));
    }

    /// One agent writes `/board/1`, the other reads `/board/2`. Sibling
    /// items are not a meeting.
    #[test]
    fn different_paths_never_meet() {
        let f = fixture();
        let (writer, reader) = (f.agent(None), f.agent(None));

        f.act(writer, "PUT /board/1", now()).unwrap();
        let outcome = f.act(reader, "GET /board/2", now()).unwrap();

        assert_eq!(outcome, ConvergenceOutcome::NoMeeting);
    }

    /// The write happened before the window began. The read meets nobody.
    #[test]
    fn touches_outside_the_window_do_not_meet() {
        let f = fixture();
        let (writer, reader) = (f.agent(None), f.agent(None));
        let long_ago = now() - WINDOW - Duration::minutes(1);

        f.act(writer, "PUT /board/1", long_ago).unwrap();
        let outcome = f.act(reader, "GET /board/1", now()).unwrap();

        assert_eq!(outcome, ConvergenceOutcome::NoMeeting);
    }

    /// The reader reads `/board/1` again. The two already met, so it is
    /// recorded once.
    #[test]
    fn the_same_meeting_is_reported_once() {
        let f = fixture();
        let (writer, reader) = (f.agent(None), f.agent(None));
        f.act(writer, "PUT /board/1", now()).unwrap();
        f.act(reader, "GET /board/1", now()).unwrap();

        let again = f.act(reader, "GET /board/1", now()).unwrap();

        assert_eq!(again, ConvergenceOutcome::NoMeeting);
        assert_eq!(f.recorded(), ["agents.converged"]);
    }

    /// An unknown method counts as a write when detecting a later reader's
    /// meeting on the same path.
    #[test]
    fn an_unknown_method_counts_as_a_write() {
        let f = fixture();
        let (writer, reader) = (f.agent(None), f.agent(None));

        f.act(writer, "PURGE /board/1", now()).unwrap();
        let outcome = f.act(reader, "GET /board/1", now()).unwrap();

        assert_eq!(outcome, met(writer.0, false));
    }

    /// A reader completing a meeting under enforced intent is suspended
    /// while the writer stays active; meeting and suspension are recorded.
    #[test]
    fn under_enforce_the_agent_completing_the_meeting_is_suspended() {
        let f = fixture();
        let writer = f.agent(None);
        let reader = f.agent(Some(DriftPolicy::Enforce(threshold())));
        f.act(writer, "PUT /board/1", now()).unwrap();

        let outcome = f.act(reader, "GET /board/1", now()).unwrap();

        assert_eq!(outcome, met(writer.0, true));
        assert_eq!(f.status_of(reader.0), AgentStatus::Suspended);
        assert_eq!(f.status_of(writer.0), AgentStatus::Active);
        assert_eq!(f.recorded(), ["agents.converged", "agents.agent_suspended"]);
    }

    /// Under `Warn`, the meeting is only an alert: the reader keeps
    /// running.
    #[test]
    fn under_warn_the_meeting_is_only_an_alert() {
        let f = fixture();
        let writer = f.agent(None);
        let reader = f.agent(Some(DriftPolicy::Warn(threshold())));
        f.act(writer, "PUT /board/1", now()).unwrap();

        let outcome = f.act(reader, "GET /board/1", now()).unwrap();

        assert_eq!(outcome, met(writer.0, false));
        assert_eq!(f.status_of(reader.0), AgentStatus::Active);
    }

    /// A path containing parent traversal is refused without recording a
    /// convergence event.
    #[test]
    fn a_path_that_cannot_be_made_canonical_is_refused() {
        let f = fixture();
        let agent = f.agent(None);

        let result = f.act(agent, "GET /board/../admin", now());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(f.recorded().is_empty());
    }

    /// After recording a meeting fails, retrying the same request still
    /// reports the meeting.
    #[test]
    fn a_meeting_whose_record_failed_is_reported_when_tried_again() {
        let f = fixture();
        let (writer, reader) = (f.agent(None), f.agent(None));
        f.act(writer, "PUT /board/1", now()).unwrap();
        let at = now();
        let failing = f.detector();
        let request = || DetectConvergenceRequest {
            agent_id: reader.0,
            delegation_id: reader.1,
            action: "GET /board/1".to_owned(),
            action_class: class_of("GET /board/1"),
            at,
        };

        let failed = block_on(failing.execute(
            &test_ctx().tenant(),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            request(),
        ));
        let again = block_on(failing.execute(
            &test_ctx().tenant(),
            &test_auditor(f.sink.clone()),
            request(),
        ))
        .unwrap();

        assert!(failed.is_err());
        assert_eq!(again, met(writer.0, false));
    }
}
