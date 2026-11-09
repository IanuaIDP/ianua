//! In-memory stand-ins for the shared counters, and the requests the
//! counting stages are tested with.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::agents::{BudgetCounter, BudgetKey};
use ianua_app::ports::runtime::FleetCounters;
use ianua_app::ports::shared::EventDispatcher;
use ianua_app::test_support::{FailingEventDispatcher, FakeEventDispatcher};
use ianua_domain::domains::agents::authority::capability::{ActionApproval, McpGrant};
use ianua_domain::domains::proxy::request::context::{
    AgentLimits, Caller, KeyBinding, Metering, PipelineContext, UserSignIn, Verified,
};
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{
    AgentId, CorrelationId, DelegationId, Expiry, Fact, IpAddress, PipelineId, PrincipalRef,
    Seconds, TenantId, UserId,
};

use super::{CounterLimits, CounterPorts, CounterStages, HeldVerdicts};

/// How a fake counter answers.
#[derive(Debug, Clone, Copy)]
enum Answer {
    Counts,
    Unreachable,
    Hangs,
}

impl Answer {
    async fn ready(self) -> Option<()> {
        match self {
            Self::Counts => Some(()),
            Self::Unreachable => None,
            Self::Hangs => std::future::pending().await,
        }
    }
}

/// The counters every instance shares, held in memory.
pub(crate) struct FakeFleet {
    answer: Answer,
    counts: Mutex<HashMap<String, u32>>,
    sets: Mutex<HashMap<String, HashSet<String>>>,
}

impl FakeFleet {
    fn answering(answer: Answer) -> Arc<Self> {
        Arc::new(Self {
            answer,
            counts: Mutex::new(HashMap::new()),
            sets: Mutex::new(HashMap::new()),
        })
    }

    /// The sum of every count whose key ends with `suffix`.
    pub(crate) fn total_under(&self, suffix: &str) -> u32 {
        self.counts
            .lock()
            .unwrap()
            .iter()
            .filter(|(key, _)| key.ends_with(suffix))
            .map(|(_, count)| *count)
            .sum()
    }

    /// The members of every set whose key ends with `suffix`.
    pub(super) fn distinct_under(&self, suffix: &str) -> usize {
        self.sets
            .lock()
            .unwrap()
            .iter()
            .filter(|(key, _)| key.ends_with(suffix))
            .map(|(_, members)| members.len())
            .sum()
    }
}

#[async_trait]
impl FleetCounters for FakeFleet {
    async fn count(&self, key: &str, window: Seconds) -> Option<u32> {
        self.add(key, 1, window).await
    }

    async fn add(&self, key: &str, delta: u32, _: Seconds) -> Option<u32> {
        self.answer.ready().await?;
        let mut counts = self.counts.lock().unwrap();
        let count = counts.entry(key.to_owned()).or_insert(0);
        *count += delta;
        Some(*count)
    }

    async fn adjust(&self, key: &str, delta: i64, _: Seconds) -> Option<u32> {
        self.answer.ready().await?;
        let mut counts = self.counts.lock().unwrap();
        let count = counts.entry(key.to_owned()).or_insert(0);
        let settled = i64::from(*count).saturating_add(delta).max(0);
        *count = u32::try_from(settled).unwrap_or(u32::MAX);
        Some(*count)
    }

    async fn read(&self, key: &str) -> Option<u32> {
        self.answer.ready().await?;
        Some(self.counts.lock().unwrap().get(key).copied().unwrap_or(0))
    }

    async fn hold(&self, key: &str, _: Seconds) -> Option<()> {
        self.answer.ready().await?;
        self.counts.lock().unwrap().insert(key.to_owned(), 1);
        Some(())
    }

    async fn add_distinct(&self, key: &str, members: &[String], _: Seconds) -> Option<u32> {
        self.answer.ready().await?;
        let mut sets = self.sets.lock().unwrap();
        let set = sets.entry(key.to_owned()).or_default();
        set.extend(members.iter().cloned());
        u32::try_from(set.len()).ok()
    }

    async fn claim_once(&self, key: &str, _: Seconds) -> Option<bool> {
        self.answer.ready().await?;
        let mut sets = self.sets.lock().unwrap();
        Some(sets.insert(key.to_owned(), HashSet::new()).is_none())
    }
}

/// The request budgets every instance shares, held in memory.
pub(super) struct FakeBudgets {
    answer: Answer,
    uses: Mutex<HashMap<BudgetKey, u32>>,
}

#[async_trait]
impl BudgetCounter for FakeBudgets {
    async fn record_use(&self, key: &BudgetKey, _: Seconds) -> Option<u32> {
        self.answer.ready().await?;
        let mut uses = self.uses.lock().unwrap();
        let count = uses.entry(*key).or_insert(0);
        *count += 1;
        Some(*count)
    }
}

/// Shared counters, a budget counter and an inbox, from which any number of
/// instances' counting stages are made.
pub(crate) struct Rig {
    pub(crate) fleet: Arc<FakeFleet>,
    budgets: Arc<FakeBudgets>,
    pub(super) events: Arc<FakeEventDispatcher>,
    inbox: Arc<dyn EventDispatcher>,
}

impl Rig {
    fn answering(answer: Answer) -> Self {
        let events = Arc::new(FakeEventDispatcher::new());
        Self {
            fleet: FakeFleet::answering(answer),
            budgets: Arc::new(FakeBudgets {
                answer,
                uses: Mutex::new(HashMap::new()),
            }),
            inbox: Arc::clone(&events) as Arc<dyn EventDispatcher>,
            events,
        }
    }

    /// Counters that count.
    pub(crate) fn counting() -> Self {
        Self::answering(Answer::Counts)
    }

    /// Counters that answer nothing.
    pub(crate) fn unreachable() -> Self {
        Self::answering(Answer::Unreachable)
    }

    /// Counters that never answer.
    pub(super) fn hanging() -> Self {
        Self::answering(Answer::Hangs)
    }

    /// Counters that count, and an inbox that refuses every record.
    pub(super) fn with_failing_inbox() -> Self {
        Self {
            inbox: Arc::new(FailingEventDispatcher),
            ..Self::counting()
        }
    }

    /// One instance's counting stages, with a verdict table of its own.
    pub(crate) fn stages(&self) -> CounterStages {
        CounterStages::new(
            CounterPorts {
                fleet: Arc::clone(&self.fleet) as Arc<dyn FleetCounters>,
                budgets: Arc::clone(&self.budgets) as Arc<dyn BudgetCounter>,
                events: Arc::clone(&self.inbox),
                held: Arc::new(HeldVerdicts::new(100)),
                publisher: None,
            },
            CounterLimits {
                counter_timeout: Duration::from_millis(50),
                record_timeout: Duration::from_millis(50),
                tarpits: 4,
            },
        )
    }
}

/// An anonymous request from 203.0.113.7 to a tenant of its own.
pub(super) fn context() -> PipelineContext {
    let mut ctx = PipelineContext::new(TenantId::new(), PipelineId::new(), CorrelationId::new());
    ctx.ip_address = Fact::Known(IpAddress::new("203.0.113.7").unwrap());
    ctx
}

/// A request from 203.0.113.7 whose credential named `caller`.
pub(super) fn signed_in(caller: Caller) -> PipelineContext {
    let mut ctx = context();
    ctx.authenticate(Verified {
        caller,
        expiry: Expiry::Never,
    })
    .unwrap();
    ctx
}

/// A request from a signed-in person.
pub(super) fn signed_in_user() -> PipelineContext {
    signed_in(Caller::User {
        user_id: UserId::new(),
        sign_in: UserSignIn::Token,
    })
}

/// A request from an agent metered by `metering`, acting for `acting_for`.
pub(super) fn signed_in_agent(metering: Metering, acting_for: PrincipalRef) -> PipelineContext {
    signed_in(Caller::Agent {
        agent_id: AgentId::new(),
        delegation_id: DelegationId::new(),
        acting_for,
        limits: Box::new(AgentLimits {
            intent_envelope: Restriction::Unrestricted,
            mcp: McpGrant::default(),
            resource_scope: Restriction::Unrestricted,
            max_data_class: Restriction::Unrestricted,
            key_binding: KeyBinding::Bearer,
            approval: ActionApproval::NotRequired,
            metering,
        }),
    })
}

/// The status a refusal carries, or `None` when the request goes on.
pub(super) fn denial_status(decision: &StageDecision) -> Option<u16> {
    let StageDecision::Deny { status, .. } = decision else {
        return None;
    };
    Some(status.code())
}

/// The value of the response header `name` the stages set.
pub(super) fn header_value(ctx: &PipelineContext, name: &str) -> Option<String> {
    ctx.response_headers
        .iter()
        .find(|header| header.name().as_str() == name)
        .map(|header| header.value().as_str().to_owned())
}
