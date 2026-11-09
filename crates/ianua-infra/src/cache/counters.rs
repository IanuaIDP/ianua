//! The counters every node shares: each consumer's quota per period, each
//! delegation's request budget, and the gateway's fleet-wide counters and
//! single-use claims.
//!
//! The quota answers an error when the count cannot be read; the budget
//! and fleet counters answer nothing. Either way the gateway refuses the
//! request: a limit counted on one node alone would let a fleet of four
//! admit four times the limit, so a cache that is down closes what it
//! counts, it never opens it.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::{BudgetCounter, BudgetKey, BudgetUsageReader};
use ianua_app::ports::consumers::ConsumerQuotaCounter;
use ianua_app::ports::runtime::FleetCounters;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::consumers::quota::QuotaPeriod;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConsumerId, DelegationId, Seconds};
use time::{Date, OffsetDateTime, Time};

use crate::cache::state::{SharedState, key};

/// When the `period` holding `now` began, and how long a count of it is
/// kept: the period itself and a minute more, so a request at its very end
/// is still counted against it.
fn period_of(period: QuotaPeriod, now: OffsetDateTime) -> (i64, Duration) {
    let day = now.date();
    let start = match period {
        QuotaPeriod::Minute => {
            day.with_time(Time::from_hms(now.hour(), now.minute(), 0).unwrap_or(Time::MIDNIGHT))
        }
        QuotaPeriod::Hour => {
            day.with_time(Time::from_hms(now.hour(), 0, 0).unwrap_or(Time::MIDNIGHT))
        }
        QuotaPeriod::Day => day.midnight(),
        QuotaPeriod::Month => Date::from_calendar_date(day.year(), day.month(), 1)
            .unwrap_or(day)
            .midnight(),
    };
    let length = match period {
        QuotaPeriod::Minute => Duration::from_secs(60),
        QuotaPeriod::Hour => Duration::from_secs(3_600),
        QuotaPeriod::Day => Duration::from_secs(86_400),
        QuotaPeriod::Month => Duration::from_secs(2_678_400),
    };
    (
        start.assume_utc().unix_timestamp(),
        length.saturating_add(Duration::from_secs(60)),
    )
}

/// The counter of each consumer's requests per quota period.
pub struct CacheConsumerQuotaCounter {
    state: Arc<dyn SharedState>,
}

impl TenantScoped for CacheConsumerQuotaCounter {}

impl CacheConsumerQuotaCounter {
    /// A counter on `state`.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl ConsumerQuotaCounter for CacheConsumerQuotaCounter {
    async fn spend(
        &self,
        tenant_id: &ScopedTenant,
        consumer: &ConsumerId,
        period: QuotaPeriod,
    ) -> Result<u64, DomainError> {
        let (start, keep) = period_of(period, clock::now());
        let counter = key(&[
            "quota",
            &tenant_id.to_string(),
            &consumer.to_string(),
            period.as_str(),
            &start.to_string(),
        ]);
        let count = self.state.count(&counter, 1, keep).await?;
        Ok(count.saturating_sub(1))
    }
}

/// The key a budget's uses are counted under.
fn budget_key(budget: &BudgetKey) -> String {
    match budget {
        BudgetKey::Delegation(id) => key(&["budget", "delegation", &id.to_string()]),
        BudgetKey::Agent(id) => key(&["budget", "agent", &id.to_string()]),
    }
}

/// `count` as the 32 bits a budget reads.
fn narrowed(count: u64) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// The fleet-wide counter of each delegation's and agent's request budget.
pub struct CacheBudgetCounter {
    state: Arc<dyn SharedState>,
}

impl CacheBudgetCounter {
    /// A counter on `state`.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl BudgetCounter for CacheBudgetCounter {
    async fn record_use(&self, key: &BudgetKey, window_seconds: Seconds) -> Option<u32> {
        self.state
            .count(&budget_key(key), 1, window_seconds.std_duration())
            .await
            .inspect_err(|error| tracing::warn!(%error, "the shared budget counter did not answer"))
            .ok()
            .map(narrowed)
    }
}

/// The read of a delegation's live budget use, for reporting.
pub struct CacheBudgetUsageReader {
    state: Arc<dyn SharedState>,
}

impl CacheBudgetUsageReader {
    /// A read of the counts `state` keeps.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl BudgetUsageReader for CacheBudgetUsageReader {
    async fn current_usage(&self, delegation_id: &DelegationId) -> Option<u32> {
        self.state
            .read(&budget_key(&BudgetKey::Delegation(*delegation_id)))
            .await
            .ok()
            .flatten()
            .map(narrowed)
    }
}

/// The gateway's fleet-wide counters and single-use claims.
pub struct CacheFleetCounters {
    state: Arc<dyn SharedState>,
}

impl CacheFleetCounters {
    /// Counters on `state`.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>) -> Self {
        Self { state }
    }
}

/// The key the gateway's `name` is kept under.
fn fleet_key(name: &str) -> String {
    key(&["fleet", name])
}

#[async_trait]
impl FleetCounters for CacheFleetCounters {
    async fn count(&self, key: &str, window: Seconds) -> Option<u32> {
        self.add(key, 1, window).await
    }

    async fn add(&self, key: &str, delta: u32, window: Seconds) -> Option<u32> {
        self.state
            .count(&fleet_key(key), u64::from(delta), window.std_duration())
            .await
            .ok()
            .map(narrowed)
    }

    async fn adjust(&self, key: &str, delta: i64, window: Seconds) -> Option<u32> {
        let held = fleet_key(key);
        let by = delta.unsigned_abs();
        let settled = if delta >= 0 {
            self.state
                .count(&held, by, window.std_duration())
                .await
                .map(Some)
        } else {
            self.state.lower(&held, by).await
        };
        settled
            .ok()
            .map(|count| narrowed(count.unwrap_or_default()))
    }

    async fn read(&self, key: &str) -> Option<u32> {
        self.state
            .read(&fleet_key(key))
            .await
            .ok()
            .map(|count| narrowed(count.unwrap_or_default()))
    }

    async fn hold(&self, key: &str, lasts: Seconds) -> Option<()> {
        self.state
            .hold(&fleet_key(key), lasts.std_duration())
            .await
            .ok()
    }

    async fn add_distinct(&self, key: &str, members: &[String], window: Seconds) -> Option<u32> {
        self.state
            .add_distinct(&fleet_key(key), members, window.std_duration())
            .await
            .ok()
            .map(narrowed)
    }

    async fn claim_once(&self, key: &str, ttl: Seconds) -> Option<bool> {
        self.state
            .claim_once(&fleet_key(key), ttl.std_duration())
            .await
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::TenantId;
    use time::Month;

    use super::*;
    use crate::cache::MemoryState;
    use crate::cache::stores::RefusingState;

    fn state() -> Arc<dyn SharedState> {
        Arc::new(MemoryState::new(1_000))
    }

    /// Each request answers how many the consumer sent before it in the
    /// period, and another consumer counts apart.
    #[tokio::test]
    async fn a_quota_counts_the_requests_before_each() {
        let counter = CacheConsumerQuotaCounter::new(state());
        let tenant = ScopedTenant::for_background(TenantId::new());
        let (billing, other) = (ConsumerId::new(), ConsumerId::new());

        let first = counter
            .spend(&tenant, &billing, QuotaPeriod::Hour)
            .await
            .unwrap();
        let second = counter
            .spend(&tenant, &billing, QuotaPeriod::Hour)
            .await
            .unwrap();
        let theirs = counter
            .spend(&tenant, &other, QuotaPeriod::Hour)
            .await
            .unwrap();

        assert_eq!((first, second, theirs), (0, 1, 0));
    }

    /// A month's quota period starts on its first day at midnight UTC.
    #[test]
    fn a_month_starts_on_its_first_day() {
        let day = |of: u8| Date::from_calendar_date(2027, Month::March, of).unwrap();
        let now = day(17)
            .with_time(Time::from_hms(14, 5, 9).unwrap())
            .assume_utc();

        let (start, _) = period_of(QuotaPeriod::Month, now);

        assert_eq!(start, day(1).midnight().assume_utc().unix_timestamp());
    }

    /// A delegation's uses are counted across calls, and the reporting read
    /// answers the same count.
    #[tokio::test]
    async fn a_budget_counts_and_reads_back() {
        let state = state();
        let counter = CacheBudgetCounter::new(state.clone());
        let reader = CacheBudgetUsageReader::new(state);
        let delegation = DelegationId::new();
        let key = BudgetKey::Delegation(delegation);

        counter.record_use(&key, Seconds::new(60)).await;
        let second = counter.record_use(&key, Seconds::new(60)).await;

        assert_eq!(second, Some(2));
        assert_eq!(reader.current_usage(&delegation).await, Some(2));
    }

    /// A fleet claim is won once, and distinct members count once each.
    #[tokio::test]
    async fn fleet_claims_and_distinct_counts_hold() {
        let fleet = CacheFleetCounters::new(state());
        let paths = |names: &[&str]| {
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>()
        };

        let first = fleet.claim_once("dpop:p-1", Seconds::new(60)).await;
        let again = fleet.claim_once("dpop:p-1", Seconds::new(60)).await;
        fleet
            .add_distinct("recon:1.2.3.4", &paths(&["/a", "/b"]), Seconds::new(60))
            .await;
        let distinct = fleet
            .add_distinct("recon:1.2.3.4", &paths(&["/b"]), Seconds::new(60))
            .await;

        assert_eq!((first, again), (Some(true), Some(false)));
        assert_eq!(distinct, Some(2));
    }

    /// A token charge settles both ways: an overrun adds, a refund takes
    /// back, and nothing goes below zero.
    #[tokio::test]
    async fn an_adjustment_adds_and_refunds() {
        let fleet = CacheFleetCounters::new(state());
        let window = Seconds::new(60);
        fleet.add("tokens:ann", 500, window).await;

        let overrun = fleet.adjust("tokens:ann", 200, window).await;
        let refund = fleet.adjust("tokens:ann", -600, window).await;
        let floored = fleet.adjust("tokens:ann", -600, window).await;

        assert_eq!(overrun, Some(700));
        assert_eq!(refund, Some(100));
        assert_eq!(floored, Some(0));
    }

    /// Refunding a missing window leaves its count at zero;
    /// the next addition starts at its full amount without inherited credit.
    #[tokio::test]
    async fn a_refund_never_starts_a_window() {
        let fleet = CacheFleetCounters::new(state());

        let refund = fleet
            .adjust("tokens:ann:lapsed", -500, Seconds::new(60))
            .await;
        let spent = fleet.add("tokens:ann:lapsed", 100, Seconds::new(60)).await;

        assert_eq!(refund, Some(0));
        assert_eq!(spent, Some(100));
    }

    /// A plain read counts nothing: a key nobody counted reads as zero, and
    /// a counted one reads as counted without moving.
    #[tokio::test]
    async fn a_read_counts_nothing() {
        let fleet = CacheFleetCounters::new(state());
        fleet.count("rate:ann", Seconds::new(60)).await;

        let counted = fleet.read("rate:ann").await;
        let again = fleet.read("rate:ann").await;
        let never = fleet.read("rate:sam").await;

        assert_eq!((counted, again, never), (Some(1), Some(1), Some(0)));
    }

    /// Holding a block marker succeeds and exposes one through the counter read.
    #[tokio::test]
    async fn a_held_key_reads_as_held() {
        let fleet = CacheFleetCounters::new(state());

        let held = fleet.hold("block:acme:1.2.3.4", Seconds::new(60)).await;

        assert_eq!(held, Some(()));
        assert_eq!(fleet.read("block:acme:1.2.3.4").await, Some(1));
    }

    /// When shared state is unavailable, counter reads, holds and adjustments return no answer.
    #[tokio::test]
    async fn a_state_that_is_down_answers_nothing() {
        let fleet = CacheFleetCounters::new(Arc::new(RefusingState));
        let window = Seconds::new(60);

        assert_eq!(fleet.read("k").await, None);
        assert_eq!(fleet.hold("k", window).await, None);
        assert_eq!(fleet.adjust("k", -1, window).await, None);
        assert_eq!(fleet.adjust("k", 1, window).await, None);
        assert_eq!(fleet.count("k", window).await, None);
    }
}
