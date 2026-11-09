//! The figures behind the metrics as their queries answer them, read back
//! into the domain's metrics values, and added up when one figure is read
//! from several databases.

use std::collections::BTreeMap;

use ianua_app::ports::metrics::RequestMetrics;
use ianua_domain::domains::metrics::{LatencyMs, LoginOutcomeCounts, TimeSeriesPoint};
use time::OffsetDateTime;

/// Sign-ins in a window, as counted.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct OutcomesRecord {
    pub(crate) succeeded: i64,
    pub(crate) failed: i64,
}

impl OutcomesRecord {
    /// The counts of `records`, added up.
    pub(crate) fn summed(records: &[Self]) -> Self {
        records.iter().fold(Self::default(), |sum, record| Self {
            succeeded: sum.succeeded.saturating_add(record.succeeded),
            failed: sum.failed.saturating_add(record.failed),
        })
    }

    /// The counts as the domain keeps them.
    pub(crate) fn into_counts(self) -> LoginOutcomeCounts {
        LoginOutcomeCounts::new(count(self.succeeded), count(self.failed))
    }
}

/// Sign-ins in one bucket of a window, as counted.
pub(crate) struct BucketRecord {
    pub(crate) bucket: OffsetDateTime,
    pub(crate) succeeded: i64,
    pub(crate) failed: i64,
}

impl BucketRecord {
    /// The points `records` make, buckets of the same start added up, in
    /// time order.
    pub(crate) fn into_series(records: Vec<Self>) -> Vec<TimeSeriesPoint> {
        let mut buckets: BTreeMap<OffsetDateTime, OutcomesRecord> = BTreeMap::new();
        for record in records {
            let sum = buckets.entry(record.bucket).or_default();
            sum.succeeded = sum.succeeded.saturating_add(record.succeeded);
            sum.failed = sum.failed.saturating_add(record.failed);
        }
        buckets
            .into_iter()
            .map(|(start, counts)| TimeSeriesPoint::new(start, counts.into_counts()))
            .collect()
    }
}

/// The measured sign-in times of a window: their total and how many.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DurationsRecord {
    pub(crate) total: i64,
    pub(crate) measured: i64,
}

impl DurationsRecord {
    /// The average of `records` together, rounded to the millisecond, or
    /// `None` when none was measured.
    pub(crate) fn into_average(records: &[Self]) -> Option<LatencyMs> {
        let total: i64 = records.iter().map(|r| r.total).fold(0, i64::saturating_add);
        let measured: i64 = records
            .iter()
            .map(|r| r.measured)
            .fold(0, i64::saturating_add);
        let average = total.checked_div(measured)?;
        let remainder = total.checked_rem(measured)?;
        let rounded = average.saturating_add(i64::from(remainder.saturating_mul(2) >= measured));
        Some(LatencyMs::new(u32::try_from(rounded).unwrap_or(u32::MAX)))
    }
}

/// The requests of a window that took one number of milliseconds: how
/// many, and how many of them were refused.
pub(crate) struct DurationRecord {
    pub(crate) duration_ms: i32,
    pub(crate) requests: i64,
    pub(crate) refused: i64,
}

impl DurationRecord {
    /// The request figures `records` make together: the count, the
    /// refusals, and the 95th percentile, interpolated between the two
    /// nearest requests as Postgres's `percentile_cont` does.
    pub(crate) fn into_metrics(records: Vec<Self>) -> RequestMetrics {
        let mut by_duration: BTreeMap<i32, (i64, i64)> = BTreeMap::new();
        for record in records {
            let sum = by_duration.entry(record.duration_ms).or_default();
            sum.0 = sum.0.saturating_add(record.requests);
            sum.1 = sum.1.saturating_add(record.refused);
        }
        let requests = by_duration
            .values()
            .map(|(n, _)| *n)
            .fold(0, i64::saturating_add);
        let refused = by_duration
            .values()
            .map(|(_, n)| *n)
            .fold(0, i64::saturating_add);
        let durations: Vec<(i32, i64)> = by_duration
            .into_iter()
            .map(|(duration, (count, _))| (duration, count))
            .collect();
        RequestMetrics {
            request_count: count(requests),
            error_count: count(refused),
            p95_latency_ms: percentile(&durations, 95),
        }
    }
}

/// The `percent`th percentile of the durations, each held by so many
/// requests, in order: the value at that place, or between the two around
/// it in proportion; `None` with no requests.
fn percentile(durations: &[(i32, i64)], percent: i64) -> Option<LatencyMs> {
    let total: i64 = durations
        .iter()
        .map(|(_, n)| *n)
        .fold(0, i64::saturating_add);
    let last = total.checked_sub(1).filter(|last| *last >= 0)?;
    let scaled = last.saturating_mul(percent);
    let below = scaled.checked_div(100)?;
    let share = scaled.checked_rem(100)?;
    let low = i64::from(nth(durations, below)?);
    let high = nth(durations, below.saturating_add(1)).map_or(low, i64::from);
    let between = high.saturating_sub(low).saturating_mul(share);
    let value = low.saturating_mul(100).saturating_add(between);
    let rounded = value.saturating_add(50).checked_div(100)?;
    Some(LatencyMs::new(u32::try_from(rounded).unwrap_or(u32::MAX)))
}

/// The duration of the `place`th request, from 0, in order.
fn nth(durations: &[(i32, i64)], place: i64) -> Option<i32> {
    let mut seen = 0_i64;
    for (duration, count) in durations {
        seen = seen.saturating_add(*count);
        if place < seen {
            return Some(*duration);
        }
    }
    None
}

/// A count a tenant's snapshot keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TenantMetric {
    /// The tenant's people.
    People,
    /// Its active sessions.
    Sessions,
}

/// A tenant's counts as one snapshot kept them.
pub(crate) struct SnapshotRecord {
    pub(crate) users_count: i64,
    pub(crate) active_sessions_count: i64,
}

impl SnapshotRecord {
    /// The count of `metric` the snapshot kept.
    pub(crate) fn into_count(self, metric: TenantMetric) -> u64 {
        match metric {
            TenantMetric::People => count(self.users_count),
            TenantMetric::Sessions => count(self.active_sessions_count),
        }
    }
}

/// A count as the domain keeps it; none below zero.
pub(crate) fn count(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requests(durations: &[(i32, i64)]) -> Vec<DurationRecord> {
        durations
            .iter()
            .map(|&(duration_ms, requests)| DurationRecord {
                duration_ms,
                requests,
                refused: 0,
            })
            .collect()
    }

    /// Requests of 1 to 100 milliseconds, one each: the 95th percentile is
    /// 95.05, read as 95, as Postgres answers it.
    #[test]
    fn the_95th_percentile_interpolates_as_postgres_does() {
        let spread: Vec<(i32, i64)> = (1..=100).map(|ms| (ms, 1)).collect();

        let metrics = DurationRecord::into_metrics(requests(&spread));

        assert_eq!(metrics.p95_latency_ms, Some(LatencyMs::new(95)));
        assert_eq!(metrics.request_count, 100);
    }

    /// The same duration read from two databases counts once with both
    /// counts, and one request alone is its own percentile.
    #[test]
    fn figures_from_two_databases_add_up() {
        let one = DurationRecord::into_metrics(requests(&[(40, 1)]));
        let two = DurationRecord::into_metrics(vec![
            DurationRecord {
                duration_ms: 10,
                requests: 3,
                refused: 1,
            },
            DurationRecord {
                duration_ms: 10,
                requests: 1,
                refused: 0,
            },
        ]);

        assert_eq!(one.p95_latency_ms, Some(LatencyMs::new(40)));
        assert_eq!(two.request_count, 4);
        assert_eq!(two.error_count, 1);
    }

    /// With no requests there is no percentile, and with no measured
    /// sign-in no average.
    #[test]
    fn nothing_measured_has_no_figure() {
        assert_eq!(
            DurationRecord::into_metrics(Vec::new()).p95_latency_ms,
            None
        );
        assert_eq!(DurationsRecord::into_average(&[]), None);
    }

    /// Sign-ins of 10 and 21 milliseconds average 15.5, read as 16.
    #[test]
    fn an_average_rounds_to_the_millisecond() {
        let average = DurationsRecord::into_average(&[
            DurationsRecord {
                total: 10,
                measured: 1,
            },
            DurationsRecord {
                total: 21,
                measured: 1,
            },
        ]);

        assert_eq!(average, Some(LatencyMs::new(16)));
    }
}
