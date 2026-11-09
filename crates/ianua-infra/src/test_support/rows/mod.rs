//! Rows the store tests build their aggregates from: valid by default, and
//! changed per test with struct update syntax. One file per context, named
//! as the context's store folder is.
//!
//! Times are whole seconds from one moment of the test run, so a value read
//! back from Postgres, which keeps microseconds, equals the one written,
//! and time passing between runs never changes what a test finds.

pub mod activity;
pub mod agents;
pub mod audit;
pub mod authentication;
pub mod authorization;
pub mod branding;
pub mod cloud;
pub mod consumers;
pub mod crypto;
pub mod data_classification;
pub mod directory;
pub mod domain;
pub mod federation;
pub mod identity;
pub mod messaging;
pub mod metrics;
pub mod notifications;
pub mod oauth;
pub mod operator;
pub mod organization;
pub mod proxy;
pub mod routing;
pub mod shared;
pub mod signals;
pub mod tenant;
pub mod webhooks;
pub mod workflows;

use std::sync::OnceLock;

use time::{Duration, OffsetDateTime};

/// How far ahead of the start of a test run the moment rows are dated from
/// lies. A row dated near the moment is still to come for the stores,
/// which judge against the clock, and one dated years before it long past.
const AHEAD_OF_THE_RUN: Duration = Duration::days(90);

/// `seconds` after the moment every test row is dated from: ninety days
/// after the test run began, to the second. The moment moves with the
/// clock, so a row a test dates as still in force stays so whenever the
/// tests run, rather than running out on a calendar day.
///
/// # Panics
///
/// Never: dropping the part of a second always gives a real time.
#[must_use]
pub fn at(seconds: i64) -> OffsetDateTime {
    static MOMENT: OnceLock<OffsetDateTime> = OnceLock::new();
    let moment = MOMENT.get_or_init(|| {
        OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .expect("a whole second is a real time")
            .saturating_add(AHEAD_OF_THE_RUN)
    });
    moment.saturating_add(Duration::seconds(seconds))
}

/// `seconds` after the one fixed moment, 2027-01-15 08:00:00 UTC, for the
/// tests that compare a stored value with its pinned text and so need the
/// same time in every run. Nothing judges these against the clock.
///
/// # Panics
///
/// Never for the offsets tests use, which stay within a few years.
#[must_use]
pub fn pinned(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000_i64.saturating_add(seconds))
        .expect("a test time is a real time")
}
