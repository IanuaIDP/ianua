//! The window a metrics overview covers, read from `?since=...&until=...`
//! (RFC 3339).
//!
//! Parsed once at the boundary, so the overview handlers receive a domain
//! window instead of raw strings and never repeat the parsing, defaulting
//! or bounding rules.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use ianua_domain::domains::metrics::MetricsWindow;
use ianua_domain::message;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::error::ApiError;
use crate::extractors::query::{Query, QueryRefusal};
use crate::extractors::time::parse_rfc3339;

/// Window length when `since` is not given.
const DEFAULT_WINDOW_DAYS: i64 = 30;

/// Largest window computed, bounding the scan cost of the underlying
/// aggregates (notably the p95 latency sort).
const MAX_WINDOW_DAYS: i64 = 90;

/// A validated [`MetricsWindow`].
///
/// An absent `until` defaults to the next-minute boundary after now, so
/// rapid dashboard polls share a window and hit the metrics cache; an
/// absent `since` defaults to 30 days before `until`. A malformed
/// timestamp, a reversed window, or a span beyond 90 days is `422`.
pub(crate) struct MetricsWindowQuery(pub MetricsWindow);

/// The raw `since`/`until` keys, before validation.
#[derive(Deserialize)]
struct WindowRaw {
    since: Option<String>,
    until: Option<String>,
}

impl<S: Send + Sync> FromRequestParts<S> for MetricsWindowQuery {
    type Rejection = QueryRefusal;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(raw) = Query::<WindowRaw>::from_request_parts(parts, state).await?;
        let window = resolve_window(raw.since.as_deref(), raw.until.as_deref())?;
        Ok(Self(window))
    }
}

/// The window `since` and `until` ask for, with either filled in when
/// missing. Refuses a bad timestamp, a reversed window, or one longer than
/// the maximum.
fn resolve_window(since: Option<&str>, until: Option<&str>) -> Result<MetricsWindow, ApiError> {
    let end = match until {
        Some(raw) => parse_rfc3339(raw)?,
        None => next_minute_boundary(OffsetDateTime::now_utc()),
    };
    let start = match since {
        Some(raw) => parse_rfc3339(raw)?,
        None => end - time::Duration::days(DEFAULT_WINDOW_DAYS),
    };
    if end - start > time::Duration::days(MAX_WINDOW_DAYS) {
        return Err(ApiError::validation(message!(
            "api-metrics-window-must-not-exceed-days",
            format!("metrics window must not exceed {MAX_WINDOW_DAYS} days")
        )));
    }
    MetricsWindow::new(start, end).map_err(ApiError::validation)
}

/// `t` rounded up to the next minute, so the default `until = now` is
/// stable across rapid polls while still including the current minute.
fn next_minute_boundary(t: OffsetDateTime) -> OffsetDateTime {
    let floored = t
        - time::Duration::seconds(i64::from(t.second()))
        - time::Duration::nanoseconds(i64::from(t.nanosecond()));
    floored + time::Duration::minutes(1)
}

impl utoipa::IntoParams for MetricsWindowQuery {
    fn into_params(
        _parameter_in_provider: impl Fn() -> Option<utoipa::openapi::path::ParameterIn>,
    ) -> Vec<utoipa::openapi::path::Parameter> {
        use utoipa::openapi::Required;
        use utoipa::openapi::path::{ParameterBuilder, ParameterIn};
        use utoipa::openapi::schema::{ObjectBuilder, Schema, SchemaFormat, Type};

        let timestamp_param = |name: &str, description: &str| {
            ParameterBuilder::new()
                .name(name)
                .parameter_in(ParameterIn::Query)
                .required(Required::False)
                .description(Some(description))
                .schema(Some(Schema::Object(
                    ObjectBuilder::new()
                        .schema_type(Type::String)
                        .format(Some(SchemaFormat::KnownFormat(
                            utoipa::openapi::KnownFormat::DateTime,
                        )))
                        .build(),
                )))
                .build()
        };

        vec![
            timestamp_param(
                "since",
                "Window start (RFC 3339). Defaults to 30 days before `until`.",
            ),
            timestamp_param("until", "Window end (RFC 3339). Defaults to now."),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The window the bounds resolve to, failing the test when they are
    /// refused.
    fn resolved(since: Option<&str>, until: Option<&str>) -> MetricsWindow {
        match resolve_window(since, until) {
            Ok(window) => window,
            Err(_) => panic!("expected a valid window"),
        }
    }

    /// Ann asks for June 1 to June 29 and gets exactly those 28 days.
    #[test]
    fn explicit_bounds_are_kept() {
        let window = resolved(Some("2026-06-01T00:00:00Z"), Some("2026-06-29T00:00:00Z"));

        assert_eq!(window.duration(), time::Duration::days(28));
    }

    /// Given only an end, the window starts thirty days before it.
    #[test]
    fn a_missing_start_is_thirty_days_before_the_end() {
        let window = resolved(None, Some("2026-06-29T00:00:00Z"));

        assert_eq!(window.duration(), time::Duration::days(30));
    }

    /// A start that is not a date is refused.
    #[test]
    fn a_malformed_timestamp_is_refused() {
        assert!(resolve_window(Some("not-a-date"), None).is_err());
    }

    /// A window that ends before it starts is refused.
    #[test]
    fn a_reversed_window_is_refused() {
        assert!(
            resolve_window(Some("2026-06-29T00:00:00Z"), Some("2026-06-01T00:00:00Z")).is_err()
        );
    }

    /// The published maximum is a window one may ask for; a second past it
    /// is not.
    #[test]
    fn exactly_the_maximum_is_accepted_and_no_more() {
        assert!(resolve_window(Some("2025-01-01T00:00:00Z"), Some("2025-04-01T00:00:00Z")).is_ok());
        assert!(
            resolve_window(Some("2025-01-01T00:00:00Z"), Some("2025-04-01T00:00:01Z")).is_err()
        );
    }

    /// With no end given, a minute and a half in becomes two minutes, so
    /// polls within the same minute share a window.
    #[test]
    fn the_default_end_rounds_up_to_the_next_minute() {
        let t = OffsetDateTime::from_unix_timestamp(90).unwrap();
        assert_eq!(next_minute_boundary(t).unix_timestamp(), 120);
    }
}
