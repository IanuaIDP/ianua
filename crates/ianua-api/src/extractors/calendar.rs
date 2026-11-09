//! Calendar-window query-parameter extractor.
//!
//! Parses `?from=YYYY-MM-DD&to=YYYY-MM-DD` into a validated
//! [`CalendarRange`] at the request boundary, so handlers receive a
//! domain range instead of raw strings and never repeat parsing or
//! defaulting rules.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use ianua_domain::domains::activity::CalendarRange;
use ianua_domain::message;
use serde::Deserialize;
use time::format_description::well_known::Iso8601;
use time::{Date, OffsetDateTime};

use crate::error::ApiError;
use crate::extractors::query::{Query, QueryRefusal};

/// Extractor yielding a validated [`CalendarRange`].
///
/// An absent `to` defaults to today (UTC); an absent `from` defaults
/// to the trailing year ending at `to`. A malformed date, reversed
/// window, or span beyond the domain maximum is rejected with
/// `422 Unprocessable Entity`.
pub(crate) struct CalendarQuery(pub CalendarRange);

/// The raw `from`/`to` keys, deserialized before date validation.
#[derive(Deserialize)]
struct CalendarRaw {
    from: Option<String>,
    to: Option<String>,
}

impl<S: Send + Sync> FromRequestParts<S> for CalendarQuery {
    type Rejection = QueryRefusal;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(raw) = Query::<CalendarRaw>::from_request_parts(parts, state).await?;
        let range = resolve_range(raw.from.as_deref(), raw.to.as_deref())?;
        Ok(Self(range))
    }
}

/// The days the query asks for: up to `to` or today, from `from` or a year
/// earlier. Refused when a date is malformed or the window is not allowed.
fn resolve_range(from: Option<&str>, to: Option<&str>) -> Result<CalendarRange, ApiError> {
    let end = match to {
        Some(raw) => parse_iso_date(raw)?,
        None => OffsetDateTime::now_utc().date(),
    };

    let Some(raw_start) = from else {
        return Ok(CalendarRange::trailing_year(end));
    };

    let start = parse_iso_date(raw_start)?;
    CalendarRange::new(start, end).map_err(ApiError::validation)
}

/// The day a `YYYY-MM-DD` string names, refused when it is not one.
fn parse_iso_date(raw: &str) -> Result<Date, ApiError> {
    Date::parse(raw, &Iso8601::DATE).map_err(|e| {
        ApiError::validation(message!(
            "api-invalid-date",
            format!("invalid date '{raw}': {e}")
        ))
    })
}

impl utoipa::IntoParams for CalendarQuery {
    fn into_params(
        _parameter_in_provider: impl Fn() -> Option<utoipa::openapi::path::ParameterIn>,
    ) -> Vec<utoipa::openapi::path::Parameter> {
        use utoipa::openapi::Required;
        use utoipa::openapi::path::{ParameterBuilder, ParameterIn};
        use utoipa::openapi::schema::{ObjectBuilder, Schema, SchemaFormat, Type};

        let date_param = |name: &str, description: &str| {
            ParameterBuilder::new()
                .name(name)
                .parameter_in(ParameterIn::Query)
                .required(Required::False)
                .description(Some(description))
                .schema(Some(Schema::Object(
                    ObjectBuilder::new()
                        .schema_type(Type::String)
                        .format(Some(SchemaFormat::KnownFormat(
                            utoipa::openapi::KnownFormat::Date,
                        )))
                        .build(),
                )))
                .build()
        };

        vec![
            date_param(
                "from",
                "First day of the window (YYYY-MM-DD, UTC, inclusive). \
                 Defaults to one year before `to`.",
            ),
            date_param(
                "to",
                "Last day of the window (YYYY-MM-DD, UTC, inclusive). Defaults to today.",
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use time::Month;

    use super::*;

    /// The calendar day given.
    fn date(year: i32, month: Month, day: u8) -> Date {
        Date::from_calendar_date(year, month, day).unwrap()
    }

    /// The range a query resolves to, for a query that must be valid.
    fn resolved(from: Option<&str>, to: Option<&str>) -> CalendarRange {
        match resolve_range(from, to) {
            Ok(range) => range,
            Err(_) => panic!("expected a valid range"),
        }
    }

    /// Ann asks for January to March and gets exactly those days.
    #[test]
    fn resolve_range_uses_explicit_window() {
        let range = resolved(Some("2026-01-01"), Some("2026-03-31"));

        assert_eq!(range.start(), date(2026, Month::January, 1));
        assert_eq!(range.end(), date(2026, Month::March, 31));
    }

    /// With no start day, the window is the year up to the end day.
    #[test]
    fn resolve_range_defaults_to_trailing_year() {
        let range = resolved(None, Some("2026-07-04"));

        assert_eq!(range.day_count(), 365);
        assert_eq!(range.end(), date(2026, Month::July, 4));
    }

    /// A date that is not `YYYY-MM-DD` is refused.
    #[test]
    fn resolve_range_rejects_malformed_date() {
        assert!(resolve_range(Some("not-a-date"), None).is_err());
    }

    /// A window that ends before it starts is refused.
    #[test]
    fn resolve_range_rejects_reversed_window() {
        assert!(resolve_range(Some("2026-03-31"), Some("2026-01-01")).is_err());
    }

    /// Two years at once is longer than the domain allows, and is refused.
    #[test]
    fn resolve_range_rejects_window_beyond_the_domain_maximum() {
        assert!(resolve_range(Some("2024-01-01"), Some("2026-01-01")).is_err());
    }
}
