//! Reference data handlers: the static catalogues a dashboard fills its
//! pickers from.

use ianua_domain::types::{Locale, Timezone};

use crate::extractors::json::Json;

#[utoipa::path(
    get,
    path = "/api/v1/locales",
    tag = "Reference",
    responses(
        (status = 200, description = "Supported BCP 47 locale tags", body = Vec<String>)
    )
)]
/// List supported locales
///
/// Returns every BCP 47 locale tag the platform accepts, such as `en-US`
/// or `de-DE`: the exact set a user's `locale` preference is checked
/// against. Useful for a locale picker. Static, public data, needing no
/// sign-in.
pub(crate) async fn list_locales() -> Json<Vec<&'static str>> {
    Json(Locale::all().collect())
}

#[utoipa::path(
    get,
    path = "/api/v1/timezones",
    tag = "Reference",
    responses(
        (status = 200, description = "Supported IANA timezone identifiers", body = Vec<String>)
    )
)]
/// List supported timezones
///
/// Returns every IANA timezone identifier the platform accepts, such as
/// `Europe/Berlin` or `America/New_York`: the exact set a user's `timezone`
/// preference is checked against. Useful for a timezone picker. Static,
/// public data, needing no sign-in.
pub(crate) async fn list_timezones() -> Json<Vec<&'static str>> {
    Json(Timezone::all().collect())
}
