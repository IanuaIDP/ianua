//! What the platform accepts for a person's language and time zone, read
//! by anyone to fill a picker.

use super::Request;
use crate::net::Call;

/// `GET /api/v1/locales`: every BCP 47 tag a `locale` is checked against.
#[must_use]
pub fn locales() -> Request<Vec<String>> {
    Request::of(Call::get("/api/v1/locales"))
}

/// `GET /api/v1/timezones`: every IANA zone a `timezone` is checked
/// against.
#[must_use]
pub fn timezones() -> Request<Vec<String>> {
    Request::of(Call::get("/api/v1/timezones"))
}
