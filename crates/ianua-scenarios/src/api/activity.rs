//! The activity calendar of an organization, across its tenants, and of
//! one tenant.

use super::{OrgPath, Request, TenantPath, with_query};
use crate::net::Call;
use crate::wire::activity::ActivityCalendar;

/// `GET …/activity?{window}` of an organization: every tenant's records
/// and its own, per day, over `window` (`from` and `to`, `YYYY-MM-DD`),
/// the year ending today when it names none.
#[must_use]
pub fn organization(org: &OrgPath, window: &[(&str, &str)]) -> Request<ActivityCalendar> {
    Request::of(Call::get(with_query(&org.at("/activity"), window)))
}

/// `GET …/tenants/{tenant}/activity?{window}`: the tenant's own records,
/// per day, over `window`.
#[must_use]
pub fn tenant(tenant: &TenantPath, window: &[(&str, &str)]) -> Request<ActivityCalendar> {
    Request::of(Call::get(with_query(&tenant.at("/activity"), window)))
}
