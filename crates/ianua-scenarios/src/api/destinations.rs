//! Where outside the app a company's notifications are posted.

use super::{OrgPath, Request};
use crate::net::Call;
use crate::wire::destinations::{
    Destination, DestinationAdded, DestinationChanged, DestinationForm,
};

/// The company's destinations, under `org`.
fn path(org: &OrgPath) -> String {
    org.at("/notifications/destinations")
}

/// `GET …/notifications/destinations`.
#[must_use]
pub fn list(org: &OrgPath) -> Request<Vec<Destination>> {
    Request::of(Call::get(path(org)))
}

/// `POST …/notifications/destinations`: adds one, active at once.
#[must_use]
pub fn add(org: &OrgPath, form: &DestinationForm) -> Request<DestinationAdded> {
    Request::of(Call::post(path(org)).json(form))
}

/// `PUT …/notifications/destinations/{id}`: replaces it whole.
#[must_use]
pub fn change(org: &OrgPath, id: &str, form: &DestinationForm) -> Request<DestinationChanged> {
    Request::of(Call::put(format!("{}/{id}", path(org))).json(form))
}

/// `POST …/notifications/destinations/{id}/pause`.
#[must_use]
pub fn pause(org: &OrgPath, id: &str) -> Request<()> {
    Request::of(Call::post(format!("{}/{id}/pause", path(org))))
}

/// `POST …/notifications/destinations/{id}/resume`.
#[must_use]
pub fn resume(org: &OrgPath, id: &str) -> Request<()> {
    Request::of(Call::post(format!("{}/{id}/resume", path(org))))
}

/// `DELETE …/notifications/destinations/{id}`.
#[must_use]
pub fn remove(org: &OrgPath, id: &str) -> Request<()> {
    Request::of(Call::delete(format!("{}/{id}", path(org))))
}
