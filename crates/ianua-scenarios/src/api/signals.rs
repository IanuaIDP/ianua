//! A tenant's security signal streams, as Shared Signals receivers and
//! the tenant's administrators use them: the transmitter's published
//! configuration, registering a stream, its lifecycle, the events a
//! receiver polls, the subjects it hears about and its deliveries.

use super::{Request, TenantPath};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::signals::{
    AskVerification, ConfirmEndpoint, NewStream, PollAnswer, PollAsk, SignalStream, StreamChange,
    StreamDelivery, StreamRegistered, StreamStatus, StreamSubject, TransmitterConfiguration,
};

/// `GET …/.well-known/ssf-configuration`: the transmitter's metadata,
/// which anyone may read.
#[must_use]
pub fn configuration(tenant: &TenantPath) -> Request<TransmitterConfiguration> {
    Request::of(Call::get(tenant.at("/.well-known/ssf-configuration")))
}

/// `POST …/streams`: registers a stream, its receiver key in the answer,
/// once.
#[must_use]
pub fn register(tenant: &TenantPath, stream: &NewStream) -> Request<StreamRegistered> {
    Request::of(Call::post(tenant.at("/streams")).json(stream))
}

/// `GET …/streams`: every stream of the tenant, one page.
#[must_use]
pub fn list(tenant: &TenantPath) -> Request<Page<SignalStream>> {
    Request::of(Call::get(tenant.at("/streams")))
}

/// `GET …/streams/{id}`.
#[must_use]
pub fn get(tenant: &TenantPath, id: &str) -> Request<SignalStream> {
    Request::of(Call::get(tenant.at(&format!("/streams/{id}"))))
}

/// `PATCH …/streams/{id}`: a field left out keeps its value.
#[must_use]
pub fn change(tenant: &TenantPath, id: &str, change: &StreamChange) -> Request<()> {
    Request::of(Call::patch(tenant.at(&format!("/streams/{id}"))).json(change))
}

/// `GET …/streams/{id}/status`.
#[must_use]
pub fn status(tenant: &TenantPath, id: &str) -> Request<StreamStatus> {
    Request::of(Call::get(tenant.at(&format!("/streams/{id}/status"))))
}

/// `POST …/streams/{id}/pause`.
#[must_use]
pub fn pause(tenant: &TenantPath, id: &str) -> Request<()> {
    Request::of(Call::post(tenant.at(&format!("/streams/{id}/pause"))))
}

/// `POST …/streams/{id}/resume`.
#[must_use]
pub fn resume(tenant: &TenantPath, id: &str) -> Request<()> {
    Request::of(Call::post(tenant.at(&format!("/streams/{id}/resume"))))
}

/// `POST …/streams/{id}/disable`.
#[must_use]
pub fn disable(tenant: &TenantPath, id: &str) -> Request<()> {
    Request::of(Call::post(tenant.at(&format!("/streams/{id}/disable"))))
}

/// `DELETE …/streams/{id}`: a stream is disabled first.
#[must_use]
pub fn delete(tenant: &TenantPath, id: &str) -> Request<()> {
    Request::of(Call::delete(tenant.at(&format!("/streams/{id}"))))
}

/// `POST …/streams/{id}/confirm`: the receiver echoes its challenge,
/// with nothing else to prove who it is.
#[must_use]
pub fn confirm(tenant: &TenantPath, id: &str, echo: &ConfirmEndpoint) -> Request<()> {
    Request::of(Call::post(tenant.at(&format!("/streams/{id}/confirm"))).json(echo))
}

/// `POST …/streams/{id}/verify`: asks for a verification event carrying
/// `ask`'s state.
#[must_use]
pub fn verify(tenant: &TenantPath, id: &str, ask: &AskVerification) -> Request<()> {
    Request::of(Call::post(tenant.at(&format!("/streams/{id}/verify"))).json(ask))
}

/// `POST …/streams/{id}/poll`: acknowledges what the receiver took and
/// hands over the events waiting.
#[must_use]
pub fn poll(tenant: &TenantPath, id: &str, ask: &PollAsk) -> Request<PollAnswer> {
    Request::of(Call::post(tenant.at(&format!("/streams/{id}/poll"))).json(ask))
}

/// `POST …/streams/{id}/subjects/add`.
#[must_use]
pub fn add_subject(tenant: &TenantPath, id: &str, subject: &StreamSubject) -> Request<()> {
    Request::of(Call::post(tenant.at(&format!("/streams/{id}/subjects/add"))).json(subject))
}

/// `POST …/streams/{id}/subjects/remove`.
#[must_use]
pub fn remove_subject(tenant: &TenantPath, id: &str, subject: &StreamSubject) -> Request<()> {
    Request::of(Call::post(tenant.at(&format!("/streams/{id}/subjects/remove"))).json(subject))
}

/// `GET …/streams/{id}/deliveries`: every delivery attempt, one page.
#[must_use]
pub fn deliveries(tenant: &TenantPath, id: &str) -> Request<Page<StreamDelivery>> {
    Request::of(Call::get(tenant.at(&format!("/streams/{id}/deliveries"))))
}
