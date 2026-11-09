//! The signal use cases the API serves: a tenant's security signal streams,
//! the subjects they hear about, their verification events, status and
//! delivery history, the poll endpoint, the receiver confirming its
//! endpoint, and the transmitter's own configuration.

use std::sync::Arc;

use ianua_app::services::issuers::TenantIssuers;
use ianua_app::use_cases::signals::transmit::TransmitPorts;
use ianua_app::use_cases::signals::{delivery, reports, streams};

use crate::deps::{Adapters, Settings};

/// The signal use cases.
#[derive(Clone)]
pub struct SignalState {
    pub register: Arc<streams::RegisterUseCase>,
    pub list: Arc<streams::ListUseCase>,
    pub get: Arc<streams::GetUseCase>,
    pub get_status: Arc<streams::GetStatusUseCase>,
    pub update: Arc<streams::UpdateUseCase>,
    pub pause: Arc<streams::PauseUseCase>,
    pub resume: Arc<streams::ResumeUseCase>,
    pub disable: Arc<streams::DisableUseCase>,
    pub delete: Arc<streams::DeleteUseCase>,
    pub confirm_endpoint: Arc<streams::ConfirmEndpointUseCase>,
    pub add_subject: Arc<streams::AddSubjectUseCase>,
    pub remove_subject: Arc<streams::RemoveSubjectUseCase>,
    pub request_verification: Arc<streams::RequestVerificationUseCase>,
    pub configuration: Arc<streams::TransmitterConfigurationUseCase>,
    pub list_deliveries: Arc<delivery::ListStreamDeliveriesUseCase>,
    pub poll: Arc<delivery::PollEventsUseCase>,
    /// The platform's public base URL, under which the transmitter's
    /// endpoints are named.
    pub app_base_url: ianua_domain::types::HttpsUrl,
}

/// Builds the signal use cases over `a`, under the platform address `s`
/// names.
pub fn build(a: &Adapters, s: &Settings) -> SignalState {
    SignalState {
        register: Arc::new(register(a, s)),
        list: Arc::new(streams::ListUseCase::new(streams::ListPorts {
            stream_store: a.signal_stream_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        get: Arc::new(streams::GetUseCase::new(streams::GetPorts {
            stream_store: a.signal_stream_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        get_status: Arc::new(get_status(a)),
        update: Arc::new(update(a, s)),
        pause: Arc::new(pause(a)),
        resume: Arc::new(streams::ResumeUseCase::new(streams::ResumePorts {
            stream_store: a.signal_stream_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        disable: Arc::new(disable(a)),
        delete: Arc::new(delete(a)),
        confirm_endpoint: Arc::new(confirm_endpoint(a)),
        add_subject: Arc::new(add_subject(a)),
        remove_subject: Arc::new(remove_subject(a)),
        request_verification: Arc::new(request_verification(a, s)),
        configuration: Arc::new(configuration(a, s)),
        list_deliveries: Arc::new(list_deliveries(a)),
        poll: Arc::new(poll(a)),
        app_base_url: s.app_base_url.clone(),
    }
}

/// Registers streams with receiver-key checks and a tenant-scoped transmitter.
fn register(a: &Adapters, s: &Settings) -> streams::RegisterUseCase {
    streams::RegisterUseCase::new(streams::RegisterPorts {
        stream_store: a.signal_stream_store.clone(),
        token_generator: a.secure_token_generator.clone(),
        receiver_keys: a.receiver_keys.clone(),
        transmit: transmit(a, s),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Reads a stream's delivery status under tenant authority.
fn get_status(a: &Adapters) -> streams::GetStatusUseCase {
    streams::GetStatusUseCase::new(streams::GetStatusPorts {
        stream_store: a.signal_stream_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Updates stream settings with tokens and transmission ports for endpoint changes.
fn update(a: &Adapters, s: &Settings) -> streams::UpdateUseCase {
    streams::UpdateUseCase::new(streams::UpdatePorts {
        stream_store: a.signal_stream_store.clone(),
        token_generator: a.secure_token_generator.clone(),
        transmit: transmit(a, s),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Pauses stream delivery under the caller's tenant authority.
fn pause(a: &Adapters) -> streams::PauseUseCase {
    streams::PauseUseCase::new(streams::PausePorts {
        stream_store: a.signal_stream_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Disables stream delivery through the tenant's authority checks.
fn disable(a: &Adapters) -> streams::DisableUseCase {
    streams::DisableUseCase::new(streams::DisablePorts {
        stream_store: a.signal_stream_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Removes a stream after resolving the caller's tenant authority.
fn delete(a: &Adapters) -> streams::DeleteUseCase {
    streams::DeleteUseCase::new(streams::DeletePorts {
        stream_store: a.signal_stream_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Records the receiver's endpoint confirmation in the stream store.
fn confirm_endpoint(a: &Adapters) -> streams::ConfirmEndpointUseCase {
    streams::ConfirmEndpointUseCase::new(streams::ConfirmEndpointPorts {
        stream_store: a.signal_stream_store.clone(),
    })
}

/// Adds stream subjects after checking their existence and receiver keys.
fn add_subject(a: &Adapters) -> streams::AddSubjectUseCase {
    streams::AddSubjectUseCase::new(streams::AddSubjectPorts {
        stream_store: a.signal_stream_store.clone(),
        principals: a.principal_existence_checker.clone(),
        receiver_keys: a.receiver_keys.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Removes stream subjects under the same principal and receiver-key checks.
fn remove_subject(a: &Adapters) -> streams::RemoveSubjectUseCase {
    streams::RemoveSubjectUseCase::new(streams::RemoveSubjectPorts {
        stream_store: a.signal_stream_store.clone(),
        principals: a.principal_existence_checker.clone(),
        receiver_keys: a.receiver_keys.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Sends throttled verification events through the tenant-scoped transmitter.
fn request_verification(a: &Adapters, s: &Settings) -> streams::RequestVerificationUseCase {
    streams::RequestVerificationUseCase::new(streams::RequestVerificationPorts {
        stream_store: a.signal_stream_store.clone(),
        throttle: a.verification_throttle.clone(),
        transmit: transmit(a, s),
        receiver_keys: a.receiver_keys.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Names transmitter endpoints using each tenant's issuer.
fn configuration(a: &Adapters, s: &Settings) -> streams::TransmitterConfigurationUseCase {
    streams::TransmitterConfigurationUseCase::new(streams::TransmitterConfigurationPorts {
        issuers: issuers(a, s),
    })
}

/// Reads a stream's delivery history under tenant authority.
fn list_deliveries(a: &Adapters) -> delivery::ListStreamDeliveriesUseCase {
    delivery::ListStreamDeliveriesUseCase::new(delivery::ListStreamDeliveriesPorts {
        stream_store: a.signal_stream_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Polls queued events after validating the stream's receiver keys and authority.
fn poll(a: &Adapters) -> delivery::PollEventsUseCase {
    delivery::PollEventsUseCase::new(delivery::PollEventsPorts {
        stream_store: a.signal_stream_store.clone(),
        poll_queue: a.signal_poll_queue.clone(),
        receiver_keys: a.receiver_keys.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// What signs a security event token and pushes it, or holds it for a poll
/// stream, under the tenant's issuer.
fn transmit(a: &Adapters, s: &Settings) -> TransmitPorts {
    TransmitPorts {
        key_store: a.signing_key_store.clone(),
        jwt_signer: a.jwt_signer.clone(),
        deliverer: a.signal_deliverer.clone(),
        poll_queue: a.signal_poll_queue.clone(),
        encryptor: a.secret_encryptor.clone(),
        issuers: issuers(a, s),
    }
}

/// Reports a signal about a person, for a workflow's send-signal step.
#[must_use]
pub fn report(a: &Adapters) -> Arc<reports::SendUseCase> {
    Arc::new(reports::SendUseCase::new(reports::SendPorts {
        tenant_authorities: a.tenant_authorities.clone(),
        users: a.user_store.clone(),
    }))
}

/// Works out each tenant's issuer, which its security event tokens carry.
fn issuers(a: &Adapters, s: &Settings) -> TenantIssuers {
    TenantIssuers::new(
        a.tenant_store.clone(),
        a.organization_store.clone(),
        s.app_base_url.clone(),
    )
}
