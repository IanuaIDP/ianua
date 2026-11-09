//! The webhook use cases the API serves: a tenant's webhook subscriptions,
//! their signing secrets, the events they may receive, and their delivery
//! history, resends and test sends.

use std::sync::Arc;

use ianua_app::use_cases::webhooks::delivery::sending::SendingPorts;
use ianua_app::use_cases::webhooks::{delivery, subscriptions};

use crate::deps::Adapters;

/// The webhook use cases.
#[derive(Clone)]
pub struct WebhookState {
    /// Subscribes an endpoint to the tenant's events.
    pub create: Arc<subscriptions::CreateUseCase>,
    pub list: Arc<subscriptions::ListUseCase>,
    pub get: Arc<subscriptions::GetUseCase>,
    pub update: Arc<subscriptions::UpdateUseCase>,
    pub pause: Arc<subscriptions::PauseUseCase>,
    pub resume: Arc<subscriptions::ResumeUseCase>,
    pub delete: Arc<subscriptions::DeleteUseCase>,
    pub rotate_secret: Arc<subscriptions::RotateSecretUseCase>,
    pub event_catalog: Arc<subscriptions::ListEventCatalogUseCase>,
    pub list_deliveries: Arc<delivery::ListAttemptsUseCase>,
    pub resend: Arc<delivery::ResendUseCase>,
    pub send_test: Arc<delivery::SendTestEventUseCase>,
}

/// Builds the webhook use cases over `a`.
pub fn build(a: &Adapters) -> WebhookState {
    WebhookState {
        create: Arc::new(create(a)),
        list: Arc::new(subscriptions::ListUseCase::new(subscriptions::ListPorts {
            webhook_store: a.webhook_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        get: Arc::new(subscriptions::GetUseCase::new(subscriptions::GetPorts {
            webhook_store: a.webhook_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        update: Arc::new(update(a)),
        pause: Arc::new(pause(a)),
        resume: Arc::new(resume(a)),
        delete: Arc::new(delete(a)),
        rotate_secret: Arc::new(rotate_secret(a)),
        event_catalog: Arc::new(subscriptions::ListEventCatalogUseCase::new(
            subscriptions::ListEventCatalogPorts {
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        list_deliveries: Arc::new(list_deliveries(a)),
        resend: Arc::new(resend(a)),
        send_test: Arc::new(send_test(a)),
    }
}

/// Subscribes endpoints with sealed signing secrets and plan enforcement.
fn create(a: &Adapters) -> subscriptions::CreateUseCase {
    subscriptions::CreateUseCase::new(subscriptions::CreatePorts {
        webhook_store: a.webhook_store.clone(),
        secret_generator: a.webhook_secret_generator.clone(),
        encryptor: a.secret_encryptor.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Updates subscription settings through tenant authority checks.
fn update(a: &Adapters) -> subscriptions::UpdateUseCase {
    subscriptions::UpdateUseCase::new(subscriptions::UpdatePorts {
        webhook_store: a.webhook_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Pauses a subscription under the caller's tenant authority.
fn pause(a: &Adapters) -> subscriptions::PauseUseCase {
    subscriptions::PauseUseCase::new(subscriptions::PausePorts {
        webhook_store: a.webhook_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Resumes delivery through the subscription's authority checks.
fn resume(a: &Adapters) -> subscriptions::ResumeUseCase {
    subscriptions::ResumeUseCase::new(subscriptions::ResumePorts {
        webhook_store: a.webhook_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Removes a subscription after resolving the caller's tenant authority.
fn delete(a: &Adapters) -> subscriptions::DeleteUseCase {
    subscriptions::DeleteUseCase::new(subscriptions::DeletePorts {
        webhook_store: a.webhook_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Rotates and seals the secret used to sign webhook deliveries.
fn rotate_secret(a: &Adapters) -> subscriptions::RotateSecretUseCase {
    subscriptions::RotateSecretUseCase::new(subscriptions::RotateSecretPorts {
        webhook_store: a.webhook_store.clone(),
        secret_generator: a.webhook_secret_generator.clone(),
        encryptor: a.secret_encryptor.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Lists delivery attempts within the caller's authorized tenant scope.
fn list_deliveries(a: &Adapters) -> delivery::ListAttemptsUseCase {
    delivery::ListAttemptsUseCase::new(delivery::ListAttemptsPorts {
        webhook_store: a.webhook_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Resends deliveries with current account standing and send throttling.
fn resend(a: &Adapters) -> delivery::ResendUseCase {
    delivery::ResendUseCase::new(delivery::ResendPorts {
        sending: sending(a),
        throttle: a.webhook_send_throttle.clone(),
        access: a.access_record_store.clone(),
        users: a.user_store.clone(),
        org_users: a.org_user_store.clone(),
        organizations: a.organization_store.clone(),
        org_grants: a.org_tenant_grant_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Sends test events through the same delivery ports and throttle as resends.
fn send_test(a: &Adapters) -> delivery::SendTestEventUseCase {
    delivery::SendTestEventUseCase::new(delivery::SendTestEventPorts {
        sending: sending(a),
        throttle: a.webhook_send_throttle.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// What signs, sends, keeps and records a try at a webhook.
fn sending(a: &Adapters) -> SendingPorts {
    SendingPorts {
        webhook_store: a.webhook_store.clone(),
        deliverer: a.webhook_deliverer.clone(),
        encryptor: a.secret_encryptor.clone(),
        unit_of_work: a.unit_of_work.clone(),
    }
}
