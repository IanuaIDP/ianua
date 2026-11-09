//! The handlers of deliveries out of the platform: webhooks, signals,
//! back-channel logout, message pushes and notification posts.
//!
//! Every one of them calls an address a tenant chose, so each client is
//! screened against the networks outbound calls may reach and holds every
//! call to a time limit of its own.

use std::sync::Arc;

use ianua_app::ports::authentication::SecretEncryptor;
use ianua_app::ports::messaging::MessageConsumer;
use ianua_app::use_cases::messaging::broker::{
    PushMessagePorts, PushMessageUseCase, PushMessagesHandler, PushPendingPorts, PushPendingUseCase,
};
use ianua_app::use_cases::notifications::{PostHandler, PostPorts, PostUseCase};
use ianua_app::use_cases::oauth::flows::{
    BackChannelLogoutHandler, NotifyBackChannelLogoutPorts, NotifyBackChannelLogoutUseCase,
};
use ianua_app::use_cases::scheduling::JobHandler;
use ianua_app::use_cases::signals::delivery::{
    DispatchSignalHandler, DispatchSignalPorts, DispatchSignalUseCase,
};
use ianua_app::use_cases::signals::transmit::TransmitPorts;
use ianua_app::use_cases::webhooks::delivery::sending::SendingPorts;
use ianua_app::use_cases::webhooks::delivery::{
    DeliverWebhookHandler, DeliverWebhookPorts, DeliverWebhookUseCase,
};
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::FailureLimit;
use ianua_infra::bus::{BusMessageConsumer, NoMessageConsumer};
use ianua_infra::crypto::Pkcs8JwtSigner;
use ianua_infra::http::{
    HttpBackChannelLogoutSender, HttpDestinationPoster, HttpPushDeliverer, HttpSignalDeliverer,
    HttpWebhookDeliverer,
};
use ianua_infra::postgres::consumers::PgConsumerStore;
use ianua_infra::postgres::identity::PgUserStore;
use ianua_infra::postgres::messaging::{PgSubscriptionStore, PgTopicStore};
use ianua_infra::postgres::notifications::PgNotificationDestinationStore;
use ianua_infra::postgres::oauth::{PgAuthCodeStore, PgOAuthClientStore};
use ianua_infra::postgres::organization::{PgOrgTenantGrantStore, PgOrgUserStore};
use ianua_infra::postgres::signals::{PgSignalPollQueue, PgSignalStreamStore};
use ianua_infra::postgres::webhooks::PgWebhookStore;

use crate::error::{PlatformError, ServerError};
use crate::worker::parts::Parts;

/// The handlers of deliveries out of the platform.
///
/// # Errors
///
/// [`ServerError`] when one cannot be built.
pub(super) fn handlers(parts: &Parts<'_>) -> Result<Vec<Arc<dyn JobHandler>>, ServerError> {
    Ok(vec![
        webhooks(parts)?,
        signals(parts)?,
        back_channel_logout(parts)?,
        message_pushes(parts)?,
        destination_posts(parts)?,
    ])
}

/// The sealer every delivery opens its stored secrets with.
fn encryptor(parts: &Parts<'_>) -> Arc<dyn SecretEncryptor> {
    parts.platform.secrets.encryptor.clone()
}

/// Posts to webhooks, within the deployment's outbound rules.
fn webhook_deliverer(parts: &Parts<'_>) -> Result<HttpWebhookDeliverer, ServerError> {
    let outbound = &parts.platform.outbound;
    let deliverer = HttpWebhookDeliverer::new(
        outbound.upstream_networks.clone(),
        parts.config.http.delivery_timeout,
        &outbound.deliveries,
    )
    .map_err(PlatformError::of("the webhook deliverer"))?;
    Ok(deliverer)
}

/// The handler sending one event to one webhook, signed, its try kept and
/// counted on the endpoint's failure streak.
fn webhooks(parts: &Parts<'_>) -> Result<Arc<dyn JobHandler>, ServerError> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let store = Arc::new(PgWebhookStore::new(Arc::clone(databases)));
    let deliverer = webhook_deliverer(parts)?;
    let deliver = DeliverWebhookUseCase::new(DeliverWebhookPorts {
        sending: SendingPorts {
            webhook_store: Arc::clone(&store) as _,
            deliverer: Arc::new(deliverer),
            encryptor: encryptor(parts),
            unit_of_work: Arc::clone(&platform.unit_of_work),
        },
        access: Arc::clone(&platform.access_records),
        users: Arc::new(PgUserStore::new(
            Arc::clone(databases),
            DomainLimits::default(),
        )),
        org_users: Arc::new(PgOrgUserStore::new(
            Arc::clone(databases),
            DomainLimits::default(),
        )),
        organizations: Arc::clone(&parts.organizations),
        org_grants: Arc::new(PgOrgTenantGrantStore::new(Arc::clone(databases))),
    });
    let handler = DeliverWebhookHandler::new(Arc::new(deliver), store)
        .map_err(PlatformError::of("the webhook delivery handler"))?;
    Ok(Arc::new(handler))
}

/// The handler handing one security signal to one stream: pushed, signed
/// under the tenant's issuer, or held for its receiver to poll.
fn signals(parts: &Parts<'_>) -> Result<Arc<dyn JobHandler>, ServerError> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let deliverer = HttpSignalDeliverer::new(
        platform.outbound.upstream_networks.clone(),
        &platform.outbound.deliveries,
    )
    .map_err(PlatformError::of("the signal deliverer"))?;
    let disable_after = FailureLimit::new(parts.config.agents.signal_disable_after_failures)
        .map_err(PlatformError::of("the signal streams' failure limit"))?;
    let dispatch = DispatchSignalUseCase::new(
        DispatchSignalPorts {
            stream_store: Arc::new(PgSignalStreamStore::new(Arc::clone(databases))),
            transmit: TransmitPorts {
                key_store: parts.signing_keys(),
                jwt_signer: Arc::new(Pkcs8JwtSigner),
                deliverer: Arc::new(deliverer),
                poll_queue: Arc::new(PgSignalPollQueue::new(Arc::clone(databases))),
                encryptor: encryptor(parts),
                issuers: parts.issuers(),
            },
            unit_of_work: Arc::clone(&platform.unit_of_work),
        },
        disable_after,
    );
    let handler = DispatchSignalHandler::new(Arc::new(dispatch))
        .map_err(PlatformError::of("the signal dispatch handler"))?;
    Ok(Arc::new(handler))
}

/// The handler telling an app a person signed out, by a logout token
/// signed under the tenant's issuer and posted to the app's back channel.
fn back_channel_logout(parts: &Parts<'_>) -> Result<Arc<dyn JobHandler>, ServerError> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let sender = HttpBackChannelLogoutSender::new(platform.outbound.upstream_networks.clone())
        .map_err(PlatformError::of("the back-channel logout sender"))?;
    let notify = NotifyBackChannelLogoutUseCase::new(NotifyBackChannelLogoutPorts {
        auth_code_store: Arc::new(PgAuthCodeStore::new(Arc::clone(databases))),
        client_store: Arc::new(PgOAuthClientStore::new(Arc::clone(databases))),
        key_store: parts.signing_keys(),
        jwt_signer: Arc::new(Pkcs8JwtSigner),
        sender: Arc::new(sender),
        issuers: parts.issuers(),
    });
    let handler = BackChannelLogoutHandler::new(Arc::new(notify))
        .map_err(PlatformError::of("the back-channel logout handler"))?;
    Ok(Arc::new(handler))
}

/// The handler posting a push subscription's waiting messages to its
/// endpoint, read from the message plane. A deployment whose bus runs in
/// the process has no plane: its push jobs fail, wait on the backoff and
/// end dead, where an operator sees them.
fn message_pushes(parts: &Parts<'_>) -> Result<Arc<dyn JobHandler>, ServerError> {
    let consumer: Arc<dyn MessageConsumer> = match &parts.platform.message_plane {
        Some(plane) => Arc::new(BusMessageConsumer::new(Arc::clone(plane))),
        None => Arc::new(NoMessageConsumer),
    };
    let handler = PushMessagesHandler::new(Arc::new(push_pending(parts, consumer)?))
        .map_err(PlatformError::of("the message push handler"))?;
    Ok(Arc::new(handler))
}

/// The push of what waits for a subscription, read through `consumer`.
fn push_pending(
    parts: &Parts<'_>,
    consumer: Arc<dyn MessageConsumer>,
) -> Result<PushPendingUseCase, ServerError> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let subscriptions = Arc::new(PgSubscriptionStore::new(Arc::clone(databases)));
    let deliverer = HttpPushDeliverer::new(
        platform.outbound.upstream_networks.clone(),
        &platform.outbound.deliveries,
    )
    .map_err(PlatformError::of("the message push deliverer"))?;
    let topics = Arc::new(PgTopicStore::new(Arc::clone(databases)));
    let push = PushMessageUseCase::new(PushMessagePorts {
        subscription_store: Arc::clone(&subscriptions) as _,
        topic_store: Arc::clone(&topics) as _,
        consumer_store: Arc::new(PgConsumerStore::new(Arc::clone(databases))),
        message_consumer: Arc::clone(&consumer),
        deliverer: Arc::new(deliverer),
        encryptor: encryptor(parts),
    });
    Ok(PushPendingUseCase::new(PushPendingPorts {
        subscription_store: subscriptions,
        topic_store: topics,
        message_consumer: consumer,
        push: Arc::new(push),
    }))
}

/// The handler posting a notification to one of an organization's
/// destinations outside the app, such as a Slack channel or a webhook.
fn destination_posts(parts: &Parts<'_>) -> Result<Arc<dyn JobHandler>, ServerError> {
    let platform = parts.platform;
    let poster = HttpDestinationPoster::new(
        encryptor(parts),
        platform.outbound.upstream_networks.clone(),
        &platform.outbound.deliveries,
    )
    .map_err(PlatformError::of("the notification poster"))?;
    let posting = PostUseCase::new(PostPorts {
        destinations: Arc::new(PgNotificationDestinationStore::new(Arc::clone(
            &platform.databases,
        ))),
        poster: Arc::new(poster),
    });
    let handler =
        PostHandler::new(posting).map_err(PlatformError::of("the notification post handler"))?;
    Ok(Arc::new(handler))
}
