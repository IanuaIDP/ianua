//! Start on a service's event: an integration's service sends the event a
//! workflow is registered for, and the version in service starts for the
//! person who published it.
//!
//! Nobody signs in for this; the service's signature with the
//! registration's secret is the only proof, and it is checked before
//! anything else is read. A delivery that does not check out, for a
//! registration nobody keeps, is refused one way, so a guess learns nothing.
//! A delivery the service sends again, under the id it sent first, starts
//! nothing twice.
//!
//! A service may first check that the platform holds an address, or hand
//! over the secret it will prove its deliveries with. Such a check is told
//! apart before anything else is read. A secret is taken only while the
//! address waits for one, so nobody who learns the address of a live
//! registration can replace what it is proven with.
//!
//! A delivery to an account's channel is proven once, with the channel's
//! secret, and then read for every workflow waiting on that account.

use std::sync::Arc;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::design::workflow::Workflow;
use ianua_domain::domains::workflows::execution::Cause;
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::domains::workflows::triggers::channel::{
    AccountChannel, ChannelCursor, ChannelStatus,
};
use ianua_domain::domains::workflows::triggers::subscription::{
    DeliveryCheck, ServiceSubscription,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{AccountChannelId, ServiceSubscriptionId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::workflows::{
    AccountChannelStore, ChannelAt, ChannelDirectory, CheckReply, DeliveryId, DeliveryLedger,
    EventReading, Greeting, PulledEvents, Reading, ReceivedEvent, Route, RouteKey,
    ServiceEventReader, ServiceSubscriptionStore, SubscriptionAt, SubscriptionDirectory,
};
use crate::services::account_channels::{channel_keys, channel_secret_place};
use crate::services::registrations::{
    RegistrationPorts, keep_renewal, lent_account, subscription_secret_place,
};
use crate::services::sealing::{opened_text, sealed_text};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::workflows::executions::starts::triggered::{
    Admission, Firing, started_for_publisher,
};
use crate::use_cases::workflows::executions::{TriggerStartPorts, TriggeredStart};

/// Where a delivery was sent.
#[derive(Clone)]
pub enum DeliveredTo {
    /// To one registration's own address.
    Registration(ServiceSubscriptionId),
    /// To the one address of an integration's app, which sends every event
    /// there.
    Integration(IntegrationKey),
    /// To the one address of an account, shared by every workflow on it.
    Channel(AccountChannelId),
}

/// One request a service sent, as it arrived.
pub struct ServiceEventRequest {
    /// Where it was sent.
    pub to: DeliveredTo,
    /// The address it was sent to, as the service signed it.
    pub address: String,
    /// Its headers, names in lowercase.
    pub headers: Vec<(String, String)>,
    /// Its body, as sent.
    pub body: Vec<u8>,
}

/// What the platform answers a service's delivery with.
#[derive(Debug, PartialEq)]
pub enum ServiceEventAnswer {
    /// The body the service asked for, to prove the platform holds the
    /// address.
    Proof(Vec<u8>),
    /// The answer to a service checking the address.
    Checked(CheckReply),
    /// Taken: what each registration it was for made of it.
    Taken(Vec<TriggeredStart>),
}

/// The ports [`StartOnServiceEventUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StartOnServiceEventPorts {
    /// Finds the registrations a delivery is for, across tenants.
    pub directory: Arc<dyn SubscriptionDirectory>,
    /// Keeps the registrations.
    pub subscriptions: Arc<dyn ServiceSubscriptionStore>,
    /// Checks and reads what services send.
    pub reader: Arc<dyn ServiceEventReader>,
    /// Opens each registration's secret.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Remembers the deliveries already started.
    pub ledger: Arc<dyn DeliveryLedger>,
    /// What a start for the publisher needs.
    pub starts: TriggerStartPorts,
    /// Finds the channel a delivery's address names, across tenants.
    pub channel_directory: Arc<dyn ChannelDirectory>,
    /// Keeps the accounts' channels.
    pub channels: Arc<dyn AccountChannelStore>,
    /// Reads a service's history through its account, for a channel whose
    /// deliveries only announce a change.
    pub registrations: RegistrationPorts,
}

/// Starts versions when their services send the events they are
/// registered for.
pub struct StartOnServiceEventUseCase {
    ports: StartOnServiceEventPorts,
}

impl StartOnServiceEventUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: StartOnServiceEventPorts) -> Self {
        Self { ports }
    }

    /// The registrations `request` is for: the one its address names, or
    /// those its key names at the integration's one address; or the body
    /// the platform's app answers with.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when no registration has the address,
    ///   or the one address refuses the delivery.
    /// - `AppError::Internal` when the directory cannot be read.
    async fn addressed(&self, request: &ServiceEventRequest) -> Result<Addressed, AppError> {
        let integration = match &request.to {
            DeliveredTo::Registration(id) => {
                let found = self.ports.directory.find(id).await.or_internal()?;
                let at = found.ok_or(AppError::Unauthenticated)?;
                return Ok(Addressed::Registrations(vec![at]));
            }
            DeliveredTo::Channel(id) => {
                let found = self.ports.channel_directory.find(id).await.or_internal()?;
                return Ok(Addressed::Channel(found.ok_or(AppError::Unauthenticated)?));
            }
            DeliveredTo::Integration(integration) => integration,
        };
        match self.ports.reader.route(integration, &received(request)) {
            Route::Keyed(key) => {
                let routed = self
                    .ports
                    .directory
                    .routed(integration, &key)
                    .await
                    .or_internal()?;
                Ok(Addressed::Registrations(routed))
            }
            Route::App(proof) => Ok(Addressed::App(proof)),
            Route::Refused => Err(AppError::Unauthenticated),
        }
    }

    /// What the registration at `at` makes of `request`: a start, the
    /// proof the service asked for, or nothing. A delivery to a channel was
    /// checked as the channel's, so only one to the registration itself may
    /// be a check of the registration.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the registration is gone, the
    ///   signature does not check out, or a check came when none is taken.
    /// - `AppError::Conflict` when the registration is no longer live, or
    ///   its version left service.
    /// - `AppError::Internal` when a store fails or a secret does not open.
    async fn delivered(
        &self,
        auditor: &RequestAuditor,
        at: SubscriptionAt,
        request: &ServiceEventRequest,
        signing: Signing<'_>,
    ) -> Result<Delivered, AppError> {
        let tenant = ScopedTenant::for_signed_delivery(at.tenant_id);
        let subscription = self.subscription(&tenant, &at.subscription_id).await?;
        if matches!(signing, Signing::Own)
            && let Some(reply) = self.answer_check(&tenant, &subscription, request).await?
        {
            return Ok(Delivered::Checked(reply));
        }
        let reading = self.read(&tenant, &subscription, request, signing).await?;
        if reading.check == DeliveryCheck::Forged {
            return Err(AppError::Unauthenticated);
        }
        match reading.reading {
            Reading::Start {
                delivery,
                input,
                exposure,
            } => {
                let arrived = Arrived {
                    delivery,
                    input,
                    exposure,
                };
                self.started(auditor, at, &subscription, arrived).await
            }
            Reading::Answer(proof) => Ok(Delivered::Proof(proof)),
            Reading::Skip => Ok(Delivered::Nothing),
        }
    }

    /// The answer to `request` when it is a service checking
    /// `subscription`'s address; `None` when it is an ordinary delivery.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the registration takes no such
    ///   check now.
    /// - `AppError::Internal` when a secret cannot be sealed or kept.
    async fn answer_check(
        &self,
        tenant: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
        request: &ServiceEventRequest,
    ) -> Result<Option<CheckReply>, AppError> {
        let integration = subscription.integration();
        match self.ports.reader.greet(integration, &received(request)) {
            Greeting::NotOne => Ok(None),
            Greeting::Prove(_) if !subscription.answers_checks() => Err(AppError::Unauthenticated),
            Greeting::Prove(reply) => Ok(Some(reply)),
            Greeting::HandsSecret { secret, reply } => {
                self.keep_handed_secret(tenant, subscription, &secret)
                    .await?;
                Ok(Some(reply))
            }
        }
    }

    /// Keeps `secret`, which the service handed over for `subscription`.
    /// Only one still waiting takes one, and only the first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when it takes none, or has one.
    /// - `AppError::Internal` when it cannot be sealed or kept.
    async fn keep_handed_secret(
        &self,
        tenant: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
        secret: &Secret,
    ) -> Result<(), AppError> {
        if !subscription.takes_service_secret() {
            return Err(AppError::Unauthenticated);
        }
        let sealed = sealed_text(
            self.ports.encryptor.as_ref(),
            secret.expose(),
            &subscription_secret_place(tenant, subscription.id()),
        )
        .await?;
        let first = self
            .ports
            .subscriptions
            .take_service_secret(tenant, subscription.id(), &sealed)
            .await
            .or_internal()?;
        if !first {
            return Err(AppError::Unauthenticated);
        }
        Ok(())
    }

    /// What `request` says to `subscription`, read with its own secret
    /// opened, or the channel's it arrived through.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the secret does not open.
    async fn read(
        &self,
        tenant: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
        request: &ServiceEventRequest,
        signing: Signing<'_>,
    ) -> Result<EventReading, AppError> {
        let reader = &self.ports.reader;
        if let Signing::Channel(secret) = signing {
            return Ok(reader.read(subscription, secret, &received(request)));
        }
        let secret = opened_text(
            self.ports.encryptor.as_ref(),
            subscription.secret(),
            &subscription_secret_place(tenant, subscription.id()),
        )
        .await
        .or_internal()?;
        Ok(reader.read(subscription, &secret, &received(request)))
    }

    /// What the account's channel at `at` makes of `request`: the answer
    /// to a check, or a start for each workflow waiting on it. Deliveries
    /// are read only while the channel is live.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the channel is gone, not live, or
    ///   the delivery is not proven.
    /// - `AppError::Upstream` when the service's history cannot be read, so
    ///   the service sends it again.
    /// - `AppError::Internal` when a store fails or a secret does not open.
    async fn through_channel(
        &self,
        auditor: &RequestAuditor,
        at: ChannelAt,
        request: &ServiceEventRequest,
    ) -> Result<ServiceEventAnswer, AppError> {
        let tenant = ScopedTenant::for_signed_delivery(at.tenant_id);
        let mut channel = self.channel(&tenant, &at.channel_id).await?;
        let check = self
            .answer_channel_check(&tenant, &mut channel, request)
            .await?;
        if let Some(reply) = check {
            return Ok(ServiceEventAnswer::Checked(reply));
        }
        if !channel.is_live() {
            return Err(AppError::Unauthenticated);
        }
        let arrivals = self.arrivals(auditor, &tenant, &channel, request).await?;
        let secret = opened_text(
            self.ports.encryptor.as_ref(),
            channel.secret(),
            &channel_secret_place(&tenant, channel.id()),
        )
        .await
        .or_internal()?;
        let taken = self
            .started_on_channel(auditor, &channel, &arrivals.requests, &secret)
            .await?;
        self.keep_cursor(&tenant, channel, arrivals.cursor).await?;
        Ok(ServiceEventAnswer::Taken(taken))
    }

    /// The tenant's channel `id`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when it is gone.
    /// - `AppError::Internal` when it cannot be read.
    async fn channel(
        &self,
        tenant: &ScopedTenant,
        id: &AccountChannelId,
    ) -> Result<AccountChannel<ResolvedTenant>, AppError> {
        self.ports
            .channels
            .find_by_id(tenant, id)
            .await
            .or_internal()?
            .ok_or(AppError::Unauthenticated)
    }

    /// The answer to `request` when it is a service checking `channel`'s
    /// address; `None` when it is an ordinary delivery.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the channel takes no such check
    ///   now.
    /// - `AppError::Internal` when a token cannot be sealed or kept.
    async fn answer_channel_check(
        &self,
        tenant: &ScopedTenant,
        channel: &mut AccountChannel<ResolvedTenant>,
        request: &ServiceEventRequest,
    ) -> Result<Option<CheckReply>, AppError> {
        let greeting = self
            .ports
            .reader
            .greet(channel.integration(), &received(request));
        match greeting {
            Greeting::NotOne => Ok(None),
            Greeting::Prove(_) if channel.status() == ChannelStatus::Lapsed => {
                Err(AppError::Unauthenticated)
            }
            Greeting::Prove(reply) => Ok(Some(reply)),
            Greeting::HandsSecret { secret, reply } => {
                self.keep_channel_token(tenant, channel, &secret).await?;
                Ok(Some(reply))
            }
        }
    }

    /// Keeps `token`, which the service sent `channel`, while it waits for
    /// one.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when it is not waiting for one.
    /// - `AppError::Internal` when it cannot be sealed or kept.
    async fn keep_channel_token(
        &self,
        tenant: &ScopedTenant,
        channel: &mut AccountChannel<ResolvedTenant>,
        token: &Secret,
    ) -> Result<(), AppError> {
        let sealed = sealed_text(
            self.ports.encryptor.as_ref(),
            token.expose(),
            &channel_secret_place(tenant, channel.id()),
        )
        .await?;
        channel
            .receive_token(sealed)
            .map_err(|_| AppError::Unauthenticated)?;
        self.ports
            .channels
            .save(tenant, channel)
            .await
            .or_internal()
    }

    /// What arrived through `channel`: `request` itself, or what it
    /// announced, read from the service through the channel's account.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when `request` is not proven, or the
    ///   channel's account is gone.
    /// - `AppError::Upstream` when the service could not be read.
    /// - `AppError::Internal` when a store fails.
    async fn arrivals(
        &self,
        auditor: &RequestAuditor,
        tenant: &ScopedTenant,
        channel: &AccountChannel<ResolvedTenant>,
        request: &ServiceEventRequest,
    ) -> Result<Arrivals, AppError> {
        let ports = &self.ports.registrations;
        if !ports.channel_setup.pulls_history(channel.integration()) {
            return Ok(Arrivals {
                requests: vec![with_body(request, request.body.clone())],
                cursor: None,
            });
        }
        let mut account = lent_account(ports, tenant, channel.account())
            .await
            .map_err(|_| AppError::Unauthenticated)?;
        let keys = channel_keys(ports, auditor, tenant, &account, channel)
            .await
            .map_err(|_| history_unread())?;
        let answer = ports
            .registrar
            .pull(tenant, channel, &keys, &received(request))
            .await;
        keep_renewal(ports, auditor, tenant, &mut account, answer.renewal).await?;
        match answer.result.map_err(|_| history_unread())? {
            PulledEvents::Forged => Err(AppError::Unauthenticated),
            PulledEvents::Fetched { deliveries, cursor } => Ok(Arrivals {
                requests: deliveries
                    .into_iter()
                    .map(|body| with_body(request, body))
                    .collect(),
                cursor: Some(cursor),
            }),
        }
    }

    /// Reads each of `arrivals` for every workflow waiting on `channel`.
    /// A workflow no longer in service is passed over, so it does not hold
    /// up the others.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when a delivery does not check out.
    /// - `AppError::Internal` when a store fails, or a start or its record
    ///   cannot be kept.
    async fn started_on_channel(
        &self,
        auditor: &RequestAuditor,
        channel: &AccountChannel<ResolvedTenant>,
        arrivals: &[ServiceEventRequest],
        secret: &Secret,
    ) -> Result<Vec<TriggeredStart>, AppError> {
        let waiting = self
            .ports
            .directory
            .routed(channel.integration(), &RouteKey::of_channel(channel.id()))
            .await
            .or_internal()?;
        let mut taken = Vec::new();
        for arrival in arrivals {
            for at in &waiting {
                let signing = Signing::Channel(secret);
                match self.delivered(auditor, *at, arrival, signing).await {
                    Ok(Delivered::Started(started)) => taken.push(started),
                    Ok(_) | Err(AppError::Conflict(_)) => {}
                    Err(other) => return Err(other),
                }
            }
        }
        Ok(taken)
    }

    /// Keeps where `channel`'s history was read up to, once every start
    /// from it was kept. Should this fail, the service's next delivery
    /// reads the same events again, and the ledger starts none twice.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when it cannot be kept.
    async fn keep_cursor(
        &self,
        tenant: &ScopedTenant,
        mut channel: AccountChannel<ResolvedTenant>,
        cursor: Option<ChannelCursor>,
    ) -> Result<(), AppError> {
        let Some(cursor) = cursor else {
            return Ok(());
        };
        channel.note_cursor(cursor);
        self.ports
            .channels
            .save(tenant, &channel)
            .await
            .or_internal()
    }

    /// Starts the version `subscription` is for on the event that
    /// `arrived`, once per delivery, for its publisher.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` when the registration is no longer live, or
    ///   its version left service.
    /// - `AppError::Internal` when a store fails, or the start or its
    ///   record cannot be kept.
    async fn started(
        &self,
        auditor: &RequestAuditor,
        at: SubscriptionAt,
        subscription: &ServiceSubscription<ResolvedTenant>,
        arrived: Arrived,
    ) -> Result<Delivered, AppError> {
        let tenant = ScopedTenant::for_signed_delivery(at.tenant_id);
        let workflow = self.in_service(&tenant, subscription).await?;
        let delivery = subscription
            .admit(DeliveryCheck::Authentic, &workflow)
            .map_err(|_| no_longer_in_service())?;
        let first = self
            .ports
            .ledger
            .first_time(&tenant, &at.subscription_id, &arrived.delivery)
            .await
            .or_internal()?;
        if !first {
            return Ok(Delivered::Nothing);
        }
        let firing = Firing {
            cause: Cause::Service,
            admission: Admission::Service(delivery),
            input: arrived.input,
            exposure: arrived.exposure,
        };
        let auditor = auditor.with_tenant(at.tenant_id);
        let started =
            started_for_publisher(&self.ports.starts, &tenant, &auditor, &workflow, firing).await?;
        Ok(Delivered::Started(started))
    }

    /// The version in service of the workflow `subscription` starts.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` when the workflow has none in service.
    /// - `AppError::Internal` when it cannot be read.
    async fn in_service(
        &self,
        tenant: &ScopedTenant,
        subscription: &ServiceSubscription<ResolvedTenant>,
    ) -> Result<Workflow<ResolvedTenant>, AppError> {
        self.ports
            .starts
            .workflows
            .find_published(tenant, subscription.workflow_id())
            .await
            .or_internal()?
            .ok_or_else(no_longer_in_service)
    }

    /// The tenant's registration `id`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when it is gone.
    /// - `AppError::Internal` when it cannot be read.
    async fn subscription(
        &self,
        tenant: &ScopedTenant,
        id: &ServiceSubscriptionId,
    ) -> Result<ServiceSubscription<ResolvedTenant>, AppError> {
        self.ports
            .subscriptions
            .find_by_id(tenant, id)
            .await
            .or_internal()?
            .ok_or(AppError::Unauthenticated)
    }
}

impl Command for StartOnServiceEventUseCase {
    type Caller = ();
    type Input = ServiceEventRequest;
    type Output = Result<ServiceEventAnswer, AppError>;

    /// Checks the delivery against each registration it is for and starts
    /// the version in service of each it is the event of, for its
    /// publisher; or answers the proof the service asked for.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for a delivery nothing admits: an
    ///   unknown address, a forged or unsigned delivery, a channel not live.
    /// - `AppError::Conflict` when the one registration it names is no
    ///   longer live.
    /// - `AppError::Upstream` when a service's history cannot be read.
    /// - `AppError::Internal` when a store fails, a secret does not open,
    ///   or a start or its record cannot be kept.
    async fn execute(
        &self,
        _caller: &(),
        auditor: &RequestAuditor,
        request: ServiceEventRequest,
    ) -> Result<ServiceEventAnswer, AppError> {
        let registrations = match self.addressed(&request).await? {
            Addressed::App(proof) => return Ok(ServiceEventAnswer::Proof(proof)),
            Addressed::Channel(at) => {
                return self.through_channel(auditor, at, &request).await;
            }
            Addressed::Registrations(registrations) => registrations,
        };
        let mut taken = Vec::new();
        for at in registrations {
            match self.delivered(auditor, at, &request, Signing::Own).await? {
                Delivered::Proof(proof) => return Ok(ServiceEventAnswer::Proof(proof)),
                Delivered::Checked(reply) => return Ok(ServiceEventAnswer::Checked(reply)),
                Delivered::Started(started) => taken.push(started),
                Delivered::Nothing => {}
            }
        }
        Ok(ServiceEventAnswer::Taken(taken))
    }
}

/// The registrations a delivery is for, or the platform app's answer.
enum Addressed {
    /// Deliver the event to each matching stored subscription.
    Registrations(Vec<SubscriptionAt>),
    /// The platform's app answers with this body.
    App(Vec<u8>),
    /// It reached this account's channel.
    Channel(ChannelAt),
}

/// Which secret proves a delivery.
#[derive(Clone, Copy)]
enum Signing<'a> {
    /// The registration's own, opened when it is read.
    Own,
    /// The channel's it arrived through, already opened.
    Channel(&'a Secret),
}

/// What arrived through a channel.
struct Arrivals {
    /// Each delivery to read.
    requests: Vec<ServiceEventRequest>,
    /// Where the service's history was read up to, if it was.
    cursor: Option<ChannelCursor>,
}

/// An event a service sent, once its signature checked out and it proved
/// to be the trigger's event.
struct Arrived {
    /// The service's id for the delivery.
    delivery: DeliveryId,
    /// The event's values.
    input: FlowData,
    /// The most sensitive data in them.
    exposure: DataClassLevel,
}

/// What one registration made of a delivery.
enum Delivered {
    /// The proof its service asked for.
    Proof(Vec<u8>),
    /// The answer to its service checking the address.
    Checked(CheckReply),
    /// A start, or a refused one.
    Started(TriggeredStart),
    /// Nothing: not its event, or a delivery already started.
    Nothing,
}

/// `request` as the reader reads it.
fn received(request: &ServiceEventRequest) -> ReceivedEvent<'_> {
    ReceivedEvent {
        address: &request.address,
        headers: &request.headers,
        body: &request.body,
    }
}

/// `request` with `body` in place of what it carried.
fn with_body(request: &ServiceEventRequest, body: Vec<u8>) -> ServiceEventRequest {
    ServiceEventRequest {
        to: request.to.clone(),
        address: request.address.clone(),
        headers: request.headers.clone(),
        body,
    }
}

/// The answer when a service's history could not be read: the service
/// sends the delivery again later.
fn history_unread() -> AppError {
    AppError::Upstream(Box::new(DomainError::infra_msg(
        "the service's history could not be read",
    )))
}

/// The answer for a delivery to a registration no longer in service, so a
/// service still sending learns to stop.
fn no_longer_in_service() -> AppError {
    AppError::Conflict(ianua_domain::message!(
        "workflows-the-registration-is-no-longer-in-service",
        "the registration this event is for is no longer in service"
    ))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::account::{AccountSharing, IntegrationAccount};
    use ianua_domain::domains::workflows::data::FieldName;
    use ianua_domain::domains::workflows::design::workflow::{Hold, Workflow};
    use ianua_domain::domains::workflows::execution::StartRefusal;
    use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
    use ianua_domain::domains::workflows::triggers::channel::{
        ChannelSetup, HistoryPlace, OpenChannel,
    };
    use ianua_domain::domains::workflows::triggers::subscription::{
        Lapse, LapseReason, RemoteRegistration,
    };
    use ianua_domain::domains::workflows::triggers::{
        EventFilter, FilterValue, ServiceTrigger, Trigger,
    };
    use ianua_domain::types::{Human, IntegrationAccountId, SealedSecret};

    use super::*;
    use crate::ports::workflows::{
        CheckBody, DeliveryId, RegistrationFailure, Routing, WorkflowStore as _,
    };
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::workflows::{
        FakeAccountChannelStore, FakeDeliveryLedger, FakeIntegrationAccountStore,
        FakeServiceEventReader, FakeServiceRegistrar, FakeServiceSubscriptionStore,
        FakeWorkflowExecutionStore, FakeWorkflowStore, SHEETS, accounts_now_of, draft_on, managing,
        person, published_by, sheets_account, tidy_step, trigger_data,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The secret the sheets service signs with, as a test writes it.
    const SIGNING: &str = "sheets signing words";

    /// What the publisher holds: running workflows, and lending the account
    /// they connected.
    const RUNS: [SystemPermission; 2] = [
        SystemPermission::Workflows(WorkflowAction::Run),
        SystemPermission::Workflows(WorkflowAction::ConnectAccounts),
    ];

    /// `publisher`'s workflow starting when a row is added to the finance
    /// sheet, registered through `account`, in service.
    fn watching_by(publisher: &Human, account: IntegrationAccountId) -> Workflow<ResolvedTenant> {
        let trigger = ServiceTrigger::from_stored(
            IntegrationKey::new(SHEETS).unwrap(),
            ServiceEventKey::new("row-added").unwrap(),
            account,
            vec![EventFilter::new(
                FieldName::new("sheet").unwrap(),
                FilterValue::new("finance").unwrap(),
            )],
        )
        .unwrap();
        published_by(
            publisher,
            draft_on(
                publisher,
                vec![tidy_step("tidy")],
                Vec::new(),
                Trigger::Service(trigger),
            ),
        )
    }

    /// One watching workflow, its live registration, and what deliveries
    /// to it wrote and recorded.
    struct Watch {
        workflow: Workflow<ResolvedTenant>,
        subscription_id: ServiceSubscriptionId,
        subscriptions: Arc<FakeServiceSubscriptionStore>,
        ledger: Arc<FakeDeliveryLedger>,
        executions: Arc<FakeWorkflowExecutionStore>,
        sink: Arc<FakeEventDispatcher>,
        publisher: Human,
        account: IntegrationAccount<ResolvedTenant>,
        workflows: Arc<FakeWorkflowStore>,
    }

    impl Watch {
        fn published() -> Self {
            let publisher = person("ann@corp.test");
            let account = sheets_account(&publisher, AccountSharing::OwnerOnly);
            let workflow = watching_by(&publisher, *account.id());
            let tenant = test_ctx().tenant();
            let id = ServiceSubscriptionId::new();
            let sealed =
                FakeEncryptor::sealed_for(SIGNING, &subscription_secret_place(&tenant, &id));
            let mut subscription = ServiceSubscription::open(&workflow, id, sealed).unwrap();
            subscription
                .register(RemoteRegistration::new("watch-1").unwrap(), Lapse::Never)
                .unwrap();
            let subscriptions = Arc::new(FakeServiceSubscriptionStore::empty());
            block_on(subscriptions.insert(&tenant, &subscription, &Routing::OwnAddress)).unwrap();
            Self {
                workflows: Arc::new(FakeWorkflowStore::holding(std::slice::from_ref(&workflow))),
                workflow,
                subscription_id: id,
                subscriptions,
                ledger: Arc::new(FakeDeliveryLedger::default()),
                executions: Arc::new(FakeWorkflowExecutionStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
                publisher,
                account,
            }
        }

        /// The sheets service sends `delivery` to the registration, signed
        /// with `signature`.
        fn delivered(
            &self,
            to: ServiceSubscriptionId,
            signature: &str,
            delivery: &str,
        ) -> Result<ServiceEventAnswer, AppError> {
            let reading = Reading::Start {
                delivery: DeliveryId::new(delivery.to_owned()),
                input: trigger_data(),
                exposure: DataClassLevel::Internal,
            };
            let use_case = StartOnServiceEventUseCase::new(StartOnServiceEventPorts {
                directory: self.subscriptions.clone(),
                subscriptions: self.subscriptions.clone(),
                reader: Arc::new(FakeServiceEventReader::signed_with(SIGNING, reading)),
                encryptor: Arc::new(FakeEncryptor),
                ledger: self.ledger.clone(),
                starts: TriggerStartPorts {
                    workflows: self.workflows.clone(),
                    executions: self.executions.clone(),
                    accounts_now: Arc::new(accounts_now_of(&[(&self.publisher, &RUNS)])),
                    accounts: Arc::new(FakeIntegrationAccountStore::holding(&self.account)),
                    ..TriggerStartPorts::fakes()
                },
                ..StartOnServiceEventPorts::fakes()
            });
            let request = ServiceEventRequest {
                to: DeliveredTo::Registration(to),
                address: "https://ianua.test/events".to_owned(),
                headers: vec![("x-signature".to_owned(), signature.to_owned())],
                body: b"{}".to_vec(),
            };
            block_on(use_case.execute(&(), &test_auditor(self.sink.clone()), request))
        }
    }

    /// What a check or a channel's delivery goes through.
    struct Through {
        reader: FakeServiceEventReader,
        channels: Arc<FakeAccountChannelStore>,
        registrar: FakeServiceRegistrar,
    }

    impl Through {
        /// A reader reading one signed delivery as an event, no channel,
        /// and a service taking everything.
        fn plain() -> Self {
            Self {
                reader: FakeServiceEventReader::signed_with(SIGNING, event_reading()),
                channels: Arc::new(FakeAccountChannelStore::empty()),
                registrar: FakeServiceRegistrar::taking("watch-1", Lapse::Never),
            }
        }

        fn greeted(self, greeting: Greeting) -> Self {
            Self {
                reader: self.reader.greeted(greeting),
                ..self
            }
        }
    }

    fn event_reading() -> Reading {
        Reading::Start {
            delivery: DeliveryId::new("delivery-1".to_owned()),
            input: trigger_data(),
            exposure: DataClassLevel::Internal,
        }
    }

    fn proving() -> Greeting {
        Greeting::Prove(CheckReply {
            body: CheckBody::PlainText(b"validation token".to_vec()),
            header: None,
        })
    }

    fn handing(secret: &str) -> Greeting {
        Greeting::HandsSecret {
            secret: Secret::new(secret.to_owned()),
            reply: CheckReply {
                body: CheckBody::Empty,
                header: Some(("x-hook-secret", secret.to_owned())),
            },
        }
    }

    impl Watch {
        /// A registration of the watching workflow still waiting on its
        /// service, and its id.
        fn waiting(&self) -> ServiceSubscriptionId {
            let tenant = test_ctx().tenant();
            let id = ServiceSubscriptionId::new();
            let sealed =
                FakeEncryptor::sealed_for(SIGNING, &subscription_secret_place(&tenant, &id));
            let waiting = ServiceSubscription::open(&self.workflow, id, sealed).unwrap();
            block_on(
                self.subscriptions
                    .insert(&tenant, &waiting, &Routing::OwnAddress),
            )
            .unwrap();
            id
        }

        /// A channel of the publisher's account set up as `setup`, and the
        /// watching workflow's live registration on it.
        fn on_channel(
            &self,
            setup: ChannelSetup,
        ) -> (Arc<FakeAccountChannelStore>, AccountChannelId) {
            let tenant = test_ctx().tenant();
            let id = AccountChannelId::new();
            let channel: AccountChannel<ResolvedTenant> = AccountChannel::open(OpenChannel {
                id,
                account: *self.account.id(),
                integration: IntegrationKey::new(SHEETS).unwrap(),
                secret: FakeEncryptor::sealed_for(SIGNING, &channel_secret_place(&tenant, &id)),
                setup,
            })
            .unwrap();
            let channels = Arc::new(FakeAccountChannelStore::empty());
            block_on(channels.insert_if_absent(&tenant, &channel)).unwrap();
            let waiting = self.waiting();
            let mut subscription = block_on(self.subscriptions.find_by_id(&tenant, &waiting))
                .unwrap()
                .unwrap();
            subscription
                .register(RemoteRegistration::new("channel").unwrap(), Lapse::Never)
                .unwrap();
            let routing = Routing::Keyed(RouteKey::of_channel(&id));
            block_on(self.subscriptions.take(&tenant, &subscription, &routing)).unwrap();
            (channels, id)
        }

        /// A channel of the publisher's account, already live.
        fn on_live_channel(&self) -> (Arc<FakeAccountChannelStore>, AccountChannelId) {
            let (channels, id) = self.on_channel(ChannelSetup::Registered);
            let tenant = test_ctx().tenant();
            let mut channel = block_on(channels.find_by_id(&tenant, &id))
                .unwrap()
                .unwrap();
            channel
                .register(
                    RemoteRegistration::new("bot-hook").unwrap(),
                    Lapse::Never,
                    HistoryPlace::Unknown,
                )
                .unwrap();
            block_on(channels.save(&tenant, &channel)).unwrap();
            (channels, id)
        }

        /// A signed request arriving at `to`, through `through`.
        fn arrives(
            &self,
            to: DeliveredTo,
            through: Through,
        ) -> Result<ServiceEventAnswer, AppError> {
            let registrar = Arc::new(through.registrar);
            let use_case = StartOnServiceEventUseCase::new(StartOnServiceEventPorts {
                directory: self.subscriptions.clone(),
                subscriptions: self.subscriptions.clone(),
                reader: Arc::new(through.reader),
                encryptor: Arc::new(FakeEncryptor),
                ledger: self.ledger.clone(),
                starts: TriggerStartPorts {
                    workflows: self.workflows.clone(),
                    executions: self.executions.clone(),
                    accounts_now: Arc::new(accounts_now_of(&[(&self.publisher, &RUNS)])),
                    accounts: Arc::new(FakeIntegrationAccountStore::holding(&self.account)),
                    ..TriggerStartPorts::fakes()
                },
                channel_directory: through.channels.clone(),
                channels: through.channels.clone(),
                registrations: RegistrationPorts {
                    accounts: Arc::new(FakeIntegrationAccountStore::holding(&self.account)),
                    registrar: registrar.clone(),
                    channel_setup: registrar,
                    channels: through.channels,
                    ..RegistrationPorts::fakes()
                },
            });
            let request = ServiceEventRequest {
                to,
                address: "https://ianua.test/events".to_owned(),
                headers: vec![("x-signature".to_owned(), SIGNING.to_owned())],
                body: b"{}".to_vec(),
            };
            block_on(use_case.execute(&(), &test_auditor(self.sink.clone()), request))
        }

        fn stored_secret(&self, id: &ServiceSubscriptionId) -> SealedSecret {
            let tenant = test_ctx().tenant();
            block_on(self.subscriptions.find_by_id(&tenant, id))
                .unwrap()
                .unwrap()
                .secret()
                .clone()
        }
    }

    /// Asana posts its secret to the address while its create call is still
    /// open. The waiting registration keeps it, sealed in place of the one
    /// the platform made, and Asana gets it echoed back.
    #[test]
    fn a_secret_handed_over_while_waiting_is_kept_and_echoed() {
        let watch = Watch::published();
        let waiting = watch.waiting();

        let answer = watch
            .arrives(
                DeliveredTo::Registration(waiting),
                Through::plain().greeted(handing("asana secret")),
            )
            .unwrap();

        let tenant = test_ctx().tenant();
        assert_eq!(
            watch.stored_secret(&waiting),
            FakeEncryptor::sealed_for(
                "asana secret",
                &subscription_secret_place(&tenant, &waiting)
            )
        );
        let ServiceEventAnswer::Checked(reply) = answer else {
            panic!("the handshake was not answered as a check");
        };
        assert_eq!(
            reply.header,
            Some(("x-hook-secret", "asana secret".to_owned()))
        );
    }

    /// Stops: Mallory learns the address of a registration still waiting
    /// and posts a second secret after Asana's. The first stands.
    #[test]
    fn only_the_first_secret_handed_over_is_kept() {
        let watch = Watch::published();
        let waiting = watch.waiting();
        let to = || DeliveredTo::Registration(waiting);
        watch
            .arrives(to(), Through::plain().greeted(handing("asana secret")))
            .unwrap();
        let first = watch.stored_secret(&waiting);

        let second = watch.arrives(to(), Through::plain().greeted(handing("mallory's")));

        assert!(matches!(second, Err(AppError::Unauthenticated)));
        assert_eq!(watch.stored_secret(&waiting), first);
    }

    /// Stops: Mallory learns the address of Ann's live registration and
    /// posts a secret of her own. It would replace what proves every
    /// delivery, so it is refused.
    #[test]
    fn a_live_registration_takes_no_handed_over_secret() {
        let watch = Watch::published();
        let before = watch.stored_secret(&watch.subscription_id);

        let refused = watch.arrives(
            DeliveredTo::Registration(watch.subscription_id),
            Through::plain().greeted(handing("mallory's")),
        );

        assert!(matches!(refused, Err(AppError::Unauthenticated)));
        assert_eq!(watch.stored_secret(&watch.subscription_id), before);
    }

    /// Microsoft Graph checks the address again as it renews a live
    /// subscription, and gets its token back; nothing starts.
    #[test]
    fn a_check_of_a_live_address_is_answered_and_starts_nothing() {
        let watch = Watch::published();

        let answer = watch
            .arrives(
                DeliveredTo::Registration(watch.subscription_id),
                Through::plain().greeted(proving()),
            )
            .unwrap();

        assert!(matches!(answer, ServiceEventAnswer::Checked(_)));
        assert!(watch.executions.all().is_empty());
    }

    /// A check of a registration that has lapsed is refused, so the service
    /// learns it is no longer wanted.
    #[test]
    fn a_check_of_a_lapsed_address_is_refused() {
        let watch = Watch::published();
        let tenant = test_ctx().tenant();
        let mut lapsed = block_on(
            watch
                .subscriptions
                .find_by_id(&tenant, &watch.subscription_id),
        )
        .unwrap()
        .unwrap();
        lapsed
            .lapse(LapseReason::new("the watch expired").unwrap())
            .unwrap();
        block_on(watch.subscriptions.save(&tenant, &lapsed)).unwrap();

        let refused = watch.arrives(
            DeliveredTo::Registration(watch.subscription_id),
            Through::plain().greeted(proving()),
        );

        assert!(matches!(refused, Err(AppError::Unauthenticated)));
    }

    /// Ann's bot sends one update to its account's one address. It is
    /// proven with the channel's secret and starts the workflow on it.
    #[test]
    fn a_delivery_to_a_live_channel_starts_the_workflow_waiting_on_it() {
        let watch = Watch::published();
        let (channels, id) = watch.on_live_channel();

        let answer = watch
            .arrives(
                DeliveredTo::Channel(id),
                Through {
                    channels,
                    ..Through::plain()
                },
            )
            .unwrap();

        let ServiceEventAnswer::Taken(started) = answer else {
            panic!("the delivery was answered as a check");
        };
        assert_eq!(started.len(), 1);
        assert_eq!(watch.executions.all().len(), 1);
    }

    /// Stops: someone who learns the address of a channel still waiting on
    /// its key sends an event. Nothing is read until the channel is live.
    #[test]
    fn a_delivery_to_a_channel_not_live_starts_nothing() {
        let watch = Watch::published();
        let (channels, id) = watch.on_channel(ChannelSetup::PastedKey);

        let refused = watch.arrives(
            DeliveredTo::Channel(id),
            Through {
                channels,
                ..Through::plain()
            },
        );

        assert!(matches!(refused, Err(AppError::Unauthenticated)));
        assert!(watch.executions.all().is_empty());
    }

    /// A delivery to an address no channel has is refused like any unknown
    /// address.
    #[test]
    fn a_delivery_to_an_unknown_channel_is_refused() {
        let watch = Watch::published();

        let refused = watch.arrives(
            DeliveredTo::Channel(AccountChannelId::new()),
            Through::plain(),
        );

        assert!(matches!(refused, Err(AppError::Unauthenticated)));
    }

    /// Notion sends its one-time token. The channel keeps it and waits for
    /// Ann to confirm she pasted it back, so it is not live yet.
    #[test]
    fn a_token_sent_to_a_channel_is_kept_and_the_channel_still_waits() {
        let watch = Watch::published();
        let (channels, id) = watch.on_channel(ChannelSetup::TokenFromService);

        watch
            .arrives(
                DeliveredTo::Channel(id),
                Through {
                    channels: channels.clone(),
                    ..Through::plain().greeted(handing("notion token"))
                },
            )
            .unwrap();

        let tenant = test_ctx().tenant();
        let kept = block_on(channels.find_by_id(&tenant, &id))
            .unwrap()
            .unwrap();
        assert_eq!(kept.status(), ChannelStatus::AwaitingConfirmation);
        assert_eq!(
            kept.secret(),
            &FakeEncryptor::sealed_for("notion token", &channel_secret_place(&tenant, &id))
        );
    }

    /// Stops: Mallory posts a token to a live channel. It would replace
    /// what proves every delivery, so it is refused.
    #[test]
    fn a_live_channel_takes_no_token() {
        let watch = Watch::published();
        let (channels, id) = watch.on_live_channel();

        let refused = watch.arrives(
            DeliveredTo::Channel(id),
            Through {
                channels,
                ..Through::plain().greeted(handing("mallory's"))
            },
        );

        assert!(matches!(refused, Err(AppError::Unauthenticated)));
    }

    /// Gmail's push only says the mailbox changed. What changed is read
    /// from its history, started, and the place in the history is kept.
    #[test]
    fn an_announced_change_is_read_and_its_place_kept() {
        let watch = Watch::published();
        let (channels, id) = watch.on_live_channel();
        let pulled = PulledEvents::Fetched {
            deliveries: vec![b"{\"message\":1}".to_vec()],
            cursor: ChannelCursor::new("1300").unwrap(),
        };

        watch
            .arrives(
                DeliveredTo::Channel(id),
                Through {
                    channels: channels.clone(),
                    registrar: FakeServiceRegistrar::taking("w", Lapse::Never).pulling(pulled),
                    ..Through::plain()
                },
            )
            .unwrap();

        let kept = block_on(channels.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap();
        assert_eq!(watch.executions.all().len(), 1);
        assert_eq!(kept.history().cursor().unwrap().as_str(), "1300");
    }

    /// Stops: a push whose Google token does not prove it is refused, and
    /// nothing is read.
    #[test]
    fn an_unproven_announcement_is_refused() {
        let watch = Watch::published();
        let (channels, id) = watch.on_live_channel();

        let refused = watch.arrives(
            DeliveredTo::Channel(id),
            Through {
                channels,
                registrar: FakeServiceRegistrar::taking("w", Lapse::Never)
                    .pulling(PulledEvents::Forged),
                ..Through::plain()
            },
        );

        assert!(matches!(refused, Err(AppError::Unauthenticated)));
        assert!(watch.executions.all().is_empty());
    }

    /// Gmail is down when its push arrives. The delivery is turned away so
    /// Pub/Sub sends it again, and the place in the history stays.
    #[test]
    fn a_history_out_of_reach_is_sent_again() {
        let watch = Watch::published();
        let (channels, id) = watch.on_live_channel();
        let down = FakeServiceRegistrar::failing(RegistrationFailure::Unreachable).pulling(
            PulledEvents::Fetched {
                deliveries: Vec::new(),
                cursor: ChannelCursor::new("1300").unwrap(),
            },
        );

        let refused = watch.arrives(
            DeliveredTo::Channel(id),
            Through {
                channels: channels.clone(),
                registrar: down,
                ..Through::plain()
            },
        );

        let kept = block_on(channels.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap();
        assert!(matches!(refused, Err(AppError::Upstream(_))));
        assert!(kept.history().cursor().is_none());
    }

    /// A row is added to the finance sheet: the service's signed delivery
    /// starts Ann's workflow, acting for her, as a service start.
    #[test]
    fn a_signed_delivery_starts_the_version_for_its_publisher() {
        let watch = Watch::published();

        let answer = watch
            .delivered(watch.subscription_id, SIGNING, "delivery-1")
            .unwrap();

        let ServiceEventAnswer::Taken(started) = answer else {
            panic!("the delivery was answered with a proof");
        };
        let [TriggeredStart::Started(id)] = started.as_slice() else {
            panic!("the delivery did not start one run: {started:?}");
        };
        let kept = watch.executions.stored(id).unwrap();
        assert!(kept.acting_for().is_same_account_as(&watch.publisher));
        assert_eq!(kept.cause(), Cause::Service);
    }

    /// A forged signature and an unknown registration each fail authentication,
    /// leaving no execution saved and no audit event recorded.
    #[test]
    fn a_forged_delivery_or_an_unknown_address_starts_nothing() {
        let watch = Watch::published();

        let forged = watch.delivered(watch.subscription_id, "guessed", "delivery-1");
        let unknown = watch.delivered(ServiceSubscriptionId::new(), SIGNING, "delivery-1");

        assert!(matches!(forged, Err(AppError::Unauthenticated)));
        assert!(matches!(unknown, Err(AppError::Unauthenticated)));
        assert!(watch.executions.all().is_empty());
        assert!(watch.sink.records.lock().unwrap().is_empty());
    }

    /// The service sends the same delivery again, as services do when an
    /// answer is slow. It starts one run, not two.
    #[test]
    fn a_delivery_sent_twice_starts_one_run() {
        let watch = Watch::published();
        let use_twice = || watch.delivered(watch.subscription_id, SIGNING, "delivery-1");

        use_twice().unwrap();
        let again = use_twice().unwrap();

        assert_eq!(again, ServiceEventAnswer::Taken(Vec::new()));
        assert_eq!(watch.executions.all().len(), 1);
    }

    /// Ann switches her sheets account off. The next row added does not
    /// start her workflow: it is held as needing an account, nothing runs,
    /// and both the hold and the refused start are recorded.
    #[test]
    fn an_account_switched_off_holds_the_workflow_at_its_next_event() {
        let mut watch = Watch::published();
        watch
            .account
            .disable(&managing(&watch.publisher.clone()))
            .unwrap();

        let answer = watch
            .delivered(watch.subscription_id, SIGNING, "delivery-1")
            .unwrap();

        let kept = block_on(
            watch
                .workflows
                .find_published(&test_ctx().tenant(), watch.workflow.id()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            answer,
            ServiceEventAnswer::Taken(vec![TriggeredStart::Refused(StartRefusal::NeedsAccount)])
        );
        assert!(matches!(kept.hold(), Hold::NeedsAccount(_)));
        assert!(watch.executions.all().is_empty());
        assert_eq!(
            *watch.sink.records.lock().unwrap(),
            ["workflows.version_held", "workflows.start_refused"]
        );
    }
}
