//! Registering a version that starts on a service's event at the service,
//! and removing the registrations of a version leaving service, for
//! publishing, archiving and the renewal sweep.
//!
//! A registration is kept as waiting, on its own, before its service is
//! called, since a service may check the address or hand over a secret
//! while that call is still open. The call is made while the version is
//! published, so a service that refuses it refuses the publish and the
//! person sees why, and the waiting row goes with it; a sweep gives up on
//! one whose publish never came back. A registration removed as its version
//! leaves service is marked removed with the version, and taken off the
//! service afterwards; a service that cannot be reached then keeps
//! sending, and every event it sends is refused, since the registration is
//! no longer live.

use std::sync::Arc;

use ianua_domain::domains::workflows::account::IntegrationAccount;
use ianua_domain::domains::workflows::design::workflow::Workflow;
use ianua_domain::domains::workflows::execution::ActingAuthority;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::triggers::Trigger;
use ianua_domain::domains::workflows::triggers::subscription::{
    ServiceSubscription, SubscriptionStatus,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{ActorRef, IntegrationAccountId, SealedSecret, ServiceSubscriptionId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{SealOwner, SealedAt, SealedField, SealedFor, SecretEncryptor};
use crate::ports::crypto::SecureTokenGenerator;
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{
    AccountChannelStore, IntegrationAccountStore, Registered, RegistrationFailure,
    RegistrationKeys, Renewal, Routing, ServiceChannelSetup, ServiceRegistrar,
    ServiceSubscriptionStore,
};
use crate::services::account_channels::channel_registered;
use crate::services::account_grants::{AccountGrants, GrantHolder};
use crate::services::account_now::AccountsNow;
use crate::services::holds;
use crate::services::kept_together::{kept_apart, kept_together};
use crate::services::sealing::sealed_text;
use crate::tenancy::ScopedTenant;
use crate::use_cases::workflows::accounts::connect::integration_credential_place;

/// How many random bytes a registration's secret holds.
const SECRET_BYTES: usize = 32;

/// The ports registering versions at services reads and writes through.
#[derive(ianua_macros::Fakes)]
pub struct RegistrationPorts {
    /// The accounts triggers register through.
    pub accounts: Arc<dyn IntegrationAccountStore>,
    /// What an account's owner holds now, for whether they may lend it.
    pub accounts_now: Arc<AccountsNow>,
    /// Keeps the registrations.
    pub subscriptions: Arc<dyn ServiceSubscriptionStore>,
    /// Keeps the channels of services with one address per account.
    pub channels: Arc<dyn AccountChannelStore>,
    /// Makes and removes registrations at the services.
    pub registrar: Arc<dyn ServiceRegistrar>,
    /// How each service's channels work.
    pub channel_setup: Arc<dyn ServiceChannelSetup>,
    /// Keeps the account's short-lived token good just before each call.
    pub grants: Arc<AccountGrants>,
    /// Seals each registration's secret.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Makes each registration's secret.
    pub tokens: Arc<dyn SecureTokenGenerator>,
    /// Keeps an account's renewed credential and its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// `account`'s credential, or what was just exchanged for it if its token
/// was near its end.
///
/// # Errors
///
/// [`RegistrationFailure::Unreachable`] when the exchange could not be
/// made now, and [`RegistrationFailure::Refused`] when the service refused
/// the grant; nothing was sent either way.
pub(crate) async fn current_credential(
    ports: &RegistrationPorts,
    auditor: &RequestAuditor,
    tenant: &ScopedTenant,
    account: &IntegrationAccount<ResolvedTenant>,
) -> Result<SealedAt, RegistrationFailure> {
    let read = SealedAt {
        secret: account.credential().clone(),
        place: integration_credential_place(tenant, account.id()),
    };
    let holder = GrantHolder {
        id: account.id(),
        integration: account.integration(),
        credential: &read,
    };
    ports
        .grants
        .current(tenant, auditor, holder)
        .await
        .map_err(|unsent| match unsent {
            ActionOutcome::Failed(why) => RegistrationFailure::Refused(why.as_str().to_owned()),
            ActionOutcome::TurnedAway(_)
            | ActionOutcome::Succeeded { .. }
            | ActionOutcome::NotYet { .. } => RegistrationFailure::Unreachable,
        })
}

/// Keeps the credential a service renewed during a call about a
/// registration on `account`, with its record, by the platform, in a unit
/// of its own: the old credential may no longer work, whatever the call
/// came to or whatever is kept after it.
///
/// # Errors
///
/// `AppError::Internal` when it cannot be kept.
pub(crate) async fn keep_renewal(
    ports: &RegistrationPorts,
    auditor: &RequestAuditor,
    tenant: &ScopedTenant,
    account: &mut IntegrationAccount<ResolvedTenant>,
    renewal: Renewal,
) -> Result<(), AppError> {
    let Renewal::Renewed(renewed) = renewal else {
        return Ok(());
    };
    account.renew_credential(renewed);
    let kept = async {
        ports.accounts.save(tenant, account).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::System, account.take_events(tenant))
            .await
            .or_internal()
    };
    kept_together(ports.unit_of_work.as_ref(), kept).await
}

/// A registration made at its service, waiting to be kept, and how the
/// service's events reach the platform.
pub(crate) struct Made {
    /// The registration, live.
    pub(crate) subscription: ServiceSubscription<ResolvedTenant>,
    /// How its events arrive.
    pub(crate) routing: Routing,
}

/// The registration `published`, put in service for `publisher`, needs,
/// made at its service through its trigger's account. None unless it
/// starts on a service's event.
///
/// # Errors
///
/// - `AppError::Domain` when the trigger's account is gone, is not lent to
///   the publisher for this, or the service refused the registration.
/// - `AppError::Upstream` when the service could not be reached; nothing
///   is kept, and publishing again later may succeed.
/// - `AppError::Internal` on storage or sealing failure.
pub(crate) async fn registered(
    ports: &RegistrationPorts,
    auditor: &RequestAuditor,
    tenant: &ScopedTenant,
    publisher: &ActingAuthority,
    published: &Workflow<ResolvedTenant>,
) -> Result<Option<Made>, AppError> {
    let Trigger::Service(on) = published.trigger() else {
        return Ok(None);
    };
    let mut account = lent_account(ports, tenant, on.account()).await?;
    let owner = owner_now(ports, tenant, &account).await?;
    account
        .ensure_lends_events(publisher, on.integration(), &owner)
        .map_err(AppError::from_domain)?;
    let mut subscription = opened(ports, tenant, published).await?;
    keep_waiting(ports, tenant, &subscription).await?;
    let outcome = taken_at_service(ports, auditor, tenant, &mut account, &subscription).await;
    let taken = match outcome {
        Ok(taken) => taken,
        Err(failed) => {
            forget_waiting(ports, tenant, std::slice::from_ref(&subscription)).await;
            return Err(failed);
        }
    };
    keep_given_secret(ports, tenant, &subscription, taken.given_secret.as_ref()).await?;
    subscription
        .register(taken.remote, taken.lapses)
        .map_err(AppError::from_domain)?;
    Ok(Some(Made {
        subscription,
        routing: taken.routing,
    }))
}

/// Keeps `subscription` as waiting in a unit of its own, so a check its
/// service sends while the publish is still open finds it.
///
/// # Errors
///
/// `AppError::Internal` when it cannot be kept.
async fn keep_waiting(
    ports: &RegistrationPorts,
    tenant: &ScopedTenant,
    subscription: &ServiceSubscription<ResolvedTenant>,
) -> Result<(), AppError> {
    let kept = async {
        ports
            .subscriptions
            .insert(tenant, subscription, &Routing::OwnAddress)
            .await
            .or_internal()
    };
    kept_apart(ports.unit_of_work.as_ref(), kept).await
}

/// What the service answered, through `account`: the registration of its
/// own, or the channel of `account` it shares.
///
/// # Errors
///
/// - `AppError::Domain` when the service refused it.
/// - `AppError::Upstream` when the service could not be reached.
/// - `AppError::Internal` on storage or sealing failure.
async fn taken_at_service(
    ports: &RegistrationPorts,
    auditor: &RequestAuditor,
    tenant: &ScopedTenant,
    account: &mut IntegrationAccount<ResolvedTenant>,
    subscription: &ServiceSubscription<ResolvedTenant>,
) -> Result<Registered, AppError> {
    let setup = ports
        .channel_setup
        .account_setup(subscription.integration());
    if let Some(setup) = setup {
        return channel_registered(ports, auditor, tenant, account, setup).await;
    }
    let mut keys = keys_of(tenant, account, subscription);
    keys.credential = current_credential(ports, auditor, tenant, account)
        .await
        .map_err(registration_refused)?;
    let answer = ports.registrar.register(tenant, subscription, &keys).await;
    keep_renewal(ports, auditor, tenant, account, answer.renewal).await?;
    answer.result.map_err(registration_refused)
}

/// Keeps the secret the service chose and showed once in its answer, if
/// it gave one. It is kept apart from the publish: if that fails, the
/// registration at the service is still proven with what it chose.
///
/// # Errors
///
/// `AppError::Internal` when it cannot be kept.
async fn keep_given_secret(
    ports: &RegistrationPorts,
    tenant: &ScopedTenant,
    subscription: &ServiceSubscription<ResolvedTenant>,
    given: Option<&SealedSecret>,
) -> Result<(), AppError> {
    let Some(given) = given else {
        return Ok(());
    };
    let kept = async {
        ports
            .subscriptions
            .take_service_secret(tenant, subscription.id(), given)
            .await
            .or_internal()
    };
    kept_apart(ports.unit_of_work.as_ref(), kept)
        .await
        .map(|_| ())
}

/// Forgets each of `waiting`, whose publish ended without it. One that
/// cannot be forgotten now is left for the sweep.
pub(crate) async fn forget_waiting(
    ports: &RegistrationPorts,
    tenant: &ScopedTenant,
    waiting: &[ServiceSubscription<ResolvedTenant>],
) {
    for subscription in waiting {
        let forgotten = async {
            ports
                .subscriptions
                .forget_waiting(tenant, subscription.id())
                .await
                .or_internal()
        };
        if kept_apart(ports.unit_of_work.as_ref(), forgotten)
            .await
            .is_err()
        {
            tracing::warn!(
                subscription = %subscription.id(),
                "a waiting registration could not be forgotten; the sweep will"
            );
        }
    }
}

/// A new registration of `published`, with a fresh secret sealed for it,
/// not yet made at its service.
///
/// # Errors
///
/// - `AppError::Domain` when `published` starts on no service's event.
/// - `AppError::Internal` when the secret cannot be sealed.
async fn opened(
    ports: &RegistrationPorts,
    tenant: &ScopedTenant,
    published: &Workflow<ResolvedTenant>,
) -> Result<ServiceSubscription<ResolvedTenant>, AppError> {
    let id = ServiceSubscriptionId::new();
    let secret = ports.tokens.generate(SECRET_BYTES);
    let sealed = sealed_text(
        ports.encryptor.as_ref(),
        secret.expose(),
        &subscription_secret_place(tenant, &id),
    )
    .await?;
    ServiceSubscription::open(published, id, sealed).map_err(AppError::from_domain)
}

/// The registrations of the version `retiring` not yet removed, marked
/// removed, as it leaves service.
///
/// # Errors
///
/// `AppError::Internal` when they cannot be read.
pub(crate) async fn retired(
    ports: &RegistrationPorts,
    tenant: &ScopedTenant,
    retiring: &Workflow<ResolvedTenant>,
) -> Result<Vec<ServiceSubscription<ResolvedTenant>>, AppError> {
    let kept = ports
        .subscriptions
        .list_for_workflow(tenant, retiring.id())
        .await
        .or_internal()?;
    let mut removed = Vec::new();
    for mut subscription in kept {
        let settled = !matches!(
            subscription.status(),
            SubscriptionStatus::Removed | SubscriptionStatus::Registering
        );
        if subscription.version() != retiring.version() || !settled {
            continue;
        }
        subscription.remove().map_err(AppError::from_domain)?;
        removed.push(subscription);
    }
    Ok(removed)
}

/// Takes each of `removed` off its service, as far as each service lets.
/// A registration whose account is gone, or whose service cannot be
/// reached, stays at the service; its events are refused from now on. One
/// that shares its account's channel has nothing of its own there: a sweep
/// closes the channel once nothing waits on it.
pub(crate) async fn unregister(
    ports: &RegistrationPorts,
    auditor: &RequestAuditor,
    tenant: &ScopedTenant,
    removed: &[ServiceSubscription<ResolvedTenant>],
) {
    for subscription in removed {
        if ports
            .channel_setup
            .account_setup(subscription.integration())
            .is_none()
        {
            unregister_one(ports, auditor, tenant, subscription).await;
        }
    }
}

/// Removes `subscription` at its service, if its account can still reach it.
async fn unregister_one(
    ports: &RegistrationPorts,
    auditor: &RequestAuditor,
    tenant: &ScopedTenant,
    subscription: &ServiceSubscription<ResolvedTenant>,
) {
    let Ok(Some(mut account)) = ports
        .accounts
        .find_by_id(tenant, &subscription.account())
        .await
    else {
        return;
    };
    let mut keys = keys_of(tenant, &account, subscription);
    let Ok(credential) = current_credential(ports, auditor, tenant, &account).await else {
        return;
    };
    keys.credential = credential;
    let answer = ports
        .registrar
        .unregister(tenant, subscription, &keys)
        .await;
    let renewal = keep_renewal(ports, auditor, tenant, &mut account, answer.renewal).await;
    if renewal.is_err() {
        tracing::warn!(account = %account.id(), "a renewed credential could not be kept");
    }
}

/// The account a trigger names, if the tenant still keeps it.
///
/// # Errors
///
/// - `AppError::Domain` when it is gone.
/// - `AppError::Internal` when it cannot be read.
pub(crate) async fn lent_account(
    ports: &RegistrationPorts,
    tenant: &ScopedTenant,
    id: IntegrationAccountId,
) -> Result<IntegrationAccount<ResolvedTenant>, AppError> {
    let found = ports.accounts.find_by_id(tenant, &id).await.or_internal()?;
    found.ok_or_else(|| {
        AppError::Domain(DomainError::invalid(message!(
            "workflows-the-trigger-s-account-is-gone",
            "the account the trigger registers through is gone"
        )))
    })
}

/// What `account`'s owner holds now, for whether they may still lend it.
///
/// # Errors
///
/// - `AppError::Domain` when their account is gone or may not act.
/// - `AppError::Internal` when it cannot be read.
async fn owner_now(
    ports: &RegistrationPorts,
    tenant: &ScopedTenant,
    account: &IntegrationAccount<ResolvedTenant>,
) -> Result<ActingAuthority, AppError> {
    let owner = holds::owner_now(&ports.accounts_now, tenant, account).await?;
    owner.ok_or_else(|| {
        AppError::Domain(DomainError::forbidden(message!(
            "workflows-the-account-s-owner-may-no",
            "the account's owner may no longer lend it"
        )))
    })
}

/// What `subscription` is registered with through `account`: the
/// account's credential and the registration's secret, each beside where
/// it is kept.
pub(crate) fn keys_of(
    tenant: &ScopedTenant,
    account: &IntegrationAccount<ResolvedTenant>,
    subscription: &ServiceSubscription<ResolvedTenant>,
) -> RegistrationKeys {
    RegistrationKeys {
        credential: SealedAt {
            secret: account.credential().clone(),
            place: integration_credential_place(tenant, account.id()),
        },
        secret: SealedAt {
            secret: subscription.secret().clone(),
            place: subscription_secret_place(tenant, subscription.id()),
        },
    }
}

/// Where `tenant`'s registration `id` keeps its secret.
pub(crate) fn subscription_secret_place(
    tenant: &ScopedTenant,
    id: &ServiceSubscriptionId,
) -> SealedFor {
    SealedFor::new(SealOwner::from(tenant), SealedField::SubscriptionSecret, id)
}

/// The error a person sees when a service would not take a registration.
pub(crate) fn registration_refused(failure: RegistrationFailure) -> AppError {
    match failure {
        RegistrationFailure::Refused(why) => AppError::Domain(DomainError::invalid(message!(
            "workflows-the-service-refused-the-registration",
            format!("the service refused to send the workflow its events: {why}")
        ))),
        RegistrationFailure::Unreachable => AppError::Upstream(Box::new(DomainError::infra_msg(
            "the service could not be reached to send the workflow its events",
        ))),
    }
}
