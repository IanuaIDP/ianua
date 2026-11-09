//! An account's channel while a version is published: found, or opened
//! once for the account, and registered at its service when that is what
//! the service takes. Every workflow on the account then shares it.
//!
//! Each step is kept in a unit of its own, so what the service was told
//! stays known even when the publish that asked fails after it.

use ianua_domain::domains::workflows::account::IntegrationAccount;
use ianua_domain::domains::workflows::triggers::channel::{
    AccountChannel, ChannelSetup, OpenChannel,
};
use ianua_domain::domains::workflows::triggers::subscription::{Lapse, RemoteRegistration};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{AccountChannelId, ActorRef};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{SealOwner, SealedAt, SealedField, SealedFor};
use crate::ports::workflows::{
    Registered, RegistrationFailure, RegistrationKeys, RouteKey, Routing,
};
use crate::services::kept_together::kept_apart;
use crate::services::registrations::{
    RegistrationPorts, current_credential, keep_renewal, registration_refused,
};
use crate::services::sealing::sealed_text;
use crate::tenancy::ScopedTenant;

/// How many random bytes a channel's own secret holds.
const SECRET_BYTES: usize = 32;

/// What a registration sharing `account`'s channel is taken as, the channel
/// found or opened, and registered at its service if it needs to be. One
/// set up by hand is not asked for yet: the workflow is published, and
/// nothing starts it until the channel's owner has finished.
///
/// # Errors
///
/// - `AppError::Domain` when the service refused the channel.
/// - `AppError::Upstream` when the service could not be reached.
/// - `AppError::Internal` on storage or sealing failure.
pub(crate) async fn channel_registered(
    ports: &RegistrationPorts,
    auditor: &RequestAuditor,
    tenant: &ScopedTenant,
    account: &mut IntegrationAccount<ResolvedTenant>,
    setup: ChannelSetup,
) -> Result<Registered, AppError> {
    let mut channel = channel_of(ports, tenant, account, setup).await?;
    if channel.needs_registering() {
        register_channel(ports, auditor, tenant, account, &mut channel).await?;
    }
    note_workflow_added(ports, tenant, &mut channel).await?;
    let id = channel.id().as_uuid().to_string();
    Ok(Registered {
        remote: RemoteRegistration::new(id)
            .map_err(|refused| AppError::from_domain(refused.into()))?,
        lapses: Lapse::Never,
        routing: Routing::Keyed(RouteKey::of_channel(channel.id())),
        given_secret: None,
    })
}

/// Marks `channel` as just used, in a unit of its own, so the idle sweep
/// leaves it alone until the publish has saved its registration.
///
/// # Errors
///
/// `AppError::Internal` when it cannot be kept.
async fn note_workflow_added(
    ports: &RegistrationPorts,
    tenant: &ScopedTenant,
    channel: &mut AccountChannel<ResolvedTenant>,
) -> Result<(), AppError> {
    channel.note_workflow_added();
    let kept = async { ports.channels.save(tenant, channel).await.or_internal() };
    kept_apart(ports.unit_of_work.as_ref(), kept).await
}

/// `account`'s channel, opened if it has none. Two publishes at once open
/// one: the second reads the first's.
///
/// # Errors
///
/// `AppError::Internal` on storage or sealing failure.
async fn channel_of(
    ports: &RegistrationPorts,
    tenant: &ScopedTenant,
    account: &IntegrationAccount<ResolvedTenant>,
    setup: ChannelSetup,
) -> Result<AccountChannel<ResolvedTenant>, AppError> {
    let kept = ports
        .channels
        .of_account(tenant, account.id())
        .await
        .or_internal()?;
    if let Some(kept) = kept {
        return Ok(kept);
    }
    let channel = opened_channel(ports, tenant, account, setup).await?;
    let inserted = async {
        ports
            .channels
            .insert_if_absent(tenant, &channel)
            .await
            .or_internal()
    };
    if kept_apart(ports.unit_of_work.as_ref(), inserted).await? {
        return Ok(channel);
    }
    ports
        .channels
        .of_account(tenant, account.id())
        .await
        .or_internal()?
        .ok_or_else(|| DomainError::infra_msg("an account's channel went as it was opened"))
        .or_internal()
}

/// A new channel for `account`, with a fresh secret sealed for it.
///
/// # Errors
///
/// `AppError::Internal` when the secret cannot be sealed.
async fn opened_channel(
    ports: &RegistrationPorts,
    tenant: &ScopedTenant,
    account: &IntegrationAccount<ResolvedTenant>,
    setup: ChannelSetup,
) -> Result<AccountChannel<ResolvedTenant>, AppError> {
    let id = AccountChannelId::new();
    let secret = ports.tokens.generate(SECRET_BYTES);
    let sealed = sealed_text(
        ports.encryptor.as_ref(),
        secret.expose(),
        &channel_secret_place(tenant, &id),
    )
    .await?;
    AccountChannel::open(OpenChannel {
        id,
        account: *account.id(),
        integration: account.integration().clone(),
        secret: sealed,
        setup,
    })
    .map_err(AppError::from_domain)
}

/// Registers `channel` at its service and keeps what it answered with its
/// record, by the platform.
///
/// # Errors
///
/// - `AppError::Domain` when the service refused it.
/// - `AppError::Upstream` when the service could not be reached; the
///   channel stays waiting, and the next publish asks again.
/// - `AppError::Internal` when it cannot be kept.
async fn register_channel(
    ports: &RegistrationPorts,
    auditor: &RequestAuditor,
    tenant: &ScopedTenant,
    account: &mut IntegrationAccount<ResolvedTenant>,
    channel: &mut AccountChannel<ResolvedTenant>,
) -> Result<(), AppError> {
    let keys = channel_keys(ports, auditor, tenant, account, channel)
        .await
        .map_err(registration_refused)?;
    let answer = ports.registrar.open_channel(tenant, channel, &keys).await;
    keep_renewal(ports, auditor, tenant, account, answer.renewal).await?;
    let taken = answer.result.map_err(registration_refused)?;
    channel
        .register(taken.remote, taken.lapses, taken.history)
        .map_err(AppError::from_domain)?;
    let kept = async {
        ports.channels.save(tenant, channel).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::System, channel.take_events(tenant))
            .await
            .or_internal()
    };
    kept_apart(ports.unit_of_work.as_ref(), kept).await
}

/// What `channel` is called about with through `account`: the account's
/// credential as it stands now and the channel's secret, each beside where
/// it is kept.
///
/// # Errors
///
/// The [`RegistrationFailure`] of a credential that could not be made
/// current; nothing was sent.
pub(crate) async fn channel_keys(
    ports: &RegistrationPorts,
    auditor: &RequestAuditor,
    tenant: &ScopedTenant,
    account: &IntegrationAccount<ResolvedTenant>,
    channel: &AccountChannel<ResolvedTenant>,
) -> Result<RegistrationKeys, RegistrationFailure> {
    Ok(RegistrationKeys {
        credential: current_credential(ports, auditor, tenant, account).await?,
        secret: SealedAt {
            secret: channel.secret().clone(),
            place: channel_secret_place(tenant, channel.id()),
        },
    })
}

/// Where `tenant`'s channel `id` keeps its secret.
pub(crate) fn channel_secret_place(tenant: &ScopedTenant, id: &AccountChannelId) -> SealedFor {
    SealedFor::new(
        SealOwner::from(tenant),
        SealedField::AccountChannelSecret,
        id,
    )
}
