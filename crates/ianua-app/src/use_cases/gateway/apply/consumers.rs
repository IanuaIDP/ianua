//! Writing the consumers a document declares, held to the same checks as
//! creating and editing one by hand.
//!
//! A document never makes a credential secret. A new consumer is made from
//! one it can state whole, a certificate fingerprint or a JWT issuer; an API
//! key is made through the consumer's own creation, where it is shown once.
//! A consumer's credential changes by rotation only, never by import.

use ianua_domain::domains::consumers::consumer::{Consumer, ConsumerStatus, CreateConsumerParams};
use ianua_domain::domains::consumers::control::ConsumerControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Issuer, Label};

use crate::error::{AppError, OrInternal};
use crate::ports::limits::ResourceKind;
use crate::use_cases::gateway::apply::state::{Apply, declared, ensure_within_limit, invalid};
use crate::use_cases::gateway::document::{ConsumerCredentialDeclaration, ConsumerDeclaration};

/// Writes the consumer the document declares under `name`.
///
/// # Errors
///
/// - `AppError::Forbidden` when the caller may not create or change
///   consumers, clears one for more than they may see, its credential
///   trusts the tenant's own issuer, or a new one would exceed the plan.
/// - `AppError::Domain` when a new consumer signs in with an API key, or a
///   consumer that exists is given another credential.
/// - `AppError::NotFound` when the tenant is not on record.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn write_consumer(apply: &mut Apply<'_>, name: &Label) -> Result<(), AppError> {
    let desired = apply.desired;
    let want = declared(&desired.consumers, name, |c| &c.name)?;
    let control = apply.applier.consumers;
    let consumer = match apply.consumers.remove(name) {
        None => {
            ensure_within_limit(apply.applier, ResourceKind::Consumers).await?;
            let issuers = &apply.applier.ports.checks.issuers;
            let issuer = issuers.of(&apply.applier.caller.tenant_id()).await?;
            created(want, &issuer, &control)?
        }
        Some(consumer) => {
            ensure_same_credential(&consumer, want)?;
            updated(consumer, want, &control).map_err(AppError::from_domain)?
        }
    };
    let store = apply.applier.ports.records.consumer_store.as_ref();
    store.save(&apply.tenant(), &consumer).await.or_internal()?;
    apply.consumers.insert(name.clone(), consumer);
    Ok(())
}

/// Removes the consumer `name`, if it still exists.
///
/// # Errors
///
/// - `AppError::Forbidden` when the caller may not delete consumers.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn delete_consumer(apply: &mut Apply<'_>, name: &Label) -> Result<(), AppError> {
    let Some(mut consumer) = apply.consumers.remove(name) else {
        return Ok(());
    };
    consumer
        .delete(&apply.applier.consumers)
        .map_err(AppError::from_domain)?;
    apply
        .applier
        .ports
        .records
        .consumer_store
        .delete(&apply.tenant(), consumer.id())
        .await
        .or_internal()
}

/// A new consumer as `want` declares it, in a tenant whose own issuer is
/// `tenant_issuer`.
fn created(
    want: &ConsumerDeclaration,
    tenant_issuer: &Issuer,
    control: &ConsumerControl<'_>,
) -> Result<Consumer<ResolvedTenant>, AppError> {
    let Some(credential) = want.credential.to_kind() else {
        return Err(invalid(format!(
            "consumer '{}' signs in with an API key, which is made and shown once when the \
             consumer is created by hand, never by a document",
            want.name
        )));
    };
    let mut consumer = Consumer::create(
        CreateConsumerParams {
            name: want.name.clone(),
            description: None,
            credential,
            credential_expiry: want.credential_expiry,
            quota: want.quota,
            clearance: want.clearance,
        },
        tenant_issuer,
        control,
    )
    .map_err(AppError::from_domain)?;
    settle_consumer_status(&mut consumer, want.status, control).map_err(AppError::from_domain)?;
    Ok(consumer)
}

/// Refuses another credential for a consumer that exists: it changes by
/// rotation, which keeps the old one working for the overlap and shows a
/// new key once.
fn ensure_same_credential(
    consumer: &Consumer<ResolvedTenant>,
    want: &ConsumerDeclaration,
) -> Result<(), AppError> {
    let held = ConsumerCredentialDeclaration::of(consumer.credentials().current().kind());
    if held == want.credential {
        return Ok(());
    }
    Err(invalid(format!(
        "consumer '{}' signs in with another credential; rotate it through the consumer, not \
         the document",
        want.name
    )))
}

/// `consumer` changed to what `want` declares.
fn updated(
    mut consumer: Consumer<ResolvedTenant>,
    want: &ConsumerDeclaration,
    control: &ConsumerControl<'_>,
) -> Result<Consumer<ResolvedTenant>, DomainError> {
    if consumer.credentials().current().expiry() != want.credential_expiry {
        consumer.change_credential_expiry(want.credential_expiry, control)?;
    }
    if consumer.quota() != want.quota {
        consumer.change_quota(want.quota, control)?;
    }
    if consumer.clearance() != want.clearance {
        consumer.change_clearance(want.clearance, control)?;
    }
    settle_consumer_status(&mut consumer, want.status, control)?;
    Ok(consumer)
}

/// Moves `consumer` to `status`, where it is not there already.
fn settle_consumer_status(
    consumer: &mut Consumer<ResolvedTenant>,
    status: ConsumerStatus,
    control: &ConsumerControl<'_>,
) -> Result<(), DomainError> {
    match (consumer.status(), status) {
        (ConsumerStatus::Active, ConsumerStatus::Active)
        | (ConsumerStatus::Disabled, ConsumerStatus::Disabled) => Ok(()),
        (ConsumerStatus::Disabled, ConsumerStatus::Active) => consumer.enable(control),
        (ConsumerStatus::Active, ConsumerStatus::Disabled) => consumer.disable(control),
    }
}
