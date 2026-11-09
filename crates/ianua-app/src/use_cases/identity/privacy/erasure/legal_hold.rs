//! Putting an erasure under a legal hold and lifting it again. Both need
//! what erasing the person needs, read from the tenant's records now.

use ianua_domain::domains::authorization::granter::right_for;
use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ErasureRequestId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::ErasureRequestStore;
use crate::use_cases::identity::account_control::account_control;
use crate::use_cases::identity::lookup::existing_erasure_request;

/// What a legal hold use case does to an erasure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::use_cases::identity) enum Ruling {
    /// Pause a pending erasure until the hold is lifted.
    Hold,
    /// Lift the hold, so the erasure waits again.
    Release,
}

/// Where a legal hold reads and writes.
#[derive(Clone, Copy)]
pub(in crate::use_cases::identity) struct HoldSources<'a> {
    /// Keeps erasure requests.
    pub(in crate::use_cases::identity) erasures: &'a dyn ErasureRequestStore,
    /// The tenant's records of who holds what.
    pub(in crate::use_cases::identity) access_records: &'a dyn AccessRecordStore,
    /// What the caller holds in their tenant.
    pub(in crate::use_cases::identity) authorities: &'a dyn TenantAuthorities,
}

/// Applies `ruling` to the erasure `request_id` of the caller's tenant,
/// saves it, and returns what the request raised.
///
/// # Errors
///
/// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without erasure rights, before reading the request.
/// - `AppError::NotFound` for a missing request; `Forbidden` when the person holds more rights.
/// - `AppError::Domain` when holding a nonpending request or releasing one not held; `Internal` on persistence failure.
pub(in crate::use_cases::identity) async fn rule_on(
    sources: HoldSources<'_>,
    ctx: &CallerContext,
    request_id: ErasureRequestId,
    ruling: Ruling,
) -> Result<Vec<DomainEvent>, AppError> {
    let tenant = ctx.tenant();
    let authority = sources.authorities.authority(ctx).await?;
    authority
        .ensure_holds(right_for(AccountAction::Erase))
        .map_err(AppError::from_domain)?;
    let mut request = existing_erasure_request(sources.erasures, &tenant, &request_id).await?;
    let user_id = *request.user_id();
    let records = sources.access_records;
    let erasing = AccountAction::Erase;
    let control = account_control(records, &tenant, &authority, &user_id, erasing).await?;
    let ruled = match ruling {
        Ruling::Hold => request.hold(&control),
        Ruling::Release => request.release(&control),
    };
    ruled.map_err(AppError::from_domain)?;
    sources
        .erasures
        .save(&tenant, &request)
        .await
        .or_internal()?;
    Ok(request.take_events(&tenant))
}
