//! Putting a member's erasure under a legal hold and lifting it again. Both
//! need what removing the member needs.

use ianua_domain::domains::organization::members::account_control::OrgAccountControl;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::ErasureRequestId;

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgErasureRequestStore, OrgUserStore};
use crate::use_cases::organization::lookup::existing_member;
use crate::use_cases::organization::privacy::lookup::existing_org_erasure;

/// What a legal hold use case does to an erasure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::use_cases::organization::privacy) enum Ruling {
    /// Pause a pending erasure until the hold is lifted.
    Hold,
    /// Lift the hold, so the erasure waits again.
    Release,
}

/// Where a legal hold reads and writes.
#[derive(Clone, Copy)]
pub(in crate::use_cases::organization::privacy) struct HoldSources<'a> {
    /// Who acts on an organization.
    pub(in crate::use_cases::organization::privacy) actors: &'a dyn OrgActors,
    /// Members' erasure requests.
    pub(in crate::use_cases::organization::privacy) erasures: &'a dyn OrgErasureRequestStore,
    /// The organization's members.
    pub(in crate::use_cases::organization::privacy) members: &'a dyn OrgUserStore,
}

/// Applies `ruling` to the erasure `request_id` of the caller's
/// organization, saves it, and returns what the request raised.
///
/// # Errors
///
/// - `AppError::Unauthenticated` when the caller's session or key no
///   longer counts.
/// - `AppError::NotFound` if the organization has no such request or
///   member.
/// - `AppError::Forbidden` when the caller may not remove the member.
/// - `AppError::Domain` when the request is not pending, for a hold, or
///   not held, for a release.
/// - `AppError::Internal` on persistence failure.
pub(in crate::use_cases::organization::privacy) async fn rule_on(
    sources: HoldSources<'_>,
    caller: &OrgCaller,
    request_id: ErasureRequestId,
    ruling: Ruling,
) -> Result<Vec<DomainEvent>, AppError> {
    let (organization, actor) = sources.actors.actor(caller).await?;
    let control = actor.control()?;
    let organization_id = organization.id();
    let mut request = existing_org_erasure(sources.erasures, organization_id, &request_id).await?;
    let target = existing_member(sources.members, organization_id, request.org_user_id()).await?;
    let on_them = OrgAccountControl::new(control, &target);
    let ruled = match ruling {
        Ruling::Hold => request.hold(&on_them),
        Ruling::Release => request.release(&on_them),
    };
    ruled.map_err(AppError::from_domain)?;
    sources.erasures.save(&request).await.or_internal()?;
    Ok(request.take_events())
}
