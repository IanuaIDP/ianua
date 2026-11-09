//! How authorization events name who acted and what they acted on: the
//! actor the record is attributed to, and the labels for a user or a
//! member, each falling back to the id when its row is gone.

use ianua_domain::types::{EventLabel, PrincipalRef, UserId};

use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::shared::{AuditLabelResolver, ControlPlaneLabelResolver};
use crate::tenancy::ScopedTenant;

/// The user's audit label, or their id when the user row is gone.
///
/// # Errors
///
/// Returns `AppError::Internal` if the label cannot be read.
pub(super) async fn user_label(
    resolver: &dyn AuditLabelResolver,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<EventLabel, AppError> {
    Ok(resolver
        .user(tenant, user_id)
        .await
        .or_internal()?
        .unwrap_or_else(|| EventLabel::of(&user_id.to_string())))
}

/// What `principal` is called in `tenant`, read outside any request, or
/// their id: a user, an agent or a consumer by name, and an organization
/// member, whose name lives with the organization, by id.
///
/// # Errors
///
/// Returns `AppError::Internal` if the label cannot be read.
pub(super) async fn tenant_principal_label(
    resolver: &dyn AuditLabelResolver,
    tenant: &ScopedTenant,
    principal: &PrincipalRef,
) -> Result<EventLabel, AppError> {
    let name = match principal {
        PrincipalRef::User(id) => resolver.user(tenant, id).await,
        PrincipalRef::Agent(id) => resolver.agent(tenant, id).await,
        PrincipalRef::Consumer(id) => resolver.consumer(tenant, id).await,
        PrincipalRef::OrgUser(_) => Ok(None),
    };
    Ok(name
        .or_internal()?
        .unwrap_or_else(|| EventLabel::of(&principal.id().to_string())))
}

/// The member's audit label, or their id when the row is gone.
///
/// # Errors
///
/// Returns `AppError::Internal` if the label cannot be read.
pub(super) async fn principal_label(
    resolver: &dyn AuditLabelResolver,
    control_plane: &dyn ControlPlaneLabelResolver,
    ctx: &CallerContext,
    member: &PrincipalRef,
) -> Result<EventLabel, AppError> {
    Ok(principal_name(resolver, control_plane, ctx, member)
        .await?
        .unwrap_or_else(|| EventLabel::of(&member.id().to_string())))
}

/// What the member is called in `ctx`'s tenant, or `None` when the row is
/// gone: a user or an organization member by name and address, an agent or
/// a consumer by its name.
///
/// # Errors
///
/// Returns `AppError::Internal` if the name cannot be read.
pub(super) async fn principal_name(
    resolver: &dyn AuditLabelResolver,
    control_plane: &dyn ControlPlaneLabelResolver,
    ctx: &CallerContext,
    member: &PrincipalRef,
) -> Result<Option<EventLabel>, AppError> {
    let tenant = ctx.tenant();
    let name = match member {
        PrincipalRef::User(id) => resolver.user(&tenant, id).await,
        PrincipalRef::OrgUser(id) => control_plane.org_user(&ctx.organization_id(), id).await,
        PrincipalRef::Agent(id) => resolver.agent(&tenant, id).await,
        PrincipalRef::Consumer(id) => resolver.consumer(&tenant, id).await,
    };
    name.or_internal()
}
