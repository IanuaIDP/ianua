//! Whose account a request is about: the signed-in person's own, or someone
//! else's that the caller acts on, and when the caller may read it.

use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
use ianua_domain::types::UserId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;

/// Whose account a privacy request is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Whose {
    /// The person signed in to the caller's session, for their own account.
    Own,
    /// Another user of the tenant, whom the caller acts for.
    OnBehalfOf(UserId),
}

/// The account `whose` names, once `ctx`'s caller may read what it holds:
/// their own always, another user's only with the right to view users.
///
/// # Errors
///
/// - `AppError::Unauthenticated` when the caller's session or key no longer
///   counts, or a person asking for their own came with no session.
/// - `AppError::Forbidden` when the caller asks for another user's without
///   the right to view users.
pub(crate) async fn readable_account(
    authorities: &dyn TenantAuthorities,
    ctx: &CallerContext,
    whose: Whose,
) -> Result<UserId, AppError> {
    let Whose::OnBehalfOf(user_id) = whose else {
        let person = authorities.signed_in(ctx).await?;
        return Ok(*person.account.id());
    };
    authorities
        .authority(ctx)
        .await?
        .ensure_holds(SystemPermission::Users(UserAction::View))
        .map_err(AppError::from_domain)?;
    Ok(user_id)
}
