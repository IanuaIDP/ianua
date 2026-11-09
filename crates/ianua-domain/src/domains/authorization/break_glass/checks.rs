//! What a new break-glass grant must pass before it is made: its window,
//! what it names, its tenant's policy, and who approves it.

use time::OffsetDateTime;

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::break_glass::{
    BreakGlassPolicy, GrantApproval, MAX_BREAK_GLASS_LENGTH, NewBreakGlass, RequestedApproval,
};
use crate::domains::authorization::granter::HeldByGranter;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::Human;

/// Refuses a grant whose window, access or policy can never stand: a window
/// over before it starts or too long, an access naming nothing or a
/// permission twice, or another tenant's policy.
pub(super) fn ensure_grantable<T: TenantScope>(
    grant: &NewBreakGlass<'_, T>,
    policy: &BreakGlassPolicy,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    ensure_window(now, grant.expires_at)?;
    if !grant.access.is_well_formed() {
        return Err(DomainError::invalid(message!(
            "authorization-a-break-glass-grant-must-name",
            "a break-glass grant must name what it grants, each permission once"
        )));
    }
    if policy.tenant_id != grant.tenant_id {
        return Err(DomainError::forbidden(message!(
            "authorization-the-break-glass-policy-is-another",
            "the break-glass policy is another tenant's"
        )));
    }
    Ok(())
}

/// Refuses a window that is over before it starts, or longer than any
/// grant may last.
fn ensure_window(now: OffsetDateTime, expires_at: OffsetDateTime) -> Result<(), DomainError> {
    if expires_at <= now {
        return Err(DomainError::invalid(message!(
            "authorization-a-break-glass-grant-must-end",
            "a break-glass grant must end in the future"
        )));
    }
    if expires_at > now.saturating_add(MAX_BREAK_GLASS_LENGTH) {
        return Err(DomainError::invalid(message!(
            "authorization-a-break-glass-grant-may-last",
            "a break-glass grant may last at most a day"
        )));
    }
    Ok(())
}

/// The approval as it is recorded, and the most it lets the grant give.
///
/// An approver who is the grantee, through any of their accounts, is a
/// self-approval and gets `policy`'s ceiling. A self-approval asked for by
/// anyone but the grantee is refused.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when the person approving was worked out
///   in another tenant than the grant's.
/// - [`DomainError::Forbidden`] when someone other than the grantee asks
///   for a self-approval.
pub(super) fn settled_approval<'p, T: TenantScope>(
    grant: &NewBreakGlass<'p, T>,
    grantee: &Human,
    policy: &'p BreakGlassPolicy,
) -> Result<(GrantApproval, HeldByGranter<'p>), DomainError> {
    match grant.approval {
        RequestedApproval::By(approver) if !approver.who().is_same_person_as(grantee) => {
            approver.ensure_within(&grant.tenant_id)?;
            Ok((
                GrantApproval::ApprovedBy(approver.who().clone()),
                approver.standing(),
            ))
        }
        RequestedApproval::By(approver) | RequestedApproval::SelfApproved(approver) => {
            approver.ensure_within(&grant.tenant_id)?;
            ensure_asked_by_the_grantee(approver, grantee)?;
            Ok((GrantApproval::SelfApproved, policy.ceiling()))
        }
    }
}

/// Refuses a self-approval asked for by someone other than the grantee.
fn ensure_asked_by_the_grantee(
    requester: &TenantAuthority,
    grantee: &Human,
) -> Result<(), DomainError> {
    if requester.who().is_same_person_as(grantee) {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "authorization-only-the-user-approves-their-own",
        "only the user approves their own emergency access"
    )))
}
