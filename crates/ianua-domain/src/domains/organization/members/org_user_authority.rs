//! Who may bring someone into an organization, and who may act on a member.
//!
//! An owner reaches every tenant. So the rules here keep anyone but an
//! owner from making an owner, or from taking over one by changing how they
//! sign in. Beyond that, each action needs its own member right, which a
//! plain member does not hold.

use crate::domains::organization::lifecycle::Founding;
use crate::domains::organization::members::control::OrgControl;
use crate::domains::organization::members::membership::OrgRole;
use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::organization::members::permission::{MemberAction, OrgPermission};
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::OrganizationId;

/// Who brings a new member into an organization. This decides whether they
/// may be made an owner. An owner reaches every tenant, so only the founder,
/// or an owner already there, makes one.
#[derive(Debug)]
pub enum AddedBy<'a> {
    /// The person founding the organization, who becomes its first owner,
    /// with the founding its creation gave.
    Founding(Founding),
    /// A member of the organization already there, with what they act
    /// through.
    Member(OrgControl<'a>),
}

/// Refuses `role` for someone joining `organization_id` through `added_by`
/// by `way`, unless the rule for it holds. A founder is always the first
/// owner, of the organization just founded. Anyone else is brought in by a
/// member holding the right for `way`, and only an owner brings in an owner.
pub(super) fn ensure_may_bring_in(
    role: OrgRole,
    organization_id: &OrganizationId,
    added_by: AddedBy<'_>,
    way: MemberAction,
) -> Result<(), DomainError> {
    match (added_by, role) {
        (AddedBy::Founding(founding), OrgRole::Owner) => ensure_founds(&founding, organization_id),
        (
            AddedBy::Founding(_),
            OrgRole::Admin | OrgRole::Member | OrgRole::Billing | OrgRole::Viewer,
        ) => Err(DomainError::invalid(message!(
            "organization-the-founder-of-an-organization-is",
            "the founder of an organization is its first owner"
        ))),
        (AddedBy::Member(by), role) => {
            by.ensure_may(organization_id, OrgPermission::Members(way))?;
            ensure_may_hand_out(role, by.by())
        }
    }
}

/// Refuses `founding` for any organization but the one it was made for.
fn ensure_founds(founding: &Founding, organization_id: &OrganizationId) -> Result<(), DomainError> {
    if founding.organization_id() != organization_id {
        return Err(DomainError::forbidden(message!(
            "organization-a-founding-makes-the-first-owner",
            "a founding makes the first owner of its own organization only"
        )));
    }
    Ok(())
}

/// Refuses `by` acting on `target` with `action`: its status, password,
/// address, role or membership. The member acting needs the member right
/// for it, and only an owner acts on an owner.
///
/// Whoever controls how an account signs in can become it. Sam is a member.
/// Without this check, Sam resets the password of Ann, an owner, signs in as
/// her and reaches every tenant.
pub(super) fn ensure_may_act_on(
    target: &OrgUser,
    by: &OrgControl<'_>,
    action: MemberAction,
) -> Result<(), DomainError> {
    by.ensure_may(target.organization_id(), OrgPermission::Members(action))?;
    ensure_may_hand_out(target.role(), by.by())
}

/// Refuses `by` taking over how `target` signs in, its password or its
/// address, as [`ensure_may_act_on`] does, and refuses it outright on the
/// member's own account.
///
/// A control is only a session or a key, which proves nothing about the
/// person. Mallory steals Ann's session. Without this, she sets Ann's
/// password without the current one, or moves Ann's address to her own
/// mailbox without a fresh sign-in, and keeps the account. Ann changes her
/// own through `change_own_password`, `reset_password` or the email-change
/// flow, which prove her.
pub(super) fn ensure_may_take_over(
    target: &OrgUser,
    by: &OrgControl<'_>,
) -> Result<(), DomainError> {
    if by.is_member(target.id()) {
        return Err(DomainError::forbidden(message!(
            "organization-a-member-s-own-password-or",
            "a member's own password or address changes only through steps that prove them"
        )));
    }
    ensure_may_act_on(target, by, MemberAction::Update)
}

/// Refuses `by` changing what `target`'s profile shows: their name,
/// language or timezone. A member changes their own through what they act
/// with. Anyone else needs the right to update members, and only an owner
/// edits an owner.
///
/// Sam is a plain member. Without this, he renames Ann, an owner, to
/// "Former employee", and the people she writes to stop trusting her.
pub(super) fn ensure_may_edit_profile(
    target: &OrgUser,
    by: &OrgControl<'_>,
) -> Result<(), DomainError> {
    if by.is_member(target.id()) {
        return by.ensure_genuine(target.organization_id());
    }
    ensure_may_act_on(target, by, MemberAction::Update)
}

/// Refuses `by` giving, taking or touching `role` unless `by`'s role may
/// hand it out, as [`OrgRole::may_hand_out`] says. Membership and activity
/// are checked by the control first.
pub(super) fn ensure_may_hand_out(role: OrgRole, by: &OrgUser) -> Result<(), DomainError> {
    if !by.role().may_hand_out(role) {
        return Err(DomainError::forbidden(message!(
            "organization-a-of-the-organization-does-not",
            format!(
                "a {} of the organization does not make, unmake or act on a {role}",
                by.role()
            )
        )));
    }
    Ok(())
}
