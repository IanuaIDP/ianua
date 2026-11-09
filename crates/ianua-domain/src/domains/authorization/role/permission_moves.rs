//! Moving a role to hold exactly the permissions wanted, in one change.

use crate::domains::authorization::granter::HeldByGranter;
use crate::domains::authorization::permission::{
    CustomPermission, PermissionSet, SystemPermission,
};
use crate::domains::authorization::role::Role;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;

/// The permissions a role is to hold after a change, of each kind.
///
/// `None` leaves that kind as it is, which differs from an empty list: the
/// first keeps the role's permissions, the second takes them all away.
pub struct WantedPermissions<'a> {
    /// The built-in permissions it is to hold, or `None` to keep them.
    pub system: Option<&'a [SystemPermission]>,
    /// The tenant-defined permissions it is to hold, or `None` to keep them.
    pub custom: Option<&'a [CustomPermission]>,
}

/// What a change of a role's permissions moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionsMoved {
    /// Nothing: the role already held what was asked.
    Nothing,
    /// The role gained permissions and lost none.
    Widened,
    /// The role lost at least one permission, and may have gained others.
    Narrowed,
}

impl<T: TenantScope> Role<T> {
    /// Moves the role to hold exactly what `wanted` names, for `editor`.
    /// Raises one `authorization.permission_granted` per kind it gains and
    /// one `authorization.permission_revoked` per kind it loses, grants
    /// first, so a save that ticks a hundred boxes is one record, not a
    /// hundred.
    ///
    /// Both sides compare by literal membership, never by what the role may
    /// do. `Manage` and `*` cover their whole area, so narrowing `Manage` to
    /// one action would see the action as held, skip granting it, revoke
    /// `Manage` and leave the role with nothing. A change that moves nothing
    /// checks nothing and raises nothing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] in the cases [`Self::ensure_editable_by`]
    ///   lists.
    /// - [`DomainError::Forbidden`] when `editor` may not hand out a
    ///   permission it gains. The role is left as it was.
    pub fn change_permissions(
        &mut self,
        wanted: &WantedPermissions<'_>,
        editor: &HeldByGranter<'_>,
    ) -> Result<PermissionsMoved, DomainError> {
        let moves = Moves::between(self, wanted);
        if moves.is_empty() {
            return Ok(PermissionsMoved::Nothing);
        }
        self.ensure_editable_by(editor)?;
        editor.ensure_may_hand_out(&moves.grant_system, &moves.grant_custom)?;
        Ok(self.moved(moves))
    }

    /// Makes `moves` and raises what they changed.
    fn moved(&mut self, moves: Moves) -> PermissionsMoved {
        let outcome = moves.outcome();
        self.system_permissions
            .extend(moves.grant_system.iter().copied());
        self.custom_permissions
            .extend(moves.grant_custom.iter().cloned());
        let revoked_system = taken_out(&mut self.system_permissions, &moves.revoke_system);
        let revoked_custom = taken_out(&mut self.custom_permissions, &moves.revoke_custom);
        self.record_grant(PermissionSet::System(moves.grant_system));
        self.record_grant(PermissionSet::Custom(moves.grant_custom));
        self.record_revocation(PermissionSet::System(revoked_system));
        self.record_revocation(PermissionSet::Custom(revoked_custom));
        outcome
    }
}

/// The permissions to grant and to revoke, of each kind, to move a role to
/// what is wanted.
struct Moves {
    grant_system: Vec<SystemPermission>,
    revoke_system: Vec<SystemPermission>,
    grant_custom: Vec<CustomPermission>,
    revoke_custom: Vec<CustomPermission>,
}

impl Moves {
    /// What moves `role` to hold exactly what `wanted` names.
    fn between<T: TenantScope>(role: &Role<T>, wanted: &WantedPermissions<'_>) -> Self {
        let (grant_system, revoke_system) = wanted
            .system
            .map(|desired| difference(&role.system_permissions, desired))
            .unwrap_or_default();
        let (grant_custom, revoke_custom) = wanted
            .custom
            .map(|desired| difference(&role.custom_permissions, desired))
            .unwrap_or_default();
        Self {
            grant_system,
            revoke_system,
            grant_custom,
            revoke_custom,
        }
    }

    /// Whether nothing moves.
    fn is_empty(&self) -> bool {
        self.grant_system.is_empty()
            && self.revoke_system.is_empty()
            && self.grant_custom.is_empty()
            && self.revoke_custom.is_empty()
    }

    /// What making these moves does to the role.
    fn outcome(&self) -> PermissionsMoved {
        if !self.revoke_system.is_empty() || !self.revoke_custom.is_empty() {
            return PermissionsMoved::Narrowed;
        }
        if self.is_empty() {
            return PermissionsMoved::Nothing;
        }
        PermissionsMoved::Widened
    }
}

/// What `desired` adds to `held`, each named once, and what it leaves out of
/// it.
fn difference<P: Clone + PartialEq>(held: &[P], desired: &[P]) -> (Vec<P>, Vec<P>) {
    (new_to(held, desired), not_in(held, desired))
}

/// The permissions of `adding` that `held` lacks, each named once.
fn new_to<P: Clone + PartialEq>(held: &[P], adding: &[P]) -> Vec<P> {
    let mut added: Vec<P> = Vec::new();
    for permission in adding {
        if !held.contains(permission) && !added.contains(permission) {
            added.push(permission.clone());
        }
    }
    added
}

/// The permissions of `held` that `kept` leaves out, in the order held.
fn not_in<P: Clone + PartialEq>(held: &[P], kept: &[P]) -> Vec<P> {
    held.iter()
        .filter(|permission| !kept.contains(permission))
        .cloned()
        .collect()
}

/// Takes every permission `taking` names out of `held`, and gives back
/// those it held, in the order held.
fn taken_out<P: PartialEq>(held: &mut Vec<P>, taking: &[P]) -> Vec<P> {
    let (taken, kept): (Vec<P>, Vec<P>) = std::mem::take(held)
        .into_iter()
        .partition(|permission| taking.contains(permission));
    *held = kept;
    taken
}
