//! What an API key may do in a tenant: the permissions its scopes name that
//! its creator holds now.
//!
//! A key acts in its creator's name. It never carries more than they hold
//! today, so a person who loses a right takes it from every key they made at
//! once, without anyone touching the keys. Break-glass access is never
//! carried: it is granted to a person for an emergency, not to their keys.

use time::OffsetDateTime;

use crate::domains::authorization::authority::{Holdings, TenantAccess, TenantAuthority};
use crate::domains::identity::account::user::User;
use crate::domains::identity::sealed::Sealed;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{ActorRef, Human, HumanAccount, PersonKey, PrincipalRef, Scope};

/// What an API key carries: its scopes, who made it, and whether it still
/// works.
///
/// The OAuth context's key answers it. Authorization sits below OAuth, so it
/// names only this.
pub trait KeyCharter: Sealed {
    /// The scopes written on the key.
    fn scopes(&self) -> &[Scope];

    /// Who made the key.
    fn creator(&self) -> &ActorRef;

    /// Whether the key still works at `now`.
    fn works_at(&self, now: OffsetDateTime) -> bool;
}

/// What `key`, made by the tenant user `creator`, may do in `access`'s
/// tenant at `now`.
///
/// Sam made a key for reporting, scoped to view users, back when he could
/// also manage roles. He has since lost that right. The key still views
/// users, and never manages roles, whatever its scopes say.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when the key no longer works.
/// - [`DomainError::Forbidden`] when `creator` did not make the key.
/// - [`DomainError::Forbidden`] when `creator` may not sign in now.
/// - The cases
///   [`TenantGrants::administrators`](crate::domains::authorization::stewardship::TenantGrants::administrators)
///   lists, for records that name a role or group that is not there.
pub fn authority_of_key<T: TenantScope>(
    access: &TenantAccess<'_, T>,
    key: &impl KeyCharter,
    creator: &User<T>,
    now: OffsetDateTime,
) -> Result<TenantAuthority, DomainError> {
    ensure_key_works(key, now)?;
    if !matches!(key.creator(), ActorRef::User(id) if id == creator.id()) {
        return Err(DomainError::forbidden(message!(
            "authorization-the-key-was-made-by-someone",
            "the key was made by someone else"
        )));
    }
    if !creator.can_authenticate() {
        return Err(DomainError::forbidden(message!(
            "authorization-the-key-s-creator-may-not",
            "the key's creator may not act now"
        )));
    }
    let who = Human::new(
        HumanAccount::User(*creator.id()),
        PersonKey::of(creator.email()),
    );
    let held = access.standing_of(PrincipalRef::User(*creator.id()))?;
    Ok(TenantAuthority::assemble(
        who,
        access.tenant,
        held.narrowed_to(key.scopes()),
        Holdings::default(),
    ))
}

/// Refuses a key that no longer works at `now`.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when it has expired.
pub(crate) fn ensure_key_works(
    key: &impl KeyCharter,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    if !key.works_at(now) {
        return Err(DomainError::forbidden(message!(
            "authorization-the-key-no-longer-works",
            "the key no longer works"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::authorization::group::{Group, GroupMembership};
    use crate::domains::authorization::permission::{RoleAction, SystemPermission, UserAction};
    use crate::domains::authorization::resource_type::ResourceType;
    use crate::domains::authorization::role::{DefaultAssignment, NewRole, Role, RoleAssignment};
    use crate::domains::authorization::stewardship::TenantGrants;
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::{label, user};
    use crate::types::{RoleId, TenantId, UserId};

    const VIEW_USERS: SystemPermission = SystemPermission::Users(UserAction::View);
    const MANAGE_ROLES: SystemPermission = SystemPermission::Roles(RoleAction::Manage);

    /// A key as a test writes it.
    struct Key {
        scopes: Vec<Scope>,
        creator: ActorRef,
        expires: OffsetDateTime,
    }

    impl Sealed for Key {}

    impl KeyCharter for Key {
        fn scopes(&self) -> &[Scope] {
            &self.scopes
        }

        fn creator(&self) -> &ActorRef {
            &self.creator
        }

        fn works_at(&self, now: OffsetDateTime) -> bool {
            now < self.expires
        }
    }

    fn key_of(account: &User<ResolvedTenant>, scopes: &[&str]) -> Key {
        Key {
            scopes: scopes.iter().map(|s| Scope::new(*s).unwrap()).collect(),
            creator: ActorRef::User(*account.id()),
            expires: crate::shared::clock::now() + Duration::days(1),
        }
    }

    fn active(address: &str) -> User<ResolvedTenant> {
        let mut account = user(UserId::new(), address);
        account.verify_email(&proof_of(account.email())).unwrap();
        account
    }

    fn role(system: &[SystemPermission]) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label("team"),
            system_permissions: system.to_vec(),
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    fn given(
        account: &User<ResolvedTenant>,
        role: &Role<ResolvedTenant>,
    ) -> RoleAssignment<ResolvedTenant> {
        RoleAssignment::create(
            PrincipalRef::User(*account.id()),
            role,
            anyone_holding(SystemPermission::all()),
        )
        .unwrap()
    }

    /// What `account` may do through `key`, when `system` is all its roles
    /// give.
    fn through(
        account: &User<ResolvedTenant>,
        system: &[SystemPermission],
        key: &Key,
    ) -> Result<TenantAuthority, DomainError> {
        let team = role(system);
        let assignments = vec![given(account, &team)];
        let roles = vec![team];
        let access = TenantAccess {
            tenant: TenantId::new(),
            grants: TenantGrants {
                roles: &roles,
                assignments: &assignments,
                groups: &[] as &[Group<ResolvedTenant>],
                memberships: &[] as &[GroupMembership<ResolvedTenant>],
            },
            catalogue: &[] as &[ResourceType<ResolvedTenant>],
            break_glass: &[],
        };
        authority_of_key(&access, key, account, crate::shared::clock::now())
    }

    /// Sam can view users and manage roles. His reporting key is scoped to
    /// viewing users, so it views users and manages nothing.
    #[test]
    fn a_key_carries_only_what_its_scopes_name() {
        let sam = active("sam@acme.test");
        let key = key_of(&sam, &["idp:users:view"]);

        let authority = through(&sam, &[VIEW_USERS, MANAGE_ROLES], &key).unwrap();

        assert!(authority.holds(VIEW_USERS));
        assert!(!authority.holds(MANAGE_ROLES));
    }

    /// A key scoped to role management and user viewing retains only user-viewing
    /// rights when those are all its creator currently holds.
    #[test]
    fn a_key_never_carries_more_than_its_creator_holds_now() {
        let sam = active("sam@acme.test");
        let key = key_of(&sam, &["idp:roles:manage", "idp:users:view"]);

        let authority = through(&sam, &[VIEW_USERS], &key).unwrap();

        assert!(authority.holds(VIEW_USERS));
        assert!(!authority.holds(MANAGE_ROLES));
    }

    /// Ann's API key cannot obtain authority for Mallory's account.
    #[test]
    fn a_key_acts_only_for_its_creator() {
        let ann = active("ann@acme.test");
        let mallory = active("mallory@acme.test");
        let key = key_of(&ann, &["idp:users:view"]);

        let result = through(&mallory, &[VIEW_USERS], &key);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An expired API key cannot obtain tenant authority for its creator.
    #[test]
    fn an_expired_key_acts_for_nobody() {
        let sam = active("sam@acme.test");
        let key = Key {
            expires: crate::shared::clock::now() - Duration::days(1),
            ..key_of(&sam, &["idp:users:view"])
        };

        let result = through(&sam, &[VIEW_USERS], &key);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An API key cannot obtain authority while its creator cannot authenticate.
    #[test]
    fn a_key_stops_when_its_creator_may_not_sign_in() {
        let sam = user(UserId::new(), "sam@acme.test");
        let key = key_of(&sam, &["idp:users:view"]);

        let result = through(&sam, &[VIEW_USERS], &key);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }
}
