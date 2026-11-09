use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::authority::TenantAccess;
use crate::domains::authorization::role::Role;
use crate::domains::authorization::role_assignment::{RoleAssignment, ensure_given_automatically};
use crate::domains::authorization::stewardship::{AdministratorCount, Stewardship};
use crate::domains::federation::account_privilege::AccountPrivilege;
use crate::domains::federation::control::{FederationControl, FederationRight};
use crate::domains::federation::events::{
    ScimDisabled, ScimEnabled, ScimSettingsUpdated, ScimTokenRotated,
};
use crate::domains::identity::account::control::{AccountAction, AccountControlCheck};
use crate::domains::identity::sealed::Sealed;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::two_cases::two_cases;
use crate::types::{Enablement, RoleId, Setting, TokenHash, UserId};

two_cases! {
    /// When a user created through SCIM may sign in. Stored as the
    /// `auto_activate` flag.
    pub enum ScimActivation {
        /// At once.
        Immediate => true,
        /// Once they confirm their email address.
        AfterConfirmation => false,
    }
}

two_cases! {
    /// What removing a user through SCIM does to their account. Stored as
    /// the `deactivate_on_remove` flag.
    pub enum ScimRemoval {
        /// The account is switched off and kept.
        Deactivate => true,
        /// The account is deleted.
        Delete => false,
    }
}

/// Per-tenant SCIM provisioning endpoint configuration.
///
/// SCIM is the System for Cross-domain Identity Management. It lets an
/// enterprise customer sync users into their Ianua tenant from an HR system
/// such as Workday or `BambooHR`, or an `IdP` such as Okta or Azure AD.
///
/// Every change names who makes it, through [`FederationControl`], and
/// needs the SCIM configure right.
///
/// An address the directory sends is never taken as proven, whatever the
/// tenant's sign-in connections trust. A leaked SCIM token or a typo in
/// the HR system must not hand anyone a verified address, so each person
/// confirms theirs by link.
///
/// It is read and written only through stores opened for the resolved
/// tenant. See [`crate::isolation`].
#[derive(Debug)]
pub struct ScimEndpoint<T: TenantScope> {
    bearer_token_hash: TokenHash,
    enabled: Enablement,
    default_role_id: Setting<RoleId>,
    auto_activate: ScimActivation,
    deactivate_on_remove: ScimRemoval,
    last_sync_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// What SCIM does with the users it creates and removes, as one change:
/// the role loaded, so the endpoint checks what it carries.
#[derive(Debug)]
pub struct DirectorySettings<'a, T: TenantScope> {
    /// The role every user SCIM creates starts with, if any.
    pub default_role: Setting<&'a Role<T>>,
    /// When a user SCIM creates may sign in.
    pub activation: ScimActivation,
    /// What removing a user through SCIM does to their account.
    pub removal: ScimRemoval,
}

/// A SCIM endpoint as stored, for rebuilding it with
/// [`ScimEndpoint::reconstitute`].
pub struct ScimEndpointRow {
    /// The one-way hash of the SCIM bearer token.
    pub bearer_token_hash: TokenHash,
    /// Whether the endpoint accepts requests.
    pub enabled: Enablement,
    /// The role assigned to SCIM-provisioned users.
    pub default_role_id: Setting<RoleId>,
    /// When SCIM-created users may sign in.
    pub auto_activate: ScimActivation,
    /// What removing a user through SCIM does to their account.
    pub deactivate_on_remove: ScimRemoval,
    /// When the last SCIM sync happened.
    pub last_sync_at: Option<OffsetDateTime>,
    /// When the endpoint was configured.
    pub created_at: OffsetDateTime,
}

impl<T: TenantScope> ScimEndpoint<T> {
    /// Creates a SCIM endpoint configuration, enabled, with no default role.
    /// Synced users sign in at once and are deactivated on removal.
    ///
    /// The infrastructure layer makes the bearer token and only its hash is
    /// stored. The tenant admin sees the raw token once, during setup.
    ///
    /// Raises `federation.scim_enabled`: setting SCIM up switches it on.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not configure SCIM.
    pub fn create(
        bearer_token_hash: TokenHash,
        control: &FederationControl<'_>,
    ) -> Result<Self, DomainError> {
        control.ensure_may(FederationRight::ConfigureScim)?;
        let now = crate::shared::clock::now();
        let mut endpoint = Self {
            bearer_token_hash,
            enabled: Enablement::Enabled,
            default_role_id: Setting::Unset,
            auto_activate: ScimActivation::Immediate,
            deactivate_on_remove: ScimRemoval::Deactivate,
            last_sync_at: None,
            created_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        endpoint.raised.raise(ScimEnabled { occurred_at: now });
        Ok(endpoint)
    }

    /// Rebuilds a SCIM endpoint from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the endpoint synced
    ///   before it was configured.
    pub fn reconstitute(row: ScimEndpointRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            bearer_token_hash: row.bearer_token_hash,
            enabled: row.enabled,
            default_role_id: row.default_role_id,
            auto_activate: row.auto_activate,
            deactivate_on_remove: row.deactivate_on_remove,
            last_sync_at: row.last_sync_at,
            created_at: row.created_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &ScimEndpointRow) -> Result<(), DomainError> {
        RowCheck::of("SCIM endpoint")
            .in_order_if(
                row.created_at,
                row.last_sync_at,
                "synced before it was configured",
            )
            .finish()
    }

    /// The one-way hash of the SCIM bearer token.
    #[must_use]
    pub fn bearer_token_hash(&self) -> &TokenHash {
        &self.bearer_token_hash
    }

    /// Whether this SCIM endpoint accepts requests.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled == Enablement::Enabled
    }

    /// The role assigned to SCIM-provisioned users.
    #[must_use]
    pub fn default_role_id(&self) -> Option<&RoleId> {
        self.default_role_id.value()
    }

    /// When SCIM-created users may sign in. That is at once, or once they
    /// confirm their address.
    #[must_use]
    pub fn auto_activate(&self) -> ScimActivation {
        self.auto_activate
    }

    /// What removing a user via SCIM does as configured. It either switches
    /// the account off and keeps it, or deletes it. What it does to one
    /// account is [`removal_for`](Self::removal_for).
    #[must_use]
    pub fn deactivate_on_remove(&self) -> ScimRemoval {
        self.deactivate_on_remove
    }

    /// What removing a user through SCIM does to an account that holds
    /// `privilege`.
    ///
    /// An account holding built-in permissions is only ever switched off,
    /// whatever the setting says. Deleting cannot be undone. A leaked token
    /// or a directory mistake would otherwise delete every admin, and leave
    /// no one to put things right. A switched-off admin can be let back in.
    #[must_use]
    pub fn removal_for(&self, privilege: AccountPrivilege) -> ScimRemoval {
        match privilege {
            AccountPrivilege::Privileged => ScimRemoval::Deactivate,
            AccountPrivilege::Ordinary => self.deactivate_on_remove,
        }
    }

    /// When the last SCIM sync operation occurred.
    #[must_use]
    pub fn last_sync_at(&self) -> Option<OffsetDateTime> {
        self.last_sync_at
    }

    /// When this SCIM endpoint was configured.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Turns the SCIM endpoint back on, keeping its token and settings.
    /// Raises `federation.scim_enabled`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not configure SCIM.
    /// - [`DomainError::InvalidTransition`] if it is already enabled.
    pub fn enable(&mut self, control: &FederationControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::ConfigureScim)?;
        if self.enabled == Enablement::Enabled {
            return Err(DomainError::invalid_transition(message!(
                "federation-scim-is-already-enabled",
                "SCIM is already enabled"
            )));
        }
        self.enabled = Enablement::Enabled;
        self.raised.raise(ScimEnabled {
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Disables the SCIM endpoint, so incoming requests are refused. Raises
    /// `federation.scim_disabled`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not configure SCIM.
    /// - [`DomainError::InvalidTransition`] if it is already disabled.
    pub fn disable(&mut self, control: &FederationControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::ConfigureScim)?;
        if self.enabled == Enablement::Disabled {
            return Err(DomainError::invalid_transition(message!(
                "federation-scim-is-already-disabled",
                "SCIM is already disabled"
            )));
        }
        self.enabled = Enablement::Disabled;
        self.raised.raise(ScimDisabled {
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Rotates the bearer token. The old token is immediately invalid.
    /// Raises `federation.scim_token_rotated`, which names no token.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not configure SCIM.
    pub fn rotate_token(
        &mut self,
        new_hash: TokenHash,
        control: &FederationControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::ConfigureScim)?;
        self.bearer_token_hash = new_hash;
        self.raised.raise(ScimTokenRotated {
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Replaces what SCIM does with the users it creates and removes with
    /// `settings`, as one change. Raises `federation.scim_settings_updated`
    /// with every setting as it now stands.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not configure SCIM.
    /// - [`DomainError::Forbidden`] when the role carries a permission the
    ///   person may not hand out, or any built-in permission. Nobody
    ///   chooses each person a directory creates, so admin rights are
    ///   always given by a person.
    ///
    /// Nothing is raised then, and the endpoint is not to be saved.
    pub fn change_settings(
        &mut self,
        settings: &DirectorySettings<'_, T>,
        control: &FederationControl<'_>,
    ) -> Result<(), DomainError> {
        self.change_default_role(settings.default_role, control)?;
        self.change_activation(settings.activation, control)?;
        self.change_removal(settings.removal, control)?;
        self.raised.raise(ScimSettingsUpdated {
            default_role_id: self.default_role_id,
            auto_activate: self.auto_activate,
            deactivate_on_remove: self.deactivate_on_remove,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Changes the role every user SCIM creates is given.
    ///
    /// Naming a role is a grant to each of those users, so the person must
    /// be able to hand out what it carries.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not configure SCIM.
    /// - [`DomainError::Forbidden`] when the role carries a permission the
    ///   person may not hand out.
    /// - [`DomainError::Forbidden`] when the role carries a built-in
    ///   permission. Nobody chooses each person a provider or directory
    ///   creates, so admin rights are always given by a person.
    fn change_default_role(
        &mut self,
        role: Setting<&Role<T>>,
        control: &FederationControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::ConfigureScim)?;
        self.default_role_id = match role {
            Setting::Set(role) => {
                ensure_given_automatically(role)?;
                control
                    .holds()
                    .ensure_may_hand_out(role.system_permissions(), role.custom_permissions())?;
                Setting::Set(*role.id())
            }
            Setting::Unset => Setting::Unset,
        };
        Ok(())
    }

    /// Gives `user`, an account this directory just made, the role it
    /// gives new accounts.
    ///
    /// Only the role named as the default goes out this way. Without this
    /// check, any role could be recorded as given by the system, with no
    /// person checked for the right to hand it out.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `role` is not this endpoint's
    ///   default role.
    /// - [`DomainError::Forbidden`] when `role` carries a built-in
    ///   permission. A role given without a person choosing it holds
    ///   app permissions only.
    pub fn default_assignment(
        &self,
        user: UserId,
        role: &Role<T>,
    ) -> Result<RoleAssignment<T>, DomainError> {
        if self.default_role_id.value() != Some(role.id()) {
            return Err(DomainError::forbidden(message!(
                "federation-this-role-is-not-the-one",
                "this role is not the one the directory gives new accounts"
            )));
        }
        RoleAssignment::by_provider(user, role)
    }

    /// Changes when a user SCIM creates may sign in.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not configure SCIM.
    fn change_activation(
        &mut self,
        activation: ScimActivation,
        control: &FederationControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::ConfigureScim)?;
        self.auto_activate = activation;
        Ok(())
    }

    /// Changes what removing a user through SCIM does to their account.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not configure SCIM.
    fn change_removal(
        &mut self,
        removal: ScimRemoval,
        control: &FederationControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::ConfigureScim)?;
        self.deactivate_on_remove = removal;
        Ok(())
    }

    /// Records that a sync happened now.
    pub fn record_sync(&mut self) {
        self.last_sync_at = Some(crate::shared::clock::now());
    }

    /// The directory acting on `account`'s sign-in, with what the account
    /// holds worked out from `access`, the account's share of the tenant's
    /// records or all of them, and whether it is the tenant's last
    /// administrator from `administrators`, the tenant's count.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the endpoint is switched off.
    /// - The cases [`TenantAccess::privilege_of`] and [`Stewardship::of`]
    ///   list, for records that name a role or group that is not there.
    pub fn control_over(
        &self,
        access: &TenantAccess<'_, T>,
        account: &UserId,
        administrators: AdministratorCount,
        now: OffsetDateTime,
    ) -> Result<DirectoryControl, DomainError> {
        if !self.enabled() {
            return Err(DomainError::forbidden(message!(
                "federation-scim-is-switched-off-so-the",
                "SCIM is switched off, so the directory acts on nobody"
            )));
        }
        Ok(DirectoryControl {
            account: *account,
            stewardship: Stewardship::of(&access.grants, account, administrators)?,
            privilege: access.privilege_of(account, now)?,
        })
    }
}

impl<T: TenantScope> Raises for ScimEndpoint<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// The tenant's directory acting on one account's sign-in: letting it in,
/// shutting it out, or changing its address.
///
/// Okta switches Bob off the day he leaves, and SCIM carries that here.
/// Nobody in the tenant is signed in, so the directory answers identity's
/// rule for acting on an account, within limits. It shuts out anyone but
/// the tenant's last administrator, so a directory mistake never leaves
/// the tenant without one. It lets in, or changes the address of, only an
/// account with no built-in permission. A leaked SCIM token would
/// otherwise move Ann's admin account to Mallory's mailbox, and a password
/// reset would hand it to her. It does nothing else.
///
/// Only [`ScimEndpoint::control_over`] makes one, while the endpoint is on,
/// from the tenant's records. It is made for one account and passes for no
/// other.
#[derive(Debug, Clone, Copy)]
pub struct DirectoryControl {
    account: UserId,
    stewardship: Stewardship,
    privilege: AccountPrivilege,
}

impl DirectoryControl {
    /// Refuses letting in or changing the address of an account that holds
    /// built-in permissions.
    fn ensure_ordinary(&self) -> Result<(), DomainError> {
        match self.privilege {
            AccountPrivilege::Ordinary => Ok(()),
            AccountPrivilege::Privileged => Err(DomainError::forbidden(message!(
                "federation-the-directory-never-lets-in-or",
                "the directory never lets in or moves an account holding built-in permissions"
            ))),
        }
    }
}

impl Sealed for DirectoryControl {}

impl AccountControlCheck for DirectoryControl {
    fn ensure_allowed(&self, account: &UserId, action: AccountAction) -> Result<(), DomainError> {
        if self.account != *account {
            return Err(DomainError::forbidden(message!(
                "authorization-the-check-was-made-for-another",
                "the check was made for another account"
            )));
        }
        match action {
            AccountAction::ShutOut => self.stewardship.ensure_not_last(),
            AccountAction::LetIn | AccountAction::ChangeSignIn => self.ensure_ordinary(),
            AccountAction::EditRecords => Ok(()),
            AccountAction::Erase
            | AccountAction::RecordForThem
            | AccountAction::EditProfile
            | AccountAction::Export
            | AccountAction::Impersonate => Err(DomainError::forbidden(message!(
                "federation-the-directory-only-lets-in-shuts",
                "the directory only lets in, shuts out, moves accounts and keeps its records"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::group::{Group, GroupMembership};
    use crate::domains::authorization::permission::{
        FederationAction, ScimAction, SystemPermission, UserAction,
    };
    use crate::domains::authorization::role::{DefaultAssignment, NewRole};
    use crate::domains::authorization::stewardship::TenantGrants;
    use crate::domains::federation::fixtures::{federation_admin, holding};
    use crate::domains::identity::account::user::User;
    use crate::domains::identity::account::user_status::UserStatus;
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::{label, user};
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{Email, PrincipalRef, TenantId};

    fn endpoint() -> ScimEndpoint<ResolvedTenant> {
        ScimEndpoint::create(
            TokenHash::from_stored("hashed_token_abc".to_owned()),
            &federation_admin(),
        )
        .unwrap()
    }

    fn email(address: &str) -> Email {
        Email::new(address).unwrap()
    }

    /// A tenant sets up SCIM with a fresh token. It starts enabled with no
    /// default role, signs synced users in at once, deactivates on removal,
    /// and has never synced.
    #[test]
    fn create_with_defaults() {
        let ep = endpoint();

        assert_eq!(ep.bearer_token_hash().as_str(), "hashed_token_abc");
        assert!(ep.enabled());
        assert!(ep.default_role_id().is_none());
        assert_eq!(ep.auto_activate(), ScimActivation::Immediate);
        assert_eq!(ep.deactivate_on_remove(), ScimRemoval::Deactivate);
        assert!(ep.last_sync_at().is_none());
    }

    /// Fay's federation management permission authorizes neither SCIM
    /// creation nor token rotation; both are forbidden and the existing
    /// token hash remains unchanged.
    #[test]
    fn scim_changes_need_the_scim_right() {
        let fay = [SystemPermission::Federation(FederationAction::Manage)];
        let mut ep = endpoint();

        let created = ScimEndpoint::<ResolvedTenant>::create(
            TokenHash::from_stored("fays_token".to_owned()),
            &holding(&fay),
        );
        let rotated = ep.rotate_token(
            TokenHash::from_stored("fays_token".to_owned()),
            &holding(&fay),
        );

        assert!(matches!(created, Err(DomainError::Forbidden(_))));
        assert!(matches!(rotated, Err(DomainError::Forbidden(_))));
        assert_eq!(ep.bearer_token_hash().as_str(), "hashed_token_abc");
    }

    /// An admin turns SCIM off and then on again. The endpoint reports each
    /// state in turn.
    #[test]
    fn disable_and_reenable() {
        let mut ep = endpoint();
        let configure = [SystemPermission::Scim(ScimAction::Configure)];

        ep.disable(&holding(&configure)).unwrap();
        assert!(!ep.enabled());

        ep.enable(&holding(&configure)).unwrap();
        assert!(ep.enabled());
    }

    /// An admin enables an endpoint that is already on, or disables one
    /// already off. Both are refused, so no event claims a change that did
    /// not happen.
    #[test]
    fn enabling_or_disabling_twice_is_refused() {
        let mut ep = endpoint();

        assert!(ep.enable(&federation_admin()).is_err());
        ep.disable(&federation_admin()).unwrap();
        assert!(ep.disable(&federation_admin()).is_err());
    }

    /// An admin rotates the SCIM token. Only the new hash is kept, so the old
    /// token no longer matches.
    #[test]
    fn rotate_token_replaces_hash() {
        let mut ep = endpoint();

        ep.rotate_token(
            TokenHash::from_stored("new_hash_xyz".to_owned()),
            &federation_admin(),
        )
        .unwrap();

        assert_eq!(ep.bearer_token_hash().as_str(), "new_hash_xyz");
    }

    fn role_granting(system: Vec<SystemPermission>) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label("synced"),
            system_permissions: system,
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    /// An owner sets a role with no built-in permission as the SCIM
    /// default. The endpoint names that role for every user it creates.
    #[test]
    fn synced_users_are_given_the_default_role() {
        let mut ep = endpoint();
        let role = role_granting(Vec::new());

        ep.change_default_role(Setting::Set(&role), &federation_admin())
            .unwrap();

        assert_eq!(ep.default_role_id(), Some(role.id()));
    }

    /// An administrator cannot set a role with user-viewing permission as
    /// the SCIM default, and the endpoint retains no default role.
    #[test]
    fn a_directory_never_gives_built_in_permissions() {
        let mut ep = endpoint();
        let role = role_granting(vec![SystemPermission::Users(UserAction::View)]);

        let result = ep.change_default_role(Setting::Set(&role), &federation_admin());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(ep.default_role_id().is_none());
    }

    /// An owner sets a default role and then clears it. The endpoint names no
    /// role, so new synced users start with none.
    #[test]
    fn a_cleared_default_role_gives_synced_users_nothing() {
        let mut ep = endpoint();
        let role = role_granting(Vec::new());
        ep.change_default_role(Setting::Set(&role), &federation_admin())
            .unwrap();

        ep.change_default_role(Setting::Unset, &federation_admin())
            .unwrap();

        assert!(ep.default_role_id().is_none());
    }

    /// Sam can configure SCIM and view users, but setting a user-management
    /// role as its default is forbidden and leaves no default role.
    #[test]
    fn a_default_role_beyond_the_granter_is_refused() {
        let mut ep = endpoint();
        let admin = role_granting(vec![SystemPermission::ManageUsers]);
        let sam = [
            SystemPermission::ManageScim,
            SystemPermission::Users(UserAction::View),
        ];

        let result = ep.change_default_role(Setting::Set(&admin), &holding(&sam));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(ep.default_role_id().is_none());
    }

    /// An admin makes synced users wait for email confirmation, then switches
    /// back. The endpoint reports each choice.
    #[test]
    fn a_changed_activation_takes_effect() {
        let mut ep = endpoint();

        ep.change_activation(ScimActivation::AfterConfirmation, &federation_admin())
            .unwrap();
        assert_eq!(ep.auto_activate(), ScimActivation::AfterConfirmation);

        ep.change_activation(ScimActivation::Immediate, &federation_admin())
            .unwrap();
        assert_eq!(ep.auto_activate(), ScimActivation::Immediate);
    }

    /// An admin makes SCIM removal delete accounts instead of switching them
    /// off. The endpoint reports delete, and an ordinary account is deleted.
    #[test]
    fn a_changed_removal_takes_effect() {
        let mut ep = endpoint();

        ep.change_removal(ScimRemoval::Delete, &federation_admin())
            .unwrap();

        assert_eq!(ep.deactivate_on_remove(), ScimRemoval::Delete);
        assert_eq!(
            ep.removal_for(AccountPrivilege::Ordinary),
            ScimRemoval::Delete
        );
    }

    /// Fay lacks SCIM configuration authority, so changing its activation
    /// setting is forbidden and immediate activation remains selected.
    #[test]
    fn changing_when_synced_users_sign_in_needs_the_scim_right() {
        let fay = [SystemPermission::Federation(FederationAction::Manage)];
        let mut ep = endpoint();

        let result = ep.change_activation(ScimActivation::AfterConfirmation, &holding(&fay));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(ep.auto_activate(), ScimActivation::Immediate);
    }

    /// Fay lacks SCIM configuration authority, so changing its removal
    /// setting to deletion is forbidden and deactivation remains selected.
    #[test]
    fn changing_what_a_removal_does_needs_the_scim_right() {
        let fay = [SystemPermission::Federation(FederationAction::Manage)];
        let mut ep = endpoint();

        let result = ep.change_removal(ScimRemoval::Delete, &holding(&fay));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(ep.deactivate_on_remove(), ScimRemoval::Deactivate);
    }

    /// A directory configured to delete removed users still selects
    /// deactivation for an account with built-in privileges.
    #[test]
    fn scim_never_deletes_an_account_holding_built_in_permissions() {
        let mut ep = endpoint();
        ep.change_removal(ScimRemoval::Delete, &federation_admin())
            .unwrap();

        let removal = ep.removal_for(AccountPrivilege::Privileged);

        assert_eq!(removal, ScimRemoval::Deactivate);
    }

    /// A new endpoint has never synced. After a sync it carries a sync time.
    #[test]
    fn record_sync_sets_timestamp() {
        let mut ep = endpoint();
        assert!(ep.last_sync_at().is_none());

        ep.record_sync();

        assert!(ep.last_sync_at().is_some());
    }

    /// A disabled endpoint with a role, confirmation, delete-on-remove and
    /// a past sync is loaded from storage. Every field comes back as
    /// stored.
    #[test]
    fn reconstitute_preserves_all_fields() {
        let role_id = RoleId::new();
        let now = crate::shared::clock::now();

        let ep = ScimEndpoint::<ResolvedTenant>::reconstitute(ScimEndpointRow {
            bearer_token_hash: TokenHash::from_stored("hash123".to_owned()),
            enabled: Enablement::Disabled,
            default_role_id: Setting::Set(role_id),
            auto_activate: ScimActivation::AfterConfirmation,
            deactivate_on_remove: ScimRemoval::Delete,
            last_sync_at: Some(now),
            created_at: now,
        })
        .unwrap();

        assert_eq!(ep.bearer_token_hash().as_str(), "hash123");
        assert!(!ep.enabled());
        assert_eq!(ep.default_role_id(), Some(&role_id));
        assert_eq!(ep.auto_activate(), ScimActivation::AfterConfirmation);
        assert_eq!(ep.deactivate_on_remove(), ScimRemoval::Delete);
        assert_eq!(ep.last_sync_at(), Some(now));
        assert_eq!(ep.created_at(), now);
    }

    /// A stored row says the last sync was one second before the endpoint
    /// was set up. Loading it is refused as a corrupt row.
    #[test]
    fn a_stored_endpoint_synced_before_it_was_configured_is_refused() {
        let endpoint = endpoint();
        let row = ScimEndpointRow {
            bearer_token_hash: endpoint.bearer_token_hash.clone(),
            enabled: endpoint.enabled,
            default_role_id: endpoint.default_role_id,
            auto_activate: endpoint.auto_activate,
            deactivate_on_remove: endpoint.deactivate_on_remove,
            last_sync_at: Some(endpoint.created_at - time::Duration::SECOND),
            created_at: endpoint.created_at,
        };

        assert!(refused_as_corrupt(
            &ScimEndpoint::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// SCIM makes an account for Ann. She is given the role the endpoint
    /// names for synced users.
    #[test]
    fn a_synced_account_is_given_the_directorys_default_role() {
        let mut ep = endpoint();
        let synced = role_granting(Vec::new());
        ep.change_default_role(Setting::Set(&synced), &federation_admin())
            .unwrap();
        let ann = UserId::new();

        let given = ep.default_assignment(ann, &synced).unwrap();

        assert_eq!(given.principal(), &PrincipalRef::User(ann));
        assert_eq!(given.role_id(), synced.id());
    }

    /// A directory with a configured default role forbids assigning a
    /// different role through its default-assignment operation.
    #[test]
    fn a_directory_gives_new_accounts_only_its_default_role() {
        let mut ep = endpoint();
        let synced = role_granting(Vec::new());
        let other = role_granting(Vec::new());
        ep.change_default_role(Setting::Set(&synced), &federation_admin())
            .unwrap();

        let result = ep.default_assignment(UserId::new(), &other);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Acme's records: Ann holds the admin role and is its only
    /// administrator. Bob holds nothing.
    struct Acme {
        roles: Vec<Role<ResolvedTenant>>,
        assignments: Vec<RoleAssignment<ResolvedTenant>>,
        ann: User<ResolvedTenant>,
        bob: User<ResolvedTenant>,
    }

    impl Acme {
        fn new() -> Self {
            let ann = active("ann@acme.test");
            let admin = role_granting(SystemPermission::all().to_vec());
            let given = RoleAssignment::create(
                PrincipalRef::User(*ann.id()),
                &admin,
                anyone_holding(SystemPermission::all()),
            )
            .unwrap();
            Self {
                roles: vec![admin],
                assignments: vec![given],
                ann,
                bob: active("bob@acme.test"),
            }
        }

        fn access(&self) -> TenantAccess<'_, ResolvedTenant> {
            TenantAccess {
                tenant: TenantId::new(),
                grants: TenantGrants {
                    roles: &self.roles,
                    assignments: &self.assignments,
                    groups: &[] as &[Group<ResolvedTenant>],
                    memberships: &[] as &[GroupMembership<ResolvedTenant>],
                },
                catalogue: &[],
                break_glass: &[],
            }
        }

        /// The switched-on directory acting on `account`.
        fn directory_over(&self, account: &User<ResolvedTenant>) -> DirectoryControl {
            let access = self.access();
            let administrators = access.grants.administrator_count().unwrap();
            endpoint()
                .control_over(
                    &access,
                    account.id(),
                    administrators,
                    crate::shared::clock::now(),
                )
                .unwrap()
        }
    }

    fn active(address: &str) -> User<ResolvedTenant> {
        let mut account = user(UserId::new(), address);
        account.verify_email(&proof_of(account.email())).unwrap();
        account
    }

    /// Okta switches Bob off the day he leaves. SCIM locks his account.
    #[test]
    fn the_directory_shuts_out_an_account_that_left() {
        let mut acme = Acme::new();
        let control = acme.directory_over(&acme.bob);

        acme.bob.lock(&control).unwrap();

        assert_eq!(acme.bob.status(), UserStatus::Locked);
    }

    /// Directory deactivation conflicts when Ann is the last administrator,
    /// leaving her account active.
    #[test]
    fn the_directory_never_shuts_out_the_last_administrator() {
        let mut acme = Acme::new();
        let control = acme.directory_over(&acme.ann);

        let result = acme.ann.deactivate(&control);

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert_eq!(acme.ann.status(), UserStatus::Active);
    }

    /// Okta changes Bob's address, and SCIM moves his account to it. A
    /// leaked SCIM token moves Ann's admin account to Mallory's mailbox,
    /// or lets it in again. Both are refused.
    #[test]
    fn the_directory_moves_and_lets_in_only_accounts_without_built_in_permissions() {
        let mut acme = Acme::new();
        let over_bob = acme.directory_over(&acme.bob);
        let over_ann = acme.directory_over(&acme.ann);

        let bob_moved = acme.bob.change_email(email("bob@new.acme.test"), &over_bob);
        let ann_moved = acme.ann.change_email(email("mallory@evil.test"), &over_ann);
        let ann_let_in = over_ann.ensure_allowed(acme.ann.id(), AccountAction::LetIn);

        assert!(bob_moved.is_ok());
        assert!(matches!(ann_moved, Err(DomainError::Forbidden(_))));
        assert!(matches!(ann_let_in, Err(DomainError::Forbidden(_))));
    }

    /// Directory authority for Bob forbids shutting out Ann and erasing
    /// Bob's account.
    #[test]
    fn the_directory_acts_only_on_its_account_and_only_on_sign_in() {
        let acme = Acme::new();
        let over_bob = acme.directory_over(&acme.bob);

        let on_ann = over_bob.ensure_allowed(acme.ann.id(), AccountAction::ShutOut);
        let erasing = over_bob.ensure_allowed(acme.bob.id(), AccountAction::Erase);

        assert!(matches!(on_ann, Err(DomainError::Forbidden(_))));
        assert!(matches!(erasing, Err(DomainError::Forbidden(_))));
    }

    /// A disabled SCIM endpoint is forbidden from creating directory
    /// authority over Bob's account.
    #[test]
    fn a_switched_off_directory_acts_on_nobody() {
        let acme = Acme::new();
        let mut ep = endpoint();
        ep.disable(&federation_admin()).unwrap();
        let access = acme.access();
        let administrators = access.grants.administrator_count().unwrap();

        let control = ep.control_over(
            &access,
            acme.bob.id(),
            administrators,
            crate::shared::clock::now(),
        );

        assert!(matches!(control, Err(DomainError::Forbidden(_))));
    }

    /// An endpoint and what it raised since it was set up, the setup taken
    /// out first.
    fn fresh_endpoint() -> ScimEndpoint<ResolvedTenant> {
        let mut ep = endpoint();
        raised_names(&mut ep);
        ep
    }

    /// Settings that have new users confirm their address and delete
    /// removed users.
    fn confirming_and_deleting() -> DirectorySettings<'static, ResolvedTenant> {
        DirectorySettings {
            default_role: Setting::Unset,
            activation: ScimActivation::AfterConfirmation,
            removal: ScimRemoval::Delete,
        }
    }

    fn text(event: &DomainEvent, key: &str) -> String {
        match event.payload().value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not text: {other:?}"),
        }
    }

    /// Ann sets SCIM up for Acme. Setting it up switches it on, which is
    /// raised.
    #[test]
    fn setting_up_raises_federation_scim_enabled() {
        let mut ep = endpoint();

        assert_eq!(raised_names(&mut ep), ["federation.scim_enabled"]);
    }

    /// Acme's endpoint is read back from storage. Loading it is no change,
    /// so it has raised nothing.
    #[test]
    fn an_endpoint_read_back_from_storage_has_raised_nothing() {
        let now = crate::shared::clock::now();
        let mut stored = ScimEndpoint::<ResolvedTenant>::reconstitute(ScimEndpointRow {
            bearer_token_hash: TokenHash::from_stored("hash123".to_owned()),
            enabled: Enablement::Enabled,
            default_role_id: Setting::Unset,
            auto_activate: ScimActivation::Immediate,
            deactivate_on_remove: ScimRemoval::Deactivate,
            last_sync_at: None,
            created_at: now,
        })
        .unwrap();

        assert!(raised_names(&mut stored).is_empty());
    }

    /// Ann switches SCIM off, back on, and rotates its token. Each is
    /// raised, in order.
    #[test]
    fn switching_and_rotating_raise_their_events() {
        let mut ep = fresh_endpoint();

        ep.disable(&federation_admin()).unwrap();
        ep.enable(&federation_admin()).unwrap();
        ep.rotate_token(
            TokenHash::from_stored("new_hash".to_owned()),
            &federation_admin(),
        )
        .unwrap();

        assert_eq!(
            raised_names(&mut ep),
            [
                "federation.scim_disabled",
                "federation.scim_enabled",
                "federation.scim_token_rotated"
            ]
        );
    }

    /// Ann has new users confirm their address and deletes removed users.
    /// One change is raised, with every setting as it now stands.
    #[test]
    fn changing_the_settings_raises_federation_scim_settings_updated() {
        let mut ep = fresh_endpoint();

        ep.change_settings(&confirming_and_deleting(), &federation_admin())
            .unwrap();

        let events = raised(&mut ep);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "federation.scim_settings_updated"
        );
        assert_eq!(text(&events[0], "auto_activate"), "false");
        assert_eq!(text(&events[0], "deactivate_on_remove"), "false");
    }

    /// Fay's unauthorized settings change and an administrator's attempt
    /// to enable an enabled endpoint both fail, raising no events.
    #[test]
    fn a_refused_change_raises_nothing() {
        let fay = [SystemPermission::Federation(FederationAction::Manage)];
        let mut ep = fresh_endpoint();

        let changed = ep.change_settings(&confirming_and_deleting(), &holding(&fay));
        let enabled = ep.enable(&federation_admin());

        assert!(changed.is_err());
        assert!(enabled.is_err());
        assert!(raised_names(&mut ep).is_empty());
    }
}
