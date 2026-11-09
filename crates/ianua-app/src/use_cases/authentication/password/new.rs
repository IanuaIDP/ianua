//! A password a person chooses for their own account, checked against the
//! tenant's rules and hashed, for changing it and for resetting it, and put
//! in force in place of the current one.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::breach::NewPasswordBreach;
use ianua_domain::domains::authentication::credentials::password::PasswordHasher as _;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::PasswordHash;

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::CredentialStore;
use crate::ports::identity::UserStore;
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::services::authentication::new_password::{
    Earlier, NewPassword, NewPasswordPorts, current_hash,
};
use crate::services::authentication::password_hashing::PasswordHashing;
use crate::services::authentication::password_rules;
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;

/// Where the tenant's rules are read and what hashes the password.
#[derive(Clone, Copy)]
pub(in crate::use_cases::authentication::password) struct PasswordSetting<'a> {
    /// The tenant, for its password rules.
    pub(in crate::use_cases::authentication::password) tenants: &'a dyn TenantStore,
    /// Hashes the chosen password, under the node's cap.
    pub(in crate::use_cases::authentication::password) hashing: &'a PasswordHashing,
}

impl PasswordSetting<'_> {
    /// The hash of `chosen`, once it meets the rules `tenant` sets for new
    /// passwords.
    ///
    /// A tenant that signs nobody in with a password takes no new one: a
    /// password set there would wait, forgotten, until password sign-in is
    /// switched on and it becomes a way in.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the tenant signs nobody in with a
    ///   password.
    /// - `AppError::Domain` when `chosen` breaks the tenant's rules.
    /// - `AppError::NotFound` when the tenant does not exist.
    /// - `AppError::Busy` when no hash could start on this node in time.
    /// - `AppError::Internal` when the tenant cannot be read or the password
    ///   cannot be hashed.
    pub(in crate::use_cases::authentication::password) async fn hashed(
        &self,
        tenant: &ScopedTenant,
        chosen: &Secret,
    ) -> Result<PasswordHash, AppError> {
        let policy = password_rules::for_new_tenant_password(self.tenants, tenant)
            .await?
            .ok_or_else(|| {
                AppError::Forbidden(message!(
                    "authentication-this-workspace-does-not-sign-in",
                    "this workspace does not sign in with passwords"
                ))
            })?;
        policy
            .validate(chosen.expose())
            .map_err(|e| AppError::Domain(DomainError::Validation(e)))?;
        self.hashing
            .permitted()
            .await?
            .hash(chosen.expose())
            .or_internal()
    }
}

/// The ports a password chosen in place of the current one is checked,
/// kept and put in force through: by a mailed reset, and by a sign-in
/// whose password must change first.
#[derive(ianua_macros::Fakes)]
pub struct ReplacementPorts {
    /// The tenant, for its password rules.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Hashes the new password, under the node's cap on hashes running at
    /// once.
    pub hashing: PasswordHashing,
    /// Checks the new password against breaches, the common list and the
    /// account's recent passwords, and keeps the old one among them.
    pub new_password: NewPasswordPorts,
    /// Writes the new password's hash.
    pub credential_store: Arc<dyn CredentialStore>,
    /// Loads and saves the account whose way in changes.
    pub user_store: Arc<dyn UserStore>,
    /// Ends every session the account held.
    pub session_store: Arc<dyn SessionStore>,
}

impl ReplacementPorts {
    /// Where the new password is checked, kept and put in force.
    pub(in crate::use_cases::authentication::password) fn replacement(
        &self,
    ) -> PasswordReplacement<'_> {
        PasswordReplacement {
            tenants: self.tenant_store.as_ref(),
            hashing: &self.hashing,
            checks: &self.new_password,
            credentials: self.credential_store.as_ref(),
            users: self.user_store.as_ref(),
            sessions: self.session_store.as_ref(),
        }
    }
}

/// Where a password chosen in place of the current one is checked, kept
/// and put in force: by a mailed reset, and by a sign-in whose password
/// must change first.
#[derive(Clone, Copy)]
pub(in crate::use_cases::authentication::password) struct PasswordReplacement<'a> {
    /// The tenant, for its password rules.
    pub(in crate::use_cases::authentication::password) tenants: &'a dyn TenantStore,
    /// Hashes the chosen password, under the node's cap.
    pub(in crate::use_cases::authentication::password) hashing: &'a PasswordHashing,
    /// Checks it against breaches, the common list and the account's recent
    /// passwords, and keeps the old one among them.
    pub(in crate::use_cases::authentication::password) checks: &'a NewPasswordPorts,
    /// Writes the new hash.
    pub(in crate::use_cases::authentication::password) credentials: &'a dyn CredentialStore,
    /// Saves the account whose way in changed.
    pub(in crate::use_cases::authentication::password) users: &'a dyn UserStore,
    /// Ends every session the account held.
    pub(in crate::use_cases::authentication::password) sessions: &'a dyn SessionStore,
}

/// A new password, checked: its hash, what the breach check found, and the
/// hash it replaces.
pub(in crate::use_cases::authentication::password) struct ChosenPassword {
    /// What is stored.
    pub(in crate::use_cases::authentication::password) hash: PasswordHash,
    /// What the breach check found.
    pub(in crate::use_cases::authentication::password) breach: NewPasswordBreach,
    /// The account's password before, kept among its retired ones.
    pub(in crate::use_cases::authentication::password) replaced: Option<PasswordHash>,
}

impl PasswordReplacement<'_> {
    /// The hash of the password `new` chooses, once it meets the tenant's
    /// rules, repeats none of the account's recent ones and passes the
    /// breach check, with what that check found and the hash it replaces.
    ///
    /// # Errors
    ///
    /// - The errors of [`PasswordSetting::hashed`].
    /// - `AppError::Domain` when it is common, recently used, or breached
    ///   where the tenant blocks that.
    pub(in crate::use_cases::authentication::password) async fn chosen(
        &self,
        new: NewPassword<'_>,
    ) -> Result<ChosenPassword, AppError> {
        let hash = PasswordSetting {
            tenants: self.tenants,
            hashing: self.hashing,
        }
        .hashed(new.tenant, new.chosen)
        .await?;
        let workspace = existing_tenant(self.tenants, new.tenant).await?;
        let breach = self.checks.screened(&workspace, new).await?;
        let replaced = current_hash(self.credentials, new).await?;
        let earlier = Earlier {
            current: replaced.as_ref(),
            hashing: self.hashing,
        };
        self.checks
            .ensure_not_repeated(&workspace, new, earlier)
            .await?;
        Ok(ChosenPassword {
            hash,
            breach,
            replaced,
        })
    }

    /// Retires the old password, writes `chosen` and records the change on
    /// `holder`, which ends every way in the account had before, then ends
    /// every session it held, so whoever knew the old password is signed
    /// out with it.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` on storage failure.
    pub(in crate::use_cases::authentication::password) async fn install(
        &self,
        tenant: &ScopedTenant,
        holder: &mut User<ResolvedTenant>,
        chosen: &ChosenPassword,
    ) -> Result<(), AppError> {
        self.checks
            .retire(tenant, holder.id(), chosen.replaced.as_ref())
            .await?;
        self.credentials
            .update_password_hash(tenant, holder.id(), &chosen.hash)
            .await
            .or_internal()?;
        holder.record_credential_change();
        self.users.save(tenant, holder).await.or_internal()?;
        self.sessions
            .revoke_all_by_user(tenant, holder.id())
            .await
            .or_internal()?;
        Ok(())
    }
}
