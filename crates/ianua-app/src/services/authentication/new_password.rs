//! What a tenant user's new password is checked for beyond its length and
//! characters, wherever it is set: sign-up, an invitation, a change, a
//! reset link and an admin's reset.
//!
//! The tenant's policy decides: whether the person's own name or address
//! may be in it, whether a common password is taken, how many earlier
//! passwords it may not repeat, and what a password found in known
//! breaches does. A breach service that cannot answer, or times out,
//! refuses the password with a "try again" where the tenant blocks
//! breached passwords; where it only warns, the password goes through as
//! unchecked and the gap is logged. Neither the password nor anything made
//! from it is logged.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::breach::{
    BreachStatus, BreachedPasswordCheck, NewPasswordBreach,
};
use ianua_domain::domains::authentication::credentials::password_rules::ensure_not_reused;
use ianua_domain::domains::authentication::operations::password_login::Lookup;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::shared::validation::ValidationError;
use ianua_domain::types::password_policy::PersonalData;
use ianua_domain::types::{PasswordHash, PasswordPolicy, UserId};

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{
    CommonPasswordList, CredentialBreachChecker, CredentialStore, PasswordHistory,
};
use crate::services::authentication::password_hashing::PasswordHashing;
use crate::tenancy::ScopedTenant;

/// The ports a new password is checked through.
#[derive(ianua_macros::Fakes)]
pub struct NewPasswordPorts {
    /// Looks the password up in known breaches.
    pub breaches: Arc<dyn CredentialBreachChecker>,
    /// The list of common passwords.
    pub common_passwords: Arc<dyn CommonPasswordList>,
    /// The account's retired passwords.
    pub history: Arc<dyn PasswordHistory>,
}

/// A password someone is about to set on an account.
#[derive(Clone, Copy)]
pub(crate) struct NewPassword<'a> {
    /// The tenant the account is in.
    pub(crate) tenant: &'a ScopedTenant,
    /// The account, whose name and address the password may not hold.
    pub(crate) account: &'a User<ResolvedTenant>,
    /// The password as chosen.
    pub(crate) chosen: &'a Secret,
}

impl NewPasswordPorts {
    /// What `new.chosen` comes to under `workspace`'s policy: refused for
    /// holding the person's name or address, for being common, or for a
    /// breach the tenant blocks; otherwise what the breach check found.
    /// Its length and characters are checked where it is hashed.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Domain` when the password holds the person's name
    /// or address, is on the common list, or, where the tenant blocks
    /// breached passwords, is breached or could not be looked up.
    pub(crate) async fn screened(
        &self,
        workspace: &Tenant,
        new: NewPassword<'_>,
    ) -> Result<NewPasswordBreach, AppError> {
        let policy = workspace.auth_config().password_policy();
        ensure_hygienic(policy, self.common_passwords.as_ref(), new)?;
        let check = workspace.auth_config().breached_passwords();
        let found = self.breach_of(check, new.chosen).await;
        let judged = check.judge(&found).map_err(AppError::from_domain)?;
        if let NewPasswordBreach::Breached(count) = judged {
            tracing::info!(count, "a user set a password found in known breaches");
        }
        Ok(judged)
    }

    /// Refuses `new.chosen` when it repeats the account's current password
    /// or one of the retired ones `workspace`'s policy counts.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when it was used recently.
    /// - `AppError::Busy` when no hash could start on this node in time.
    /// - `AppError::Internal` when the history cannot be read or a stored
    ///   hash cannot be checked.
    pub(crate) async fn ensure_not_repeated(
        &self,
        workspace: &Tenant,
        new: NewPassword<'_>,
        earlier: Earlier<'_>,
    ) -> Result<(), AppError> {
        let limit = workspace.auth_config().password_policy().hygiene().reuse;
        if limit.count() == 0 {
            return Ok(());
        }
        let retired = self
            .history
            .recent(new.tenant, new.account.id(), u32::from(limit.count()))
            .await
            .or_internal()?;
        let hashes: Vec<PasswordHash> = earlier
            .current
            .into_iter()
            .cloned()
            .chain(retired)
            .collect();
        let hasher = earlier.hashing.permitted().await?;
        ensure_not_reused(new.chosen.expose(), &hashes, limit, &hasher)
            .map_err(AppError::from_domain)
    }

    /// Keeps `current`, the password being replaced, among the account's
    /// retired ones, so a later password may not repeat it. Written before
    /// the new hash, so a history that cannot be written leaves the old
    /// password in place.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` when the history cannot be written.
    pub(crate) async fn retire(
        &self,
        tenant: &ScopedTenant,
        user_id: &UserId,
        current: Option<&PasswordHash>,
    ) -> Result<(), AppError> {
        let Some(current) = current else {
            return Ok(());
        };
        self.history
            .record(tenant, user_id, current)
            .await
            .or_internal()
    }

    /// What the breach service says of `password`, unless the tenant does
    /// not check. A service that cannot be reached answers unavailable.
    async fn breach_of(
        &self,
        check: BreachedPasswordCheck,
        password: &Secret,
    ) -> Lookup<BreachStatus> {
        if !check.checks_passwords() {
            return Lookup::Unknown;
        }
        match self.breaches.check(password).await {
            Ok(status) => Lookup::Known(status),
            Err(error) => {
                tracing::warn!(%error, "new password: the breach check could not be reached");
                Lookup::Unavailable
            }
        }
    }
}

/// The passwords a new one is checked against: the account's current one,
/// if it has one, and what checks a password against a hash.
#[derive(Clone, Copy)]
pub(crate) struct Earlier<'a> {
    /// The current password's hash.
    pub(crate) current: Option<&'a PasswordHash>,
    /// Checks a password against a stored hash, under the node's cap.
    pub(crate) hashing: &'a PasswordHashing,
}

/// The account's current password hash, or none when it has no password.
///
/// # Errors
///
/// Returns `AppError::Internal` when the hash cannot be read.
pub(crate) async fn current_hash(
    credentials: &dyn CredentialStore,
    new: NewPassword<'_>,
) -> Result<Option<PasswordHash>, AppError> {
    credentials
        .find_password_hash(new.tenant, new.account.id())
        .await
        .or_internal()
}

/// Refuses a password holding the person's name or address, or on the
/// common list, as `policy` asks.
fn ensure_hygienic(
    policy: &PasswordPolicy,
    common: &dyn CommonPasswordList,
    new: NewPassword<'_>,
) -> Result<(), AppError> {
    let names = [new.account.display_name().as_str()];
    let person = PersonalData {
        email: new.account.email(),
        names: &names,
    };
    policy
        .check_personal_data(new.chosen.expose(), person)
        .map_err(refused)?;
    policy
        .check_common(common.verdict(new.chosen))
        .map_err(refused)
}

/// A rule a new password broke, as the caller is told it.
fn refused(error: ValidationError) -> AppError {
    AppError::Domain(DomainError::Validation(error))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::password::PasswordHasher;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::test_support::fakes::FakeHasher;
    use ianua_domain::types::UserId;
    use ianua_domain::types::password_policy::{PasswordHygiene, ReuseLimit};

    use super::*;
    use crate::test_support::authentication::{
        FakeBreachChecker, FakeCommonPasswords, FakePasswordHistory, UnreachableBreachChecker,
    };
    use crate::test_support::identity::stored_user;
    use crate::test_support::tenant::tenant_for_ctx_signing_in_with;
    use crate::test_support::{block_on, test_ctx};

    const ANNS_CHOICE: &str = "violet-harbour-lantern";

    fn ann() -> User<ResolvedTenant> {
        stored_user(UserId::new(), "ann.lee@acme.test", UserStatus::Active)
    }

    fn ports(breaches: Arc<dyn CredentialBreachChecker>) -> NewPasswordPorts {
        NewPasswordPorts {
            breaches,
            common_passwords: Arc::new(FakeCommonPasswords::holding(&["password1"])),
            ..NewPasswordPorts::fakes()
        }
    }

    fn screened(
        ports: &NewPasswordPorts,
        workspace: &Tenant,
        chosen: &str,
    ) -> Result<NewPasswordBreach, AppError> {
        let account = ann();
        let tenant = test_ctx().tenant();
        let chosen = Secret::new(chosen);
        block_on(ports.screened(
            workspace,
            NewPassword {
                tenant: &tenant,
                account: &account,
                chosen: &chosen,
            },
        ))
    }

    fn breaching() -> Arc<dyn CredentialBreachChecker> {
        Arc::new(FakeBreachChecker {
            status: BreachStatus::Breached(9),
        })
    }

    fn workspace(check: BreachedPasswordCheck) -> Tenant {
        tenant_for_ctx_signing_in_with(TenantAuthSettings {
            breached_passwords: check,
            ..TenantAuthSettings::default()
        })
    }

    /// A tenant that rejects passwords matching its three most recent hashes.
    fn workspace_remembering_passwords() -> Tenant {
        let reuse = PasswordHygiene {
            reuse: ReuseLimit::new(3).unwrap(),
            ..PasswordHygiene::default()
        };
        tenant_for_ctx_signing_in_with(TenantAuthSettings {
            password_policy: PasswordPolicy::default().with_hygiene(reuse),
            ..TenantAuthSettings::default()
        })
    }

    /// A password reported as breached is rejected when the tenant's
    /// breach policy is Block.
    #[test]
    fn a_breached_password_is_refused_where_the_tenant_blocks() {
        let result = screened(
            &ports(breaching()),
            &workspace(BreachedPasswordCheck::Block),
            ANNS_CHOICE,
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Where Acme only warns, the same password is taken and the caller is
    /// told how often it was found.
    #[test]
    fn a_breached_password_passes_with_a_warning_where_the_tenant_warns() {
        let result = screened(
            &ports(breaching()),
            &workspace(BreachedPasswordCheck::Warn),
            ANNS_CHOICE,
        );

        assert_eq!(result.unwrap(), NewPasswordBreach::Breached(9));
    }

    /// When the breach checker fails under the Block policy, screening
    /// returns a domain refusal rather than an unchecked password.
    #[test]
    fn an_unreachable_service_refuses_the_password_where_the_tenant_blocks() {
        let result = screened(
            &ports(Arc::new(UnreachableBreachChecker::default())),
            &workspace(BreachedPasswordCheck::Block),
            ANNS_CHOICE,
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// The breach service is down where Acme only warns. Ann's password is
    /// taken unchecked rather than leaving her unable to set one.
    #[test]
    fn an_unreachable_service_lets_the_password_through_where_the_tenant_warns() {
        let result = screened(
            &ports(Arc::new(UnreachableBreachChecker::default())),
            &workspace(BreachedPasswordCheck::Warn),
            ANNS_CHOICE,
        );

        assert_eq!(result.unwrap(), NewPasswordBreach::Unchecked);
    }

    /// Ann's name in the chosen password causes a refusal even with breach
    /// checking turned off.
    #[test]
    fn a_password_holding_the_persons_name_is_refused() {
        let result = screened(
            &ports(Arc::new(FakeBreachChecker::default())),
            &workspace(BreachedPasswordCheck::Off),
            "AnnLee2024!",
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// The common-password list rejects `Password1` even though its entry
    /// is lowercase and breach checking is off.
    #[test]
    fn a_common_password_is_refused() {
        let result = screened(
            &ports(Arc::new(FakeBreachChecker::default())),
            &workspace(BreachedPasswordCheck::Off),
            "Password1",
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann's chosen password matches a retired hash. A policy remembering
    /// three passwords rejects it even when no current hash is supplied.
    #[test]
    fn a_recently_used_password_is_refused() {
        let account = ann();
        let old = FakeHasher.hash(ANNS_CHOICE).unwrap();
        let history = Arc::new(FakePasswordHistory::with_entry(*account.id(), old));
        let ports = NewPasswordPorts {
            history,
            ..NewPasswordPorts::fakes()
        };
        let workspace = workspace_remembering_passwords();
        let hashing = PasswordHashing::fakes();
        let tenant = test_ctx().tenant();
        let chosen = Secret::new(ANNS_CHOICE);
        let new = NewPassword {
            tenant: &tenant,
            account: &account,
            chosen: &chosen,
        };

        let result = block_on(ports.ensure_not_repeated(
            &workspace,
            new,
            Earlier {
                current: None,
                hashing: &hashing,
            },
        ));

        assert!(matches!(result, Err(AppError::Domain(_))));
    }
}
