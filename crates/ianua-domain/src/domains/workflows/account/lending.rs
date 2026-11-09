//! Whether an account lends itself to someone's workflow: switched on, its
//! owner still allowed to lend it, and shared with them or theirs. A step
//! asks before it acts through it, a registration before it is made, and a
//! version in service whenever it is checked for the accounts it needs.

use crate::domains::workflows::account::{AccountSharing, AccountStatus, IntegrationAccount};
use crate::domains::workflows::design::workflow::{AccountUnusable, UsedAccount};
use crate::domains::workflows::execution::ActingAuthority;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;

impl<T: TenantScope> IntegrationAccount<T> {
    /// Why a version published by `acting_for` can no longer use this
    /// account as `used` says, or nothing when it still can. `owner` is
    /// what the account's owner holds right now.
    ///
    /// Answers what [`grant_use`](Self::grant_use) and
    /// [`ensure_lends_events`](Self::ensure_lends_events) refuse, so a
    /// version is held for exactly what would refuse its run.
    #[must_use]
    pub fn unusable_for(
        &self,
        acting_for: &ActingAuthority,
        used: &UsedAccount,
        owner: &ActingAuthority,
    ) -> Option<AccountUnusable> {
        if self.status != AccountStatus::Active {
            return Some(AccountUnusable::Disabled);
        }
        if !owner.may_lend_accounts(&self.owner) {
            return Some(AccountUnusable::OwnerCannotLend);
        }
        if self.sharing == AccountSharing::OwnerOnly
            && !self.owner.is_same_account_as(acting_for.person())
        {
            return Some(AccountUnusable::NotLent);
        }
        let allowed = self.integration == used.integration
            && used
                .operation
                .as_ref()
                .is_none_or(|operation| self.scope.allows(operation));
        match allowed {
            true => None,
            false => Some(AccountUnusable::NotForThisUse),
        }
    }

    /// Refuses lending the account to `acting_for` when it is disabled, its
    /// owner may no longer lend it, or it is kept to its owner and
    /// `acting_for` is someone else.
    pub(super) fn ensure_lent_to(
        &self,
        acting_for: &ActingAuthority,
        owner: &ActingAuthority,
    ) -> Result<(), DomainError> {
        self.ensure_lendable(owner)?;
        if self.sharing == AccountSharing::OwnerOnly
            && !self.owner.is_same_account_as(acting_for.person())
        {
            return Err(DomainError::forbidden(message!(
                "workflows-only-its-owner-s-workflows-may",
                "only its owner's workflows may act through this account"
            )));
        }
        Ok(())
    }

    /// Refuses lending a disabled account, or one whose owner may no longer
    /// lend it.
    fn ensure_lendable(&self, owner: &ActingAuthority) -> Result<(), DomainError> {
        if self.status != AccountStatus::Active {
            return Err(DomainError::forbidden(message!(
                "workflows-this-account-is-disabled",
                "this account is disabled"
            )));
        }
        if !owner.may_lend_accounts(&self.owner) {
            return Err(DomainError::forbidden(message!(
                "workflows-the-account-s-owner-may-no",
                "the account's owner may no longer lend it"
            )));
        }
        Ok(())
    }
}
