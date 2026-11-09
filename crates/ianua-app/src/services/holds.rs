//! Whether a version in service still has every account it acts through,
//! and holding it when it does not.
//!
//! Asked when a start is attempted, and when an account changes, so a
//! version whose account stopped lending itself is held and its people are
//! told, rather than failing every run at that step.

use ianua_domain::domains::workflows::account::IntegrationAccount;
use ianua_domain::domains::workflows::design::workflow::{
    AccountUnusable, MissingAccount, Publication, Workflow,
};
use ianua_domain::domains::workflows::execution::ActingAuthority;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::error::{AppError, OrInternal};
use crate::ports::workflows::IntegrationAccountStore;
use crate::services::account_now::AccountsNow;
use crate::tenancy::ScopedTenant;

/// Where the accounts a check reads come from.
#[derive(Clone, Copy)]
pub(crate) struct AccountReads<'a> {
    /// The tenant's accounts.
    pub(crate) accounts: &'a dyn IntegrationAccountStore,
    /// What the accounts' owners hold now.
    pub(crate) people: &'a AccountsNow,
}

/// The first account `workflow` acts through that can no longer be used
/// for `publisher`, with where and why, or none when every one still can.
///
/// # Errors
///
/// `AppError::Internal` when an account or its owner's records cannot be
/// read.
pub(crate) async fn missing_account(
    reads: AccountReads<'_>,
    tenant: &ScopedTenant,
    workflow: &Workflow<ResolvedTenant>,
    publisher: &ActingAuthority,
) -> Result<Option<MissingAccount>, AppError> {
    for used in workflow.accounts_used() {
        let found = reads
            .accounts
            .find_by_id(tenant, &used.account)
            .await
            .or_internal()?;
        let why = match found {
            None => Some(AccountUnusable::Gone),
            Some(account) => match owner_now(reads.people, tenant, &account).await? {
                None => Some(AccountUnusable::OwnerCannotLend),
                Some(owner) => account.unusable_for(publisher, &used, &owner),
            },
        };
        if let Some(why) = why {
            return Ok(Some(MissingAccount {
                account: used.account,
                at: used.at,
                why,
            }));
        }
    }
    Ok(None)
}

/// What the person who published `workflow` holds now through their
/// account, or none when it was never published, or their account is gone
/// or may not act.
///
/// # Errors
///
/// `AppError::Internal` when their records name a role that is not there,
/// or cannot be read.
pub(crate) async fn publisher_now(
    people: &AccountsNow,
    tenant: &ScopedTenant,
    workflow: &Workflow<ResolvedTenant>,
) -> Result<Option<ActingAuthority>, AppError> {
    let Publication::PublishedBy(publisher) = workflow.publication() else {
        return Ok(None);
    };
    let Some(records) = people.person(tenant, publisher, &[]).await? else {
        return Ok(None);
    };
    records.authority(|account, access, resources| {
        ActingAuthority::of_publisher(workflow, account, access, resources)
    })
}

/// What `account`'s owner holds now, or none when their account is gone
/// or may not act.
///
/// # Errors
///
/// `AppError::Internal` when their records cannot be read.
pub(crate) async fn owner_now(
    people: &AccountsNow,
    tenant: &ScopedTenant,
    account: &IntegrationAccount<ResolvedTenant>,
) -> Result<Option<ActingAuthority>, AppError> {
    let Some(held) = people.person(tenant, account.owner(), &[]).await? else {
        return Ok(None);
    };
    held.authority(|records, access, _| ActingAuthority::of_account_owner(account, records, access))
}
