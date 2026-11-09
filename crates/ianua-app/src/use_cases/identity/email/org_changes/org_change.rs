//! The account an organization-plane email change was asked for: a member
//! of an organization or a platform operator, both kept in the control
//! plane and both changing their address the same way.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::account::email_change::{ChangingAccount, PendingEmailChange};
use ianua_domain::domains::identity::account::verified_email::VerifiedEmail;
use ianua_domain::domains::operator::identity::Operator;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::message;
use ianua_domain::types::{Email, OperatorId, OrgUserId, TokenHash};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::operator::OperatorStore;
use crate::ports::organization::OrgUserStore;
use crate::ports::shared::OrgEmailChangeStore;

/// The control-plane stores an organization-plane change reads and writes,
/// and what hashes its links.
#[derive(ianua_macros::Fakes)]
pub struct OrgChangePorts {
    /// Loads and saves pending email changes.
    pub change_store: Arc<dyn OrgEmailChangeStore>,
    /// Loads and saves organization members.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// Loads and saves operators.
    pub operator_store: Arc<dyn OperatorStore>,
    /// Makes and hashes confirmation links.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Whose address an organization-plane change moves.
pub(in crate::use_cases::identity) enum OrgAccount {
    /// A member of an organization.
    Member(OrgUser),
    /// A platform operator.
    Operator(Operator),
}

impl OrgAccount {
    /// The account as a change checks it.
    pub(in crate::use_cases::identity) fn changing(&self) -> ChangingAccount<'_> {
        match self {
            Self::Member(member) => ChangingAccount::from(member),
            Self::Operator(operator) => ChangingAccount::from(operator),
        }
    }

    /// The address the account has now.
    pub(in crate::use_cases::identity) fn email(&self) -> &Email {
        match self {
            Self::Member(member) => member.email(),
            Self::Operator(operator) => operator.email(),
        }
    }

    /// Moves the account onto the address `proof` shows its holder reads.
    pub(in crate::use_cases::identity) fn move_to(&mut self, proof: VerifiedEmail) {
        match self {
            Self::Member(member) => member.change_verified_email(proof),
            Self::Operator(operator) => operator.change_verified_email(proof),
        }
    }
}

/// The change whose confirmation link hashes to `token_hash`.
///
/// # Errors
///
/// - `AppError::NotFound` when no change carries that link.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::identity) async fn org_change_by_link(
    ports: &OrgChangePorts,
    token_hash: &TokenHash,
) -> Result<PendingEmailChange, AppError> {
    ports
        .change_store
        .find_by_token_hash(token_hash)
        .await
        .or_internal()?
        .or_not_found(message!(
            "identity-invalid-email-change-link",
            "invalid email change link"
        ))
}

/// The change whose cancel link, mailed to the old address, hashes to
/// `cancel_token_hash`.
///
/// # Errors
///
/// - `AppError::NotFound` when no change carries that link.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::identity) async fn org_change_by_cancel_link(
    ports: &OrgChangePorts,
    cancel_token_hash: &TokenHash,
) -> Result<PendingEmailChange, AppError> {
    ports
        .change_store
        .find_by_cancel_token_hash(cancel_token_hash)
        .await
        .or_internal()?
        .or_not_found(message!(
            "identity-invalid-email-change-cancel-link",
            "invalid email change cancel link"
        ))
}

/// The member or operator `change` was asked for, as they stand now.
///
/// # Errors
///
/// - `AppError::NotFound` when neither exists any more.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::identity) async fn changing_account(
    ports: &OrgChangePorts,
    change: &PendingEmailChange,
) -> Result<OrgAccount, AppError> {
    let id = *change.principal_id().as_uuid();
    let member = ports
        .org_user_store
        .find_by_id(&OrgUserId::from_uuid(id))
        .await
        .or_internal()?;
    if let Some(member) = member {
        return Ok(OrgAccount::Member(member));
    }
    ports
        .operator_store
        .find_by_id(&OperatorId::from_uuid(id))
        .await
        .or_internal()?
        .map(OrgAccount::Operator)
        .or_not_found(message!(
            "identity-invalid-email-change-link",
            "invalid email change link"
        ))
}

/// Refuses `email` when another account of `account`'s kind took it while
/// the change waited: a member's address is held by no other member of
/// their organization, an operator's by no other operator. An account on it
/// in another organization leaves a member's change free.
///
/// # Errors
///
/// - `AppError::Conflict` when the address is taken.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::identity) async fn ensure_still_free(
    ports: &OrgChangePorts,
    account: &OrgAccount,
    email: &Email,
) -> Result<(), AppError> {
    let taken = match account {
        OrgAccount::Member(member) => ports
            .org_user_store
            .find_by_email(member.organization_id(), email)
            .await
            .map(|held| held.is_some()),
        OrgAccount::Operator(_) => ports
            .operator_store
            .find_by_email(email)
            .await
            .map(|held| held.is_some()),
    };
    if taken.or_internal()? {
        return Err(AppError::Conflict(message!(
            "identity-email-already-taken",
            "email already taken"
        )));
    }
    Ok(())
}

/// Saves `account` where it is kept.
///
/// # Errors
///
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::identity) async fn save_account(
    ports: &OrgChangePorts,
    account: &OrgAccount,
) -> Result<(), AppError> {
    match account {
        OrgAccount::Member(member) => ports.org_user_store.save(member).await.or_internal(),
        OrgAccount::Operator(operator) => ports.operator_store.save(operator).await.or_internal(),
    }
}
