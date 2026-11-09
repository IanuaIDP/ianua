//! The account a repository is read or pushed through: its id and its
//! credential, sealed for it, and keeping a credential its service renewed
//! on the way.

use ianua_domain::domains::workflows::account::IntegrationAccount;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::UntrustedText;

use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::authentication::SealedAt;
use crate::ports::workflows::{Renewal, RepositoryAccount, RepositoryRefusal};
use crate::services::account_grants::{AccountGrants, GrantHolder};
use crate::services::renewals::Renewing;
use crate::tenancy::ScopedTenant;
use crate::use_cases::workflows::accounts::connect::integration_credential_place;

/// An account a repository call goes through.
pub(in crate::use_cases::workflows::sandboxes) struct Through {
    /// The account, as the repositories port is handed it.
    pub(in crate::use_cases::workflows::sandboxes) account: RepositoryAccount,
    /// The integration whose service issued its credential.
    integration: IntegrationKey,
}

impl Through {
    /// Through `account` of `tenant`.
    pub(in crate::use_cases::workflows::sandboxes) fn of(
        tenant: &ScopedTenant,
        account: &IntegrationAccount<ResolvedTenant>,
    ) -> Self {
        Self {
            account: RepositoryAccount {
                id: *account.id(),
                credential: SealedAt {
                    secret: account.credential().clone(),
                    place: integration_credential_place(tenant, account.id()),
                },
            },
            integration: account.integration().clone(),
        }
    }

    /// The same account, holding what was just exchanged for its grant if
    /// its token was near its end.
    ///
    /// # Errors
    ///
    /// [`RepositoryRefusal::Unreachable`] when the exchange could not be
    /// made now, and [`RepositoryRefusal::Refused`] when the service
    /// refused the grant.
    pub(in crate::use_cases::workflows::sandboxes) async fn with_current_grant(
        mut self,
        grants: &AccountGrants,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
    ) -> Result<Self, RepositoryRefusal> {
        let holder = GrantHolder {
            id: &self.account.id,
            integration: &self.integration,
            credential: &self.account.credential,
        };
        self.account.credential = grants
            .current(tenant, auditor, holder)
            .await
            .map_err(refusal_of)?;
        Ok(self)
    }

    /// Keeps `renewal` on the account, recorded as the person `ctx` names.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when it cannot be kept.
    pub(in crate::use_cases::workflows::sandboxes) async fn keep_renewal(
        &self,
        renewing: &Renewing<'_>,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        renewal: Renewal,
    ) -> Result<(), AppError> {
        renewing.keep(ctx, auditor, &self.account.id, renewal).await
    }
}

/// How a call that was not sent is told as a repository refusing.
fn refusal_of(unsent: ActionOutcome) -> RepositoryRefusal {
    match unsent {
        ActionOutcome::Failed(why) => RepositoryRefusal::Refused(why),
        ActionOutcome::TurnedAway(why) => RepositoryRefusal::Unreachable(why),
        ActionOutcome::Succeeded { .. } | ActionOutcome::NotYet { .. } => {
            RepositoryRefusal::Unreachable(UntrustedText::record("the account was not ready"))
        }
    }
}
