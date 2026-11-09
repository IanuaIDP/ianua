//! Keeping a credential a service renewed during a call a person made
//! through an account, such as filling a picker or reading a repository's
//! file: the renewed one replaces the old, which may no longer work, with
//! its record, all or nothing.

use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::IntegrationAccountId;

use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{IntegrationAccountStore, Renewal};
use crate::services::kept_together::kept_together;

/// Where a renewed credential is kept.
pub(crate) struct Renewing<'a> {
    /// The tenant's integration accounts.
    pub(crate) accounts: &'a dyn IntegrationAccountStore,
    /// Keeps the account and its record together.
    pub(crate) unit_of_work: &'a dyn UnitOfWork,
}

impl Renewing<'_> {
    /// Keeps `renewal` on account `id` of the tenant `ctx` acts in,
    /// recorded as the person `ctx` names. An account removed in the
    /// meantime keeps nothing.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when it cannot be read or kept.
    pub(crate) async fn keep(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: &IntegrationAccountId,
        renewal: Renewal,
    ) -> Result<(), AppError> {
        let Renewal::Renewed(renewed) = renewal else {
            return Ok(());
        };
        let tenant = ctx.tenant();
        let Some(mut kept) = self.accounts.find_by_id(&tenant, id).await.or_internal()? else {
            return Ok(());
        };
        kept.renew_credential(renewed);
        kept_together(self.unit_of_work, async {
            self.accounts.save(&tenant, &kept).await.or_internal()?;
            auditor
                .dispatch_by(&ctx.actor(), kept.take_events(&tenant))
                .await
                .or_internal()
        })
        .await
    }
}
