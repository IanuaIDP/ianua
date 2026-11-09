//! Verify audit chain: show whether the tenant's audit log is untampered.
//!
//! The scheduled sweep walks the tenant's hash-linked records and keeps its
//! verdict. This answers that verdict, with when it was found, so an
//! auditor gets evidence that no record was removed, reordered or edited,
//! without walking a chain of millions of records inside their request.

use std::sync::Arc;

use ianua_domain::domains::audit::verdict::ChainVerdict;
use ianua_domain::domains::authorization::permission::{AuditLogAction, SystemPermission};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::audit::AuditChainVerdictStore;
use crate::use_case::Query;

/// The ports [`VerifyChainUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct VerifyChainPorts {
    /// The verdicts the sweep keeps.
    pub verdicts: Arc<dyn AuditChainVerdictStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Answers the last verdict on the caller's tenant's audit chain.
pub struct VerifyChainUseCase {
    ports: VerifyChainPorts,
}

impl VerifyChainUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: VerifyChainPorts) -> Self {
        Self { ports }
    }
}

impl Query for VerifyChainUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Option<ChainVerdict>, AppError>;

    /// The sweep's last verdict on the caller's tenant's audit chain: when
    /// it was found, whether the chain held and where it broke if not.
    /// `None` until the first sweep has walked it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not read the audit log.
    /// - `AppError::Internal` when the verdict cannot be read.
    async fn execute(&self, ctx: &CallerContext, (): ()) -> Result<Option<ChainVerdict>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::AuditLog(AuditLogAction::View))
            .map_err(AppError::from_domain)?;
        self.ports.verdicts.find(&ctx.tenant()).await.or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::checkpoint::ChainStart;
    use ianua_domain::domains::audit::verdict::ChainVerdictRow;
    use ianua_domain::domains::audit::walk::ChainStanding;
    use ianua_domain::shared::clock;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::audit::FakeChainVerdictStore;
    use crate::test_support::{block_on, test_ctx};

    fn verify(ports: VerifyChainPorts) -> Result<Option<ChainVerdict>, AppError> {
        block_on(VerifyChainUseCase::new(ports).execute(&test_ctx(), ()))
    }

    fn kept(standing: ChainStanding) -> Arc<FakeChainVerdictStore> {
        let store = FakeChainVerdictStore::default();
        let verdict = ChainVerdict::reconstitute(ChainVerdictRow {
            verified_at: clock::now(),
            standing,
            checkpoint: ChainStart::Genesis,
        })
        .unwrap();
        store.keep(test_ctx().tenant_id(), verdict);
        Arc::new(store)
    }

    /// Ann, an auditor, asks before the first sweep. She hears it is not
    /// verified yet, never that it is intact.
    #[test]
    fn a_chain_no_sweep_walked_is_not_verified_yet() {
        let verdict = verify(VerifyChainPorts::fakes()).unwrap();

        assert!(verdict.is_none());
    }

    /// Someone rewrote record 7, and last night's sweep found it. Ann reads
    /// that verdict, with where the chain breaks.
    #[test]
    fn the_last_sweeps_break_is_answered() {
        let verdict = verify(VerifyChainPorts {
            verdicts: kept(ChainStanding::BrokenAt(7)),
            ..VerifyChainPorts::fakes()
        })
        .unwrap()
        .unwrap();

        assert_eq!(verdict.standing(), ChainStanding::BrokenAt(7));
    }

    /// Reading an audit-chain verdict requires the audit-log view right.
    #[test]
    fn a_caller_who_may_not_read_the_audit_log_is_refused() {
        let result = verify(VerifyChainPorts {
            verdicts: kept(ChainStanding::Intact),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
        });

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read the audit-chain verdict.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = verify(VerifyChainPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..VerifyChainPorts::fakes()
        });

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// The verdict store cannot be read. Ann gets an internal error, not a
    /// chain reported unverified or intact.
    #[test]
    fn an_unreadable_verdict_is_internal() {
        let result = verify(VerifyChainPorts {
            verdicts: Arc::new(FakeChainVerdictStore::failing()),
            ..VerifyChainPorts::fakes()
        });

        assert!(matches!(result, Err(AppError::Internal(_))));
    }
}
