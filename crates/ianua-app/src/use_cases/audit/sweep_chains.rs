//! Sweep audit chains: verify every tenant's chain on a schedule, and keep
//! what was found.
//!
//! A tamper-evident chain that is only checked when someone asks proves
//! nothing until someone asks. This walks every tenant's chain from the
//! last link the previous sweep verified, a bounded stretch at a time, and
//! keeps the verdict and the new checkpoint. A record is rehashed once, not
//! on every sweep, and an auditor reads the kept verdict instead of walking
//! the chain in their request. A chain found broken for the first time
//! raises `tenant.audit_chain_broken`, so a rewritten record reaches
//! whoever watches the tenant within one sweep.
//!
//! It runs outside any request, for nobody, so no one's rights are asked.

use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_domain::domains::audit::verdict::{ChainHistory, ChainVerdict};
use ianua_domain::domains::audit::walk::{ChainStanding, ChainWalked, WalkStep};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::ActorRef;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::audit::{AuditChainVerdictStore, AuditChainVerifier};
use crate::ports::tenant::TenantStore;
use crate::services::tenant_batches::TenantBatches;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// How many records one stretch of a walk rehashes.
const STRETCH: NonZeroU32 = NonZeroU32::MIN.saturating_add(999);

/// How many stretches one tenant's walk takes per sweep. A longer chain is
/// finished on the next sweep, from where this one paused, so one large
/// tenant never holds the others back.
const STRETCHES_PER_SWEEP: u32 = 200;

/// What one sweep found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Tenants whose chain verified intact, to its end or as far as this
    /// sweep walked.
    pub intact: u64,
    /// Tenants whose chain is broken.
    pub broken: u64,
    /// Tenants whose chain could not be read, or whose verdict could not be
    /// kept, this time.
    pub unverified: u64,
}

/// What verifying one tenant's chain found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainOutcome {
    /// The chain verified.
    Intact,
    /// The chain is broken.
    Broken,
    /// The chain could not be read, or the verdict kept, this time.
    Unverified,
}

impl SweepReport {
    /// This report with one more tenant's outcome counted.
    fn counting(mut self, outcome: ChainOutcome) -> Self {
        match outcome {
            ChainOutcome::Intact => self.intact += 1,
            ChainOutcome::Broken => self.broken += 1,
            ChainOutcome::Unverified => self.unverified += 1,
        }
        self
    }
}

/// Ports needed by the sweep.
#[derive(ianua_macros::Fakes)]
pub struct SweepChainsPorts {
    /// Lists the tenants to verify.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Rehashes one stretch of a tenant's chain.
    pub verifier: Arc<dyn AuditChainVerifier>,
    /// Keeps each tenant's last verdict and checkpoint.
    pub verdicts: Arc<dyn AuditChainVerdictStore>,
}

/// Verifies every live tenant's audit chain past its last checkpoint.
pub struct SweepChainsUseCase {
    ports: SweepChainsPorts,
}

impl SweepChainsUseCase {
    /// Creates the sweep.
    #[must_use]
    pub fn new(ports: SweepChainsPorts) -> Self {
        Self { ports }
    }

    /// Verifies one tenant's chain from its last checkpoint, announces a
    /// new break through `auditor`, and keeps the verdict.
    ///
    /// A chain that cannot be read, or a verdict that cannot be kept, is
    /// logged and counted as unverified rather than failing the sweep: it
    /// is walked again next time, and the other tenants still get checked.
    async fn sweep_one(
        &self,
        tenant_id: &ScopedTenant,
        auditor: &RequestAuditor,
    ) -> Result<ChainOutcome, AppError> {
        let (history, walked) = match self.walked(tenant_id).await {
            Ok(found) => found,
            Err(e) => {
                tracing::warn!(tenant_id = %**tenant_id, error = %e, "audit chain could not be verified");
                return Ok(ChainOutcome::Unverified);
            }
        };
        self.announce(tenant_id, &history, &walked, auditor).await?;
        Ok(self.kept(tenant_id, &walked).await)
    }

    /// Keeps what `walked` found as the tenant's verdict and checkpoint,
    /// and answers how the tenant counts. A verdict that cannot be kept
    /// counts the tenant unverified; the next sweep walks the same stretch
    /// again.
    async fn kept(&self, tenant_id: &ScopedTenant, walked: &ChainWalked) -> ChainOutcome {
        let verdict = ChainVerdict::of(walked, clock::now());
        if let Err(e) = self.ports.verdicts.save(tenant_id, &verdict).await {
            tracing::warn!(tenant_id = %**tenant_id, error = %e, "audit chain verdict could not be kept");
            return ChainOutcome::Unverified;
        }
        outcome_of(walked.standing())
    }

    /// What is known of the tenant's chain, and this sweep's walk of it
    /// from there, one stretch at a time up to the sweep's budget.
    async fn walked(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<(ChainHistory, ChainWalked), DomainError> {
        let history = self
            .ports
            .verdicts
            .find(tenant_id)
            .await?
            .map_or(ChainHistory::NeverVerified, ChainHistory::Verified);
        let mut walk = history.walk();
        for _ in 0..STRETCHES_PER_SWEEP {
            let stretch = self
                .ports
                .verifier
                .verify_stretch(tenant_id, walk.start(), STRETCH)
                .await?;
            walk = match walk.take(stretch) {
                WalkStep::Onward(next) => next,
                WalkStep::Done(walked) => return Ok((history, walked)),
            };
        }
        Ok((history, walk.paused()))
    }

    /// Records `tenant.audit_chain_broken` for a break the last verdict
    /// did not already hold, scoped to the tenant and attributed to the
    /// system.
    async fn announce(
        &self,
        tenant_id: &ScopedTenant,
        history: &ChainHistory,
        walked: &ChainWalked,
        auditor: &RequestAuditor,
    ) -> Result<(), AppError> {
        let events = history.alarm(walked, tenant_id);
        if events.is_empty() {
            return Ok(());
        }
        tracing::error!(tenant_id = %**tenant_id, standing = walked.standing().as_str(), "audit chain is broken");
        auditor
            .with_tenant(**tenant_id)
            .dispatch_by(&ActorRef::System, events)
            .await
            .or_internal()
    }
}

impl Command for SweepChainsUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<SweepReport, AppError>;

    /// Verifies every tenant's chain past its last checkpoint once, keeps
    /// each verdict, and records `tenant.audit_chain_broken` for each break
    /// first found through `auditor`, scoped to that tenant and attributed
    /// to the system.
    ///
    /// One tenant whose chain cannot be read does not stop the others; it is
    /// counted as unverified and walked again next sweep.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` when the tenant list cannot be read, or a
    /// new break cannot be announced. An alarm that fails to sound must not
    /// be reported as a quiet sweep.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<SweepReport, AppError> {
        let mut report = SweepReport::default();
        let mut tenants = TenantBatches::over(self.ports.tenant_store.as_ref());
        while let Some(batch) = tenants.next().await? {
            for tenant in &batch {
                let tenant_id = ScopedTenant::for_background(*tenant.id());
                report = report.counting(self.sweep_one(&tenant_id, auditor).await?);
            }
        }
        Ok(report)
    }
}

/// The count a walk that left the chain `standing` goes under.
fn outcome_of(standing: ChainStanding) -> ChainOutcome {
    match standing {
        ChainStanding::Intact | ChainStanding::IntactSoFar => ChainOutcome::Intact,
        ChainStanding::BrokenAt(_) => ChainOutcome::Broken,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::checkpoint::ChainStart;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::audit::{FakeChainVerdictStore, ScriptedChain};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant};
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, block_on, test_auditor,
    };

    struct Sweep {
        uc: SweepChainsUseCase,
        chain: Arc<ScriptedChain>,
        verdicts: Arc<FakeChainVerdictStore>,
        dispatcher: Arc<FakeEventDispatcher>,
        tenants: Vec<TenantId>,
    }

    fn sweep(count: usize) -> Sweep {
        let store = Arc::new(FakeTenantStore::empty());
        let tenants: Vec<TenantId> = (0..count)
            .map(|n| {
                let tenant = test_tenant(&format!("t{n}"), &format!("t{n}.example.com"));
                let id = *tenant.id();
                block_on(store.save(&tenant)).unwrap();
                id
            })
            .collect();
        let chain = Arc::new(ScriptedChain::default());
        let verdicts = Arc::new(FakeChainVerdictStore::default());
        Sweep {
            uc: SweepChainsUseCase::new(SweepChainsPorts {
                tenant_store: store,
                verifier: chain.clone(),
                verdicts: verdicts.clone(),
            }),
            chain,
            verdicts,
            dispatcher: Arc::new(FakeEventDispatcher::new()),
            tenants,
        }
    }

    impl Sweep {
        fn run(&self) -> Result<SweepReport, AppError> {
            block_on(
                self.uc
                    .execute(&(), &test_auditor(self.dispatcher.clone()), ()),
            )
        }

        fn announced(&self) -> Vec<String> {
            self.dispatcher.records.lock().unwrap().clone()
        }
    }

    /// Three tenants' chains of 2,500 records all verify. The sweep counts
    /// them intact, raises nothing, and keeps record 2,500 as each one's
    /// checkpoint.
    #[test]
    fn intact_chains_are_kept_with_their_checkpoint() {
        let s = sweep(3);
        for tenant in &s.tenants {
            s.chain.holding(*tenant, 2_500);
        }

        let report = s.run().unwrap();

        assert_eq!(report.intact, 3);
        assert!(s.announced().is_empty());
        let kept = s.verdicts.kept(s.tenants[0]).unwrap();
        assert_eq!(kept.standing(), ChainStanding::Intact);
        assert_eq!(kept.checkpoint().verified_through(), Some(2_500));
    }

    /// The last sweep verified Acme's chain through record 2,500 and 100
    /// records were written since. This sweep rehashes only those 100.
    #[test]
    fn a_sweep_verifies_only_past_the_last_checkpoint() {
        let s = sweep(1);
        s.chain.holding(s.tenants[0], 2_500);
        s.run().unwrap();
        s.chain.holding(s.tenants[0], 2_600);
        s.chain.forget_reads();

        s.run().unwrap();

        assert_eq!(s.chain.records_read(), 100);
        let kept = s.verdicts.kept(s.tenants[0]).unwrap();
        assert_eq!(kept.checkpoint().verified_through(), Some(2_600));
    }

    /// Someone rewrote record 42 of the second tenant's chain. The sweep
    /// announces that tenant's broken chain, and only that one, and keeps
    /// where it broke.
    #[test]
    fn a_broken_chain_is_announced_and_kept() {
        let s = sweep(3);
        for tenant in &s.tenants {
            s.chain.holding(*tenant, 100);
        }
        s.chain.breaking(s.tenants[1], 42);

        let report = s.run().unwrap();

        assert_eq!(report.broken, 1);
        assert_eq!(report.intact, 2);
        assert_eq!(s.announced(), ["tenant.audit_chain_broken"]);
        let kept = s.verdicts.kept(s.tenants[1]).unwrap();
        assert_eq!(kept.standing(), ChainStanding::BrokenAt(42));
    }

    /// The break at record 42 was announced last sweep. This sweep finds it
    /// again and keeps it, but nobody is told twice.
    #[test]
    fn a_known_break_is_not_announced_again() {
        let s = sweep(1);
        s.chain.holding(s.tenants[0], 100);
        s.chain.breaking(s.tenants[0], 42);
        s.run().unwrap();

        let report = s.run().unwrap();

        assert_eq!(report.broken, 1);
        assert_eq!(s.announced(), ["tenant.audit_chain_broken"]);
    }

    /// A chain of 500,000 records is more than one sweep walks. The sweep
    /// pauses it intact so far, and the next one goes on from there.
    #[test]
    fn a_long_chain_is_finished_over_several_sweeps() {
        let s = sweep(1);
        s.chain.holding(s.tenants[0], 500_000);

        s.run().unwrap();
        let first = s.verdicts.kept(s.tenants[0]).unwrap();
        s.run().unwrap();
        let second = s.verdicts.kept(s.tenants[0]).unwrap();
        s.run().unwrap();

        assert_eq!(first.standing(), ChainStanding::IntactSoFar);
        assert_eq!(first.checkpoint().verified_through(), Some(200_000));
        assert_eq!(second.checkpoint().verified_through(), Some(400_000));
        let third = s.verdicts.kept(s.tenants[0]).unwrap();
        assert_eq!(third.standing(), ChainStanding::Intact);
    }

    /// The first tenant's chain cannot be read and the third's is broken.
    /// The first is counted unverified and keeps no verdict, and the sweep
    /// still reaches the third and announces it.
    #[test]
    fn one_unreadable_chain_does_not_stop_the_sweep() {
        let s = sweep(3);
        for tenant in &s.tenants {
            s.chain.holding(*tenant, 10);
        }
        s.chain.unreachable(s.tenants[0]);
        s.chain.breaking(s.tenants[2], 7);

        let report = s.run().unwrap();

        assert_eq!(report.unverified, 1);
        assert_eq!(report.broken, 1, "the tenants after it were still checked");
        assert!(s.verdicts.kept(s.tenants[0]).is_none());
    }

    /// A chain is broken, but the audit sink is down, so the alarm cannot be
    /// recorded. The sweep fails rather than reporting a quiet run, and keeps
    /// no verdict that would silence the next one.
    #[test]
    fn an_alarm_that_cannot_sound_fails_the_sweep() {
        let s = sweep(1);
        s.chain.holding(s.tenants[0], 10);
        s.chain.breaking(s.tenants[0], 3);

        let result =
            block_on(s.uc.execute(&(), &test_auditor(Arc::new(FailingEventDispatcher)), ()));

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert!(s.verdicts.kept(s.tenants[0]).is_none());
    }

    /// A tenant's chain holds no record yet. It is intact, with nothing
    /// verified to start after.
    #[test]
    fn an_empty_chain_is_intact() {
        let s = sweep(1);

        s.run().unwrap();

        let kept = s.verdicts.kept(s.tenants[0]).unwrap();
        assert_eq!(kept.standing(), ChainStanding::Intact);
        assert_eq!(kept.checkpoint(), &ChainStart::Genesis);
    }
}
