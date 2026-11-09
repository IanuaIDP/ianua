//! Run clone: the worker copies each part a clone names, and records it
//! copied or the clone failed.
//!
//! The worker runs it from the clone's job, queued when the clone started,
//! again when the job is retried, and again when the reconciliation sweep
//! finds the clone left copying. Each part is saved as copied as soon as it
//! is, so a worker that stops half-way starts again at the first part not
//! yet copied, and copied in one unit, so one that fails half way leaves
//! nothing of itself in the target. A clone that has ended is left as it
//! is.
//!
//! It runs outside any request, for nobody: whoever started the clone held
//! the right to make tenants, and the clone vouches for it.

use std::sync::Arc;

use ianua_domain::domains::tenant::clone::{CloneFailure, ClonePart, CloneState, TenantClone};
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::domains::tenant::status::TenantStatus;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, TenantCloneId, TenantId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::{Settlement, UnitOfWork, atomically};
use crate::ports::tenant::{ClonePartCopier, TenantCloneStore, TenantStore};
use crate::use_case::Command;
use crate::use_cases::tenant::clones::lookup::existing_clone;

/// The ports [`RunUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RunPorts {
    /// Tenants, both copied from and filled.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Where clones are kept.
    pub clone_store: Arc<dyn TenantCloneStore>,
    /// Copies every part but the tenant's own settings.
    pub copier: Arc<dyn ClonePartCopier>,
    /// Keeps each part's copy whole: all of it or none.
    pub unit: Arc<dyn UnitOfWork>,
}

/// Copies the parts a clone still has to copy.
pub struct RunUseCase {
    ports: RunPorts,
}

/// How copying one part went.
#[derive(Clone, Copy)]
enum PartOutcome {
    /// It was copied.
    Copied,
    /// The clone cannot go on, for this reason.
    Stopped(CloneFailure),
}

/// The two tenants of a clone, while the copy can still go on.
enum Pair {
    /// Both are there to copy between.
    Ready {
        /// The tenant copied from.
        source: Box<Tenant>,
        /// The tenant filled.
        target: Box<Tenant>,
    },
    /// One of them is gone, for this reason.
    Gone(CloneFailure),
}

impl RunUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RunPorts) -> Self {
        Self { ports }
    }

    /// Copies each remaining part of `clone` in turn, saving and recording
    /// after each, until every part is copied or the clone stops.
    async fn copy_remaining(
        &self,
        clone: &mut TenantClone,
        auditor: &RequestAuditor,
    ) -> Result<(), AppError> {
        for part in clone.remaining() {
            let outcome = self.copy_part(clone, part, auditor).await?;
            settle(clone, part, outcome)?;
            self.ports.clone_store.save(clone).await.or_internal()?;
            auditor
                .dispatch_by(&ActorRef::System, clone.take_events())
                .await
                .or_internal()?;
            if clone.state() != CloneState::Copying {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Copies `part` of `clone`, or says why the clone cannot go on.
    async fn copy_part(
        &self,
        clone: &TenantClone,
        part: ClonePart,
        auditor: &RequestAuditor,
    ) -> Result<PartOutcome, AppError> {
        let (source, mut target) = match self.pair(clone).await? {
            Pair::Ready { source, target } => (source, target),
            Pair::Gone(reason) => return Ok(PartOutcome::Stopped(reason)),
        };
        if part == ClonePart::Settings {
            return self
                .copy_settings(&source, &mut target, clone, auditor)
                .await;
        }
        self.copied_whole(clone, part).await
    }

    /// Copies `part` of `clone` in one unit, so a part that fails half way
    /// leaves none of it in the target, and says how it went.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when what was copied cannot be committed; the
    /// worker runs the clone again from this part.
    async fn copied_whole(
        &self,
        clone: &TenantClone,
        part: ClonePart,
    ) -> Result<PartOutcome, AppError> {
        let copied = atomically(
            self.ports.unit.as_ref(),
            self.ports.copier.copy(clone, part),
            |copied| match copied {
                Ok(()) => Settlement::Commit,
                Err(_) => Settlement::Rollback,
            },
        )
        .await
        .or_internal()?;
        Ok(copied_or_stopped(copied))
    }

    /// Copies the source's settings into the target through the target
    /// itself, and records what changed in it.
    async fn copy_settings(
        &self,
        source: &Tenant,
        target: &mut Tenant,
        clone: &TenantClone,
        auditor: &RequestAuditor,
    ) -> Result<PartOutcome, AppError> {
        if let Err(error) = target.copy_settings_from(source, clone) {
            tracing::warn!(clone_id = %clone.id(), %error, "clone: settings not copied");
            return Ok(PartOutcome::Stopped(CloneFailure::CopyFailed));
        }
        self.ports.tenant_store.save(target).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::System, target.take_events())
            .await
            .or_internal()?;
        Ok(PartOutcome::Copied)
    }

    /// The clone's two tenants, read fresh, or which of them is gone.
    async fn pair(&self, clone: &TenantClone) -> Result<Pair, AppError> {
        let Some(source) = self.tenant(clone.source()).await? else {
            return Ok(Pair::Gone(CloneFailure::SourceGone));
        };
        if is_closed(&source) {
            return Ok(Pair::Gone(CloneFailure::SourceGone));
        }
        let Some(target) = self.tenant(clone.target()).await? else {
            return Ok(Pair::Gone(CloneFailure::TargetGone));
        };
        if !target.status().is_open() {
            return Ok(Pair::Gone(CloneFailure::TargetGone));
        }
        Ok(Pair::Ready {
            source: Box::new(source),
            target: Box::new(target),
        })
    }

    /// The tenant `id`, or `None` when it is gone.
    async fn tenant(&self, id: &TenantId) -> Result<Option<Tenant>, AppError> {
        self.ports.tenant_store.find_by_id(id).await.or_internal()
    }
}

impl Command for RunUseCase {
    type Caller = ();
    type Input = TenantCloneId;
    type Output = Result<CloneState, AppError>;

    /// Copies every part the clone `id` has still to copy, recording
    /// `tenant.clone_completed` once the last is copied, or
    /// `tenant.clone_failed` when a tenant is gone or a part cannot be
    /// copied. What was copied stays. Returns where the clone ended up.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when there is no such clone.
    /// - `AppError::Internal` when a store or the audit fails; the worker
    ///   runs it again, and it starts at the first part not yet copied.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        id: TenantCloneId,
    ) -> Result<CloneState, AppError> {
        let mut clone = existing_clone(self.ports.clone_store.as_ref(), &id).await?;
        if clone.state() != CloneState::Copying {
            return Ok(clone.state());
        }
        let auditor = auditor.with_tenant(*clone.target());
        self.copy_remaining(&mut clone, &auditor).await?;
        Ok(clone.state())
    }
}

/// Records `outcome` of copying `part` on `clone`.
///
/// # Errors
///
/// - `AppError::Conflict` when the clone has already ended.
fn settle(clone: &mut TenantClone, part: ClonePart, outcome: PartOutcome) -> Result<(), AppError> {
    let settled = match outcome {
        PartOutcome::Copied => clone.mark_copied(part),
        PartOutcome::Stopped(reason) => clone.fail(reason),
    };
    settled.map_err(AppError::from_domain)
}

/// What the copier's answer means for the clone. A failed copy is logged
/// and stops the clone.
fn copied_or_stopped(copied: Result<(), DomainError>) -> PartOutcome {
    let Err(error) = copied else {
        return PartOutcome::Copied;
    };
    tracing::warn!(%error, "clone: part not copied");
    PartOutcome::Stopped(CloneFailure::CopyFailed)
}

/// Whether `tenant` was closed, so its setup is no longer copied.
fn is_closed(tenant: &Tenant) -> bool {
    matches!(
        tenant.status(),
        TenantStatus::Archived | TenantStatus::Deleted
    )
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::status::PlatformHold;
    use ianua_domain::types::ActedBy;

    use super::*;
    use crate::test_support::tenant::{
        FakeClonePartCopier, FakeTenantCloneStore, FakeTenantStore, archived_tenant_for_ctx,
        test_tenant_for_ctx, test_tenant_in,
    };
    use crate::test_support::{
        FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor, test_ctx,
    };

    struct Setup {
        uc: RunUseCase,
        clones: Arc<FakeTenantCloneStore>,
        copier: Arc<FakeClonePartCopier>,
        unit: Arc<RecordingUnitOfWork>,
        audit: Arc<FakeEventDispatcher>,
        id: TenantCloneId,
    }

    impl Setup {
        fn over(source: Tenant, parts: Vec<ClonePart>, copier: FakeClonePartCopier) -> Self {
            let target =
                test_tenant_in(test_ctx().organization_id(), "staging", "staging.acme.com");
            let clone =
                TenantClone::start(parts, &test_tenant_for_ctx(), &target, ActedBy::Platform)
                    .unwrap();
            let id = *clone.id();
            let clones = Arc::new(FakeTenantCloneStore::empty());
            block_on(clones.save(&clone)).unwrap();
            let copier = Arc::new(copier);
            let unit = Arc::new(RecordingUnitOfWork::default());
            Self {
                uc: RunUseCase::new(RunPorts {
                    tenant_store: Arc::new(FakeTenantStore::holding_all([source, target])),
                    clone_store: clones.clone(),
                    copier: copier.clone(),
                    unit: unit.clone(),
                }),
                clones,
                copier,
                unit,
                audit: Arc::new(FakeEventDispatcher::new()),
                id,
            }
        }

        fn new(parts: Vec<ClonePart>) -> Self {
            Self::over(test_tenant_for_ctx(), parts, FakeClonePartCopier::copying())
        }

        fn run(&self) -> CloneState {
            block_on(
                self.uc
                    .execute(&(), &test_auditor(self.audit.clone()), self.id),
            )
            .unwrap()
        }

        fn stored(&self) -> TenantClone {
            self.clones.stored(&self.id).unwrap()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann's clone copies settings and routes into staging. The worker
    /// copies the settings through the tenant, hands the routes to the
    /// copier, and completes the clone.
    #[test]
    fn every_part_is_copied_and_the_clone_completes() {
        let setup = Setup::new(vec![ClonePart::Settings, ClonePart::Routes]);

        let state = setup.run();

        assert!(matches!(state, CloneState::Completed { .. }));
        assert_eq!(setup.copier.copied(), [ClonePart::Routes]);
        assert_eq!(setup.stored().copied().len(), 2);
        assert_eq!(
            setup.recorded(),
            vec![
                "tenant.auth_config_updated",
                "tenant.mtls_config_updated",
                "tenant.clone_completed"
            ]
        );
    }

    /// The copier cannot copy the routes. The clone fails, the branding
    /// copied before it stays, what the routes wrote is rolled back, and the
    /// failure is recorded.
    #[test]
    fn a_part_that_cannot_be_copied_fails_the_clone() {
        let setup = Setup::over(
            test_tenant_for_ctx(),
            vec![ClonePart::Branding, ClonePart::Routes],
            FakeClonePartCopier::failing_on(ClonePart::Routes),
        );

        let state = setup.run();

        assert!(matches!(
            state,
            CloneState::Failed {
                reason: CloneFailure::CopyFailed,
                ..
            }
        ));
        assert_eq!(setup.stored().copied(), [ClonePart::Branding]);
        assert_eq!(setup.recorded(), vec!["tenant.clone_failed"]);
        assert_eq!(
            setup.unit.settlements(),
            [Settlement::Commit, Settlement::Rollback]
        );
    }

    /// Production was archived after Ann started the clone. Nothing more is
    /// copied out of it, and the clone fails as its source is gone.
    #[test]
    fn a_closed_source_fails_the_clone() {
        let setup = Setup::over(
            archived_tenant_for_ctx(1, PlatformHold::Free),
            vec![ClonePart::Routes],
            FakeClonePartCopier::copying(),
        );

        let state = setup.run();

        assert!(matches!(
            state,
            CloneState::Failed {
                reason: CloneFailure::SourceGone,
                ..
            }
        ));
        assert!(setup.copier.copied().is_empty());
    }

    /// The worker is told about the clone twice. The second run finds it
    /// complete and copies nothing again.
    #[test]
    fn a_clone_that_has_ended_is_left_as_it_is() {
        let setup = Setup::new(vec![ClonePart::Routes]);
        setup.run();

        let state = setup.run();

        assert!(matches!(state, CloneState::Completed { .. }));
        assert_eq!(setup.copier.copied(), [ClonePart::Routes]);
        assert_eq!(setup.recorded(), vec!["tenant.clone_completed"]);
    }

    /// The worker names a clone nobody started. It is not found.
    #[test]
    fn an_unknown_clone_is_not_found() {
        let uc = RunUseCase::new(RunPorts::fakes());

        let result = block_on(uc.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            TenantCloneId::new(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
