//! Carrying out members' erasures whose grace period has ended.
//!
//! A member who asks to be forgotten gets a grace period to change their
//! mind. Once it has passed, this removes their account, the sessions it
//! held and what it granted, on a schedule, without anyone having to
//! remember to.
//!
//! What the audit log records about an erasure names the member by their id
//! only. The records are permanent, so a name or an address written into
//! them here would outlive the very data the member asked to have removed.

use std::sync::Arc;

use ianua_domain::domains::identity::privacy::erasure_status::ErasureStatus;
use ianua_domain::domains::organization::members::privacy::erasure::OrgErasureRequest;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::ActorRef;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::{ErasureBatch, ErasurePosition};
use crate::ports::organization::{OrgErasureRequestStore, OrgSessionStore, OrgUserStore};
use crate::ports::runtime::UnitOfWork;
use crate::services::authorization::grant_revocation::OrgGrantRevocation;
use crate::services::kept_together::kept_together;
use crate::use_case::Command;
use crate::use_cases::organization::sign_in::sessions::sign_out::sign_out_member;

/// What one run carried out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OrgErasureReport {
    /// Erasures carried out in full.
    pub completed: u64,
    /// Erasures that failed this time; each is tried again next run.
    pub failed: u64,
}

/// How one erasure ended this run.
enum Outcome {
    Completed,
    Failed,
}

/// The ports [`ProcessOrgErasuresUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ProcessOrgErasuresPorts {
    /// Finds and records members' erasure requests.
    pub erasures: Arc<dyn OrgErasureRequestStore>,
    /// Deletes the member's account.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Members' sessions, ended before the account goes.
    pub org_sessions: Arc<dyn OrgSessionStore>,
    /// Revokes what the member granted, in every tenant.
    pub grant_revocation: OrgGrantRevocation,
    /// Keeps each erasure's changes and the records of them together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Carries out every member's erasure that is due.
pub struct ProcessOrgErasuresUseCase {
    ports: ProcessOrgErasuresPorts,
}

impl ProcessOrgErasuresUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ProcessOrgErasuresPorts) -> Self {
        Self { ports }
    }

    /// Attempts a bounded set once, keeping each erasure and its audit atomic.
    async fn process_batch(
        &self,
        auditor: &RequestAuditor,
        due: Vec<OrgErasureRequest>,
        now: OffsetDateTime,
    ) -> Result<OrgErasureReport, AppError> {
        let mut report = OrgErasureReport::default();
        for request in due {
            let carried_out = self.carry_out(auditor, request, now);
            match kept_together(self.ports.unit_of_work.as_ref(), carried_out).await? {
                Outcome::Completed => report.completed = report.completed.saturating_add(1),
                Outcome::Failed => report.failed = report.failed.saturating_add(1),
            }
        }
        Ok(report)
    }

    /// Takes one erasure through to completed or failed, recording each
    /// step against its organization.
    async fn carry_out(
        &self,
        auditor: &RequestAuditor,
        mut request: OrgErasureRequest,
        now: OffsetDateTime,
    ) -> Result<Outcome, AppError> {
        let auditor = auditor.with_organization(*request.organization_id());
        self.begin(&auditor, &mut request, now).await?;
        let Ok(revoked) = self.erase_member(&request).await else {
            tracing::error!(
                organization_id = %request.organization_id(),
                org_user_id = %request.org_user_id(),
                "member erasure failed; retried next run"
            );
            request
                .fail()
                .map_err(|error| AppError::from_domain(error.into()))?;
            self.save_and_record(&auditor, &mut request, Vec::new())
                .await?;
            return Ok(Outcome::Failed);
        };
        request
            .complete()
            .map_err(|error| AppError::from_domain(error.into()))?;
        self.save_and_record(&auditor, &mut request, revoked)
            .await?;
        Ok(Outcome::Completed)
    }

    /// Marks the erasure as being carried out, a first attempt or a retry
    /// of one that failed, and records that it started.
    async fn begin(
        &self,
        auditor: &RequestAuditor,
        request: &mut OrgErasureRequest,
        now: OffsetDateTime,
    ) -> Result<(), AppError> {
        let begun = match request.status() {
            ErasureStatus::Failed => request.retry().map_err(DomainError::from),
            _ => request.start_processing(now),
        };
        begun.map_err(AppError::from_domain)?;
        self.save_and_record(auditor, request, Vec::new()).await
    }

    /// Removes the member's account, the sessions it held and what it
    /// granted, returning the records of what was revoked.
    async fn erase_member(
        &self,
        request: &OrgErasureRequest,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let member = request.org_user_id();
        let revoked = self
            .ports
            .grant_revocation
            .revoke_all_granted_by(request.organization_id(), member, &ActorRef::System)
            .await
            .or_internal()?;
        sign_out_member(self.ports.org_sessions.as_ref(), member).await?;
        self.ports.org_users.delete(member).await.or_internal()?;
        Ok(revoked)
    }

    /// Saves `request` and records what it raised, with `also`, by the
    /// platform.
    async fn save_and_record(
        &self,
        auditor: &RequestAuditor,
        request: &mut OrgErasureRequest,
        also: Vec<DomainEvent>,
    ) -> Result<(), AppError> {
        self.ports.erasures.save(request).await.or_internal()?;
        let mut events = request.take_events();
        events.extend(also);
        auditor
            .dispatch_by(&ActorRef::System, events)
            .await
            .or_internal()
    }
}

impl Command for ProcessOrgErasuresUseCase {
    type Caller = ();
    type Input = OffsetDateTime;
    type Output = Result<OrgErasureReport, AppError>;

    /// Carries out every member's erasure due by `now`, in every
    /// organization, and records `organization.org_user_erasure_started`
    /// and then `organization.org_user_erasure_completed` or
    /// `organization.org_user_erasure_failed` for each, by the platform.
    ///
    /// An erasure that fails is marked failed and tried again on the next
    /// run; it does not stop the others.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if a due erasure refuses the status change it
    ///   is taken through.
    /// - `AppError::Internal` when the due erasures cannot be read, or
    ///   what was done cannot be recorded.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        now: OffsetDateTime,
    ) -> Result<OrgErasureReport, AppError> {
        let mut report = OrgErasureReport::default();
        let mut batch = ErasureBatch::first(now);
        loop {
            let due = self.ports.erasures.find_due(batch).await.or_internal()?;
            let count = due.len();
            batch.after = due.last().map(|request| ErasurePosition {
                scheduled_at: request.scheduled_at(),
                id: *request.id(),
            });
            let finished = self.process_batch(auditor, due, now).await?;
            report.completed = report.completed.saturating_add(finished.completed);
            report.failed = report.failed.saturating_add(finished.failed);
            if count < ErasureBatch::LIMIT {
                return Ok(report);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::privacy::erasure::ErasureState;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{ErasureRequestId, OrgUserId};

    use super::*;
    use crate::test_support::organization::{
        FakeOrgErasureStore, FakeOrgUserStore, RecordingOrgSessionStore, org_user_store_with,
        stored_org_erasure, test_org_member_at,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Run {
        report: OrgErasureReport,
        users: Arc<FakeOrgUserStore>,
        erasures: Arc<FakeOrgErasureStore>,
        sessions: Arc<RecordingOrgSessionStore>,
        audit: Arc<FakeEventDispatcher>,
        sam: OrgUserId,
    }

    /// Sam's erasure, asked `days_ago` days ago with fourteen days' grace,
    /// standing at `state`, and a run over it now.
    fn run_over(days_ago: i64, state: ErasureState) -> (Run, ErasureRequestId) {
        let sam = test_org_member_at(
            test_org_caller().organization_id(),
            "sam@acme.test",
            OrgUserStatus::Closing,
        );
        let erasure = stored_org_erasure(&sam, (days_ago, 14), state);
        let (id, sam_id) = (*erasure.id(), *sam.id());
        let users = Arc::new(org_user_store_with([sam]));
        let erasures = Arc::new(FakeOrgErasureStore::holding([erasure]));
        let sessions = Arc::new(RecordingOrgSessionStore::new());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = ProcessOrgErasuresUseCase::new(ProcessOrgErasuresPorts {
            erasures: erasures.clone(),
            org_users: users.clone(),
            org_sessions: sessions.clone(),
            ..ProcessOrgErasuresPorts::fakes()
        });
        let report =
            block_on(use_case.execute(&(), &test_auditor(audit.clone()), clock::now())).unwrap();
        let run = Run {
            report,
            users,
            erasures,
            sessions,
            audit,
            sam: sam_id,
        };
        (run, id)
    }

    /// Sam's grace period ended yesterday. His account is deleted, his
    /// sessions end, the erasure completes, and both steps are recorded.
    #[test]
    fn a_due_erasure_removes_the_member() {
        let (run, id) = run_over(15, ErasureState::Pending);

        assert_eq!(run.report.completed, 1);
        assert_eq!(run.users.count(), 0);
        assert_eq!(run.erasures.status_of(&id), Some(ErasureStatus::Completed));
        assert!(run.sessions.revoked(&run.sam));
        assert_eq!(
            *run.audit.records.lock().unwrap(),
            [
                "organization.org_user_erasure_started",
                "organization.org_user_erasure_completed"
            ]
        );
    }

    /// A backlog spans more than one read. Every member is erased once,
    /// sessions end and both audit steps remain, while reads stay bounded.
    #[test]
    fn organization_erasures_are_read_in_bounded_batches() {
        let members = closing_members();
        let requests = members
            .iter()
            .map(|member| stored_org_erasure(member, (15, 14), ErasureState::Pending));
        let erasures = Arc::new(FakeOrgErasureStore::holding(requests));
        let member_ids: Vec<_> = members.iter().map(|member| *member.id()).collect();
        let users = Arc::new(org_user_store_with(members));
        let audit = Arc::new(FakeEventDispatcher::new());
        let sessions = Arc::new(RecordingOrgSessionStore::new());
        let use_case = ProcessOrgErasuresUseCase::new(ProcessOrgErasuresPorts {
            erasures: erasures.clone(),
            org_users: users.clone(),
            org_sessions: sessions.clone(),
            ..ProcessOrgErasuresPorts::fakes()
        });

        let report =
            block_on(use_case.execute(&(), &test_auditor(audit.clone()), clock::now())).unwrap();

        assert_eq!(
            report,
            OrgErasureReport {
                completed: 501,
                failed: 0
            }
        );
        assert_eq!(users.count(), 0);
        assert_eq!(audit.records.lock().unwrap().len(), 1002);
        assert!(member_ids.iter().all(|id| sessions.revoked(id)));
        assert_eq!(erasures.due_batch_sizes(), [500, 1]);
    }

    /// Builds enough closing accounts to require a second erasure batch.
    fn closing_members() -> Vec<OrgUser> {
        let organization = test_org_caller().organization_id();
        (0..501)
            .map(|index| {
                test_org_member_at(
                    organization,
                    &format!("member-{index}@acme.test"),
                    OrgUserStatus::Closing,
                )
            })
            .collect()
    }

    /// Sam's grace period has a week to go. Nothing is touched, so he can
    /// still cancel.
    #[test]
    fn an_erasure_still_in_its_grace_period_waits() {
        let (run, id) = run_over(7, ErasureState::Pending);

        assert_eq!(run.report, OrgErasureReport::default());
        assert_eq!(run.users.count(), 1);
        assert_eq!(run.erasures.status_of(&id), Some(ErasureStatus::Pending));
        assert!(run.audit.records.lock().unwrap().is_empty());
    }

    /// An erasure under legal hold stays held after its grace period, and
    /// the member's account remains stored.
    #[test]
    fn a_held_erasure_is_not_carried_out() {
        let (run, id) = run_over(20, ErasureState::Held);

        assert_eq!(run.users.count(), 1);
        assert_eq!(run.erasures.status_of(&id), Some(ErasureStatus::Held));
    }

    /// The last run failed part way through Sam's erasure. This run tries
    /// it again and completes it.
    #[test]
    fn a_failed_erasure_is_retried() {
        let (run, id) = run_over(20, ErasureState::Failed);

        assert_eq!(run.report.completed, 1);
        assert_eq!(run.erasures.status_of(&id), Some(ErasureStatus::Completed));
    }
}
