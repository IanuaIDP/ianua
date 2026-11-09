//! Start policy draft: open the next version of a tenant's policy beside
//! the live one, blank, as a copy of the live version, or as a copy of a
//! past version brought back.
//!
//! The live version goes on deciding requests while the draft is written
//! and reviewed. A tenant has at most one open draft, and the domain finds
//! it, and the live version, in the whole history: a caller never names
//! them. Rules and the default action are then changed through the draft's
//! own steps.

use std::sync::Arc;

use ianua_domain::domains::authorization::policy::set::PolicySet;
use ianua_domain::domains::authorization::policy::version::{DraftStart, PolicyHistory};
use ianua_domain::shared::events::raised::Raises as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::PolicyStore;
use crate::use_case::Command;
use crate::use_cases::authorization::lookup::policy_versions;

/// The ports [`StartDraftUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StartDraftPorts {
    /// Loads the versions and saves the draft.
    pub policy_store: Arc<dyn PolicyStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Opens the next version of the caller's tenant's policy as a draft.
pub struct StartDraftUseCase {
    ports: StartDraftPorts,
}

impl StartDraftUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: StartDraftPorts) -> Self {
        Self { ports }
    }
}

impl Command for StartDraftUseCase {
    type Caller = CallerContext;
    type Input = DraftStart;
    type Output = Result<PolicySet, AppError>;

    /// Saves a draft starting from `start`, numbered one past the highest
    /// version, for the caller, and records it. Restoring a past version is
    /// a draft copied from it, under a new number.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update the policy.
    /// - `AppError::Conflict` when a draft is already open, being written or
    ///   in review, or the version to restore is live or open.
    /// - `AppError::NotFound` when copying the live version and none is
    ///   live, or restoring a version the tenant does not have.
    /// - `AppError::Internal` when the versions cannot be read or written,
    ///   or the draft cannot be recorded.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        start: DraftStart,
    ) -> Result<PolicySet, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let versions = policy_versions(self.ports.policy_store.as_ref(), &tenant).await?;
        let history = PolicyHistory::of(&versions).map_err(AppError::from_domain)?;
        let mut draft =
            PolicySet::start_draft(&history, start, &authority).map_err(AppError::from_domain)?;

        self.ports
            .policy_store
            .save(&tenant, &draft)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), draft.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(draft)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{PolicySetAction, SystemPermission};
    use ianua_domain::domains::authorization::policy::action::PolicyAction;
    use ianua_domain::domains::authorization::policy::status::PolicyStatus;
    use ianua_domain::domains::authorization::policy::version::{PolicyVersion, VersionBase};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakePolicyStore, block_admin_rule, policy_in};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The tenant's policy store, holding a first version in `status` with
    /// the "block-admin" rule, or none.
    fn store_in(status: Option<PolicyStatus>) -> Arc<FakePolicyStore> {
        let tenant = test_ctx().tenant_id();
        Arc::new(match status {
            Some(status) => {
                FakePolicyStore::holding(tenant, policy_in(status, vec![block_admin_rule()]))
            }
            None => FakePolicyStore::empty(),
        })
    }

    fn ports_over(store: &Arc<FakePolicyStore>) -> StartDraftPorts {
        StartDraftPorts {
            policy_store: store.clone(),
            ..StartDraftPorts::fakes()
        }
    }

    fn start(ports: StartDraftPorts, start: DraftStart) -> Result<PolicySet, AppError> {
        start_recorded(ports, start, &Arc::new(FakeEventDispatcher::new()))
    }

    fn start_recorded(
        ports: StartDraftPorts,
        start: DraftStart,
        sink: &Arc<FakeEventDispatcher>,
    ) -> Result<PolicySet, AppError> {
        block_on(StartDraftUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            start,
        ))
    }

    fn versions(store: &FakePolicyStore) -> usize {
        store.versions_of(test_ctx().tenant_id()).len()
    }

    /// Ann's tenant never saved a policy. She opens a blank draft that
    /// allows by default; it is saved as version 1 with no rules, and
    /// recorded.
    #[test]
    fn a_tenant_without_a_policy_opens_a_blank_first_version() {
        let store = store_in(None);
        let sink = Arc::new(FakeEventDispatcher::new());

        let draft = start_recorded(
            ports_over(&store),
            DraftStart::Blank(PolicyAction::Allow),
            &sink,
        )
        .unwrap();

        assert_eq!(draft.version(), PolicyVersion::FIRST);
        assert!(draft.rules().is_empty());
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.policy_draft_started"]
        );
    }

    /// Ann opens a draft beside the live policy as a copy of it. The draft
    /// is version 2 with "block-admin", and version 1 stays live.
    #[test]
    fn a_draft_opens_beside_the_live_policy() {
        let store = store_in(Some(PolicyStatus::Active));

        let draft = start(ports_over(&store), DraftStart::FromLive).unwrap();

        assert_eq!(draft.status(), PolicyStatus::Draft);
        assert_eq!(draft.based_on(), VersionBase::CopyOf(PolicyVersion::FIRST));
        assert_eq!(draft.rules()[0].name().as_str(), "block-admin");
        let live = store
            .version(test_ctx().tenant_id(), PolicyVersion::FIRST)
            .unwrap();
        assert_eq!(live.status(), PolicyStatus::Active);
    }

    /// Ann brings back version 1, which was taken out of use. The draft is
    /// a new number restored from it, keeping its rule.
    #[test]
    fn a_past_version_is_restored_as_a_new_draft() {
        let store = store_in(Some(PolicyStatus::Archived));

        let draft = start(
            ports_over(&store),
            DraftStart::Restore(PolicyVersion::FIRST),
        )
        .unwrap();

        assert_ne!(draft.version(), PolicyVersion::FIRST);
        assert_eq!(
            draft.based_on(),
            VersionBase::RestoredFrom(PolicyVersion::FIRST)
        );
        assert_eq!(draft.rule_count(), 1);
    }

    /// Ann restores the live version. It is in use already, so she is
    /// refused and nothing is saved.
    #[test]
    fn the_live_version_is_not_restored() {
        let store = store_in(Some(PolicyStatus::Active));

        let result = start(
            ports_over(&store),
            DraftStart::Restore(PolicyVersion::FIRST),
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(versions(&store), 1);
    }

    /// Ann copies the live version in a tenant with nothing live. There is
    /// nothing to copy.
    #[test]
    fn copying_the_live_version_when_none_is_live_is_not_found() {
        let store = store_in(None);

        let result = start(ports_over(&store), DraftStart::FromLive);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A version in review prevents opening another draft; only the existing
    /// version remains stored.
    #[test]
    fn a_second_draft_is_refused_while_one_is_open() {
        let store = store_in(Some(PolicyStatus::Review));

        let result = start(ports_over(&store), DraftStart::Blank(PolicyAction::Allow));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(versions(&store), 1);
    }

    /// Policy view permission cannot open a draft. The archived version remains
    /// the only stored version and no draft creation is recorded.
    #[test]
    fn a_caller_who_may_not_update_the_policy_is_refused() {
        let store = store_in(Some(PolicyStatus::Archived));
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = StartDraftPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::PolicySet(PolicySetAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = start_recorded(ports, DraftStart::Blank(PolicyAction::Allow), &sink);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(versions(&store), 1);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot start a policy draft.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = store_in(None);
        let ports = StartDraftPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = start(ports, DraftStart::FromLive);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
