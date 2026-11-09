//! Publish workflow: a person puts the draft they reviewed into service.
//!
//! Whatever the version's trigger starts from then on acts for them, so the
//! draft must be the revision they looked at. Every action step must fit an
//! operation the catalog offers now, as the tenant treats it, and a workflow
//! on an event starts only on one they may see. Every code step must name a
//! sandbox version that may run: kept, built, and of a sandbox not
//! archived. When the workflow's evaluation set says so, the draft's last
//! evaluation must have tried it as it stands and passed. The version in
//! service is archived in the same unit, so a schedule never fires two
//! versions. A
//! version starting on a service's event is registered at the service
//! before anything is kept, and the registrations of the version it
//! replaces are removed.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::delegation::HeldResources;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::design::workflow::{
    PublishFacts, Replaces, Revision, RunnableCode, Workflow,
};
use ianua_domain::domains::workflows::execution::ActingAuthority;
use ianua_domain::domains::workflows::integration::events::ServiceEventSpec;
use ianua_domain::domains::workflows::integration::risk_override::TenantOperation;
use ianua_domain::domains::workflows::triggers::Trigger;
use ianua_domain::domains::workflows::triggers::subscription::ServiceSubscription;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::WorkflowId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{
    EvaluationSetStore, EvaluationStore, IntegrationCatalog, OperationRiskOverrideStore,
    SandboxStore, SandboxVersionStore, WorkflowStore,
};
use crate::services::kept_together::kept_together;
use crate::services::registrations::{
    Made, RegistrationPorts, forget_waiting, registered, retired, unregister,
};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::workflows::lookup::latest_version;
use crate::use_cases::workflows::offers::Offers;
use crate::use_cases::workflows::runnable::Runnable;

/// Which workflow's draft to publish, and the revision of it the publisher
/// reviewed.
pub struct PublishWorkflowRequest {
    /// The workflow whose latest version is the draft.
    pub workflow_id: WorkflowId,
    /// The revision the publisher looked at, as their client handed it back.
    pub reviewed: Revision,
}

/// The ports [`PublishWorkflowUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PublishWorkflowPorts {
    /// Keeps the versions.
    pub workflows: Arc<dyn WorkflowStore>,
    /// What the installed integrations offer now.
    pub catalog: Arc<dyn IntegrationCatalog>,
    /// The tenant's raised views of operations.
    pub risks: Arc<dyn OperationRiskOverrideStore>,
    /// The sandboxes whose versions code steps run.
    pub sandboxes: Arc<dyn SandboxStore>,
    /// The sandbox versions code steps name.
    pub sandbox_versions: Arc<dyn SandboxVersionStore>,
    /// The workflows' evaluation sets, whose gate may hold a draft back.
    pub evaluation_sets: Arc<dyn EvaluationSetStore>,
    /// The evaluations, for the draft's last one.
    pub evaluations: Arc<dyn EvaluationStore>,
    /// Registers a version starting on a service's event at the service,
    /// and removes the registrations of the version it replaces.
    pub registrations: RegistrationPorts,
    /// Keeps the new version, the one it replaces and their records together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Puts workflow drafts into service.
pub struct PublishWorkflowUseCase {
    ports: PublishWorkflowPorts,
}

impl PublishWorkflowUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PublishWorkflowPorts) -> Self {
        Self { ports }
    }

    /// Registers `change`'s draft, put in service by `publisher`, at its
    /// trigger's service, removes the replaced version's registrations, and
    /// keeps it all with its records. A registration made for a change
    /// that could not be kept is taken off its service again.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the trigger's account may not register it
    ///   or its service refused.
    /// - `AppError::Upstream` when the trigger's service could not be
    ///   reached; nothing is kept.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn register_and_keep(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        publisher: &ActingAuthority,
        change: Change<'_>,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let registrations = &self.ports.registrations;
        let mut made = registered(registrations, auditor, &tenant, publisher, change.draft).await?;
        let mut retiring = match change.current.as_deref() {
            Some(retiring) => retired(registrations, &tenant, retiring).await?,
            None => Vec::new(),
        };
        let changes = Published {
            published: change.draft,
            archived: change.current,
            made: made.as_mut(),
            retiring: &mut retiring,
        };
        let saved = kept_together(
            self.ports.unit_of_work.as_ref(),
            keep(&self.ports, ctx, auditor, changes),
        )
        .await;
        if let Err(failed) = saved {
            let orphaned: Vec<_> = made.into_iter().map(|made| made.subscription).collect();
            unregister(registrations, auditor, &tenant, &orphaned).await;
            forget_waiting(registrations, &tenant, &orphaned).await;
            return Err(failed);
        }
        unregister(registrations, auditor, &tenant, &retiring).await;
        Ok(())
    }
}

/// The version being put in service and the one it replaces, if any.
struct Change<'a> {
    draft: &'a mut Workflow<ResolvedTenant>,
    current: Option<&'a mut Workflow<ResolvedTenant>>,
}

impl Command for PublishWorkflowUseCase {
    type Caller = CallerContext;
    type Input = PublishWorkflowRequest;
    type Output = Result<Workflow<ResolvedTenant>, AppError>;

    /// Publishes the workflow's draft as the person `ctx` names, archiving
    /// the version in service.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing tenant workflow; `Forbidden` without update rights or visibility of the triggering event.
    /// - `AppError::Conflict` for a changed reviewed draft, concurrent publication, or a draft its evaluation gate holds back.
    /// - `AppError::Domain` for a nondraft, unavailable/incompatible operation/event, unrunnable sandbox, missing immediate high-risk approval, or refused/unauthorized trigger registration.
    /// - `AppError::Upstream` for an unreachable trigger service, keeping nothing; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: PublishWorkflowRequest,
    ) -> Result<Workflow<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let mut draft =
            latest_version(self.ports.workflows.as_ref(), &tenant, &request.workflow_id).await?;
        let mut current = self
            .ports
            .workflows
            .find_published(&tenant, draft.id())
            .await
            .or_internal()?;
        ensure_evaluated(&self.ports, &tenant, &draft).await?;
        let offered = Offered {
            operations: offered_now(&self.ports, &tenant, &draft).await?,
            events: events_now(self.ports.catalog.as_ref(), &draft).await?,
            runnable: runnable_now(&self.ports, &tenant, &draft).await?,
        };
        let change = Change {
            draft: &mut draft,
            current: current.as_mut(),
        };
        let publisher = put_in_service(change, &authority, request.reviewed, &offered)?;
        let change = Change {
            draft: &mut draft,
            current: current.as_mut(),
        };
        self.register_and_keep(ctx, auditor, &publisher, change)
            .await?;
        Ok(draft)
    }
}

/// What publishing changed: the version put in service, the one it
/// replaced, the new registration at a service and those being removed.
struct Published<'a> {
    published: &'a mut Workflow<ResolvedTenant>,
    archived: Option<&'a mut Workflow<ResolvedTenant>>,
    made: Option<&'a mut Made>,
    retiring: &'a mut [ServiceSubscription<ResolvedTenant>],
}

/// What the catalog offers a draft now: the operations its steps use, as
/// the tenant treats them, the events its trigger may start on, and the
/// sandbox versions its code steps name that may run.
struct Offered {
    operations: Vec<TenantOperation>,
    events: Vec<ServiceEventSpec>,
    runnable: Vec<RunnableCode>,
}

/// Refuses `draft` unless its workflow's evaluation set lets it through:
/// no set saved, a gate that is off, or a last evaluation that tried the
/// draft as it stands and passed every case.
///
/// # Errors
///
/// - `AppError::Conflict` when the gate holds the draft back.
/// - `AppError::Internal` when a store fails.
async fn ensure_evaluated(
    ports: &PublishWorkflowPorts,
    tenant: &ScopedTenant,
    draft: &Workflow<ResolvedTenant>,
) -> Result<(), AppError> {
    let Some(set) = ports
        .evaluation_sets
        .find(tenant, draft.id())
        .await
        .or_internal()?
    else {
        return Ok(());
    };
    let last = ports
        .evaluations
        .latest_of(tenant, draft.id(), 1)
        .await
        .or_internal()?;
    set.ensure_publishable(draft, last.first())
        .map_err(AppError::from_domain)
}

/// Publishes `change`'s draft as `authority` reviewed it at `reviewed`,
/// against what is `offered`, retiring the version it replaces, and what
/// its publisher holds now.
///
/// # Errors
///
/// `AppError::Domain`, `AppError::Forbidden` or `AppError::Conflict` when
/// the domain refuses to publish it.
fn put_in_service(
    change: Change<'_>,
    authority: &TenantAuthority,
    reviewed: Revision,
    offered: &Offered,
) -> Result<ActingAuthority, AppError> {
    let replaces = change.current.map_or(Replaces::Nothing, Replaces::Version);
    let publisher = publisher_now(authority)?;
    let facts = PublishFacts {
        offered: &offered.operations,
        events: &offered.events,
        sees: &publisher,
        runnable: &offered.runnable,
    };
    change
        .draft
        .publish(&WorkflowControl::new(authority), reviewed, replaces, facts)
        .map_err(AppError::from_domain)?;
    Ok(publisher)
}

/// The service events `draft`'s trigger may start on, as its integration
/// offers them now; none for any other trigger.
async fn events_now(
    catalog: &dyn IntegrationCatalog,
    draft: &Workflow<ResolvedTenant>,
) -> Result<Vec<ServiceEventSpec>, AppError> {
    let Trigger::Service(on) = draft.trigger() else {
        return Ok(Vec::new());
    };
    catalog.events(on.integration()).await.or_internal()
}

/// The operations `draft`'s action steps use, as the catalog offers them
/// now and the tenant treats them.
async fn offered_now(
    ports: &PublishWorkflowPorts,
    tenant: &ScopedTenant,
    draft: &Workflow<ResolvedTenant>,
) -> Result<Vec<TenantOperation>, AppError> {
    Offers {
        catalog: ports.catalog.as_ref(),
        risks: ports.risks.as_ref(),
    }
    .used_by(tenant, draft.graph())
    .await
}

/// The sandbox versions `draft`'s code steps name that may run now, each
/// with whether its code reaches the network.
async fn runnable_now(
    ports: &PublishWorkflowPorts,
    tenant: &ScopedTenant,
    draft: &Workflow<ResolvedTenant>,
) -> Result<Vec<RunnableCode>, AppError> {
    Runnable {
        sandboxes: ports.sandboxes.as_ref(),
        versions: ports.sandbox_versions.as_ref(),
    }
    .in_graph(tenant, draft.graph())
    .await
}

/// What the publisher signed in as `authority` holds now, which says what
/// events they may see. Seeing events needs no resources.
fn publisher_now(authority: &TenantAuthority) -> Result<ActingAuthority, AppError> {
    let none = HeldResources::answered(authority.who().principal(), Vec::new());
    ActingAuthority::of_signed_in(authority, &none).map_err(AppError::from_domain)
}

/// Saves `archived` first, then `published`, and what each raised, in that
/// order.
async fn saved_versions(
    ports: &PublishWorkflowPorts,
    tenant: &ScopedTenant,
    archived: Option<&mut Workflow<ResolvedTenant>>,
    published: &mut Workflow<ResolvedTenant>,
) -> Result<Vec<DomainEvent>, AppError> {
    let mut events = Vec::new();
    if let Some(archived) = archived {
        ports
            .workflows
            .save(tenant, archived)
            .await
            .map_err(AppError::from_domain)?;
        events.extend(archived.take_events(tenant));
    }
    ports
        .workflows
        .save(tenant, published)
        .await
        .map_err(AppError::from_domain)?;
    events.extend(published.take_events(tenant));
    Ok(events)
}

/// Saves the archived version first, then the published one, then the
/// registrations removed and made, and records what each raised, in that
/// order.
async fn keep(
    ports: &PublishWorkflowPorts,
    ctx: &CallerContext,
    auditor: &RequestAuditor,
    changes: Published<'_>,
) -> Result<(), AppError> {
    let tenant = ctx.tenant();
    let mut events = saved_versions(ports, &tenant, changes.archived, changes.published).await?;
    let subscriptions = ports.registrations.subscriptions.as_ref();
    for removed in changes.retiring.iter_mut() {
        subscriptions.save(&tenant, removed).await.or_internal()?;
        events.extend(removed.take_events(&tenant));
    }
    if let Some(made) = changes.made {
        subscriptions
            .take(&tenant, &made.subscription, &made.routing)
            .await
            .or_internal()?;
        events.extend(made.subscription.take_events(&tenant));
    }
    auditor
        .dispatch_by(&ctx.actor(), events)
        .await
        .or_internal()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::account::{AccountSharing, IntegrationAccount};
    use ianua_domain::domains::workflows::data::FieldName;
    use ianua_domain::domains::workflows::design::workflow::WorkflowStatus;
    use ianua_domain::domains::workflows::evaluation::run::Evaluation;
    use ianua_domain::domains::workflows::evaluation::set::PublishGate;
    use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
    use ianua_domain::domains::workflows::integration::{InputNeed, InputSpec, IntegrationKey};
    use ianua_domain::domains::workflows::triggers::channel::ChannelSetup;
    use ianua_domain::domains::workflows::triggers::subscription::{Lapse, SubscriptionStatus};
    use ianua_domain::domains::workflows::triggers::{EventFilter, FilterValue, ServiceTrigger};
    use ianua_domain::shared::clock;
    use ianua_domain::shared::model::aggregate::Aggregate;
    use ianua_domain::types::{ActionClass, IntegrationAccountId, Label, SealedSecret};

    use super::*;
    use crate::ports::workflows::RegistrationFailure;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::caller_person;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::workflows::{
        FakeAccountChannelStore, FakeEvaluationSetStore, FakeEvaluationStore,
        FakeIntegrationAccountStore, FakeIntegrationCatalog, FakeSandboxStore,
        FakeSandboxVersionStore, FakeServiceRegistrar, FakeServiceSubscriptionStore,
        FakeWorkflowStore, SHEETS, account_credential_place, accounts_now_of, append_row,
        append_step, code_step, draft_by, draft_on, managing, parcel_case, passed_evaluation,
        published_by, python_sandbox, ready_in_sandbox, set_for, sheets_account, tidy_step,
        version_of,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The versions a publish reads and writes, and what it recorded.
    struct Publishing {
        workflows: Arc<FakeWorkflowStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Publishing {
        fn of(versions: &[Workflow<ResolvedTenant>]) -> Self {
            Self {
                workflows: Arc::new(FakeWorkflowStore::holding(versions)),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self, authorities: FakeTenantAuthorities) -> PublishWorkflowPorts {
            PublishWorkflowPorts {
                workflows: self.workflows.clone(),
                catalog: Arc::new(FakeIntegrationCatalog::offering(vec![append_row(
                    ActionClass::Write,
                )])),
                tenant_authorities: Arc::new(authorities),
                ..PublishWorkflowPorts::fakes()
            }
        }

        fn publish(
            &self,
            ports: PublishWorkflowPorts,
            draft: &Workflow<ResolvedTenant>,
            reviewed: Revision,
        ) -> Result<Workflow<ResolvedTenant>, AppError> {
            let use_case = PublishWorkflowUseCase::new(ports);
            let request = PublishWorkflowRequest {
                workflow_id: *draft.id(),
                reviewed,
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), request))
        }

        fn status_of(&self, draft: &Workflow<ResolvedTenant>) -> WorkflowStatus {
            self.workflows
                .stored(draft.id(), draft.version())
                .unwrap()
                .status()
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    fn draft() -> Workflow<ResolvedTenant> {
        draft_by(&caller_person(), vec![tidy_step("tidy")], Vec::new())
    }

    fn publisher() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::Update)])
    }

    /// Ann's draft has a set whose gate must pass, and `last` is its
    /// latest evaluation, if any.
    fn gated(
        publishing: &Publishing,
        draft: &Workflow<ResolvedTenant>,
        last: Option<&Evaluation<ResolvedTenant>>,
    ) -> PublishWorkflowPorts {
        let set = set_for(
            draft,
            &caller_person(),
            vec![parcel_case("late")],
            PublishGate::MustPass,
        );
        let evaluations = match last {
            Some(evaluation) => FakeEvaluationStore::holding(evaluation),
            None => FakeEvaluationStore::empty(),
        };
        PublishWorkflowPorts {
            evaluation_sets: Arc::new(FakeEvaluationSetStore::holding(&set)),
            evaluations: Arc::new(evaluations),
            ..publishing.ports(publisher())
        }
    }

    /// Ann turned on the gate of her draft's set and never evaluated it.
    /// Publishing is refused and the draft stays a draft.
    #[test]
    fn a_gated_draft_never_evaluated_is_refused() {
        let draft = draft();
        let publishing = Publishing::of(std::slice::from_ref(&draft));

        let refused =
            publishing.publish(gated(&publishing, &draft, None), &draft, draft.revision());

        assert!(matches!(refused, Err(AppError::Conflict(_))));
        assert_eq!(publishing.status_of(&draft), WorkflowStatus::Draft);
    }

    /// Ann's last evaluation of the draft as it stands passed every case,
    /// so the gate lets it into service.
    #[test]
    fn a_gated_draft_whose_evaluation_passed_is_published() {
        let draft = draft();
        let set = set_for(
            &draft,
            &caller_person(),
            vec![parcel_case("late")],
            PublishGate::MustPass,
        );
        let passed = passed_evaluation(&set, &draft, &caller_person());
        let publishing = Publishing::of(std::slice::from_ref(&draft));

        publishing
            .publish(
                gated(&publishing, &draft, Some(&passed)),
                &draft,
                draft.revision(),
            )
            .unwrap();

        assert_eq!(publishing.status_of(&draft), WorkflowStatus::Published);
    }

    /// Ann publishes the draft she reviewed. It is in service and its
    /// publication is recorded.
    #[test]
    fn the_reviewed_draft_is_published_and_recorded() {
        let draft = draft();
        let publishing = Publishing::of(std::slice::from_ref(&draft));

        publishing
            .publish(publishing.ports(publisher()), &draft, draft.revision())
            .unwrap();

        assert_eq!(publishing.status_of(&draft), WorkflowStatus::Published);
        assert_eq!(publishing.records(), ["workflows.version_published"]);
    }

    /// Ann's draft cleans titles with version 1 of her sandbox, whose
    /// packages are built. It is published.
    #[test]
    fn a_draft_running_a_built_version_is_published() {
        let (sandbox, version) = ready_in_sandbox();
        let draft = draft_by(
            &caller_person(),
            vec![code_step("clean", *version.id())],
            Vec::new(),
        );
        let publishing = Publishing::of(std::slice::from_ref(&draft));
        let ports = PublishWorkflowPorts {
            sandboxes: Arc::new(FakeSandboxStore::holding(&sandbox)),
            sandbox_versions: Arc::new(FakeSandboxVersionStore::holding(&version)),
            ..publishing.ports(publisher())
        };

        publishing.publish(ports, &draft, draft.revision()).unwrap();

        assert_eq!(publishing.status_of(&draft), WorkflowStatus::Published);
    }

    /// A code step referencing an unbuilt sandbox version prevents publication.
    /// The workflow remains a draft and no audit event is recorded.
    #[test]
    fn a_draft_running_a_version_still_building_is_not_published() {
        let mut sandbox = python_sandbox();
        let version = version_of(&mut sandbox);
        let draft = draft_by(
            &caller_person(),
            vec![code_step("clean", *version.id())],
            Vec::new(),
        );
        let publishing = Publishing::of(std::slice::from_ref(&draft));
        let ports = PublishWorkflowPorts {
            sandboxes: Arc::new(FakeSandboxStore::holding(&sandbox)),
            sandbox_versions: Arc::new(FakeSandboxVersionStore::holding(&version)),
            ..publishing.ports(publisher())
        };

        let result = publishing.publish(ports, &draft, draft.revision());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(publishing.status_of(&draft), WorkflowStatus::Draft);
        assert!(publishing.records().is_empty());
    }

    /// Version 1 is in service and Ann publishes version 2. Version 1 is
    /// archived in the same step, and both are recorded, the archive first.
    #[test]
    fn publishing_a_version_archives_the_one_in_service() {
        let first = published_by(&caller_person(), draft());
        let second = first.next_draft(&managing(&caller_person())).unwrap();
        let publishing = Publishing::of(&[first.clone(), second.clone()]);

        publishing
            .publish(publishing.ports(publisher()), &second, second.revision())
            .unwrap();

        assert_eq!(publishing.status_of(&first), WorkflowStatus::Archived);
        assert_eq!(publishing.status_of(&second), WorkflowStatus::Published);
        assert_eq!(
            publishing.records(),
            ["workflows.version_archived", "workflows.version_published"]
        );
    }

    /// Renaming a draft after review makes publication of the reviewed revision
    /// conflict. The workflow remains a draft and no audit event is recorded.
    #[test]
    fn a_draft_changed_since_it_was_reviewed_is_not_published() {
        let mut draft = draft();
        let reviewed = draft.revision();
        let _later = clock::freeze(Aggregate::updated_at(&draft) + time::Duration::seconds(1));
        draft
            .rename(
                &managing(&caller_person()),
                Label::new("name", "Pay Bob").unwrap(),
            )
            .unwrap();
        let publishing = Publishing::of(std::slice::from_ref(&draft));

        let result = publishing.publish(publishing.ports(publisher()), &draft, reviewed);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(publishing.status_of(&draft), WorkflowStatus::Draft);
        assert!(publishing.records().is_empty());
    }

    /// An action absent from the current catalog prevents publication. The
    /// workflow remains a draft and no audit event is recorded.
    #[test]
    fn a_draft_using_an_operation_no_longer_offered_is_not_published() {
        let draft = draft_by(
            &caller_person(),
            vec![append_step("append", IntegrationAccountId::new())],
            Vec::new(),
        );
        let publishing = Publishing::of(std::slice::from_ref(&draft));
        let ports = PublishWorkflowPorts {
            catalog: Arc::new(FakeIntegrationCatalog::offering_nothing()),
            ..publishing.ports(publisher())
        };

        let result = publishing.publish(ports, &draft, draft.revision());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(publishing.status_of(&draft), WorkflowStatus::Draft);
        assert!(publishing.records().is_empty());
    }

    /// Ann's draft appends rows to a sheet, an operation the catalog offers.
    /// It is published.
    #[test]
    fn a_draft_using_an_offered_operation_is_published() {
        let draft = draft_by(
            &caller_person(),
            vec![append_step("append", IntegrationAccountId::new())],
            Vec::new(),
        );
        let publishing = Publishing::of(std::slice::from_ref(&draft));

        publishing
            .publish(publishing.ports(publisher()), &draft, draft.revision())
            .unwrap();

        assert_eq!(publishing.status_of(&draft), WorkflowStatus::Published);
    }

    /// A workflow viewer cannot publish a draft, which remains in draft status.
    #[test]
    fn a_caller_who_may_not_update_workflows_is_refused() {
        let draft = draft();
        let publishing = Publishing::of(std::slice::from_ref(&draft));
        let sam =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let result = publishing.publish(publishing.ports(sam), &draft, draft.revision());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(publishing.status_of(&draft), WorkflowStatus::Draft);
    }

    /// A signed-out session cannot publish a workflow draft.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let draft = draft();
        let publishing = Publishing::of(std::slice::from_ref(&draft));
        let mallory = FakeTenantAuthorities::refusing(Refusal::SignedOut);

        let result = publishing.publish(publishing.ports(mallory), &draft, draft.revision());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// The sheets service's "a row is added" event, watching one sheet.
    fn row_added() -> ServiceEventSpec {
        ServiceEventSpec::new(
            IntegrationKey::new(SHEETS).unwrap(),
            ServiceEventKey::new("row-added").unwrap(),
            vec![InputSpec::new(
                FieldName::new("sheet").unwrap(),
                InputNeed::Required,
            )],
        )
        .unwrap()
    }

    /// The caller's draft starting when a row is added to the finance
    /// sheet, registered through `account`.
    fn watching(account: IntegrationAccountId) -> Workflow<ResolvedTenant> {
        let trigger = ServiceTrigger::new(
            &row_added(),
            account,
            vec![EventFilter::new(
                FieldName::new("sheet").unwrap(),
                FilterValue::new("finance").unwrap(),
            )],
        )
        .unwrap();
        draft_on(
            &caller_person(),
            vec![tidy_step("tidy")],
            Vec::new(),
            Trigger::Service(trigger),
        )
    }

    /// What publishing a workflow on a service event reads and writes.
    struct Registering {
        account: IntegrationAccount<ResolvedTenant>,
        accounts: Arc<FakeIntegrationAccountStore>,
        subscriptions: Arc<FakeServiceSubscriptionStore>,
        registrar: Arc<FakeServiceRegistrar>,
        channels: Arc<FakeAccountChannelStore>,
    }

    impl Registering {
        fn through(registrar: FakeServiceRegistrar) -> Self {
            let account = sheets_account(&caller_person(), AccountSharing::OwnerOnly);
            Self {
                accounts: Arc::new(FakeIntegrationAccountStore::holding(&account)),
                account,
                subscriptions: Arc::new(FakeServiceSubscriptionStore::empty()),
                registrar: Arc::new(registrar),
                channels: Arc::new(FakeAccountChannelStore::empty()),
            }
        }

        fn ports(&self, publishing: &Publishing) -> PublishWorkflowPorts {
            let connects = [
                SystemPermission::Workflows(WorkflowAction::Update),
                SystemPermission::Workflows(WorkflowAction::ConnectAccounts),
            ];
            PublishWorkflowPorts {
                catalog: Arc::new(
                    FakeIntegrationCatalog::offering(vec![append_row(ActionClass::Write)])
                        .with_events(vec![row_added()]),
                ),
                registrations: RegistrationPorts {
                    accounts: self.accounts.clone(),
                    accounts_now: Arc::new(accounts_now_of(&[(&caller_person(), &connects)])),
                    subscriptions: self.subscriptions.clone(),
                    channels: self.channels.clone(),
                    registrar: self.registrar.clone(),
                    channel_setup: self.registrar.clone(),
                    encryptor: Arc::new(FakeEncryptor),
                    ..RegistrationPorts::fakes()
                },
                ..publishing.ports(FakeTenantAuthorities::holding(&connects))
            }
        }

        fn kept(&self) -> Vec<ServiceSubscription<ResolvedTenant>> {
            self.subscriptions.all(test_ctx().tenant_id())
        }
    }

    /// Ann publishes a workflow starting when a row is added to the finance
    /// sheet. It is registered at the sheets service through her account,
    /// kept live, and the registration is recorded after the publication.
    #[test]
    fn a_workflow_on_a_service_event_is_registered_when_published() {
        let registering =
            Registering::through(FakeServiceRegistrar::taking("hook-1", Lapse::Never));
        let draft = watching(*registering.account.id());
        let publishing = Publishing::of(std::slice::from_ref(&draft));

        publishing
            .publish(registering.ports(&publishing), &draft, draft.revision())
            .unwrap();

        let kept = registering.kept();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].status(), SubscriptionStatus::Live);
        assert_eq!(registering.registrar.asked(), ["register"]);
        assert_eq!(
            publishing.records(),
            [
                "workflows.version_published",
                "workflows.subscription_registered"
            ]
        );
    }

    /// The sheets service rotates grants, so registering replaces the
    /// account's credential: the replacement is kept on the account, with
    /// its record, and the old one is never used again.
    #[test]
    fn a_credential_replaced_while_registering_is_kept() {
        let account = sheets_account(&caller_person(), AccountSharing::OwnerOnly);
        let renewed =
            FakeEncryptor::sealed_for("the next grant", &account_credential_place(account.id()));
        let registering = Registering::through(
            FakeServiceRegistrar::taking("hook-1", Lapse::Never).renewing(renewed.clone()),
        );
        let draft = watching(*registering.account.id());
        let publishing = Publishing::of(std::slice::from_ref(&draft));

        publishing
            .publish(registering.ports(&publishing), &draft, draft.revision())
            .unwrap();

        let kept = registering
            .accounts
            .stored(registering.account.id())
            .unwrap();
        assert_eq!(kept.credential(), &renewed);
        assert!(
            publishing
                .records()
                .contains(&"workflows.account_credential_renewed".to_owned())
        );
    }

    /// A service's registration refusal prevents publication. The workflow
    /// remains a draft, no registration is saved and no audit event is recorded.
    #[test]
    fn a_registration_the_service_refuses_publishes_nothing() {
        let registering = Registering::through(FakeServiceRegistrar::failing(
            RegistrationFailure::Refused("the account may not add watches".to_owned()),
        ));
        let draft = watching(*registering.account.id());
        let publishing = Publishing::of(std::slice::from_ref(&draft));

        let result = publishing.publish(registering.ports(&publishing), &draft, draft.revision());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(publishing.status_of(&draft), WorkflowStatus::Draft);
        assert!(registering.kept().is_empty());
        assert!(publishing.records().is_empty());
    }

    /// Telegram has one webhook per bot. Ann's first workflow on the bot
    /// registers it; the workflow is routed to the channel, and is live.
    #[test]
    fn a_service_with_one_address_per_account_registers_the_channel_once() {
        let registering = Registering::through(
            FakeServiceRegistrar::taking("bot-hook", Lapse::Never)
                .by_channel(ChannelSetup::Registered),
        );
        let draft = watching(*registering.account.id());
        let publishing = Publishing::of(std::slice::from_ref(&draft));

        publishing
            .publish(registering.ports(&publishing), &draft, draft.revision())
            .unwrap();

        let kept = registering.kept();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].status(), SubscriptionStatus::Live);
        assert_eq!(registering.channels.count(), 1);
        assert_eq!(registering.registrar.asked(), ["open_channel"]);
        assert!(
            publishing
                .records()
                .contains(&"workflows.channel_ready".to_owned())
        );
    }

    /// Notion is set up by a person in its own settings. Publishing opens
    /// the channel for Ann to finish, and calls nobody.
    #[test]
    fn a_channel_set_up_by_hand_is_opened_and_nobody_is_called() {
        let registering = Registering::through(
            FakeServiceRegistrar::taking("unused", Lapse::Never)
                .by_channel(ChannelSetup::TokenFromService),
        );
        let draft = watching(*registering.account.id());
        let publishing = Publishing::of(std::slice::from_ref(&draft));

        publishing
            .publish(registering.ports(&publishing), &draft, draft.revision())
            .unwrap();

        assert_eq!(registering.channels.count(), 1);
        assert!(registering.registrar.asked().is_empty());
    }

    /// Telegram refuses the bot's token. Nothing is published, and the
    /// registration kept waiting for the answer is gone.
    #[test]
    fn a_channel_the_service_refuses_publishes_nothing() {
        let registering = Registering::through(
            FakeServiceRegistrar::failing(RegistrationFailure::Refused(
                "the token is wrong".to_owned(),
            ))
            .by_channel(ChannelSetup::Registered),
        );
        let draft = watching(*registering.account.id());
        let publishing = Publishing::of(std::slice::from_ref(&draft));

        let result = publishing.publish(registering.ports(&publishing), &draft, draft.revision());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(publishing.status_of(&draft), WorkflowStatus::Draft);
        assert!(registering.kept().is_empty());
    }

    /// Stripe shows its webhook's secret once, in its answer. It replaces
    /// the secret the platform made, so what Stripe signs can be proven.
    #[test]
    fn a_secret_shown_in_the_answer_is_kept() {
        let given = SealedSecret::new("v1.c3RyaXBl").unwrap();
        let registering = Registering::through(
            FakeServiceRegistrar::taking("hook-1", Lapse::Never).giving_secret(given.clone()),
        );
        let draft = watching(*registering.account.id());
        let publishing = Publishing::of(std::slice::from_ref(&draft));

        publishing
            .publish(registering.ports(&publishing), &draft, draft.revision())
            .unwrap();

        assert_eq!(registering.kept()[0].secret(), &given);
    }

    /// Ann publishes version 2 of her watching workflow. Version 1's
    /// registration is removed and taken off the service, and version 2 is
    /// registered afresh.
    #[test]
    fn publishing_a_new_version_replaces_the_registration() {
        let registering =
            Registering::through(FakeServiceRegistrar::taking("hook-1", Lapse::Never));
        let first = watching(*registering.account.id());
        let publishing = Publishing::of(std::slice::from_ref(&first));
        publishing
            .publish(registering.ports(&publishing), &first, first.revision())
            .unwrap();
        let first = publishing.workflows.stored(first.id(), 1).unwrap();
        let second = first.next_draft(&managing(&caller_person())).unwrap();
        block_on(publishing.workflows.insert(&test_ctx().tenant(), &second)).unwrap();

        publishing
            .publish(registering.ports(&publishing), &second, second.revision())
            .unwrap();

        let statuses: Vec<_> = registering
            .kept()
            .iter()
            .map(|kept| (kept.version(), kept.status()))
            .collect();
        assert!(statuses.contains(&(1, SubscriptionStatus::Removed)));
        assert!(statuses.contains(&(2, SubscriptionStatus::Live)));
        assert_eq!(
            registering.registrar.asked(),
            ["register", "register", "unregister"]
        );
    }
}
