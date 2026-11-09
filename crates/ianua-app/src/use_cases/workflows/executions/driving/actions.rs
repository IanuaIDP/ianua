//! Running an action step: one call of an integration's operation.
//!
//! Every question is asked again before each call, a first one or one made
//! again after the integration turned it away: what the catalog offers now
//! as the tenant treats it, what the person the execution acts for holds
//! now, and whether the step's account may be used for them, which needs
//! its owner to be able to lend it still. A Protected apps step acts as
//! that person themselves, through a pass made just before its one call
//! for the route it names; the gateway asks the route's policy of them. A
//! Protected data step does the same on the stream route it names, and is
//! handed the login the route keeps for workflows. A memory step is run by
//! the platform itself, on the memory it names, and so is a company step,
//! as the person the run acts for.
//! The step is started and kept
//! first, the call is made outside any unit of work, and its outcome is
//! settled on the execution read back afresh.

use std::sync::Arc;

use ianua_domain::domains::routing::stream::{StreamWorkflowUse, WorkflowLogin};
use ianua_domain::domains::workflows::account::IntegrationAccount;
use ianua_domain::domains::workflows::design::node::NodeKey;
use ianua_domain::domains::workflows::execution::step::{ActionOutcome, StepRefusal};
use ianua_domain::domains::workflows::execution::{
    ActingAuthority, ActionCall, ActionClearance, ActionStart, Offer, WorkflowExecution,
};
use ianua_domain::domains::workflows::integration::{AccountNeed, ActionAccount, ActionStep};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    HumanAccount, IntegrationAccountId, StreamRouteId, UntrustedText, UserId, WorkflowExecutionId,
};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authentication::{PassReach, SealedAt};
use crate::ports::routing::{StreamRouteLogins, StreamRouteStore};
use crate::ports::workflows::{
    ActionRun, ActionRunner, CallCredential, DataCall, ExecutionVersion, IntegrationAccountStore,
    IntegrationCatalog, OperationRiskOverrideStore, Renewal, RunPassGrant, RunPasses,
};
use crate::services::account_grants::{AccountGrants, GrantHolder};
use crate::services::issuers::TenantIssuers;
use crate::services::kept_together::kept_together;
use crate::use_cases::routing::stream_routes::set_workflow_use::stream_route_login_place;
use crate::use_cases::workflows::accounts::connect::integration_credential_place;
use crate::use_cases::workflows::executions::driving::Driving;
use crate::use_cases::workflows::executions::driving::company::CompanyRun;
use crate::use_cases::workflows::offers::Offers;

/// The ports an action step's call goes through.
#[derive(ianua_macros::Fakes)]
pub struct ActionPorts {
    /// What the integrations offer now.
    pub catalog: Arc<dyn IntegrationCatalog>,
    /// The tenant's raised views of operations.
    pub risks: Arc<dyn OperationRiskOverrideStore>,
    /// The accounts actions act through.
    pub accounts: Arc<dyn IntegrationAccountStore>,
    /// Makes an action's call through its integration.
    pub action_runner: Arc<dyn ActionRunner>,
    /// Keeps an account's short-lived token good just before a call.
    pub grants: Arc<AccountGrants>,
    /// Makes the pass a Protected apps or Protected data step's call
    /// carries.
    pub run_passes: Arc<dyn RunPasses>,
    /// The stream routes Protected data steps reach.
    pub stream_routes: Arc<dyn StreamRouteStore>,
    /// The logins kept for stream routes open to workflows.
    pub stream_route_logins: Arc<dyn StreamRouteLogins>,
    /// The tenant's own token issuer, which a pass names.
    pub issuers: TenantIssuers,
}

/// What lets an action step act, and what its call goes through.
struct Cleared {
    clearance: ActionClearance<ResolvedTenant>,
    through: Through,
}

/// Whether an action step may act, or why it is refused.
enum Clearing {
    Cleared(Cleared),
    Refused(StepRefusal),
}

/// What an action step's call goes through, before it is made.
enum Through {
    /// Nothing: its operation needs no account.
    Nothing,
    /// The account's sealed credential, beside where the account keeps it.
    Account(SealedAt),
    /// A pass made for the call, acting as this person of the tenant's.
    RunPerson(UserId),
    /// A pass made for the call on a stream route, acting as this person of
    /// the tenant's, with the login the route keeps.
    RunPersonData(UserId),
    /// The platform itself, on the tenant's memory the call names.
    Memory,
    /// The platform itself, acting on the tenant as the run's person.
    Company(CompanyRun),
}

/// What a call is handed once it is about to be made.
enum Handed {
    Nothing,
    Account(SealedAt),
    Pass(Secret),
    Data(DataCall),
}

impl Handed {
    /// The credential the runner is handed.
    fn credential(&self) -> CallCredential<'_> {
        match self {
            Self::Nothing => CallCredential::Nothing,
            Self::Account(sealed) => CallCredential::Account(sealed),
            Self::Pass(pass) => CallCredential::Pass(pass),
            Self::Data(data) => CallCredential::Data(data),
        }
    }
}

impl Driving<'_> {
    /// Starts the ready action step `key` of `execution`, read at `read`,
    /// and makes its call, or fails it with the reason it may not run.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` or `AppError::Conflict` when the step is not
    ///   ready, or its call is not due again yet.
    /// - `AppError::Internal` when a store, the catalog or the audit trail
    ///   fails.
    pub(super) async fn run_action(
        &self,
        mut execution: WorkflowExecution<ResolvedTenant>,
        read: ExecutionVersion,
        key: &NodeKey,
        step: &ActionStep,
    ) -> Result<(), AppError> {
        let offered = self.offers().for_step(self.tenant, step).await?;
        let Some(acting) = self.acting_for(&execution, &[]).await? else {
            return self
                .refuse(execution, read, key, StepRefusal::PersonLacksAuthority)
                .await;
        };
        let need = offered.as_ref().map(|offer| offer.spec().account());
        let cleared = match self.cleared(step, need, &acting, execution.id()).await? {
            Clearing::Cleared(cleared) => cleared,
            Clearing::Refused(refusal) => return self.refuse(execution, read, key, refusal).await,
        };
        let offer = offered.as_ref().map_or(Offer::Withdrawn, Offer::Current);
        let started = execution
            .begin_action(key, offer, &cleared.clearance, &acting)
            .map_err(AppError::from_domain)?;
        match started {
            ActionStart::Call(call, records) => {
                self.keep(&execution, read, records).await?;
                self.call(&execution, key, &call, &cleared.through).await
            }
            ActionStart::Stopped(records) => self.keep(&execution, read, records).await,
        }
    }

    /// Makes `call` through its integration, then settles its outcome on
    /// the execution as stored once the call came back.
    async fn call(
        &self,
        execution: &WorkflowExecution<ResolvedTenant>,
        key: &NodeKey,
        call: &ActionCall,
        through: &Through,
    ) -> Result<(), AppError> {
        let ran = self.ran(call, through).await;
        self.keep_renewal(call.account, ran.renewal).await?;
        let mut now = self
            .ports
            .executions
            .find_by_id(self.tenant, execution.id())
            .await
            .or_internal()?
            .or_not_found(message!(
                "workflows-workflow-execution",
                "workflow execution"
            ))?;
        let read = ExecutionVersion::of(&now);
        let records = now
            .settle_action(key, call.call_id, ran.outcome)
            .map_err(AppError::from_domain)?;
        self.keep(&now, read, records).await
    }

    /// How `call` went: run by the platform itself on a memory or on the
    /// tenant, or by its integration through what it is handed.
    async fn ran(&self, call: &ActionCall, through: &Through) -> ActionRun {
        let by_platform = match through {
            Through::Memory => Some(self.memory_call(call).await),
            Through::Company(run) => Some(self.company_call(*run, call).await),
            Through::Nothing
            | Through::Account(_)
            | Through::RunPerson(_)
            | Through::RunPersonData(_) => None,
        };
        if let Some(outcome) = by_platform {
            return ActionRun {
                outcome,
                renewal: Renewal::Unchanged,
            };
        }
        match self.handed(call, through).await {
            Ok(handed) => {
                self.ports
                    .actions
                    .action_runner
                    .run(self.tenant, call, handed.credential())
                    .await
            }
            Err(unsent) => ActionRun {
                outcome: unsent,
                renewal: Renewal::Unchanged,
            },
        }
    }

    /// Keeps the credential the service renewed during the call on the
    /// account it was made through, with its record, before the outcome is
    /// settled: the old one may no longer work, whatever the call came to.
    /// An account removed in the meantime keeps nothing.
    async fn keep_renewal(&self, account: ActionAccount, renewal: Renewal) -> Result<(), AppError> {
        let (ActionAccount::Account(id), Renewal::Renewed(renewed)) = (account, renewal) else {
            return Ok(());
        };
        let Some(mut kept) = self.account(&id).await? else {
            return Ok(());
        };
        kept.renew_credential(renewed);
        let tenant = self.tenant;
        let accounts = self.ports.actions.accounts.as_ref();
        let auditor = self.auditor;
        kept_together(self.ports.unit_of_work.as_ref(), async {
            accounts.save(tenant, &kept).await.or_internal()?;
            auditor
                .dispatch(&kept.take_events(tenant))
                .await
                .or_internal()
        })
        .await
    }

    /// What `call` is handed, made just before it goes: a pass is made for
    /// this one call. A call no pass could be made for is turned away, since
    /// nothing was sent, and tried again later.
    async fn handed(&self, call: &ActionCall, through: &Through) -> Result<Handed, ActionOutcome> {
        match through {
            Through::Nothing => Ok(Handed::Nothing),
            Through::Account(sealed) => {
                self.handed_account(call, sealed).await.map(Handed::Account)
            }
            Through::RunPerson(user_id) => self.handed_pass(call, *user_id).await.map(Handed::Pass),
            Through::RunPersonData(user_id) => {
                self.handed_data(call, *user_id).await.map(Handed::Data)
            }
            Through::Memory | Through::Company(_) => Err(ActionOutcome::Failed(
                UntrustedText::record("the step is run by the platform itself"),
            )),
        }
    }

    /// The credential `call` goes through: `sealed`, or what was just
    /// exchanged for it if its token was near its end. A call that names
    /// no account has nothing to exchange.
    async fn handed_account(
        &self,
        call: &ActionCall,
        sealed: &SealedAt,
    ) -> Result<SealedAt, ActionOutcome> {
        let ActionAccount::Account(id) = &call.account else {
            return Ok(sealed.clone());
        };
        let holder = GrantHolder {
            id,
            integration: &call.integration,
            credential: sealed,
        };
        self.ports
            .actions
            .grants
            .current(self.tenant, self.auditor, holder)
            .await
    }

    /// The pass for `call` on the route it names, acting as `user_id`.
    async fn handed_pass(
        &self,
        call: &ActionCall,
        user_id: UserId,
    ) -> Result<Secret, ActionOutcome> {
        let Some(route_id) = call.reached_route() else {
            return Err(names_nothing());
        };
        self.made_pass(call, user_id, PassReach::Route(route_id))
            .await
    }

    /// The pass for `call` on the stream route it names, acting as
    /// `user_id`, with the login the route keeps for workflows. A route that
    /// is gone or closed to workflows keeps no login, and fails the call:
    /// trying again would find the same.
    async fn handed_data(
        &self,
        call: &ActionCall,
        user_id: UserId,
    ) -> Result<DataCall, ActionOutcome> {
        let Some(stream_route_id) = call.reached_stream_route() else {
            return Err(names_nothing());
        };
        let login = self.workflow_login(&stream_route_id).await?;
        let pass = self
            .made_pass(call, user_id, PassReach::StreamRoute(stream_route_id))
            .await?;
        Ok(DataCall {
            pass,
            user: login.user().clone(),
            password: SealedAt {
                secret: login.password().clone(),
                place: stream_route_login_place(self.tenant, &stream_route_id),
            },
            tls: login.tls().clone(),
        })
    }

    /// The login kept for stream route `id`, while it is open to workflows.
    async fn workflow_login(&self, id: &StreamRouteId) -> Result<WorkflowLogin, ActionOutcome> {
        let unreadable = |error: DomainError| {
            tracing::warn!(%error, "a stream route could not be read for a call");
            ActionOutcome::TurnedAway(UntrustedText::record("the stream route could not be read"))
        };
        let route = self
            .ports
            .actions
            .stream_routes
            .find_by_id(self.tenant, id)
            .await
            .map_err(unreadable)?;
        let open = route.is_some_and(|route| route.workflow_use() == StreamWorkflowUse::Open);
        let login = match open {
            true => self
                .ports
                .actions
                .stream_route_logins
                .find(self.tenant, id)
                .await
                .map_err(unreadable)?,
            false => None,
        };
        login.ok_or_else(|| {
            ActionOutcome::Failed(UntrustedText::record(
                "the stream route is not open to workflows",
            ))
        })
    }

    /// The pass for `call`, acting as `user_id`, reaching what `reaches`
    /// names. A call no pass could be made for is turned away, since
    /// nothing was sent, and tried again later.
    async fn made_pass(
        &self,
        call: &ActionCall,
        user_id: UserId,
        reaches: PassReach,
    ) -> Result<Secret, ActionOutcome> {
        let grant = RunPassGrant {
            call_id: call.call_id,
            user_id,
            reaches,
        };
        self.pass(&grant).await.map_err(|error| {
            tracing::warn!(%error, "no pass could be made for a call");
            ActionOutcome::TurnedAway(UntrustedText::record("no pass could be made for the call"))
        })
    }

    /// The pass for `grant`, naming the tenant's issuer.
    async fn pass(&self, grant: &RunPassGrant) -> Result<Secret, AppError> {
        let issuer = self.ports.actions.issuers.of(self.tenant).await?;
        self.ports
            .actions
            .run_passes
            .issue(self.tenant, &issuer, grant)
            .await
            .map_err(AppError::from_domain)
    }

    /// What lets `step` of the run `execution` act for `acting`, its
    /// operation needing what `need` says, or `None` when it is no longer
    /// offered: no account, a pass acting as the person, the platform acting
    /// as them, or permission its account grants.
    async fn cleared(
        &self,
        step: &ActionStep,
        need: Option<AccountNeed>,
        acting: &ActingAuthority,
        execution: &WorkflowExecutionId,
    ) -> Result<Clearing, AppError> {
        match (step.account(), need) {
            (ActionAccount::Account(id), _) => self.through_account(step, acting, &id).await,
            (ActionAccount::NoAccount, Some(AccountNeed::RunPerson)) => {
                Ok(as_run_person(acting, Through::RunPerson))
            }
            (ActionAccount::NoAccount, Some(AccountNeed::RunPersonData)) => {
                Ok(as_run_person(acting, Through::RunPersonData))
            }
            (ActionAccount::NoAccount, Some(AccountNeed::TenantMemory)) => {
                Ok(by_platform(Through::Memory))
            }
            (ActionAccount::NoAccount, Some(AccountNeed::Company)) => {
                Ok(by_platform(Through::Company(CompanyRun {
                    execution: *execution,
                    person: acting.person().account(),
                })))
            }
            (
                ActionAccount::NoAccount,
                Some(AccountNeed::Account | AccountNeed::NoAccount) | None,
            ) => Ok(Clearing::Cleared(Cleared {
                clearance: ActionClearance::NoAccount,
                through: Through::Nothing,
            })),
        }
    }

    /// The permission account `id` grants `acting` for `step`, refused when
    /// the account is gone, its owner may no longer lend it, or it may not
    /// be used for this.
    async fn through_account(
        &self,
        step: &ActionStep,
        acting: &ActingAuthority,
        id: &IntegrationAccountId,
    ) -> Result<Clearing, AppError> {
        let unusable = Clearing::Refused(StepRefusal::AccountNotUsable);
        let Some(account) = self.account(id).await? else {
            return Ok(unusable);
        };
        let Some(owner) = self.owner_now(&account).await? else {
            return Ok(unusable);
        };
        let Ok(granted) = account.grant_use(acting, step.operation(), &owner) else {
            return Ok(unusable);
        };
        Ok(Clearing::Cleared(Cleared {
            clearance: ActionClearance::Account(granted),
            through: Through::Account(SealedAt {
                secret: account.credential().clone(),
                place: integration_credential_place(self.tenant, id),
            }),
        }))
    }

    /// The tenant's account `id`, if it is still kept.
    async fn account(
        &self,
        id: &IntegrationAccountId,
    ) -> Result<Option<IntegrationAccount<ResolvedTenant>>, AppError> {
        self.ports
            .actions
            .accounts
            .find_by_id(self.tenant, id)
            .await
            .or_internal()
    }

    /// What the owner of `account` holds now, for whether they may still
    /// lend it. `None` when their account is gone or may not act.
    async fn owner_now(
        &self,
        account: &IntegrationAccount<ResolvedTenant>,
    ) -> Result<Option<ActingAuthority>, AppError> {
        let Some(owner) = self
            .ports
            .accounts_now
            .person(self.tenant, account.owner(), &[])
            .await?
        else {
            return Ok(None);
        };
        owner.authority(|records, access, _| {
            ActingAuthority::of_account_owner(account, records, access)
        })
    }

    /// Where the operations the tenant is offered are read from.
    fn offers(&self) -> Offers<'_> {
        Offers {
            catalog: self.ports.actions.catalog.as_ref(),
            risks: self.ports.actions.risks.as_ref(),
        }
    }
}

/// A step acting as the person `acting` holds for, its call going through
/// what `through` makes of them: a person of the tenant's own. An
/// organization member has no account a route's policy names, so their
/// step is refused.
fn as_run_person(acting: &ActingAuthority, through: fn(UserId) -> Through) -> Clearing {
    let HumanAccount::User(user_id) = acting.person().account() else {
        return Clearing::Refused(StepRefusal::PersonLacksAuthority);
    };
    Clearing::Cleared(Cleared {
        clearance: ActionClearance::NoAccount,
        through: through(user_id),
    })
}

/// A step the platform makes itself, through `through`, needing no account.
fn by_platform(through: Through) -> Clearing {
    Clearing::Cleared(Cleared {
        clearance: ActionClearance::NoAccount,
        through,
    })
}

/// The outcome of a call acting as the run's person whose route input names
/// no id: nothing was sent, and trying again would find the same.
fn names_nothing() -> ActionOutcome {
    ActionOutcome::Failed(UntrustedText::record("the step names no route by its id"))
}
