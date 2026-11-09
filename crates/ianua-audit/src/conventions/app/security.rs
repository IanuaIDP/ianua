//! The order and shape of the app's security code, read from its calls and
//! its port traits:
//!
//! - **A right checked after a load it does not need.** A use case or
//!   service loads a record (`existing_*`, `owned_*`, `load_*`, or a
//!   store's `find_*`, `load_*` or `fetch_*`) and only then checks a right
//!   (an `ensure_*` call handed a proof, one of the [`PROOF_WORDS`] in its
//!   name, or a call that hands out a control once the right is held, as
//!   `actor.control()`, `account_control(..)` and
//!   `account_control_to_shut_out(..)` do) whose statement names
//!   nothing loaded. Checking first keeps a caller without the right from
//!   learning whether the record exists: a `403` for a real id and a `404`
//!   for a made-up one tell them which ids are there.
//! - **A load before any right.** A use case or service loads a record
//!   before checking any right, and only afterwards hands a proof (one of
//!   the [`HANDED_PROOF_WORDS`]) to the aggregate, which checks it there.
//!   The right the record does not decide is checked before the load. A
//!   right that does depend on the record, such as its owner's, is handed
//!   to the lookup itself, which reads a record the caller may not act on
//!   as missing (`owned_*(.., &control)`), so "not found" and "not yours"
//!   answer the same. The lookup's own body uses the proof on what it read,
//!   which is the point, and naming who acted (`authority.actor()`) hands
//!   no proof on.
//! - **A silent command.** A command's `execute` takes the auditor and
//!   never dispatches through it, nor hands it or an auditor narrowed from
//!   it (`with_tenant`, `with_organization`, ..) on, so what it changes is
//!   never recorded.
//! - **A save nothing is taken after.** A use case's `execute`, or a
//!   function holding the auditor that hands no events back, saves and then
//!   takes no events, dispatches nothing and hands the auditor on to
//!   nothing: what the aggregate raised is dropped with it.
//! - **An unscoped store.** A `*Store` or `*Repository` port that takes a
//!   `ScopedTenant` without extending `TenantScoped` and without being named
//!   `CrossTenant*`.
//! - **A scoped method without its tenant.** A method of a `TenantScoped`
//!   port that does not take the `ScopedTenant` first.
//!
//! Each rule has a list of exceptions, each with the reason. A reason that
//! starts with `TO FIX:` marks a defect kept only until it is fixed. An
//! entry that matches nothing fails the build, so no list keeps an
//! exception that is gone.

use std::collections::BTreeSet;

use syn::visit::{self, Visit};
use syn::{
    Block, Expr, ExprCall, ExprMethodCall, FnArg, ImplItem, Item, ItemImpl, Macro, Pat, ReturnType,
    Signature, Stmt, TraitItem, Type, TypeParamBound,
};

use crate::conventions::app::source::{Findings, SourceFile, line_of, production_files};

/// What a command records through.
const AUDITOR: &str = "RequestAuditor";

/// The tenant a scoped store method takes first.
const SCOPED_TENANT: &str = "ScopedTenant";

/// The marker a tenant's store extends.
const TENANT_SCOPED: &str = "TenantScoped";

/// Calls that hand what a change raised over to be recorded.
const RECORDING: &[&str] = &["take_events", "dispatch", "dispatch_by"];

/// Rights checked after a load they do not need, or with no right checked
/// before the load, on purpose: the file, the function, and why.
const LATE_CHECKS_ALLOWED: &[Exception] = &[
    (
        "use_cases/scheduling/retry_dead.rs",
        "RetryDeadUseCase::execute",
        "every operator may retry a job, so nothing about the job can refuse them before it is read; the operator is proven first, and the record of the retry needs the job it names",
    ),
    (
        "use_cases/agents/approvals/approve_action.rs",
        "released_run",
        "the authority named here is the delegation's, loaded to spend the approval on the run's call; the approver's right was checked before the request was read",
    ),
    (
        "use_cases/agents/delegation/granting/attenuate.rs",
        "AttenuateUseCase::by_person",
        "a person passes part of a delegation on as the holding agent's owner or as a steward holding what is passed; who may depends on the parent delegation, its agent and the capabilities asked",
    ),
    (
        "use_cases/agents/delegation/resources/grant.rs",
        "GrantResourceUseCase::execute",
        "who may widen a delegation depends on where it sits in its chain: its delegator or an agent administrator for a root, the agent holding the parent or a person speaking for it for a child",
    ),
    (
        "use_cases/agents/delegation/resources/grant.rs",
        "parent_source",
        "a child is widened by the agent holding its parent or a person speaking for it as owner or steward, which depends on the parent and the capabilities asked",
    ),
    (
        "use_cases/authorization/roles/delete.rs",
        "replacement",
        "the right to delete roles is checked before the role is read; whether its holders may move depends on what the replacement grants",
    ),
    (
        "use_cases/authorization/policies/versions/change_status.rs",
        "ChangeStatusUseCase::retired",
        "the live policy is the tenant's one live version, named by no id the caller gives",
    ),
    (
        "use_cases/scim/users/remove.rs",
        "RemoveScimUseCase::execute",
        DIRECTORY_TOKEN,
    ),
    (
        "use_cases/scim/users/update.rs",
        "UpdateScimUseCase::execute",
        DIRECTORY_TOKEN,
    ),
    (
        "use_cases/operator/accounts/change_email.rs",
        "ChangeOperatorEmailUseCase::execute",
        OPERATOR_ON_OPERATORS,
    ),
    (
        "use_cases/operator/accounts/disable.rs",
        "DisableOperatorUseCase::execute",
        OPERATOR_ON_OPERATORS,
    ),
    (
        "use_cases/operator/accounts/enable.rs",
        "EnableOperatorUseCase::execute",
        OPERATOR_ON_OPERATORS,
    ),
    (
        "use_cases/operator/impersonation/grant.rs",
        "GrantUseCase::execute",
        "every active operator may ask for a grant and sees every tenant; the tenant's own posture, read from it, decides",
    ),
    (
        "use_cases/organization/billing/arrange_plan.rs",
        "ArrangePlanUseCase::execute",
        "every active operator may arrange any organization's plan and sees every organization; nothing in the record decides who may",
    ),
    (
        "use_cases/organization/billing/choose_plan.rs",
        "ChoosePlanUseCase::moved",
        "reads the caller's own organization's subscription once `execute` checked the right to choose a plan",
    ),
    (
        "use_cases/organization/invitations/offers/invite_org_user.rs",
        "InviteOrgUserUseCase::invitee",
        "the right to invite is checked in `execute` before this; the load is by the invited address, not an id",
    ),
];

/// A directory acting over SCIM: its token is its right.
const DIRECTORY_TOKEN: &str = "the directory's token is its right, checked when the endpoint is resolved before the user is read; what it may then do depends on what the user holds";

/// An operator acting on another operator's account.
const OPERATOR_ON_OPERATORS: &str = "every active operator may act on any other operator's account and sees every account; the only refusal, their own account, comes from the id named, not the record";

/// Giving up a factor setup that never took effect: the domain raises
/// nothing for it.
const SETUP_GIVEN_UP: &str = "giving up a factor setup that never took effect raises nothing in the domain; the factor never let anyone in";

/// An endpoint answering its challenge: the domain raises nothing for it.
const ENDPOINT_CONFIRMED: &str = "the domain raises nothing when a stream's endpoint echoes its challenge; the stream only starts delivering, and nobody acted";

/// A service sending a browser back with its code: the domain raises
/// nothing for it.
const CONNECTION_ANSWERED: &str = "holding a service's credential until the person who began the connection finishes it is not anything anyone did; beginning it and finishing it are recorded, and the sweep removes it otherwise";

/// Planning work from a recorded event: the domain raises nothing for it.
const PLANNING_ONLY_QUEUES: &str = "planning queues jobs for an event already recorded; each job records what it changes when it runs";

/// Commands that take the auditor and record nothing, on purpose: the file,
/// the use case, and why.
const SILENT_COMMANDS_ALLOWED: &[Exception] = &[
    (
        "use_cases/workflows/executions/live.rs",
        "PublishLiveUseCase",
        "pushing a recorded event to whoever watches a run or a draft is a view of it, not anything anyone did; the event it shows is already in the trail",
    ),
    (
        "use_cases/workflows/accounts/connections/answer.rs",
        "AnswerUseCase",
        CONNECTION_ANSWERED,
    ),
    (
        "use_cases/workflows/accounts/connections/sweep.rs",
        "SweepUseCase",
        "removing sign-ins nobody finished is housekeeping; an account connected from one was recorded when it was connected",
    ),
    (
        "use_cases/workflows/published/registrations/forget.rs",
        "ForgetUseCase",
        "forgetting which deliveries already started a run, once no service would send them again, is housekeeping; each run they started was recorded when it started",
    ),
    (
        "use_cases/workflows/published/registrations/abandon.rs",
        "AbandonUseCase",
        "forgetting a registration whose publish never came back is housekeeping; it was never in service, so a record would claim one that never was",
    ),
    (
        "use_cases/tenant/certificates.rs",
        "MaintainPlatformCertificatesUseCase",
        "renews infrastructure certificates for existing addresses; tenant creation and readable-address consent are already audited, and retries must not fabricate another tenant action",
    ),
    (
        "use_cases/onboarding/signup.rs",
        "SignupUseCase",
        "a sign-up founds nothing until its link comes back; there is no organization yet to record it in, and confirming it records the founding",
    ),
    (
        "use_cases/authentication/mfa/enrollment/abandon.rs",
        "AbandonUseCase",
        SETUP_GIVEN_UP,
    ),
    (
        "use_cases/federation/idp/receive_sign_in.rs",
        "ReceiveSignInUseCase",
        "holding an app's sign-in request is not anything anyone did; answering it records the assertion issued",
    ),
    (
        "use_cases/organization/mfa/enrollment_abandon.rs",
        "OrgAbandonUseCase",
        SETUP_GIVEN_UP,
    ),
    (
        "use_cases/signals/streams/verification/confirm_endpoint.rs",
        "ConfirmEndpointUseCase",
        ENDPOINT_CONFIRMED,
    ),
    (
        "use_cases/notifications/inbox/purge_old.rs",
        "PurgeOldUseCase",
        "removing notices past their keeping is housekeeping of a feed; what they told of stays in the audit trail",
    ),
    (
        "use_cases/proxy/forget_old_records.rs",
        "ForgetOldRecordsUseCase",
        "removing the gateway's request and stream records past a tenant's retention is housekeeping of traffic logs, as its retention asks; they were never the audit trail",
    ),
    (
        "use_cases/authentication/sessions/purge_ended.rs",
        "PurgeEndedUseCase",
        "removing sessions long over is housekeeping of rows; every sign-in and sign-out stays in the audit trail",
    ),
    (
        "use_cases/metrics/capture_snapshots.rs",
        "CaptureSnapshotsUseCase",
        "a snapshot measures usage; it changes nothing anyone holds",
    ),
    (
        "use_cases/organization/sign_in/password/mark_credential_used.rs",
        "MarkCredentialUsedUseCase",
        "touching a session or stamping a key's last use is bookkeeping, not an action anyone took, and the domain raises nothing for it",
    ),
    (
        "use_cases/oauth/flows/device/expire_authorizations.rs",
        "ExpireDeviceAuthorizationsUseCase",
        "a device request nobody answered in time lapses; the domain raises nothing for it, since nobody acted",
    ),
    (
        "use_cases/scheduling/claim_due.rs",
        "ClaimDueUseCase",
        "claiming a sweep's round is coordination between workers; each sweep records what it changes",
    ),
    (
        "use_cases/webhooks/delivery/plan.rs",
        "PlanUseCase",
        PLANNING_ONLY_QUEUES,
    ),
    (
        "use_cases/signals/delivery/plan.rs",
        "PlanUseCase",
        PLANNING_ONLY_QUEUES,
    ),
    (
        "use_cases/workflows/published/holds/plan.rs",
        "PlanAccountChecksUseCase",
        PLANNING_ONLY_QUEUES,
    ),
    (
        "use_cases/audit/plan_streams.rs",
        "PlanStreamsUseCase",
        PLANNING_ONLY_QUEUES,
    ),
    (
        "use_cases/oauth/flows/logout/plan_back_channel.rs",
        "PlanBackChannelUseCase",
        PLANNING_ONLY_QUEUES,
    ),
    (
        "use_cases/messaging/broker/pushing/plan.rs",
        "PlanPushesUseCase",
        PLANNING_ONLY_QUEUES,
    ),
    (
        "use_cases/workflows/executions/starts/plan_events.rs",
        "PlanEventStartsUseCase",
        PLANNING_ONLY_QUEUES,
    ),
    (
        "use_cases/workflows/executions/starts/fire_schedules.rs",
        "FireSchedulesUseCase",
        PLANNING_ONLY_QUEUES,
    ),
    (
        "use_cases/tenant/setup/plan.rs",
        "PlanUseCase",
        PLANNING_ONLY_QUEUES,
    ),
    (
        "use_cases/tenant/teardown/plan.rs",
        "PlanUseCase",
        PLANNING_ONLY_QUEUES,
    ),
    (
        "use_cases/scheduling/reconcile.rs",
        "ReconcileUseCase",
        "handing work left half-done out again queues its jobs; recording anything would say a tenant was provisioned or deleted twice, and each job records what it changes",
    ),
    (
        "use_cases/notifications/delivery/fan_out.rs",
        "FanOutUseCase",
        "telling people about an event that is already recorded changes nothing anyone holds",
    ),
    (
        "use_cases/notifications/delivery/post.rs",
        "PostUseCase",
        "posting a recorded event's notification to a channel changes nothing anyone holds",
    ),
    (
        "use_cases/audit/exports/write.rs",
        "WriteUseCase",
        AUDIT_EXPORT_WRITTEN,
    ),
    (
        "use_cases/audit/exports/expire.rs",
        "ExpireUseCase",
        "an audit log export's window running out, or its deadline passing, is the clock, not anyone's action; the domain raises nothing for it and its status shows it",
    ),
    (
        "use_cases/agents/approvals/gate_action.rs",
        "GateActionUseCase",
        "the gateway writes no approvals: the API opens and records the request over the sealed channel, and the gateway records the action itself, allowed or refused",
    ),
    (
        "use_cases/agents/approvals/spend.rs",
        "SpendUseCase",
        "spending an approval lets exactly one action through, which the gateway records as agents.action_authorized; the domain raises nothing for the spend",
    ),
    (
        "use_cases/workflows/sandboxes/trying/run.rs",
        "RunTrialUseCase",
        "a trial's end is its runner reporting how the code went, not anyone's action; its start is recorded with who started it and on which version, and the trial is for that person to read back",
    ),
    (
        "use_cases/workflows/sandboxes/trying/purge.rs",
        "PurgeEndedTrialsUseCase",
        "removing trials past their keeping is housekeeping of rows; each trial's start stays in the audit trail",
    ),
    (
        "use_cases/workflows/executions/purge.rs",
        "PurgeEndedRunsUseCase",
        "removing runs past their keeping is housekeeping of rows; each run's start and end stay in the audit trail for its own year",
    ),
    (
        "use_cases/scheduling/remove_ended.rs",
        "RemoveEndedJobsUseCase",
        "removing finished jobs is housekeeping of the queue's rows, past the time any event could be delivered again; the work each did is on the trail",
    ),
    (
        "use_cases/workflows/evaluations/purge.rs",
        "PurgeEndedUseCase",
        "removing evaluations past their keeping is housekeeping of rows; each evaluation's start and end stay in the audit trail",
    ),
    (
        "use_cases/workflows/executions/approvals/show_items.rs",
        "ShowItemsUseCase",
        "a page of items opened is kept only as evidence for the approval; who saw how many items, and when, is recorded with the approval itself",
    ),
];

/// The worker writing an audit log export's file: the domain raises nothing
/// for it.
const AUDIT_EXPORT_WRITTEN: &str = "writing an audit log export's file is the worker's bookkeeping; the request was recorded when it was made, and each download is recorded when its link is handed out";

/// Saves nothing is taken after, on purpose: the file, the function, and
/// why.
const UNRECORDED_SAVES_ALLOWED: &[Exception] = &[
    (
        "use_cases/workflows/accounts/connections/answer.rs",
        "AnswerUseCase::execute",
        CONNECTION_ANSWERED,
    ),
    (
        "use_cases/authentication/mfa/enrollment/abandon.rs",
        "AbandonUseCase::execute",
        SETUP_GIVEN_UP,
    ),
    (
        "use_cases/organization/mfa/enrollment_abandon.rs",
        "OrgAbandonUseCase::execute",
        SETUP_GIVEN_UP,
    ),
    (
        "use_cases/signals/streams/verification/confirm_endpoint.rs",
        "ConfirmEndpointUseCase::execute",
        ENDPOINT_CONFIRMED,
    ),
    (
        "use_cases/audit/exports/write.rs",
        "WriteUseCase::execute",
        AUDIT_EXPORT_WRITTEN,
    ),
];

/// Stores taking a scoped tenant without being `TenantScoped`, on purpose:
/// the file, the port, and why.
const UNSCOPED_STORES_ALLOWED: &[Exception] = &[];

/// Methods of `TenantScoped` ports that do not take the tenant first, on
/// purpose: the file, `Port::method`, and why.
const TENANTLESS_METHODS_ALLOWED: &[Exception] = &[];

/// One place a rule is broken: the file, the line, what it is about and
/// what is wrong.
struct Break {
    path: String,
    line: usize,
    subject: String,
    message: String,
}

impl Break {
    fn at(file: &SourceFile, line: usize, subject: String, message: String) -> Self {
        Self {
            path: file.path.clone(),
            line,
            subject,
            message,
        }
    }

    fn excused_by(&self, allowed: &[Exception]) -> bool {
        allowed
            .iter()
            .any(|(path, subject, _)| *path == self.path && *subject == self.subject)
    }
}

/// An exception to a rule: the file under `src/`, what it is about (a
/// function as `Owner::name`, a use case, a port or `Port::method`), and
/// why.
type Exception = (&'static str, &'static str, &'static str);

/// A rule, its name, and its exceptions.
struct Rule {
    name: &'static str,
    check: fn(&[SourceFile]) -> Vec<Break>,
    allowed: &'static [Exception],
}

impl Rule {
    /// The breaks of `files` no exception covers.
    fn unexcused(&self, files: &[SourceFile]) -> Findings {
        let mut findings = Findings::default();
        let breaks = (self.check)(files);
        for found in breaks
            .iter()
            .filter(|found| !found.excused_by(self.allowed))
        {
            findings.flag_at(&found.path, found.line, &found.message);
        }
        findings
    }

    /// The exceptions no break of `files` matches any more.
    fn stale(&self, files: &[SourceFile]) -> Vec<String> {
        let breaks = (self.check)(files);
        self.allowed
            .iter()
            .filter(|(path, subject, _)| {
                !breaks
                    .iter()
                    .any(|found| found.path == *path && found.subject == *subject)
            })
            .map(|(path, subject, _)| format!("{path}: {subject}"))
            .collect()
    }
}

/// Every rule.
const RULES: [Rule; 5] = [
    Rule {
        name: "rights checked late",
        check: late_checks,
        allowed: LATE_CHECKS_ALLOWED,
    },
    Rule {
        name: "silent commands",
        check: silent_commands,
        allowed: SILENT_COMMANDS_ALLOWED,
    },
    Rule {
        name: "unrecorded saves",
        check: unrecorded_saves,
        allowed: UNRECORDED_SAVES_ALLOWED,
    },
    Rule {
        name: "unscoped stores",
        check: unscoped_stores,
        allowed: UNSCOPED_STORES_ALLOWED,
    },
    Rule {
        name: "scoped methods without the tenant",
        check: tenantless_methods,
        allowed: TENANTLESS_METHODS_ALLOWED,
    },
];

/// The files that run use cases: the use cases and the services they share.
fn running_files(files: &[SourceFile]) -> impl Iterator<Item = &SourceFile> {
    files
        .iter()
        .filter(|file| file.path.starts_with("use_cases/") || file.path.starts_with("services/"))
}

/// The files that declare ports.
fn port_files(files: &[SourceFile]) -> impl Iterator<Item = &SourceFile> {
    files
        .iter()
        .filter(|file| file.path.starts_with("ports/") || file.path.starts_with("acting/"))
}

/// A function with a body, and the type whose `impl` holds it.
struct Body<'a> {
    owner: Option<String>,
    signature: &'a Signature,
    block: &'a Block,
}

impl Body<'_> {
    /// `Owner::function`, or the function's name alone.
    fn subject(&self) -> String {
        let name = &self.signature.ident;
        self.owner
            .as_ref()
            .map_or_else(|| name.to_string(), |owner| format!("{owner}::{name}"))
    }

    /// Whether the body owes a record of what it saves: it is a use case's
    /// `execute` or holds the auditor, and neither hands events back to its
    /// caller nor is itself a save.
    fn owes_a_record(&self) -> bool {
        let hands_back = match &self.signature.output {
            ReturnType::Type(_, ty) => names_in_type(ty).iter().any(|name| name.contains("Event")),
            ReturnType::Default => false,
        };
        let holds_auditor = parameter_types(self.signature).any(|ty| mentions(ty, AUDITOR));
        let records_here = self.signature.ident == "execute" || holds_auditor;
        let is_a_save = self.signature.ident.to_string().starts_with("save");
        records_here && !hands_back && !is_a_save
    }
}

/// Every function with a body in `items`, those of inline modules too.
fn bodies(items: &[Item]) -> Vec<Body<'_>> {
    items
        .iter()
        .flat_map(|item| match item {
            Item::Fn(function) => vec![Body {
                owner: None,
                signature: &function.sig,
                block: &function.block,
            }],
            Item::Impl(block) => impl_bodies(block),
            Item::Mod(module) => module
                .content
                .as_ref()
                .map(|(_, inner)| bodies(inner))
                .unwrap_or_default(),
            _ => Vec::new(),
        })
        .collect()
}

fn impl_bodies(block: &ItemImpl) -> Vec<Body<'_>> {
    let owner = type_name(&block.self_ty);
    block
        .items
        .iter()
        .filter_map(|member| match member {
            ImplItem::Fn(function) => Some(Body {
                owner: owner.clone(),
                signature: &function.sig,
                block: &function.block,
            }),
            _ => None,
        })
        .collect()
}

/// The last name of a path type, such as `Topic` for `topic::Topic<T>`.
fn type_name(ty: &Type) -> Option<String> {
    let Type::Path(path) = ty else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

/// Every name written in a node, macros left out.
#[derive(Default)]
struct Names(BTreeSet<String>);

impl<'ast> Visit<'ast> for Names {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        self.0.insert(ident.to_string());
    }
}

fn names_in_type(ty: &Type) -> BTreeSet<String> {
    let mut names = Names::default();
    names.visit_type(ty);
    names.0
}

fn mentions(ty: &Type, name: &str) -> bool {
    names_in_type(ty).contains(name)
}

/// The types of a signature's parameters other than `self`.
fn parameter_types(signature: &Signature) -> impl Iterator<Item = &Type> {
    signature.inputs.iter().filter_map(|input| match input {
        FnArg::Typed(typed) => Some(typed.ty.as_ref()),
        FnArg::Receiver(_) => None,
    })
}

/// The name an expression is last known by, looking through references and
/// `as_ref()`: `self.ports.topic_store.as_ref()` is `topic_store`.
fn last_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Field(field) => match &field.member {
            syn::Member::Named(ident) => Some(ident.to_string()),
            syn::Member::Unnamed(_) => last_name(&field.base),
        },
        Expr::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        Expr::MethodCall(call) if call.method == "as_ref" => last_name(&call.receiver),
        Expr::Reference(reference) => last_name(&reference.expr),
        _ => None,
    }
}

fn is_load(name: &str) -> bool {
    ["find_", "existing_", "load_", "fetch_"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn is_store(receiver: &Expr) -> bool {
    last_name(receiver).is_some_and(|name| {
        let name = name.to_ascii_lowercase();
        name.contains("store") || name.contains("repo")
    })
}

/// Words in the names of the proofs a right is checked against.
const PROOF_WORDS: &[&str] = &["authority", "control", "standing", "actor"];

/// Words in the names of the proofs an aggregate is handed to check a right
/// itself. `actor` is left out: `ctx.actor()` only names who acts, for the
/// record.
const HANDED_PROOF_WORDS: &[&str] = &["authority", "control", "standing"];

fn is_handed_proof(name: &str) -> bool {
    HANDED_PROOF_WORDS.iter().any(|word| name.contains(word))
}

/// Whether a call named `name`, writing `names`, checks a right: one that
/// hands out a control once the right is held (`actor.control()`,
/// `account_control(..)`), or an `ensure_*` handed a proof.
fn checks_a_right(name: &str, names: &Names) -> bool {
    let given_a_proof = names
        .0
        .iter()
        .any(|written| PROOF_WORDS.iter().any(|word| written.contains(word)));
    let hands_out_a_control =
        name == "control" || name.ends_with("_control") || name.contains("_control_");
    hands_out_a_control || (name.starts_with("ensure_") && given_a_proof)
}

/// What one statement does: the lines it loads, checks a right and names a
/// proof on, and every name it writes.
#[derive(Default)]
struct Statement {
    loads: Vec<usize>,
    checks: Vec<usize>,
    proofs: Vec<usize>,
    names: BTreeSet<String>,
}

impl Statement {
    fn of(stmt: &Stmt) -> Self {
        let mut found = Self::default();
        found.visit_stmt(stmt);
        found
    }
}

impl<'ast> Visit<'ast> for Statement {
    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let name = call.method.to_string();
        if is_load(&name) && is_store(&call.receiver) {
            self.loads.push(line_of(&call.method));
        }
        let mut call_names = Names::default();
        call_names.visit_expr_method_call(call);
        if checks_a_right(&name, &call_names) {
            self.checks.push(line_of(&call.method));
        }
        if name == "actor" {
            self.names.extend(call_names.0);
            return;
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(path) = call.func.as_ref()
            && let Some(last) = path.path.segments.last()
        {
            let name = last.ident.to_string();
            if ["existing_", "owned_", "load_"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
            {
                self.loads.push(line_of(&last.ident));
            }
            let mut call_names = Names::default();
            call_names.visit_expr_call(call);
            if checks_a_right(&name, &call_names) {
                self.checks.push(line_of(&last.ident));
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        let name = ident.to_string();
        if is_handed_proof(&name) {
            self.proofs.push(line_of(ident));
        }
        self.names.insert(name);
    }
}

/// The variables a pattern binds.
#[derive(Default)]
struct Bindings(BTreeSet<String>);

impl<'ast> Visit<'ast> for Bindings {
    fn visit_pat_ident(&mut self, binding: &'ast syn::PatIdent) {
        self.0.insert(binding.ident.to_string());
        visit::visit_pat_ident(self, binding);
    }
}

/// The variables a `let` binds.
fn bound_names(stmt: &Stmt) -> BTreeSet<String> {
    let Stmt::Local(local) = stmt else {
        return BTreeSet::new();
    };
    let mut bindings = Bindings::default();
    bindings.visit_pat(&local.pat);
    bindings.0
}

/// A right a body checks too late, with the lines of the load and of the
/// check.
enum LateRight {
    /// Checked after a load it does not need.
    Unneeded { load: usize, check: usize },
    /// Never checked before the load, and handed to the aggregate after it.
    Unchecked { load: usize, handed: usize },
}

impl LateRight {
    /// Whether this is a lookup handed the proof (`owned_*`, `existing_*`)
    /// using it on what it read: that is how it reads a record the caller
    /// may not act on as missing.
    fn is_the_lookups_own(&self, body: &Body<'_>) -> bool {
        let name = body.signature.ident.to_string();
        let is_lookup = name.starts_with("owned_") || name.starts_with("existing_");
        matches!(self, Self::Unchecked { .. }) && is_lookup
    }

    fn line(&self) -> usize {
        match self {
            Self::Unneeded { check, .. } => *check,
            Self::Unchecked { handed, .. } => *handed,
        }
    }

    fn message(&self, subject: &str) -> String {
        match self {
            Self::Unneeded { load, check } => format!(
                "`{subject}` loads a record on line {load} and then checks a right on line {check} that does not need it; check first"
            ),
            Self::Unchecked { load, handed } => format!(
                "`{subject}` loads a record on line {load} before checking any right and hands a proof on on line {handed}; check the right first, or hand the proof to the lookup so a record the caller may not act on reads as missing"
            ),
        }
    }
}

/// Where a body walked so far stands with its first load.
enum Loading {
    /// Nothing loaded yet, and no right checked.
    Nothing,
    /// A right was checked, or handed to the lookup, before anything else
    /// was loaded.
    Checked,
    /// Loaded on the line, before any right was checked.
    Unchecked(usize),
}

impl Loading {
    /// Where the body stands once `found` has run.
    fn after(self, found: &Statement) -> Self {
        match self {
            Self::Nothing => Self::first(found),
            settled => settled,
        }
    }

    /// Where a body that had loaded nothing stands once `found` has run: a
    /// load handed a proof checks the right as it reads.
    fn first(found: &Statement) -> Self {
        let checked_at_load = !found.loads.is_empty() && !found.proofs.is_empty();
        if !found.checks.is_empty() || checked_at_load {
            return Self::Checked;
        }
        found
            .loads
            .first()
            .map_or(Self::Nothing, |load| Self::Unchecked(*load))
    }
}

/// The first right checked too late in `block`: a check after a load that
/// names nothing loaded, or anything bound from what was loaded, or a proof
/// handed on after a load no right came before.
fn late_check(block: &Block) -> Option<LateRight> {
    let mut loaded = BTreeSet::new();
    let mut first_load = None;
    let mut loading = Loading::Nothing;
    for stmt in &block.stmts {
        let found = Statement::of(stmt);
        if let (Some(load), Some(check)) = (first_load, found.checks.first())
            && found.names.is_disjoint(&loaded)
        {
            return Some(LateRight::Unneeded {
                load,
                check: *check,
            });
        }
        if let (Loading::Unchecked(load), Some(handed)) = (&loading, found.proofs.first()) {
            return Some(LateRight::Unchecked {
                load: *load,
                handed: *handed,
            });
        }
        loading = loading.after(&found);
        if !found.loads.is_empty() || !found.names.is_disjoint(&loaded) {
            loaded.extend(bound_names(stmt));
        }
        first_load = first_load.or_else(|| found.loads.first().copied());
    }
    None
}

/// Rights checked after a load they do not need, or not before it at all.
fn late_checks(files: &[SourceFile]) -> Vec<Break> {
    let mut found = Vec::new();
    for file in running_files(files) {
        for body in bodies(file.items()) {
            let Some(late) = late_check(body.block) else {
                continue;
            };
            if late.is_the_lookups_own(&body) {
                continue;
            }
            let subject = body.subject();
            let message = late.message(&subject);
            found.push(Break::at(file, late.line(), subject, message));
        }
    }
    found
}

/// How a command's body uses its auditor.
struct AuditorUse {
    name: String,
    mentions: usize,
    kept_to_itself: usize,
    in_macros: bool,
    dispatches: bool,
}

impl AuditorUse {
    fn of(block: &Block, name: &str) -> Self {
        let mut found = Self {
            name: name.to_owned(),
            mentions: 0,
            kept_to_itself: 0,
            in_macros: false,
            dispatches: false,
        };
        found.visit_block(block);
        found
    }

    /// Whether the body dispatches, or hands the auditor on.
    fn records(&self) -> bool {
        self.dispatches || self.in_macros || self.mentions > self.kept_to_itself
    }

    fn named_in(&self, tokens: proc_macro2::TokenStream) -> bool {
        tokens.into_iter().any(|tree| match tree {
            proc_macro2::TokenTree::Ident(ident) => ident == self.name,
            proc_macro2::TokenTree::Group(group) => self.named_in(group.stream()),
            _ => false,
        })
    }
}

impl<'ast> Visit<'ast> for AuditorUse {
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if path.path.is_ident(&self.name) {
            self.mentions += 1;
        }
        visit::visit_expr_path(self, path);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let method = call.method.to_string();
        let on_auditor =
            matches!(call.receiver.as_ref(), Expr::Path(path) if path.path.is_ident(&self.name));
        if on_auditor && !method.starts_with("with_") {
            self.kept_to_itself += 1;
        }
        self.dispatches |= RECORDING.contains(&method.as_str());
        visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.in_macros |= self.named_in(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// What a command does with the auditor it is handed.
enum AuditorParameter {
    /// It names it, so it may use it.
    Bound(String),
    /// It ignores it: `_` or `_auditor`.
    Ignored,
}

impl AuditorParameter {
    /// Whether `body` dispatches through the auditor or hands it on.
    fn records_in(&self, body: &Block) -> bool {
        match self {
            Self::Bound(name) => AuditorUse::of(body, name).records(),
            Self::Ignored => false,
        }
    }
}

/// The auditor parameter of `signature`, if it takes one.
fn auditor_parameter(signature: &Signature) -> Option<AuditorParameter> {
    signature.inputs.iter().find_map(|input| match input {
        FnArg::Typed(typed) if mentions(&typed.ty, AUDITOR) => Some(match typed.pat.as_ref() {
            Pat::Ident(binding) if !binding.ident.to_string().starts_with('_') => {
                AuditorParameter::Bound(binding.ident.to_string())
            }
            _ => AuditorParameter::Ignored,
        }),
        _ => None,
    })
}

fn implements(block: &ItemImpl, name: &str) -> bool {
    block
        .trait_
        .as_ref()
        .and_then(|(_, path, _)| path.segments.last())
        .is_some_and(|segment| segment.ident == name)
}

/// The `execute` of a command, with the command's name.
fn command_executes(file: &SourceFile) -> Vec<(String, &syn::ImplItemFn)> {
    file.items()
        .iter()
        .filter_map(|item| match item {
            Item::Impl(block) if implements(block, "Command") => Some(block),
            _ => None,
        })
        .filter_map(|block| {
            let execute = block.items.iter().find_map(|member| match member {
                ImplItem::Fn(function) if function.sig.ident == "execute" => Some(function),
                _ => None,
            })?;
            Some((type_name(&block.self_ty)?, execute))
        })
        .collect()
}

/// Commands that take the auditor and never record through it.
fn silent_commands(files: &[SourceFile]) -> Vec<Break> {
    let mut found = Vec::new();
    for file in running_files(files) {
        for (command, execute) in command_executes(file) {
            let Some(auditor) = auditor_parameter(&execute.sig) else {
                continue;
            };
            if auditor.records_in(&execute.block) {
                continue;
            }
            let message = format!(
                "`{command}` takes the auditor and never dispatches through it or hands it on"
            );
            found.push(Break::at(
                file,
                line_of(&execute.sig.ident),
                command,
                message,
            ));
        }
    }
    found
}

/// The saves and the recordings in one body, in source order.
#[derive(Default)]
struct Saves {
    saves: Vec<(usize, usize)>,
    records: Vec<(usize, usize)>,
}

fn position_of(node: &impl syn::spanned::Spanned) -> (usize, usize) {
    let start = node.span().start();
    (start.line, start.column)
}

fn is_recording(name: &str) -> bool {
    RECORDING.contains(&name) || name.starts_with("record")
}

impl Saves {
    fn note_tokens(&mut self, tokens: proc_macro2::TokenStream) {
        for tree in tokens {
            match tree {
                proc_macro2::TokenTree::Ident(ident)
                    if is_recording(&ident.to_string()) || ident == "auditor" =>
                {
                    self.records.push(position_of(&ident));
                }
                proc_macro2::TokenTree::Group(group) => self.note_tokens(group.stream()),
                _ => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for Saves {
    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let name = call.method.to_string();
        if name == "save" {
            self.saves.push(position_of(&call.method));
        }
        if is_recording(&name) {
            self.records.push(position_of(&call.method));
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(path) = call.func.as_ref()
            && path
                .path
                .segments
                .last()
                .is_some_and(|last| is_recording(&last.ident.to_string()))
        {
            self.records.push(position_of(path));
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if path.path.is_ident("auditor") {
            self.records.push(position_of(path));
        }
        visit::visit_expr_path(self, path);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.note_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// The line of the last save in `body` when nothing is recorded after it.
fn unrecorded_save(body: &Body<'_>) -> Option<usize> {
    if !body.owes_a_record() {
        return None;
    }
    let mut saves = Saves::default();
    saves.visit_block(body.block);
    let last_save = saves.saves.iter().max()?;
    let recorded_after = saves.records.iter().any(|record| record > last_save);
    (!recorded_after).then_some(last_save.0)
}

/// Saves with no event taken or dispatched after them.
fn unrecorded_saves(files: &[SourceFile]) -> Vec<Break> {
    let mut found = Vec::new();
    for file in running_files(files) {
        for body in bodies(file.items()) {
            let Some(line) = unrecorded_save(&body) else {
                continue;
            };
            let subject = body.subject();
            let message = format!(
                "`{subject}` saves and then takes no events and dispatches nothing; take what the aggregate raised"
            );
            found.push(Break::at(file, line, subject, message));
        }
    }
    found
}

/// One method of a port trait: its name, its line, and whether it takes
/// the scoped tenant first, or at all.
struct PortMethod {
    name: String,
    line: usize,
    tenant_first: bool,
    takes_tenant: bool,
}

/// A port trait: its name, its line, what it extends and its methods.
struct Port {
    name: String,
    line: usize,
    supertraits: Vec<String>,
    methods: Vec<PortMethod>,
}

fn ports_in(file: &SourceFile) -> Vec<Port> {
    file.items()
        .iter()
        .filter_map(|item| match item {
            Item::Trait(declared) if matches!(declared.vis, syn::Visibility::Public(_)) => {
                Some(declared)
            }
            _ => None,
        })
        .map(|declared| Port {
            name: declared.ident.to_string(),
            line: line_of(&declared.ident),
            supertraits: supertraits_of(declared),
            methods: (declared.items.iter())
                .filter_map(|member| match member {
                    TraitItem::Fn(function) => Some(port_method(&function.sig)),
                    _ => None,
                })
                .collect(),
        })
        .collect()
}

/// The names of the traits `declared` requires, last path segment only.
fn supertraits_of(declared: &syn::ItemTrait) -> Vec<String> {
    (declared.supertraits.iter())
        .filter_map(|bound| match bound {
            TypeParamBound::Trait(bound) => bound
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string()),
            _ => None,
        })
        .collect()
}

fn port_method(signature: &Signature) -> PortMethod {
    PortMethod {
        name: signature.ident.to_string(),
        line: line_of(&signature.ident),
        tenant_first: parameter_types(signature)
            .next()
            .is_some_and(|ty| mentions(ty, SCOPED_TENANT)),
        takes_tenant: parameter_types(signature).any(|ty| mentions(ty, SCOPED_TENANT)),
    }
}

impl Port {
    fn is_scoped(&self) -> bool {
        self.supertraits.iter().any(|name| name == TENANT_SCOPED)
    }

    fn is_unscoped_store(&self) -> bool {
        let is_store = self.name.ends_with("Store") || self.name.ends_with("Repository");
        let cross_tenant = self.name.starts_with("CrossTenant");
        is_store
            && !cross_tenant
            && !self.is_scoped()
            && self.methods.iter().any(|method| method.takes_tenant)
    }
}

/// Stores taking a scoped tenant that are not `TenantScoped`.
fn unscoped_stores(files: &[SourceFile]) -> Vec<Break> {
    let mut found = Vec::new();
    for file in port_files(files) {
        for port in ports_in(file).into_iter().filter(Port::is_unscoped_store) {
            let message = format!(
                "`{}` takes a scoped tenant but neither extends `TenantScoped` nor is named `CrossTenant*`",
                port.name
            );
            found.push(Break::at(file, port.line, port.name, message));
        }
    }
    found
}

/// Methods of `TenantScoped` ports that do not take the tenant first.
fn tenantless_methods(files: &[SourceFile]) -> Vec<Break> {
    let mut found = Vec::new();
    for file in port_files(files) {
        for port in ports_in(file).into_iter().filter(Port::is_scoped) {
            for method in port.methods.iter().filter(|method| !method.tenant_first) {
                let subject = format!("{}::{}", port.name, method.name);
                let message = format!(
                    "`{subject}` is on a `TenantScoped` port and does not take the scoped tenant first"
                );
                found.push(Break::at(file, method.line, subject, message));
            }
        }
    }
    found
}

fn assert_kept(rule: &Rule) {
    rule.unexcused(&production_files()).assert_none(rule.name);
}

#[cfg_attr(test, test)]
pub(crate) fn rights_are_checked_before_a_load_they_do_not_need() {
    assert_kept(&RULES[0]);
}

#[cfg_attr(test, test)]
pub(crate) fn every_command_records_through_its_auditor() {
    assert_kept(&RULES[1]);
}

#[cfg_attr(test, test)]
pub(crate) fn every_save_is_followed_by_its_events() {
    assert_kept(&RULES[2]);
}

#[cfg_attr(test, test)]
pub(crate) fn a_store_taking_a_scoped_tenant_is_tenant_scoped() {
    assert_kept(&RULES[3]);
}

#[cfg_attr(test, test)]
pub(crate) fn every_scoped_port_method_takes_the_tenant_first() {
    assert_kept(&RULES[4]);
}

/// An exception the code no longer needs would let the next break through
/// unread.
#[cfg_attr(test, test)]
pub(crate) fn every_security_exception_still_matches_a_break() {
    let files = production_files();
    let gone: Vec<String> = RULES.iter().flat_map(|rule| rule.stale(&files)).collect();

    assert!(gone.is_empty(), "exceptions that match nothing: {gone:?}");
}

/// Every exception says why, and a defect waiting for its fix says so the
/// same way each time, so a search for `TO FIX:` finds them all.
#[cfg_attr(test, test)]
pub(crate) fn every_security_exception_gives_its_reason() {
    let unexplained: Vec<&str> = RULES
        .iter()
        .flat_map(|rule| rule.allowed.iter())
        .filter(|(_, _, reason)| {
            reason.trim().is_empty()
                || (reason.starts_with("TO FIX") && !reason.starts_with("TO FIX:"))
        })
        .map(|(_, subject, _)| *subject)
        .collect();

    assert!(
        unexplained.is_empty(),
        "exceptions without a reason: {unexplained:?}"
    );
}

/// Each rule, run over files that break it on purpose, finds the break, and
/// leaves alone the shapes it allows. So a rule that stops looking fails
/// here instead of passing everything.
#[cfg_attr(test, test)]
pub(crate) fn every_security_rule_finds_its_planted_break() {
    let files = [
        SourceFile::planted("use_cases/planted.rs", PLANTED),
        SourceFile::planted("ports/planted.rs", PLANTED_PORTS),
    ];
    let expected: [&[&str]; 5] = [
        &["Archive::execute", "Retitle::execute"],
        &["RenameUseCase"],
        &["pause"],
        &["TopicStore"],
        &["ScopedStore::by_token"],
    ];

    let found: Vec<Vec<String>> = RULES
        .iter()
        .map(|rule| {
            (rule.check)(&files)
                .into_iter()
                .map(|found| found.subject)
                .collect()
        })
        .collect();

    for (rule, (found, wanted)) in RULES.iter().zip(found.iter().zip(expected)) {
        assert_eq!(found, wanted, "{}", rule.name);
    }
}

/// Use cases breaking each function rule, beside the shapes the rules
/// allow: a right that needs the record, a lookup handed the proof and the
/// lookup using it, a record naming who acted after a load, a command
/// handing a narrowed auditor on, and a save whose events are taken. The late rights rule is broken twice: a right checked after a
/// load it does not need, and a load before any right.
const PLANTED: &str = r"
impl Archive {
    async fn execute(&self, store: &dyn TopicStore) {
        authority.ensure_holds(MessagingAction::View)?;
        let topic = existing_topic(store, &tenant, &id).await?;
        let owner = topic.owner();
        control.ensure_may(owner, MessagingAction::Delete)?;
        authority.ensure_holds(MessagingAction::Delete)?;
    }
}
impl Retitle {
    async fn execute(&self, store: &dyn TopicStore) {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let mut topic = existing_topic(store, &tenant, &id).await?;
        topic.retitle(title, &MessagingControl::new(&authority))?;
    }
}
async fn owned(store: &dyn TopicStore) {
    authority.ensure_holds(MessagingAction::View)?;
    let topic = self.ports.topic_store.find_by_id(&tenant, &id).await?;
    topic.ensure_owned_by(&caller)?;
}
async fn steered(store: &dyn TopicStore) {
    let control = MessagingControl::new(&authority);
    let mut topic = owned_topic(store, &tenant, &id, &control).await?;
    topic.steer(&control)?;
}
async fn owned_topic(store: &dyn TopicStore, control: &MessagingControl<'_>) {
    let topic = store.find_by_id(&tenant, &id).await?;
    topic.filter(|topic| control.may_steer(topic))
}
impl Publish {
    async fn execute(&self, store: &dyn TopicStore) {
        let mut topic = existing_topic(store, &tenant, &id).await?;
        auditor.dispatch_by(&authority.actor(), topic.take_events(&tenant)).await
    }
}
async fn pause(store: &dyn TopicStore, auditor: &RequestAuditor) {
    store.save(&tenant, &topic).await?;
    Ok(())
}
async fn resume(store: &dyn TopicStore, auditor: &RequestAuditor) {
    store.save(&tenant, &topic).await?;
    auditor.dispatch(&topic.take_events(&tenant)).await
}
async fn stopped(store: &dyn TopicStore, auditor: &RequestAuditor) -> Vec<DomainEvent> {
    store.save(&tenant, &topic).await;
    events
}
impl Command for RenameUseCase {
    async fn execute(&self, caller: &CallerContext, _: &RequestAuditor, input: Input) {
        self.helper.run(input).await
    }
}
impl Command for SweepUseCase {
    async fn execute(&self, caller: &(), auditor: &RequestAuditor, input: Input) {
        let narrowed = auditor.with_tenant(tenant);
        self.sweep(&narrowed).await
    }
}
";

/// Ports breaking each port rule once, beside the shapes the rules allow.
const PLANTED_PORTS: &str = r"
pub trait TopicStore: Send + Sync {
    async fn find(&self, tenant: &ScopedTenant, id: &TopicId);
}
pub trait CrossTenantTopicStore: Send + Sync {
    async fn find(&self, tenant: &ScopedTenant, id: &TopicId);
}
pub trait ScopedStore: Send + Sync + TenantScoped {
    async fn find(&self, tenant: &ScopedTenant, id: &TopicId);
    async fn by_token(&self, token: &Token);
}
";
