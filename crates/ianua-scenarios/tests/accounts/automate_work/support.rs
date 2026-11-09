//! What the workflow scenarios share: an account connected to the outside
//! service, the graphs that call it with and without an approval, a loop
//! running either for each issue, Tess's draft, Ann's publication of the
//! revision she reviewed, a run started by hand, and reading a run until
//! it ends.

use ianua_scenarios::actors::{Member, Person};
use ianua_scenarios::api::{member_factors, people, roles, workflows};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::expect::eventually;
use ianua_scenarios::wire::factors::ConfirmFactor;
use ianua_scenarios::wire::organization::OrgRole;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::roles::{NewRole, SystemPermission};
use ianua_scenarios::wire::sign_in::{MemberFactorSetup, MemberProof};
use ianua_scenarios::wire::workflows::{
    Approve, Edge, Execution, ExecutionDecided, Graph, MappedField, NewAccount, NewWorkflow, Node,
    Publication, Source, StartExecution, Step, Trigger, Workflow,
};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use crate::service::Service;

/// The key of the step that calls the outside service.
pub(crate) const DELIVERY_STEP: &str = "deliver";

/// The key of the step that waits for an approval before the delivery.
pub(crate) const APPROVAL_STEP: &str = "consent";

/// The key of the step that loops over the trigger's issues.
pub(crate) const LOOP_STEP: &str = "each";

/// How long the approval may wait to be decided: two minutes, longer than
/// any scenario takes to decide it.
const APPROVAL_WINDOW_SECONDS: u32 = 120;

/// The longest a run may take: five minutes, longer than any scenario's
/// run.
const RUN_LIMIT_SECONDS: u32 = 300;

/// Tess connects an account for the outside service, shared with the
/// whole tenant, holding the service's credential; the account's id.
pub(crate) async fn connected_account(world: &World<'_>, service: &Service) -> String {
    account_at(world, "http", &service.credential()).await
}

/// Tess connects an account at `integration`, shared with the whole
/// tenant, holding `credential`; the account's id.
pub(crate) async fn account_at(world: &World<'_>, integration: &str, credential: &str) -> String {
    let account = NewAccount {
        integration: integration.to_owned(),
        name: format!("Tenant {integration} account"),
        credential: credential.to_owned(),
        sharing: "tenant".to_owned(),
    };
    workflows::connect_account(world.tenant(), &account)
        .send(world.admin().client())
        .await
        .ok()
        .id
}

/// The integration operation a workflow action invokes.
#[derive(Clone, Copy)]
pub(crate) struct Action<'a> {
    /// The catalog integration that owns the operation.
    pub(crate) integration: &'a str,
    /// The operation key within that integration.
    pub(crate) operation: &'a str,
}

/// A step calling `action` through `account_id`, as `effect` says,
/// its inputs filled as `inputs` says. Its key is
/// `<integration>-<operation>`, which later steps read its output under.
pub(crate) fn action(
    action: Action<'_>,
    account_id: &str,
    effect: &str,
    inputs: Vec<(&str, Source)>,
) -> Node {
    let Action {
        integration,
        operation,
    } = action;
    Node {
        key: format!("{integration}-{operation}"),
        name: format!("{integration} {operation}"),
        step: Step::Action {
            integration: integration.to_owned(),
            operation: operation.to_owned(),
            account_id: Some(account_id.to_owned()),
            effect: effect.to_owned(),
            ceiling: "internal".to_owned(),
            inputs: inputs
                .into_iter()
                .map(|(field, source)| MappedField {
                    field: field.to_owned(),
                    source,
                })
                .collect(),
        },
    }
}

/// An input written out as `value`, such as text or a list.
pub(crate) fn written(value: impl Into<serde_json::Value>) -> Source {
    Source::Literal {
        value: value.into(),
    }
}

/// An input read at `path` in the step's input, such as an earlier step's
/// `github-create-issue.json.number`.
pub(crate) fn read(path: &str) -> Source {
    Source::Input {
        path: path.to_owned(),
    }
}

/// The step that calls the outside service through `account_id`: a read,
/// handed nothing above internal data.
fn delivery(service: &Service, account_id: &str) -> Node {
    Node {
        key: DELIVERY_STEP.to_owned(),
        name: "Deliver externally".to_owned(),
        step: Step::Action {
            integration: "http".to_owned(),
            operation: "get-with-account".to_owned(),
            account_id: Some(account_id.to_owned()),
            effect: "read".to_owned(),
            ceiling: "internal".to_owned(),
            inputs: vec![MappedField {
                field: "url".to_owned(),
                source: written(service.url()),
            }],
        },
    }
}

/// A graph of the one delivery step: a run that reaches the end called
/// the outside service.
pub(crate) fn delivery_graph(service: &Service, account_id: &str) -> Graph {
    Graph {
        nodes: vec![delivery(service, account_id)],
        edges: vec![],
    }
}

/// A graph where an approval must be given before the delivery step
/// runs.
pub(crate) fn approved_delivery_graph(service: &Service, account_id: &str) -> Graph {
    Graph {
        nodes: vec![
            Node {
                key: APPROVAL_STEP.to_owned(),
                name: "Approve delivery".to_owned(),
                step: Step::Approval {
                    summary: "Approve this external delivery".to_owned(),
                    action_class: "read".to_owned(),
                    window_seconds: APPROVAL_WINDOW_SECONDS,
                },
            },
            delivery(service, account_id),
        ],
        edges: vec![Edge {
            from: APPROVAL_STEP.to_owned(),
            to: DELIVERY_STEP.to_owned(),
        }],
    }
}

/// A graph of one loop, keyed [`LOOP_STEP`], over the trigger's `issues`,
/// running the steps of `body` for each issue, `at_once` at a time.
pub(crate) fn each_issue(body: Graph, at_once: u32) -> Graph {
    Graph {
        nodes: vec![Node {
            key: LOOP_STEP.to_owned(),
            name: "Each issue".to_owned(),
            step: Step::Loop {
                over: "trigger.issues".to_owned(),
                steps: body,
                most_items: 10,
                at_once,
            },
        }],
        edges: vec![],
    }
}

/// Tess drafts a workflow started by `trigger` running `graph`; the
/// draft, with the revision a publisher must say they reviewed.
pub(crate) async fn drafted(world: &World<'_>, trigger: Trigger, graph: Graph) -> Workflow {
    let workflow = NewWorkflow {
        name: "Outside delivery workflow".to_owned(),
        trigger,
        graph,
        run_limit_seconds: RUN_LIMIT_SECONDS,
    };
    workflows::create_draft(world.tenant(), &workflow)
        .send(world.admin().client())
        .await
        .ok()
}

/// Ann, not the drafter, publishes exactly the revision of `draft` she
/// reviewed.
pub(crate) async fn published(world: &World<'_>, draft: &Workflow) -> Workflow {
    let publication = Publication {
        revision: draft.revision.clone(),
    };
    workflows::publish(world.tenant(), &draft.id, &publication)
        .send(world.owner().client())
        .await
        .ok()
}

/// Tess starts the published `workflow` by hand with an order in its
/// input.
pub(crate) async fn started(world: &World<'_>, workflow: &Workflow) -> ExecutionDecided {
    started_with(world, workflow, json!({"order": "visible-order"})).await
}

/// Tess starts the published `workflow` by hand with `input`.
pub(crate) async fn started_with(
    world: &World<'_>,
    workflow: &Workflow,
    input: serde_json::Value,
) -> ExecutionDecided {
    let start = StartExecution {
        input,
        exposure: "internal".to_owned(),
    };
    workflows::start(world.tenant(), &workflow.id, &start)
        .send(world.admin().client())
        .await
        .ok()
}

/// The run `execution_id`, as Tess reads it.
pub(crate) async fn run(world: &World<'_>, execution_id: &str) -> Execution {
    workflows::execution(world.tenant(), execution_id)
        .send(world.admin().client())
        .await
        .ok()
}

/// The run `execution_id` once it has ended, which must be as `expected`
/// says, such as `succeeded`.
pub(crate) async fn ended(world: &World<'_>, execution_id: &str, expected: &str) -> Execution {
    eventually("the run to end", || async {
        let execution = run(world, execution_id).await;
        if execution.status == "running" {
            return None;
        }
        assert_eq!(
            execution.status, expected,
            "the run ended as expected: {:?}",
            execution.steps
        );
        Some(execution)
    })
    .await
}

/// Pat, invited by Tess into the tenant with a role that may run
/// workflows, accepted and signed in.
pub(crate) async fn pat(world: &World<'_>) -> Person {
    invited(
        world,
        ("pat", "Pat Runner"),
        &[("Workflows", "View"), ("Workflows", "Run")],
    )
    .await
}

/// The person `who` names, by their handle and their name, invited by
/// Tess into the tenant with a role of their own giving `rights`, each a
/// resource and an action, accepted and signed in.
pub(crate) async fn invited(
    world: &World<'_>,
    who: (&str, &str),
    rights: &[(&str, &str)],
) -> Person {
    let role_id = create_person_role(world, who.1, rights).await;
    invited_to(world, who, role_id).await
}

/// Tess invites `who`, a handle and a display name, into the tenant with
/// the role `role_id` already there; they accept and sign in.
pub(crate) async fn invited_to(world: &World<'_>, who: (&str, &str), role_id: String) -> Person {
    let (handle, name) = who;
    let mut person = world.newcomer(handle, name);
    let invitation = people::invite(
        world.tenant(),
        &InviteUser {
            email: person.email().to_owned(),
            display_name: person.account().display_name.clone(),
            role_id,
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    person.record_invitation(&invitation.id);
    person.accept_invitation(world.stack()).await;
    person.sign_in(world.stack()).await;
    person
}

/// Tess creates the person's dedicated role with exactly the requested resource actions.
async fn create_person_role(world: &World<'_>, name: &str, rights: &[(&str, &str)]) -> String {
    roles::create(
        world.tenant(),
        &NewRole {
            name: format!("{name}'s role"),
            system_permissions: rights
                .iter()
                .map(|(resource, action)| SystemPermission::new(resource, action))
                .collect(),
        },
    )
    .send(world.admin().client())
    .await
    .ok()
    .id
}

/// A colleague who may approve a high-risk step: an administrator of the
/// organization, neither an author of the workflow nor the person its run
/// acts for, with an authenticator app whose fresh code each approval
/// takes.
pub(crate) struct Approver {
    member: Member,
    phone: TotpApp,
}

/// The running approval step an approver is deciding.
#[derive(Clone, Copy)]
pub(crate) struct ApprovalStep<'a> {
    /// The execution waiting for a decision.
    pub(crate) execution_id: &'a str,
    /// The key of its approval step.
    pub(crate) step: &'a str,
}

impl Approver {
    /// `display_name`, invited by Ann as an administrator, signed in to
    /// the tenant, who set up an authenticator app from that session.
    pub(crate) async fn joined(world: &World<'_>, name: &str, display_name: &str) -> Self {
        let mut member = world.colleague(name, display_name, OrgRole::Admin).await;
        member.land_in(world.tenant().slug());
        member.sign_in(world.stack()).await;
        let phone = authenticator_of(world, &member).await;
        Self { member, phone }
    }

    /// The client they are signed in with.
    pub(crate) fn client(&self) -> &ianua_scenarios::net::Client {
        self.member.client()
    }

    /// They approve exactly `shown` at the named running step, with a fresh code.
    pub(crate) async fn approve(
        &mut self,
        world: &World<'_>,
        target: ApprovalStep<'_>,
        shown: &Value,
    ) {
        let approval = Approve {
            shown: shown.clone(),
            mfa_code: Some(self.phone.code().await),
        };
        workflows::approve(world.tenant(), target.execution_id, target.step, &approval)
            .send(self.member.client())
            .await
            .ok();
    }
}

/// The authenticator app `member` set up from the session they hold.
async fn authenticator_of(world: &World<'_>, member: &Member) -> TotpApp {
    let setup = MemberFactorSetup {
        proof: MemberProof {
            password: member.password().to_owned(),
            code: None,
        },
    };
    let begun = member_factors::begin_totp(world.org(), &setup)
        .send(member.client())
        .await
        .ok();
    let mut phone = TotpApp::scanning(&begun.otpauth_uri);
    let confirm = ConfirmFactor {
        code: phone.code().await,
        session_id: None,
    };
    member_factors::confirm_totp(world.org(), &confirm)
        .send(member.client())
        .await
        .ok();
    phone
}
