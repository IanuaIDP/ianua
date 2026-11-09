//! Separation of duties: nobody holds both of two roles declared apart.
//! The rule refuses the second role however it would arrive: given
//! straight, through a group, by an approved request, or by moving a
//! group under one carrying it. Lifting the rule lets the roles be held
//! together again, and nothing changes what was given while it stood.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{Request, control_access, policies, roles};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::control_access::{GroupPlacement, NewSeparationRule};
use ianua_scenarios::wire::policies::{AskForGroup, AskedGroup, NewGroupMember};
use ianua_scenarios::wire::roles::AssignRole;
use ianua_scenarios::world::World;

use crate::support::{USER, add_to_group, group, group_with_role, person, role_with};

/// The audit record a rule added leaves.
const ADDED: &str = "authorization.separation_rule_added";

/// The two roles Tess keeps apart.
struct Duties {
    payments: String,
    approvals: String,
}

impl Duties {
    /// Payments and Approvals, each carrying one reading right.
    async fn new(world: &World<'_>) -> Self {
        Self {
            payments: role_with(world, "Payments", &[("Users", "View")]).await,
            approvals: role_with(world, "Approvals", &[("Roles", "View")]).await,
        }
    }

    /// The body keeping them apart.
    fn rule(&self) -> NewSeparationRule {
        NewSeparationRule {
            name: "payments-vs-approvals".to_owned(),
            first_role_id: self.payments.clone(),
            second_role_id: self.approvals.clone(),
        }
    }

    /// Tess keeps them apart.
    async fn kept_apart(&self, world: &World<'_>) -> String {
        control_access::add_separation(world.tenant(), &self.rule())
            .send(world.admin().client())
            .await
            .ok()
            .id
    }
}

/// Tess gives the role `role` straight to `person`.
fn assign(world: &World<'_>, role: &str, person: &Person) -> Request<()> {
    roles::assign(
        world.tenant(),
        role,
        &AssignRole {
            user_id: person.id().to_owned(),
        },
    )
}

/// Tess keeps Payments and Approvals apart, and Pat holds Payments. Pat
/// then cannot get Approvals: not straight, not by joining a group
/// carrying it, not through a request Tess approves, and not by the
/// group she sits in being moved under one carrying it. What she holds
/// stays Payments alone, and the rule is recorded and reads back.
#[tokio::test]
async fn pat_cannot_hold_both_duties_however_they_would_arrive() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    let duties = Duties::new(&world).await;
    duties.kept_apart(&world).await;
    let listed = control_access::separation_rules(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(listed.len(), 1, "the rule reads back");
    world.trail().recorded(ADDED).await;
    assign(&world, &duties.payments, &pat)
        .send(world.admin().client())
        .await
        .ok();

    assign(&world, &duties.approvals, &pat)
        .send(world.admin().client())
        .await
        .refused(Status::CONFLICT, "conflict");

    let approvals_desk = group_with_role(&world, "Approvals desk", &duties.approvals).await;
    let member = NewGroupMember {
        kind: USER.to_owned(),
        id: pat.id().to_owned(),
    };
    policies::add_member(world.tenant(), &approvals_desk, &member)
        .send(world.admin().client())
        .await
        .refused(Status::CONFLICT, "conflict");

    let asked = AskForGroup {
        asked: AskedGroup {
            kind: "role",
            id: duties.approvals.clone(),
        },
        reason: "I cover approvals while Lee is away".to_owned(),
        length_seconds: 3600,
    };
    let request = pat
        .send(policies::ask_for_group(world.tenant(), &asked))
        .await
        .ok();
    policies::approve_request(world.tenant(), &request.id)
        .send(world.admin().client())
        .await
        .refused(Status::CONFLICT, "conflict");

    let night_shift = group(&world, "Night shift").await;
    add_to_group(&world, &night_shift, &pat).await;
    let under_the_desk = GroupPlacement {
        parent_id: Some(approvals_desk.clone()),
    };
    control_access::move_group(world.tenant(), &night_shift, &under_the_desk)
        .send(world.admin().client())
        .await
        .refused(Status::CONFLICT, "conflict");

    let held = control_access::principal_access(world.tenant(), USER, pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        held.direct_roles
            .iter()
            .any(|direct| direct.role.id == duties.payments),
        "Pat holds Payments"
    );
    assert!(
        held.direct_roles
            .iter()
            .all(|direct| direct.role.id != duties.approvals),
        "Pat was not given Approvals straight"
    );
    assert!(
        held.through_groups
            .iter()
            .all(|role| role.role.id != duties.approvals),
        "Approvals reaches Pat through no group"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Max, Sam and nobody signed in may not declare a rule, and Tess may
/// not declare a role against itself or an unknown one. Max may not read
/// the rules or lift them. Tess lifts the rule: Pat may be given both
/// roles again, and the rule's addition and removal are each recorded.
#[tokio::test]
async fn tess_alone_declares_and_lifts_the_separation() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let duties = Duties::new(&world).await;

    Matrix::new(
        "declaring a separation rule",
        control_access::add_separation(world.tenant(), &duties.rule()).call(),
    )
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
    assert_eq!(
        world.trail().count(ADDED).await,
        0,
        "no refused rule is recorded"
    );
    let same_role = NewSeparationRule {
        name: "one-role".to_owned(),
        first_role_id: duties.payments.clone(),
        second_role_id: duties.payments.clone(),
    };
    control_access::add_separation(world.tenant(), &same_role)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let unknown_role = NewSeparationRule {
        name: "unknown-role".to_owned(),
        first_role_id: duties.payments.clone(),
        second_role_id: "00000000-0000-4000-8000-000000000000".to_owned(),
    };
    control_access::add_separation(world.tenant(), &unknown_role)
        .send(world.admin().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    let rule = duties.kept_apart(&world).await;
    control_access::separation_rules(world.tenant())
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    control_access::lift_separation(world.tenant(), &rule)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    assign(&world, &duties.payments, &pat)
        .send(world.admin().client())
        .await
        .ok();
    assign(&world, &duties.approvals, &pat)
        .send(world.admin().client())
        .await
        .refused(Status::CONFLICT, "conflict");

    control_access::lift_separation(world.tenant(), &rule)
        .send(world.admin().client())
        .await
        .ok();
    assign(&world, &duties.approvals, &pat)
        .send(world.admin().client())
        .await
        .ok();
    let held = control_access::principal_access(world.tenant(), USER, pat.id())
        .send(world.admin().client())
        .await
        .ok();
    for role in [&duties.payments, &duties.approvals] {
        assert!(
            held.direct_roles
                .iter()
                .any(|direct| direct.role.id == *role),
            "Pat holds both once the rule is lifted"
        );
    }
    assert!(
        control_access::separation_rules(world.tenant())
            .send(world.admin().client())
            .await
            .ok()
            .is_empty()
    );
    assert_eq!(world.trail().count(ADDED).await, 1);
    world
        .trail()
        .recorded("authorization.separation_rule_removed")
        .await;
    stack.stop().await.expect("the stack stops cleanly");
}
