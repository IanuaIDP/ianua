//! Company steps about access: Pat's workflows ask what Lee may do and who
//! is in Sales, move Lee from Ops to Support, approve Lee's request for
//! Support and lend him Ops for two hours, and give Lee emergency access.
//! Every change to who can do what waits for Bea's and Cal's yes; Pat's
//! run cannot give what Pat could not give by hand, however many say yes.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{Request, people, policies};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::eventually;
use ianua_scenarios::net::Call;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::policies::{
    AskForGroup, AskedGroup, GroupRole, NewGroup, NewGroupMember,
};
use ianua_scenarios::wire::roles::RoleMade;
use ianua_scenarios::wire::workflows::{Graph, Node};
use ianua_scenarios::world::{MEMBER_ROLE, World};
use serde_json::{Value, json};

use super::{
    TwoApprovers, company_step, in_order, output, phase, started_by, through_run, waiting_at, yes,
};
use crate::support::{ended, invited, invited_to, written};

/// The key of the first approval in a run.
const FIRST_YES: &str = "first-yes";

/// The key of the second approval in a run.
const SECOND_YES: &str = "second-yes";

/// The key of the step giving emergency access.
const GLASS_STEP: &str = "break-glass";

/// The key of the step granting Ops for a while.
const LEND_STEP: &str = "lend";

/// What Pat may do to change groups by hand: run workflows, find people,
/// and read and assign roles.
const MANAGES_GROUPS: &[(&str, &str)] = &[
    ("Workflows", "View"),
    ("Workflows", "Run"),
    ("Users", "View"),
    ("Roles", "View"),
    ("Roles", "Assign"),
];

/// What Pat may do when she manages people, and so may hand out rights.
const MANAGES_PEOPLE: &[(&str, &str)] = &[
    ("Workflows", "View"),
    ("Workflows", "Run"),
    ("Users", "Manage"),
];

/// What Pat may do when she only reads people.
const READS_PEOPLE: &[(&str, &str)] = &[
    ("Workflows", "View"),
    ("Workflows", "Run"),
    ("Users", "View"),
];

/// What Lee may do himself: see the workflows.
const SEES_WORKFLOWS: &[(&str, &str)] = &[("Workflows", "View")];

/// Tess makes the group `name`; its id.
async fn group(world: &World<'_>, name: &str) -> String {
    policies::create_group(
        world.tenant(),
        &NewGroup {
            name: name.to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok()
    .id
}

/// Tess adds the person `user_id` to the group `group_id`.
async fn add(world: &World<'_>, group_id: &str, user_id: &str) {
    policies::add_member(
        world.tenant(),
        group_id,
        &NewGroupMember {
            kind: "user".to_owned(),
            id: user_id.to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
}

/// Whether the person `user_id` is in the group `group_id`, as Tess reads
/// its members.
async fn is_in(world: &World<'_>, group_id: &str, user_id: &str) -> bool {
    policies::members(world.tenant(), group_id)
        .send(world.admin().client())
        .await
        .ok()
        .items
        .iter()
        .any(|member| member.kind == "user" && member.id == user_id)
}

/// Tess declares Acme's orders, read by the Order readers role, which the
/// Sales group holds; Sales' id.
async fn sales_reading_orders(world: &World<'_>) -> String {
    let tess = world.admin().client();
    let declared: Request<Value> = Request::of(
        Call::post(world.tenant().at("/resource-types")).json(&json!({
            "key": "orders",
            "display_name": "Orders",
            "actions": [{"key": "read", "display_name": "Read", "implies": []}],
            "data_class": "Internal",
        })),
    );
    declared.send(tess).await.ok();
    let role: Request<RoleMade> = Request::of(
        Call::post(world.tenant().at("/authorization/roles")).json(&json!({
            "name": "Order readers",
            "system_permissions": [],
            "custom_permissions": [{"resource": "orders", "action": "read"}],
        })),
    );
    let role_id = role.send(tess).await.ok().id;
    let sales = group(world, "Sales").await;
    policies::grant_group_role(world.tenant(), &sales, &GroupRole { role_id })
        .send(tess)
        .await
        .ok();
    sales
}

/// Ask whether `who` may read orders, under the step `key`.
fn may_read_orders(key: &str, who: &str) -> Node {
    company_step(
        key,
        "check-access",
        "read",
        vec![
            ("person", written(who)),
            ("action", written("read")),
            ("resource", written("orders")),
        ],
    )
}

/// Lee is in Sales, which reads orders; Bea is in no group. Pat's workflow
/// asks whether each may read orders, then lists Sales: Lee may, through
/// his permission, Bea may not, and Sales has Lee as its one member.
#[tokio::test]
async fn pat_s_run_says_what_lee_may_do_and_who_is_in_sales() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), MANAGES_GROUPS).await;
    let member = world.role_id(MEMBER_ROLE).await;
    let lee = invited_to(&world, ("lee", "Lee Lost"), member.clone()).await;
    let bea = invited_to(&world, ("bea", "Bea Busy"), member).await;
    let sales = sales_reading_orders(&world).await;
    add(&world, &sales, lee.id()).await;
    let graph = checking_and_listing(&lee, &bea, &sales);

    let execution_id = started_by(&world, &mut pat, graph).await;
    let finished = ended(&world, &execution_id, "succeeded").await;

    assert_eq!(output(&finished, "lee-reads")["allowed"], true);
    assert_eq!(output(&finished, "lee-reads")["why"], "permission");
    assert_eq!(output(&finished, "bea-reads")["allowed"], false);
    let members = output(&finished, "sales");
    assert_eq!(members["count"], 1.0);
    assert!(
        members["members"].to_string().contains(lee.id()),
        "{members}"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ask whether Lee and then Bea may read orders, then list Sales.
fn checking_and_listing(lee: &Person, bea: &Person, sales: &str) -> Graph {
    in_order(vec![
        may_read_orders("lee-reads", lee.email()),
        may_read_orders("bea-reads", bea.email()),
        company_step(
            "sales",
            "list-members",
            "read",
            vec![("group", written(sales))],
        ),
    ])
}

/// Lee is in Ops. Pat's workflow adds Lee to Support and takes him out of
/// Ops, each once Bea and Cal say yes. Before the first yes Lee is in Ops
/// alone; once both changes are approved he is in Support and not in Ops,
/// each change recorded as Pat's, through the run.
#[tokio::test]
async fn pat_s_run_moves_lee_from_ops_to_support_once_two_people_say_yes() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), MANAGES_GROUPS).await;
    let lee = invited(&world, ("lee", "Lee Lost"), SEES_WORKFLOWS).await;
    let (ops, support) = (group(&world, "Ops").await, group(&world, "Support").await);
    add(&world, &ops, lee.id()).await;
    let mut approvers = TwoApprovers::joined(&world).await;

    let execution_id = started_by(&world, &mut pat, moving(&lee, &ops, &support)).await;
    waiting_at(&world, &execution_id, FIRST_YES).await;
    let before = is_in(&world, &support, lee.id()).await;
    approvers.approve(&world, &execution_id, FIRST_YES).await;
    approvers.approve(&world, &execution_id, SECOND_YES).await;
    ended(&world, &execution_id, "succeeded").await;

    assert!(!before, "nothing changes before the yes");
    assert!(is_in(&world, &support, lee.id()).await, "Lee is in Support");
    assert!(!is_in(&world, &ops, lee.id()).await, "Lee left Ops");
    for change in [
        "authorization.group_member_added",
        "authorization.group_member_removed",
    ] {
        through_run(&world, change, &execution_id, pat.email()).await;
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Add Lee to Support, then take him out of Ops, each once two people say
/// yes.
fn moving(lee: &Person, ops: &str, support: &str) -> Graph {
    in_order(vec![
        yes(FIRST_YES, "Add Lee to Support"),
        company_step(
            "join",
            "add-to-group",
            "admin",
            vec![
                ("person", written(lee.email())),
                ("group", written(support)),
            ],
        ),
        yes(SECOND_YES, "Take Lee out of Ops"),
        company_step(
            "leave",
            "remove-from-group",
            "admin",
            vec![("person", written(lee.email())), ("group", written(ops))],
        ),
    ])
}

/// Lee asks to join Support for a week. Pat's workflow approves his
/// request, then lends him Ops for two hours, each once Bea and Cal say
/// yes. Lee is in Support and in Ops, the loan ends at a set time, and
/// the trail records the approval as Pat's, through the run.
#[tokio::test]
async fn pat_s_run_approves_lee_s_request_and_lends_him_ops_for_two_hours() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), MANAGES_GROUPS).await;
    let mut lee = invited(&world, ("lee", "Lee Lost"), SEES_WORKFLOWS).await;
    let (ops, support) = (group(&world, "Ops").await, group(&world, "Support").await);
    let request_id = lee_asks_for(&world, &mut lee, &support).await;
    let mut approvers = TwoApprovers::joined(&world).await;

    let graph = deciding_and_lending(&lee, &request_id, &ops);
    let execution_id = started_by(&world, &mut pat, graph).await;
    approvers.approve(&world, &execution_id, FIRST_YES).await;
    approvers.approve(&world, &execution_id, SECOND_YES).await;
    let finished = ended(&world, &execution_id, "succeeded").await;

    assert!(
        is_in(&world, &support, lee.id()).await,
        "Lee's request let him in"
    );
    assert!(is_in(&world, &ops, lee.id()).await, "Lee is lent Ops");
    assert!(output(&finished, LEND_STEP)["ends_at"].is_string());
    through_run(
        &world,
        "authorization.access_request_approved",
        &execution_id,
        pat.email(),
    )
    .await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Lee asks to join the group `group_id` for a week; his request's id.
async fn lee_asks_for(world: &World<'_>, lee: &mut Person, group_id: &str) -> String {
    let asked = AskForGroup {
        asked: AskedGroup {
            kind: "group",
            id: group_id.to_owned(),
        },
        reason: "I cover the help desk next week".to_owned(),
        length_seconds: 7 * 24 * 3600,
    };
    lee.send(policies::ask_for_group(world.tenant(), &asked))
        .await
        .ok()
        .id
}

/// Approve the request `request_id`, then lend Lee the group `ops` for two
/// hours, each once two people say yes.
fn deciding_and_lending(lee: &Person, request_id: &str, ops: &str) -> Graph {
    in_order(vec![
        yes(FIRST_YES, "Approve Lee's request for Support"),
        company_step(
            "decide",
            "decide-request",
            "admin",
            vec![
                ("request", written(request_id)),
                ("decision", written("approve")),
            ],
        ),
        yes(SECOND_YES, "Lend Lee Ops for two hours"),
        company_step(
            LEND_STEP,
            "grant-access",
            "admin",
            vec![
                ("person", written(lee.email())),
                ("group", written(ops)),
                ("hours", written(2)),
            ],
        ),
    ])
}

/// Give Lee the right to view people for five minutes, once two people
/// say yes.
fn breaking_glass(lee: &Person) -> Graph {
    in_order(vec![
        yes(FIRST_YES, "Give Lee emergency access"),
        company_step(
            GLASS_STEP,
            "break-glass",
            "admin",
            vec![
                ("person", written(lee.email())),
                ("permissions", written(json!(["users:view"]))),
                ("minutes", written(5)),
                ("reason", written("Lee covers the help desk tonight")),
            ],
        ),
    ])
}

/// Whether Lee may read the tenant's people.
async fn lee_reads_people(world: &World<'_>, lee: &Person) -> Status {
    people::list(world.tenant(), None)
        .send(lee.client())
        .await
        .status()
}

/// Lee may not read people. Pat, who manages people, runs a workflow
/// giving him that right for five minutes; once Bea and Cal say yes, it
/// is given, Lee reads people, and the trail records the grant as Pat's,
/// through the run.
#[tokio::test]
async fn pat_s_run_gives_lee_emergency_access_for_five_minutes() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), MANAGES_PEOPLE).await;
    let lee = invited(&world, ("lee", "Lee Lost"), SEES_WORKFLOWS).await;
    assert_eq!(lee_reads_people(&world, &lee).await, Status::FORBIDDEN);
    let mut approvers = TwoApprovers::joined(&world).await;

    let execution_id = started_by(&world, &mut pat, breaking_glass(&lee)).await;
    approvers.approve(&world, &execution_id, FIRST_YES).await;
    let finished = ended(&world, &execution_id, "succeeded").await;

    assert!(output(&finished, GLASS_STEP)["grant_id"].is_string());
    eventually("Lee to read people under his emergency access", || async {
        (lee_reads_people(&world, &lee).await == Status::OK).then_some(())
    })
    .await;
    through_run(
        &world,
        "authentication.break_glass_granted",
        &execution_id,
        pat.email(),
    )
    .await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat may only read people, so she could not hand Lee a right by hand.
/// Her workflow giving Lee emergency access fails at that step even after
/// Bea and Cal said yes, and Lee still may not read people.
#[tokio::test]
async fn emergency_access_from_a_run_whose_person_may_not_hand_out_rights_fails() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), READS_PEOPLE).await;
    let lee = invited(&world, ("lee", "Lee Lost"), SEES_WORKFLOWS).await;
    let mut approvers = TwoApprovers::joined(&world).await;

    let execution_id = started_by(&world, &mut pat, breaking_glass(&lee)).await;
    approvers.approve(&world, &execution_id, FIRST_YES).await;
    let finished = ended(&world, &execution_id, "failed").await;

    assert_eq!(phase(&finished, GLASS_STEP), "failed");
    assert_eq!(lee_reads_people(&world, &lee).await, Status::FORBIDDEN);
    stack.stop().await.expect("the stack stops cleanly");
}
