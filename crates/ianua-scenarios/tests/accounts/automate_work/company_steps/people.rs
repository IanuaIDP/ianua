//! Company steps about people: Pat's workflows find Lee, suspend Lee and
//! invite Uma in Lee's place, forget Lee's laptop and clear Lee's
//! authenticator, end the keys Lee made, and resume a paused key. Each
//! acts as Pat, through the action Pat could take by hand, and the trail
//! names Pat and the run; a run Pat could not take by hand fails and Lee's
//! key still works.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{api_keys, people, workflows};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::api_keys::NewApiKey;
use ianua_scenarios::wire::sign_in::{DeviceRemembered, Devices, RememberDevice};
use ianua_scenarios::wire::workflows::{Graph, Source};
use ianua_scenarios::world::{MEMBER_ROLE, World};

use super::{
    TwoApprovers, company_step, in_order, output, phase, started_by, taking_up_to, through_run,
    waiting_at, yes,
};
use crate::support::{ended, invited, written};

/// The key of the step suspending Lee.
const SUSPEND_STEP: &str = "suspend";

/// The key of the step inviting Uma.
const INVITE_STEP: &str = "invite";

/// The key of the step forgetting Lee's laptop.
const FORGET_STEP: &str = "forget";

/// The key of the step clearing Lee's authenticator.
const RESET_STEP: &str = "reset";

/// The key of the step ending Lee's keys.
const REVOKE_STEP: &str = "revoke";

/// The key of the step pausing Lee's key.
const PAUSE_STEP: &str = "pause";

/// The key of the step resuming Lee's key.
const RESUME_STEP: &str = "resume";

/// The key of the first approval in a run.
const FIRST_YES: &str = "first-yes";

/// The key of the second approval in a run.
const SECOND_YES: &str = "second-yes";

/// What Pat may do when she may read people.
const READS_PEOPLE: &[(&str, &str)] = &[
    ("Workflows", "View"),
    ("Workflows", "Run"),
    ("Users", "View"),
];

/// What Pat may do when she manages people and gives their roles, the
/// Member role's view of the tenant's numbers among them, since a role
/// can be handed out only by someone holding all it gives.
const MANAGES_PEOPLE: &[(&str, &str)] = &[
    ("Workflows", "View"),
    ("Workflows", "Run"),
    ("Users", "Manage"),
    ("Roles", "View"),
    ("Roles", "Assign"),
    ("Metrics", "View"),
];

/// What Pat may do when she offboards people: manage them and end their keys.
const OFFBOARDS_PEOPLE: &[(&str, &str)] = &[
    ("Workflows", "View"),
    ("Workflows", "Run"),
    ("Users", "Manage"),
    ("Groups", "Manage"),
    ("ApiKeys", "Manage"),
    ("Roles", "View"),
    ("Roles", "Assign"),
    ("Metrics", "View"),
];

/// What Pat may do when she manages API keys.
const MANAGES_KEYS: &[(&str, &str)] = &[
    ("Workflows", "View"),
    ("Workflows", "Run"),
    ("Users", "View"),
    ("ApiKeys", "Manage"),
];

/// What Lee may do: read people, and make API keys that do so.
const MAKES_KEYS: &[(&str, &str)] = &[
    ("Workflows", "View"),
    ("Users", "View"),
    ("ApiKeys", "Manage"),
];

/// Lee, holding `rights`, invited and signed in.
async fn invited_lee(world: &World<'_>, rights: &[(&str, &str)]) -> Person {
    invited(world, ("lee", "Lee Lost"), rights).await
}

/// Pat may read people. Her workflow finds Lee by his address: the step
/// gives back Lee's id, name, address and that he is active.
#[tokio::test]
async fn pat_s_run_finds_lee_in_the_directory() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), READS_PEOPLE).await;
    let lee = invited_lee(&world, &[("Workflows", "View")]).await;
    let graph = in_order(vec![company_step(
        "find",
        "find-person",
        "read",
        vec![("person", written(lee.email()))],
    )]);

    let execution_id = started_by(&world, &mut pat, graph).await;
    let found = output(&ended(&world, &execution_id, "succeeded").await, "find");

    assert_eq!(found["user_id"], lee.id());
    assert_eq!(found["email"], lee.email());
    assert_eq!(found["name"], "Lee Lost");
    assert_eq!(found["status"], "active");
    stack.stop().await.expect("the stack stops cleanly");
}

/// What the platform offers as the limit of the company step `operation`.
async fn offered_limit(world: &World<'_>, operation: &str) -> String {
    workflows::operations(world.tenant())
        .send(world.admin().client())
        .await
        .ok()
        .into_iter()
        .find(|offered| offered.integration == "ianua" && offered.operation == operation)
        .unwrap_or_else(|| panic!("the platform offers {operation}"))
        .ceiling
}

/// Lee leaves. Pat's workflow looks him up, then signs him out by the id
/// it found. A directory answer is confidential and stays in the company,
/// so the next company step may take it.
#[tokio::test]
async fn pat_s_run_signs_out_the_person_it_looked_up() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), MANAGES_PEOPLE).await;
    let lee = invited_lee(&world, &[("Workflows", "View")]).await;
    let limit = offered_limit(&world, "sign-out").await;
    let found_id = Source::Input {
        path: "find.user_id".to_owned(),
    };
    let graph = in_order(vec![
        company_step(
            "find",
            "find-person",
            "read",
            vec![("person", written(lee.email()))],
        ),
        taking_up_to(
            company_step("sign-out", "sign-out", "write", vec![("person", found_id)]),
            &limit,
        ),
    ]);

    let execution_id = started_by(&world, &mut pat, graph).await;

    ended(&world, &execution_id, "succeeded").await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Lee leaves. Pat's workflow finds him, signs him out and ends his keys at
/// once, then waits for Bea's and Cal's yes before taking him out of his
/// groups and again before suspending him. Until the first yes he still
/// holds his account; after the last, it is locked and the run is done.
#[tokio::test]
async fn pat_s_run_offboards_lee_step_by_step_as_people_say_yes() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), OFFBOARDS_PEOPLE).await;
    let lee = invited_lee(&world, &[("Workflows", "View")]).await;
    let graph = offboarding(&world, lee.email()).await;
    let mut approvers = TwoApprovers::joined(&world).await;

    let execution_id = started_by(&world, &mut pat, graph).await;
    waiting_at(&world, &execution_id, FIRST_YES).await;
    let before = status_of(&world, lee.id()).await;
    approvers.approve(&world, &execution_id, FIRST_YES).await;
    approvers.approve(&world, &execution_id, SECOND_YES).await;
    ended(&world, &execution_id, "succeeded").await;

    assert_eq!(before, "Active", "his account stands until the first yes");
    assert_eq!(status_of(&world, lee.id()).await, "Locked");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Find the person at `address`, sign them out and end their keys, then
/// take their groups and suspend them, each once two people say yes.
async fn offboarding(world: &World<'_>, address: &str) -> Graph {
    let limit = offered_limit(world, "sign-out").await;
    let acting_on_found = |key: &str, operation: &str, effect: &str| {
        let found = Source::Input {
            path: "find.user_id".to_owned(),
        };
        taking_up_to(
            company_step(key, operation, effect, vec![("person", found)]),
            &limit,
        )
    };
    in_order(vec![
        company_step(
            "find",
            "find-person",
            "read",
            vec![("person", written(address))],
        ),
        acting_on_found("sign-out", "sign-out", "write"),
        acting_on_found(REVOKE_STEP, "revoke-keys", "write"),
        yes(FIRST_YES, "Take them out of every group"),
        acting_on_found("groups", "remove-groups", "admin"),
        yes(SECOND_YES, "Suspend their account"),
        acting_on_found(SUSPEND_STEP, "suspend-person", "admin"),
    ])
}

/// Lee leaves, and Pat's workflow suspends him, then invites Uma in his
/// place with the Member role: both change who can do what, so each waits
/// for Bea's and Cal's yes. Before the first yes Lee is still active. Once
/// both are given, Lee is locked, Uma is invited, and the trail says Pat
/// did both, through the run.
#[tokio::test]
async fn pat_s_run_suspends_lee_and_invites_uma_once_two_people_say_yes() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), MANAGES_PEOPLE).await;
    let lee = invited_lee(&world, &[("Workflows", "View")]).await;
    let uma = world.address("uma");
    let graph = replacing(&world, &lee, &uma).await;
    let mut approvers = TwoApprovers::joined(&world).await;

    let execution_id = started_by(&world, &mut pat, graph).await;
    waiting_at(&world, &execution_id, FIRST_YES).await;
    let before = status_of(&world, lee.id()).await;
    approvers.approve(&world, &execution_id, FIRST_YES).await;
    approvers.approve(&world, &execution_id, SECOND_YES).await;
    ended(&world, &execution_id, "succeeded").await;

    assert_eq!(before, "Active", "nothing changes before the yes");
    assert_eq!(status_of(&world, lee.id()).await, "Locked");
    check_uma_invited(&world, &uma).await;
    through_run(
        &world,
        "identity.user_status_changed",
        &execution_id,
        pat.email(),
    )
    .await;
    through_run(&world, "identity.user_invited", &execution_id, pat.email()).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Suspend Lee once two people say yes, then invite Uma with the Member
/// role once they say yes again.
async fn replacing(world: &World<'_>, lee: &Person, uma: &str) -> Graph {
    let member_role = world.role_id(MEMBER_ROLE).await;
    in_order(vec![
        yes(FIRST_YES, "Suspend Lee"),
        company_step(
            SUSPEND_STEP,
            "suspend-person",
            "admin",
            vec![("person", written(lee.email()))],
        ),
        yes(SECOND_YES, "Invite Uma in Lee's place"),
        company_step(
            INVITE_STEP,
            "invite-person",
            "admin",
            vec![
                ("email", written(uma)),
                ("name", written("Uma Newcomer")),
                ("role", written(member_role)),
            ],
        ),
    ])
}

/// The status of the person `user_id`, as Tess reads it.
async fn status_of(world: &World<'_>, user_id: &str) -> String {
    people::get(world.tenant(), user_id)
        .send(world.admin().client())
        .await
        .ok()
        .status
}

/// Uma, at `address`, is in the tenant's directory, invited.
async fn check_uma_invited(world: &World<'_>, address: &str) {
    let listed = people::list(world.tenant(), Some(address))
        .send(world.admin().client())
        .await
        .ok();
    let uma = listed
        .items
        .iter()
        .find(|user| user.email == address)
        .expect("Uma is in the directory");
    assert_eq!(uma.status, "Invited");
}

/// Lee set up his authenticator and remembered his laptop. Pat's workflow
/// forgets every device Lee remembered, at once, as forgetting only
/// narrows; then clears Lee's authenticator, which waits for Bea's and
/// Cal's yes. Lee's laptop is revoked before anyone says yes; once both
/// do, one factor is cleared, and the trail says Pat did both through the
/// run.
#[tokio::test]
async fn pat_s_run_forgets_lee_s_laptop_and_clears_his_authenticator() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), MANAGES_PEOPLE).await;
    let mut lee = invited_lee(&world, &[("Workflows", "View")]).await;
    let laptop = laptop_of(&world, &mut lee).await;
    let mut approvers = TwoApprovers::joined(&world).await;

    let execution_id = started_by(&world, &mut pat, resetting(&lee)).await;
    waiting_at(&world, &execution_id, FIRST_YES).await;
    let devices = devices_of(&world, &lee).await;
    approvers.approve(&world, &execution_id, FIRST_YES).await;
    let finished = ended(&world, &execution_id, "succeeded").await;

    assert!(
        devices
            .devices
            .iter()
            .any(|device| device.id == laptop && device.status == "revoked"),
        "Lee's laptop is forgotten: {devices:?}"
    );
    assert_eq!(output(&finished, FORGET_STEP)["devices_forgotten"], 1.0);
    assert_eq!(output(&finished, RESET_STEP)["factors_removed"], 1.0);
    for change in [
        "authentication.device_revoked",
        "authentication.factors_reset",
    ] {
        through_run(&world, change, &execution_id, pat.email()).await;
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Forget Lee's devices, then clear his second factors once two people
/// say yes.
fn resetting(lee: &Person) -> Graph {
    in_order(vec![
        company_step(
            FORGET_STEP,
            "forget-devices",
            "write",
            vec![("person", written(lee.email()))],
        ),
        yes(FIRST_YES, "Clear Lee's authenticator"),
        company_step(
            RESET_STEP,
            "reset-two-step",
            "admin",
            vec![("person", written(lee.email()))],
        ),
    ])
}

/// Lee sets up his authenticator, signs in with it and remembers his
/// laptop; the laptop's id.
async fn laptop_of(world: &World<'_>, lee: &mut Person) -> String {
    lee.set_up_authenticator().await;
    lee.sign_in(world.stack()).await;
    let remember = RememberDevice {
        fingerprint_hash: "7a".repeat(32),
        device_name: "Lee's laptop".to_owned(),
    };
    lee.client()
        .post::<DeviceRemembered>(&world.tenant().at("/auth/device/trust/add"), &remember)
        .await
        .ok()
        .device_id
}

/// The devices Lee remembered, as Lee reads them.
async fn devices_of(world: &World<'_>, lee: &Person) -> Devices {
    lee.client()
        .get::<Devices>(&world.tenant().at("/auth/device/trust"))
        .await
        .ok()
}

/// A key Lee made, and the client his script calls with it.
struct LeeKey {
    id: String,
    script: Client,
}

/// Lee makes a key that reads people, for his script.
async fn lee_s_key(world: &World<'_>, lee: &mut Person) -> LeeKey {
    let key = NewApiKey {
        name: "Lee's script".to_owned(),
        scopes: vec!["idp:users:view".to_owned()],
    };
    let made = lee.send(api_keys::create(world.tenant(), &key)).await.ok();
    let mut script = Client::new(world.stack(), "Lee's script").expect("a client for the script");
    script.authorize(&made.raw_key);
    LeeKey {
        id: made.id,
        script,
    }
}

/// Whether Lee's script still reads people with its key.
async fn script_reads(world: &World<'_>, key: &LeeKey) -> Status {
    people::list(world.tenant(), None)
        .send(&key.script)
        .await
        .status()
}

/// A graph of one step ending every key the person at `address` made.
fn revoking(address: &str) -> Graph {
    in_order(vec![company_step(
        REVOKE_STEP,
        "revoke-keys",
        "write",
        vec![("person", written(address))],
    )])
}

/// Pat manages keys. Her workflow ends every key Lee made: it runs at
/// once, as it only narrows, ends Lee's one key, and Lee's script is
/// refused from then on. The trail says Pat ended it, through the run.
#[tokio::test]
async fn pat_s_run_ends_every_key_lee_made() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), MANAGES_KEYS).await;
    let mut lee = invited_lee(&world, MAKES_KEYS).await;
    let key = lee_s_key(&world, &mut lee).await;
    assert_eq!(script_reads(&world, &key).await, Status::OK);

    let execution_id = started_by(&world, &mut pat, revoking(lee.email())).await;
    let finished = ended(&world, &execution_id, "succeeded").await;

    assert_eq!(output(&finished, REVOKE_STEP)["keys_revoked"], 1.0);
    assert_eq!(script_reads(&world, &key).await, Status::UNAUTHORIZED);
    through_run(&world, "oauth.api_key_revoked", &execution_id, pat.email()).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat may read people but not manage keys. Her workflow ending Lee's
/// keys fails at its step, and Lee's script still reads people.
#[tokio::test]
async fn a_run_whose_person_may_not_manage_keys_ends_none() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), READS_PEOPLE).await;
    let mut lee = invited_lee(&world, MAKES_KEYS).await;
    let key = lee_s_key(&world, &mut lee).await;

    let execution_id = started_by(&world, &mut pat, revoking(lee.email())).await;
    let finished = ended(&world, &execution_id, "failed").await;

    assert_eq!(phase(&finished, REVOKE_STEP), "failed");
    assert_eq!(script_reads(&world, &key).await, Status::OK);
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat's workflow pauses Lee's key, at once, then resumes it, which gives
/// access back and so waits for Bea's and Cal's yes. While it waits, Lee's
/// script is refused; once both say yes, it reads people again, and the
/// trail says Pat resumed the key, through the run.
#[tokio::test]
async fn pat_s_run_resumes_a_paused_key_once_two_people_say_yes() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), MANAGES_KEYS).await;
    let mut lee = invited_lee(&world, MAKES_KEYS).await;
    let key = lee_s_key(&world, &mut lee).await;
    let mut approvers = TwoApprovers::joined(&world).await;

    let execution_id = started_by(&world, &mut pat, pausing_then_resuming(&key.id)).await;
    waiting_at(&world, &execution_id, FIRST_YES).await;
    let while_paused = script_reads(&world, &key).await;
    approvers.approve(&world, &execution_id, FIRST_YES).await;
    ended(&world, &execution_id, "succeeded").await;

    assert_eq!(while_paused, Status::UNAUTHORIZED);
    assert_eq!(script_reads(&world, &key).await, Status::OK);
    through_run(&world, "oauth.api_key_resumed", &execution_id, pat.email()).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pause the key `key_id`, then resume it once two people say yes.
fn pausing_then_resuming(key_id: &str) -> Graph {
    in_order(vec![
        company_step(
            PAUSE_STEP,
            "pause-key",
            "write",
            vec![("key", written(key_id))],
        ),
        yes(FIRST_YES, "Resume Lee's key"),
        company_step(
            RESUME_STEP,
            "resume-key",
            "admin",
            vec![("key", written(key_id))],
        ),
    ])
}
