//! Reporter and Helper doing what they must not, each misstep refused: an
//! assertion used twice, another agent's name, a stolen token, a token
//! wider than its grant, a hand-on wider than what it holds, and bodies
//! with a misspelt field. The trail shows the refusals the platform
//! records, and nothing for those it does not.

use ianua_scenarios::agent::external::{ExternalAgent, IssuedToken};
use ianua_scenarios::api::agents::delegation;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::agents::authority::{Attenuation, Capabilities, Grant, Granted, Limits};
use ianua_scenarios::wire::agents::token::TokenAsk;
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{Witness, granted_by_owner, profile, report, reports_topic};

/// How long Ann's grant lasts, in seconds: an hour, longer than any token
/// asked under it.
const GRANT_SECONDS: u32 = 3600;

/// How long a token or a hand-on lasts, in seconds: ten minutes, inside
/// the grant.
const TOKEN_SECONDS: u32 = 600;

/// The agents, Ann's grant to Reporter and Reporter's topic.
struct Scene {
    reporter: ExternalAgent,
    helper: ExternalAgent,
    grant: Granted,
    topic: String,
}

/// What Reporter asks for to report: publishing to its topic, for ten
/// minutes.
fn reporting(topic: &str) -> TokenAsk {
    TokenAsk::bearer(Capabilities::default().publishing_to(topic), TOKEN_SECONDS)
}

/// Reporter and Helper, made by Ann; Reporter holds Ann's grant of one
/// permission and publishing to its topic, passed on at most once.
async fn scene(stack: &Stack, world: &World<'_>) -> Scene {
    let owner = world.owner().client();
    let reporter = ExternalAgent::enrolled(stack, world.tenant(), owner, "Reporter").await;
    let helper = ExternalAgent::enrolled(stack, world.tenant(), owner, "Helper").await;
    let topic = reports_topic(world, &reporter).await;
    let grant = Grant {
        granted: Capabilities::http(&["users:view"]).publishing_to(&topic),
        limits: Limits {
            ttl_seconds: GRANT_SECONDS,
            max_depth: 1,
            ..Limits::default()
        },
        name: None,
    };
    let grant = granted_by_owner(world, &reporter, &grant).await;
    Scene {
        reporter,
        helper,
        grant,
        topic,
    }
}

/// Reporter's assertion signs it in once: the same assertion again is
/// refused, so a copy Mallory took off the wire is worth nothing. The
/// refusal mints nothing.
#[tokio::test]
async fn a_replayed_assertion_is_refused() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let scene = scene(&stack, &world).await;
    let mut witness = Witness::of(&world).await;
    let ask = reporting(&scene.topic);

    let assertion = scene.reporter.assertion();
    scene.reporter.exchange_with(&assertion, &ask).await.ok();
    witness.recorded("agents.token_issued").await;

    scene
        .reporter
        .replay(&assertion, &ask)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    witness.nothing_new("agents.token_issued").await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Helper tries to be Reporter: its own assertion at Reporter's endpoint,
/// one naming Reporter but signed with Helper's key, and Reporter's token
/// beside a proof made with Helper's key. Every one is refused, and none
/// mints or relays anything.
#[tokio::test]
async fn another_agents_name_or_token_is_refused() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let mut scene = scene(&stack, &world).await;
    let ask = reporting(&scene.topic);
    let stolen = IssuedToken::of(
        scene
            .reporter
            .ask_token(&ask.clone().key_bound())
            .await
            .ok(),
    );
    let witness = Witness::of(&world).await;

    scene
        .helper
        .pose_as(&scene.reporter, &ask)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    scene
        .helper
        .forge_for(&scene.reporter, &ask)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    scene
        .helper
        .publish_with_stolen(&stolen, &scene.topic, &report("Not mine to send."))
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    witness.nothing_new("agents.token_issued").await;
    witness.nothing_new("agents.message_authorized").await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Reporter asks for more than Ann gave it: a permission she did not
/// grant is refused; asked beside one she did, it is left out of the
/// token; a token passed on deeper than her grant allows is refused.
#[tokio::test]
async fn a_token_wider_than_its_grant_is_refused() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let scene = scene(&stack, &world).await;
    let mut witness = Witness::of(&world).await;

    let outside = TokenAsk::bearer(Capabilities::http(&["users:deactivate"]), TOKEN_SECONDS);
    scene
        .reporter
        .ask_token(&outside)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    witness.nothing_new("agents.token_issued").await;

    assert_mixed_token_capped(&scene.reporter).await;
    witness.recorded("agents.token_issued").await;

    let deeper = TokenAsk {
        max_depth: 3,
        ..TokenAsk::bearer(Capabilities::http(&["users:view"]), TOKEN_SECONDS)
    };
    scene
        .reporter
        .ask_token(&deeper)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    witness.nothing_new("agents.token_issued").await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// A mixed request receives only the permission covered by Ann's grant.
async fn assert_mixed_token_capped(reporter: &ExternalAgent) {
    let mixed = TokenAsk::bearer(
        Capabilities::http(&["users:view", "users:deactivate"]),
        TOKEN_SECONDS,
    );
    let capped = IssuedToken::of(reporter.ask_token(&mixed).await.ok());
    assert_eq!(
        capped.granted(),
        &Capabilities::http(&["users:view"]),
        "the token carries only what Ann granted"
    );
}

/// Reporter passes part of Ann's grant on to Helper, but wider than it:
/// a permission Ann never gave it, then a depth past hers. Both are
/// refused, Helper is handed nothing, and nothing new is on record.
#[tokio::test]
async fn a_hand_on_that_widens_is_refused() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let scene = scene(&stack, &world).await;
    let mut witness = Witness::of(&world).await;
    witness.caught_up().await;

    refuse_wider_hand_on(&scene).await;
    let helpers = delegation::list(world.tenant(), scene.helper.id())
        .send(world.owner().client())
        .await
        .ok();
    assert!(helpers.is_empty(), "Helper was handed {helpers:?}");
    witness.nothing_new("agents.delegation_granted").await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Reporter can pass neither extra permissions nor excess delegation depth to Helper.
async fn refuse_wider_hand_on(scene: &Scene) {
    let wider = Attenuation {
        delegate: scene.helper.id().to_owned(),
        granted: Capabilities::http(&["users:view", "users:deactivate"]),
        limits: Limits {
            ttl_seconds: TOKEN_SECONDS,
            ..Limits::default()
        },
    };
    scene
        .reporter
        .pass_on(&scene.grant.delegation_id, &wider)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let deeper = Attenuation {
        granted: Capabilities::http(&["users:view"]),
        limits: Limits {
            ttl_seconds: TOKEN_SECONDS,
            max_depth: 2,
            ..Limits::default()
        },
        ..wider
    };
    scene
        .reporter
        .pass_on(&scene.grant.delegation_id, &deeper)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// A misspelt field is refused, never dropped in silence: Reporter's
/// `sender_constraind` would have bought it a bearer token anyone holding
/// it can use, and Ann's `requires_aproval` a grant that waits for nobody.
/// Neither body mints anything.
#[tokio::test]
async fn a_misspelt_field_is_refused() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let scene = scene(&stack, &world).await;
    let mut witness = Witness::of(&world).await;
    witness.caught_up().await;

    let problem = scene
        .reporter
        .ask_misspelt(&reporting(&scene.topic), "sender_constraind", json!(true))
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    assert!(
        problem.message().contains("sender_constraind"),
        "the refusal names the misspelt field: {problem}"
    );

    refuse_misspelt_grant(&world, &scene.reporter).await;
    witness.nothing_new("agents.token_issued").await;
    witness.nothing_new("agents.delegation_granted").await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann's misspelt approval field is rejected instead of silently issuing a grant.
async fn refuse_misspelt_grant(world: &World<'_>, reporter: &ExternalAgent) {
    let mut misspelt = serde_json::to_value(Grant {
        granted: Capabilities::http(&["users:view"]),
        limits: Limits {
            ttl_seconds: TOKEN_SECONDS,
            ..Limits::default()
        },
        name: None,
    })
    .expect("a grant is JSON");
    misspelt["requires_aproval"] = json!(true);
    delegation::grant_raw(world.tenant(), reporter.id(), &misspelt)
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
}
