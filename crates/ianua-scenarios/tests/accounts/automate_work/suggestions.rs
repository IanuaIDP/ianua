//! Steps suggested by the tenant's own model. Its answer is untrusted: a
//! step the integrations do not offer is left out with a note, never
//! invented, and the arrow to it goes too. Nothing is saved. Only someone
//! who may change workflows asks.

use ianua_scenarios::agent::model::{ModelBackend, Reply, Script, Steering, Turn};
use ianua_scenarios::api::workflows;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::workflows::SuggestSteps;
use ianua_scenarios::world::World;

use crate::spending::connect_priced_model;

/// What the model answers: a sentence around a fetch the catalog offers
/// and a commit GitHub does not, joined by an arrow.
const ANSWER: &str = r#"Here is a plan: {"steps": [
  {"key": "fetch", "title": "Fetch the order", "kind": "action",
   "integration": "http", "operation": "get-with-account", "inputs": {}},
  {"key": "commit", "title": "Commit the order", "kind": "action",
   "integration": "github", "operation": "commit", "inputs": {}}],
 "edges": [{"from": "fetch", "port": "next", "to": "commit"}]}"#;

/// Tess asks the model for a workflow fetching an order and committing
/// it. The fetch is kept; the commit, which GitHub does not offer, is left
/// out with a note naming it, and so is the arrow to it. Max may not ask.
/// No workflow was saved.
#[tokio::test]
async fn a_suggested_step_no_integration_offers_is_left_out_and_nothing_is_saved() {
    let script = Script::new().then(Turn::answer(Reply::text(ANSWER)));
    let backend = ModelBackend::for_steering(&Steering::Scripted(script))
        .await
        .expect("the scripted model listens");
    let networks = backend.private_networks().unwrap_or("127.0.0.0/8");
    let stack = Stack::start(Profile::standard().with("ALLOW_PRIVATE_MODEL_ENDPOINTS", networks))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let asked = SuggestSteps {
        provider_id: connect_priced_model(&world, &backend).await,
        words: "Fetch each new order and commit it to the repository.".to_owned(),
    };

    workflows::suggest(world.tenant(), &asked)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let proposal = workflows::suggest(world.tenant(), &asked)
        .send(world.admin().client())
        .await
        .ok();
    let saved = workflows::list_workflows(world.tenant())
        .send(world.admin().client())
        .await
        .ok()
        .items;

    let kept: Vec<(&str, &str)> = proposal
        .steps
        .iter()
        .map(|step| (step.key.as_str(), step.kind.as_str()))
        .collect();
    assert_eq!(kept, [("fetch", "action")]);
    assert!(
        proposal.edges.is_empty(),
        "no arrow leads to a dropped step"
    );
    assert!(
        proposal
            .notes
            .iter()
            .any(|note| note.contains("github") && note.contains("commit")),
        "a note names what was left out: {:?}",
        proposal.notes
    );
    assert!(saved.is_empty(), "nothing was saved");
    stack.stop().await.expect("the stack stops cleanly");
}
