//! Memory: Acme keeps its support tickets in a memory, and a workflow
//! finds the ones most alike a new ticket for the agent answering it.
//!
//! The vectors come from the platform's own embedding server, a stand-in
//! speaking OpenAI's embeddings API or the real text-embeddings-inference,
//! or from Acme's own model provider; they are kept in pgvector or in a
//! Qdrant-protocol vector server. A memory is deleted only after its name
//! is typed, takes no texts while it waits to be deleted, and comes back
//! with every text when brought back.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::agents::models;
use ianua_scenarios::api::{memories, workflows};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::systems;
use ianua_scenarios::upstreams::{LETTER_VECTOR_SIZE, LetterEmbeddings};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::agents::models::{ConnectProvider, EmbeddingModel};
use ianua_scenarios::wire::memories::{DeleteMemory, Memory, MemoryEntryPage, NewMemory};
use ianua_scenarios::wire::workflows::{
    Execution, Graph, MappedField, Node, StartExecution, Step, Trigger,
};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use crate::support::{drafted, ended, pat, published, read, written};

/// The key of the memory step.
const MEMORY_STEP: &str = "memory";

/// The model the stand-in platform server says it serves.
const LETTERS: &str = "letters-v1";

/// Acme's past tickets.
const TICKETS: [&str; 3] = [
    "I want my money back please",
    "Where is my parcel",
    "The app crashes when I start it",
];

/// A stack whose platform embedding server is `embeddings`, with `extra`
/// settings.
async fn stack_with(embeddings: &LetterEmbeddings, extra: &[(&str, &str)]) -> Stack {
    let mut profile = Profile::standard()
        .with("EMBEDDING_URL", &embeddings.base())
        .with("EMBEDDING_MODEL", LETTERS);
    for (name, value) in extra {
        profile = profile.with(name, value);
    }
    Stack::start(profile).await.expect("the stack starts")
}

/// Tess makes the support tickets memory, filled by `provider_id` or the
/// platform's server.
async fn tickets_memory(world: &World<'_>, provider_id: Option<String>) -> Memory {
    memories::create(
        world.tenant(),
        &NewMemory {
            name: "Support tickets".to_owned(),
            provider_id,
            clearance: "Internal".to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok()
}

/// A graph of one memory step: `operation` on `memory`, its text read from
/// the run's input, and `count` when given.
fn memory_graph(operation: &str, memory: &Memory, count: Option<u8>) -> Graph {
    let inputs = memory_inputs(memory, count);
    let effect = if operation == "remember" {
        "write"
    } else {
        "read"
    };
    Graph {
        nodes: vec![Node {
            key: MEMORY_STEP.to_owned(),
            name: "Use the tickets memory".to_owned(),
            step: Step::Action {
                integration: "memory".to_owned(),
                operation: operation.to_owned(),
                account_id: None,
                effect: effect.to_owned(),
                ceiling: "internal".to_owned(),
                inputs,
            },
        }],
        edges: vec![],
    }
}

/// The memory step takes its text from the trigger and optionally bounds its result count.
fn memory_inputs(memory: &Memory, count: Option<u8>) -> Vec<MappedField> {
    let mut inputs = vec![
        MappedField {
            field: "memory".to_owned(),
            source: written(memory.id.as_str()),
        },
        MappedField {
            field: "text".to_owned(),
            source: read("trigger.text"),
        },
    ];
    if let Some(count) = count {
        inputs.push(MappedField {
            field: "count".to_owned(),
            source: written(count),
        });
    }
    inputs
}

/// The workflow `graph`, drafted by Tess and published by Ann.
async fn workflow(world: &World<'_>, graph: Graph) -> String {
    let draft = drafted(world, Trigger::Manual, graph).await;
    published(world, &draft).await.id
}

/// The text sent to a memory workflow and the status its run must reach.
struct MemoryRun<'a> {
    text: &'a str,
    expected: &'a str,
}

/// Pat runs `workflow` with the specified text and expected terminal status.
async fn run(
    world: &World<'_>,
    pat: &mut Person,
    workflow: &str,
    input: MemoryRun<'_>,
) -> Execution {
    let start = StartExecution {
        input: json!({ "text": input.text }),
        exposure: "internal".to_owned(),
    };
    let started = pat
        .send(workflows::start(world.tenant(), workflow, &start))
        .await
        .ok();
    ended(world, &started.execution_id, input.expected).await
}

/// The output of the memory step of `run`.
fn output(run: &Execution) -> Value {
    run.steps
        .iter()
        .find(|step| step.key == MEMORY_STEP)
        .and_then(|step| step.output.clone())
        .expect("the memory step gave its output")
}

/// The texts of a page, in its order.
fn texts_of(page: &MemoryEntryPage) -> Vec<&str> {
    page.entries
        .iter()
        .map(|entry| entry.text.as_str())
        .collect()
}

/// Pat keeps each past ticket, then finds the one most like a new ticket
/// about money: the money-back ticket comes first.
async fn keep_tickets_and_find(world: &World<'_>, pat: &mut Person, memory: &Memory) -> Value {
    let remember = workflow(world, memory_graph("remember", memory, None)).await;
    let find = workflow(world, memory_graph("find-similar", memory, Some(1))).await;
    for ticket in TICKETS {
        run(
            world,
            pat,
            &remember,
            MemoryRun {
                text: ticket,
                expected: "succeeded",
            },
        )
        .await;
    }
    output(
        &run(
            world,
            pat,
            &find,
            MemoryRun {
                text: "money back",
                expected: "succeeded",
            },
        )
        .await,
    )
}

/// Tess makes a memory on the platform's embedding server: it keeps the
/// server's model and the length of its vectors. Pat's runs keep three
/// tickets, and a search for "money back" finds the money-back ticket
/// first. Making the memory is recorded, and Tess reads the three tickets
/// back in the order they were kept, as she would before deleting it.
#[tokio::test]
async fn pat_s_run_finds_the_ticket_most_alike() {
    let embeddings = LetterEmbeddings::start().await.expect("the server starts");
    let stack = stack_with(&embeddings, &[]).await;
    let world = World::new(&stack).await;
    let mut pat = pat(&world).await;

    let memory = tickets_memory(&world, None).await;
    let found = keep_tickets_and_find(&world, &mut pat, &memory).await;
    let copy = memories::entries(world.tenant(), &memory.id)
        .send(world.admin().client())
        .await
        .ok();

    assert_eq!(memory.embedding_source, "platform");
    assert_eq!(texts_of(&copy), TICKETS);
    assert!(copy.next.is_none());
    assert!(copy.entries.iter().all(|entry| !entry.kept_at.is_empty()));
    assert_eq!(memory.embedding_model, LETTERS);
    assert_eq!(usize::from(memory.vector_size), LETTER_VECTOR_SIZE);
    assert_eq!(found["found_count"], 1);
    assert_eq!(found["found"][0]["text"], TICKETS[0]);
    assert!(
        embeddings
            .asked()
            .iter()
            .all(|asked| asked.model == LETTERS)
    );
    assert_eq!(world.trail().count("workflows.memory_created").await, 1);

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess cannot request deletion with the wrong memory name. With the right
/// name the memory waits to be deleted, and Pat's run keeping a ticket in
/// it fails. Tess brings it back, and the next run keeps the ticket.
/// The trail records one deletion request and one restoration.
#[tokio::test]
async fn a_memory_waiting_to_be_deleted_takes_no_texts_until_brought_back() {
    let embeddings = LetterEmbeddings::start().await.expect("the server starts");
    let stack = stack_with(&embeddings, &[]).await;
    let world = World::new(&stack).await;
    let mut pat = pat(&world).await;
    let memory = tickets_memory(&world, None).await;
    let remember = workflow(&world, memory_graph("remember", &memory, None)).await;
    let deletion = delete_memory(&world, &memory).await;
    let refused = run(
        &world,
        &mut pat,
        &remember,
        MemoryRun {
            text: TICKETS[0],
            expected: "failed",
        },
    )
    .await;
    let restored = restore_memory(&world, &mut pat, &remember, &memory).await;
    check_deletion(&deletion, &refused, &restored);
    assert_eq!(
        world
            .trail()
            .count("workflows.memory_deletion_requested")
            .await,
        1
    );
    assert_eq!(world.trail().count("workflows.memory_restored").await, 1);
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess restores the memory, and Pat's next run successfully keeps the refused ticket.
async fn restore_memory(
    world: &World<'_>,
    pat: &mut Person,
    remember: &str,
    memory: &Memory,
) -> Memory {
    let restored = memories::restore(world.tenant(), &memory.id)
        .send(world.admin().client())
        .await
        .ok();
    run(
        world,
        pat,
        remember,
        MemoryRun {
            text: TICKETS[0],
            expected: "succeeded",
        },
    )
    .await;
    restored
}

/// Results of the mistyped deletion attempt and the request with the correct name.
struct Deletion {
    mistyped: Status,
    deleted: Memory,
}

/// Tess tries the wrong name before requesting deletion with the memory's full name.
async fn delete_memory(world: &World<'_>, memory: &Memory) -> Deletion {
    let tess = world.admin().client();

    let mistyped = memories::delete(
        world.tenant(),
        &memory.id,
        &DeleteMemory {
            name: "tickets".to_owned(),
        },
    )
    .send(tess)
    .await;
    let deleted = memories::delete(
        world.tenant(),
        &memory.id,
        &DeleteMemory {
            name: "Support tickets".to_owned(),
        },
    )
    .send(tess)
    .await
    .ok();
    Deletion {
        mistyped: mistyped.status(),
        deleted,
    }
}

/// Pending deletion blocks the memory step, and restoration returns the memory to active status.
fn check_deletion(deletion: &Deletion, refused: &Execution, restored: &Memory) {
    assert_eq!(deletion.mistyped, Status::UNPROCESSABLE_ENTITY);
    assert_eq!(deletion.deleted.status, "deletion_requested");
    assert!(deletion.deleted.deleted_after.is_some());
    assert!(
        refused
            .steps
            .iter()
            .any(|step| step.key == MEMORY_STEP && step.phase == "failed")
    );
    assert_eq!(restored.status, "active");
}

/// Acme connects its own OpenAI-style provider and has it offer an
/// embedding model. A memory filled through it sends every text to that
/// model, with Acme's key, and finds the money-back ticket.
#[tokio::test]
async fn a_provider_s_embedding_model_fills_a_memory() {
    let embeddings = LetterEmbeddings::start().await.expect("the server starts");
    let stack = stack_with(
        &embeddings,
        &[("ALLOW_PRIVATE_MODEL_ENDPOINTS", "127.0.0.0/8")],
    )
    .await;
    let world = World::new(&stack).await;
    let mut pat = pat(&world).await;
    let provider_id = connect_embeddings(&world, &embeddings).await;

    let memory = tickets_memory(&world, Some(provider_id)).await;
    let found = keep_tickets_and_find(&world, &mut pat, &memory).await;

    assert_eq!(memory.embedding_source, "provider");
    assert_eq!(memory.embedding_model, "acme-embed");
    assert_eq!(found["found"][0]["text"], TICKETS[0]);
    let asked = embeddings.asked();
    assert!(!asked.is_empty());
    assert!(
        asked.iter().all(|asked| asked.model == "acme-embed"
            && asked.bearer.as_deref() == Some("acme provider key"))
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The tenant connects its own provider and selects its embedding model.
async fn connect_embeddings(world: &World<'_>, embeddings: &LetterEmbeddings) -> String {
    let tess = world.admin().client();
    let provider = models::connect(
        world.tenant(),
        &ConnectProvider {
            name: "acme-models".to_owned(),
            kind: "self_hosted".to_owned(),
            endpoint: embeddings.base(),
            model: "acme-chat".to_owned(),
            api_key: Some("acme provider key".to_owned()),
            clearance: Some("Internal".to_owned()),
            pricing: None,
        },
    )
    .send(tess)
    .await
    .ok();
    models::offer_embeddings(
        world.tenant(),
        &provider.id,
        &EmbeddingModel {
            embedding_model: Some("acme-embed".to_owned()),
        },
    )
    .send(tess)
    .await
    .ok();

    provider.id
}

/// The deployment keeps memories' vectors in a Qdrant-protocol vector
/// server instead of pgvector: the tickets are kept there and the
/// money-back ticket is found first all the same.
#[tokio::test]
async fn texts_kept_in_a_vector_server_are_found() {
    let embeddings = LetterEmbeddings::start().await.expect("the server starts");
    let vectors = systems::vector_server().await;
    let address = format!("http://127.0.0.1:{}", vectors.port());
    let stack = stack_with(&embeddings, &[("VECTOR_STORE_URL", &address)]).await;
    let world = World::new(&stack).await;
    let mut pat = pat(&world).await;

    let memory = tickets_memory(&world, None).await;
    let found = keep_tickets_and_find(&world, &mut pat, &memory).await;

    let copy = memories::entries(world.tenant(), &memory.id)
        .send(world.admin().client())
        .await
        .ok();

    assert_eq!(found["found"][0]["text"], TICKETS[0]);
    assert_eq!(texts_of(&copy), TICKETS);
    let kept: Value = reqwest::get(format!("{address}/collections/ianua_memories_26"))
        .await
        .expect("the vector server answers")
        .json()
        .await
        .expect("it answers JSON");
    assert_eq!(kept["result"]["points_count"], 3);

    stack.stop().await.expect("the stack stops cleanly");
}

/// The platform runs the real text-embeddings-inference with a small
/// model. A memory on it finds "I want my money back" for "refund please",
/// which share no word: the match is by meaning.
#[tokio::test]
async fn the_real_embedding_server_matches_by_meaning() {
    let model = "BAAI/bge-small-en-v1.5";
    let server = systems::embedding_server(model).await;
    let base = format!("http://127.0.0.1:{}/v1", server.port());
    let stack = Stack::start(
        Profile::standard()
            .with("EMBEDDING_URL", &base)
            .with("EMBEDDING_MODEL", model),
    )
    .await
    .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = pat(&world).await;
    let memory = tickets_memory(&world, None).await;
    let found = find_refund(&world, &mut pat, &memory).await;

    assert_eq!(memory.vector_size, 384);
    assert_eq!(found["found"][0]["text"], "I want my money back");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat keeps both tickets before searching for a refund using a phrase absent from either ticket.
async fn find_refund(world: &World<'_>, pat: &mut Person, memory: &Memory) -> Value {
    let remember = workflow(world, memory_graph("remember", memory, None)).await;
    let find = workflow(world, memory_graph("find-similar", memory, Some(1))).await;

    for ticket in ["I want my money back", "Where is my parcel"] {
        run(
            world,
            pat,
            &remember,
            MemoryRun {
                text: ticket,
                expected: "succeeded",
            },
        )
        .await;
    }
    output(
        &run(
            world,
            pat,
            &find,
            MemoryRun {
                text: "refund please",
                expected: "succeeded",
            },
        )
        .await,
    )
}
