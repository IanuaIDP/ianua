//! Notion as a workflow step: Tess connects the team's integration token,
//! which Notion is asked about first, and Ann publishes a workflow that
//! queries the support database, adds a ticket page to it and comments on
//! the page. A stand-in for Notion's API shows what arrived: the token,
//! Notion's version 2025-09-03 on every call, the query at the database's
//! data source and the page made under that data source, and the comment
//! on the page Notion gave its id. A token Notion refuses is never
//! connected, and a page Notion refuses fails the run.

use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::workflows::{Graph, Node};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use crate::integrations::calls::{Offered, chain, failed_step, never_connected, only_call, ran};
use crate::support::{Action, account_at, action, read, written};

/// The team's integration token: a sentence, so no scanner takes it for a
/// key.
const TOKEN: &str = "acme notion token for workflows";

/// The Notion version every call is pinned to.
const VERSION: &str = "2025-09-03";

/// Where Notion says which bot a token is.
const ME: &str = "/users/me";

/// Where the support database's data source is queried.
const QUERY: &str = "/data_sources/ds-support/query";

/// Where a page is made.
const PAGES: &str = "/pages";

/// Where a comment is added.
const COMMENTS: &str = "/comments";

/// Tess connects the token, which Notion is asked about once. Ann
/// publishes a workflow that queries the support database's data source
/// for open tickets, adds a ticket page under that data source and
/// comments on the page by the id Notion answered with. Tess runs it:
/// Notion receives the three calls, each signed with the token and pinned
/// to version 2025-09-03, and the run succeeds. The token is nowhere in
/// the trail.
#[tokio::test]
async fn a_run_queries_a_database_adds_a_page_and_comments_on_it() {
    let notion = notion_answering(Canned::json(
        &json!({ "id": "page-42", "url": "https://notion.test/page-42" }),
    ))
    .await;
    let stack = Stack::start(profile(&notion))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "notion", TOKEN).await;
    let asked = only_call(&notion, "GET", ME);
    assert_eq!(asked.header("notion-version"), Some(VERSION));
    ran(&world, ticket_graph(&account), "succeeded").await;
    check_ticket_calls(&notion);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[TOKEN]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Notion refuses the page with 404, as for a database not shared with
/// the integration. The page step and the run fail after one request, and
/// no comment is added.
#[tokio::test]
async fn a_page_notion_refuses_fails_the_run() {
    let notion = notion_answering(Canned::refusing(404)).await;
    let stack = Stack::start(profile(&notion))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "notion", TOKEN).await;

    let run = ran(&world, ticket_graph(&account), "failed").await;

    failed_step(&run, "notion-create-page");
    assert_eq!(notion.asked_for(PAGES), 1, "a refusal is not tried again");
    assert_eq!(
        notion.asked_for(COMMENTS),
        0,
        "nothing was said on a missing page"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Notion does not know Tess's mistyped token: asked once, it answers 401,
/// and no account is connected.
#[tokio::test]
async fn a_token_notion_refuses_is_never_connected() {
    let notion = CannedApp::start([(ME, Canned::refusing(401))])
        .await
        .expect("the Notion stand-in starts");
    let stack = Stack::start(profile(&notion))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let offered = Offered {
        integration: "notion",
        credential: "a mistyped notion token",
    };

    never_connected(&world, offered).await;

    assert_eq!(notion.asked_for(ME), 1, "Notion was asked about the token");
    stack.stop().await.expect("the stack stops cleanly");
}

/// The workflow queries the support database's open tickets, adds a page
/// under its data source and comments on the page Notion gave back.
fn ticket_graph(account: &str) -> Graph {
    let query = action(
        Action {
            integration: "notion",
            operation: "query-data-source",
        },
        account,
        "read",
        vec![
            ("data_source", written("ds-support")),
            ("filter", written(open_filter())),
        ],
    );
    let comment = action(
        Action {
            integration: "notion",
            operation: "comment-on-page",
        },
        account,
        "communicate",
        vec![
            ("page", read("notion-create-page.json.id")),
            (
                "text",
                written(json!([{ "text": { "content": "Taken by Pat." } }])),
            ),
        ],
    );
    chain(vec![query, page_step(account), comment])
}

/// The step adding a ticket page under the support database's data
/// source.
fn page_step(account: &str) -> Node {
    action(
        Action {
            integration: "notion",
            operation: "create-page",
        },
        account,
        "write",
        vec![
            ("data_source", written("ds-support")),
            ("properties", written(ticket_properties())),
        ],
    )
}

/// Notion received the query at the data source, the page under it and
/// the comment on page-42, each signed with the token and pinned to
/// version 2025-09-03.
fn check_ticket_calls(notion: &CannedApp) {
    let query = only_call(notion, "POST", QUERY);
    let page = only_call(notion, "POST", PAGES);
    let comment = only_call(notion, "POST", COMMENTS);
    for call in [&query, &page, &comment] {
        assert_eq!(
            call.header("authorization"),
            Some(format!("Bearer {TOKEN}").as_str())
        );
        assert_eq!(call.header("notion-version"), Some(VERSION));
    }
    assert_eq!(query.json(), json!({ "filter": open_filter() }));
    assert_eq!(
        page.json(),
        json!({ "parent": { "data_source_id": "ds-support" }, "properties": ticket_properties() })
    );
    assert_eq!(
        comment.json(),
        json!({
            "parent": { "page_id": "page-42" },
            "rich_text": [{ "text": { "content": "Taken by Pat." } }]
        })
    );
}

/// Only the tickets whose status is Open, as Notion writes a filter.
fn open_filter() -> Value {
    json!({ "property": "Status", "status": { "equals": "Open" } })
}

/// The ticket's title and status, as Notion writes properties.
fn ticket_properties() -> Value {
    json!({
        "Name": { "title": [{ "text": { "content": "Printer offline" } }] },
        "Status": { "status": { "name": "Open" } }
    })
}

/// A Notion stand-in that knows the token, finds no open tickets, answers
/// a new page with `page`, and takes any comment.
async fn notion_answering(page: Canned) -> CannedApp {
    CannedApp::start([
        (
            ME,
            Canned::json(&json!({ "object": "user", "type": "bot" })),
        ),
        (
            QUERY,
            Canned::json(&json!({ "results": [], "has_more": false })),
        ),
        (PAGES, page),
        (COMMENTS, Canned::json(&json!({ "id": "comment-7" }))),
    ])
    .await
    .expect("the Notion stand-in starts")
}

/// The standard deployment, its Notion steps calling `notion`.
fn profile(notion: &CannedApp) -> Profile {
    Profile::standard().with("NOTION_API_URL", &notion.url())
}
