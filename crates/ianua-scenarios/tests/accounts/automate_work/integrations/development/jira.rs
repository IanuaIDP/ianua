//! Jira's action steps: Tess signs in at a stand-in for Atlassian naming
//! acme.atlassian.net, and the account reaches Acme's site through
//! Atlassian's gateway with a token its grant was exchanged for. Ann
//! publishes a workflow that creates an issue in OPS and comments on it.
//! The stand-in shows what arrived: the issue's fields nested where Jira
//! reads them and the comment on the issue Jira gave its key, both signed
//! with the token kept from connecting. A pasted account naming a site the
//! deployment does not allow is never connected and reaches nothing, and
//! an issue Jira refuses fails the run. A pasted account naming a company's
//! own Jira site, reached at a stand-in under an authority the deployment
//! trusts, shows the exact requests sent with the user and API token.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp, OutsideReceiver};
use ianua_scenarios::wire::workflows::Graph;
use ianua_scenarios::world::World;
use serde_json::json;

use crate::integrations::calls::{Offered, chain, failed_step, never_connected, only_call, ran};
use crate::integrations::events::connect::{SignIn, signed_in};
use crate::support::{Action, account_at, action, read, written};

/// The refresh grant Atlassian issues: a sentence, so no scanner takes it
/// for a key.
const GRANT: &str = "acme atlassian grant for action steps";

/// The hour's token Atlassian issues for the grant.
const ISSUED: &str = "acme hour long atlassian token";

/// The platform's Atlassian app.
const CLIENT_ID: &str = "acme platform atlassian app";

/// Where Atlassian swaps codes and exchanges grants.
const TOKEN_PATH: &str = "/oauth/token";

/// Where Atlassian lists the sites a grant reaches.
const RESOURCES: &str = "/oauth/token/accessible-resources";

/// Where the gateway proves the account: who it is on Acme's site.
const MYSELF: &str = "/ex/jira/acme-cloud/rest/api/2/myself";

/// Where an issue is created on Acme's site.
const ISSUES: &str = "/ex/jira/acme-cloud/rest/api/2/issue";

/// Where the comment goes: on the issue Jira gave the key OPS-12.
const COMMENTS: &str = "/ex/jira/acme-cloud/rest/api/2/issue/OPS-12/comment";

/// Tess signs in at Atlassian naming acme.atlassian.net, and the account
/// is tried on Acme's site before it is kept. Ann publishes a workflow
/// creating a bug in OPS and commenting on it by the key Jira answered
/// with. Tess runs it: Jira receives the issue and the comment on OPS-12
/// through the gateway, both signed with the token kept from connecting,
/// so the token address is not asked again. The grant is nowhere in the
/// trail.
#[tokio::test]
async fn a_run_creates_an_issue_and_comments_on_it_through_the_gateway() {
    let atlassian =
        atlassian_answering(Canned::json(&json!({ "id": "10012", "key": "OPS-12" }))).await;
    let stack = Stack::start(profile(&atlassian))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connect_jira(&world, &atlassian).await;
    let exchanges = atlassian.asked_for(TOKEN_PATH);
    ran(&world, issue_graph(&account), "succeeded").await;
    assert_eq!(
        atlassian.asked_for(TOKEN_PATH),
        exchanges,
        "the run reused the token kept"
    );
    check_issue_and_comment(&atlassian);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[GRANT, ISSUED]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Jira refuses the issue with 400, as for a type OPS does not have. The
/// issue step and the run fail after one request, and no comment is
/// posted.
#[tokio::test]
async fn an_issue_jira_refuses_fails_the_run() {
    let atlassian = atlassian_answering(Canned::refusing(400)).await;
    let stack = Stack::start(profile(&atlassian))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connect_jira(&world, &atlassian).await;

    let run = ran(&world, issue_graph(&account), "failed").await;

    failed_step(&run, "jira-create-issue");
    assert_eq!(
        atlassian.asked_for(ISSUES),
        1,
        "a refusal is not tried again"
    );
    assert_eq!(
        atlassian.asked_for(COMMENTS),
        0,
        "nothing was said on a missing issue"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess pastes an email and API token for jira.acme.example, a site that
/// is no Jira Cloud site this deployment allows: no account is connected,
/// and nothing anywhere is asked, so the token never leaves.
#[tokio::test]
async fn a_site_the_deployment_does_not_allow_is_never_connected() {
    let atlassian = atlassian_answering(Canned::json(&json!({ "key": "OPS-12" }))).await;
    let stack = Stack::start(profile(&atlassian))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let offered = json!({
        "site": "https://jira.acme.example",
        "user": "tess@acme.test",
        "token": "acme pasted jira token"
    })
    .to_string();

    never_connected(
        &world,
        Offered {
            integration: "jira",
            credential: &offered,
        },
    )
    .await;

    assert!(atlassian.received().is_empty(), "Atlassian was never asked");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess connects Acme's site by signing in at Atlassian; the account is
/// tried there with the token issued.
async fn connect_jira(world: &World<'_>, atlassian: &CannedApp) -> String {
    let authorize = format!("{}/authorize", atlassian.url());
    let account = signed_in(
        world,
        &SignIn {
            integration: "jira",
            authorize: &authorize,
            client_id: CLIENT_ID,
            place: Some("acme.atlassian.net"),
        },
    )
    .await;
    let tried = only_call(atlassian, "GET", MYSELF);
    assert_eq!(
        tried.header("authorization"),
        Some(format!("Bearer {ISSUED}").as_str())
    );
    account
}

/// The workflow creates a bug in OPS and comments on it by the key Jira
/// gave back.
fn issue_graph(account: &str) -> Graph {
    let create = action(
        Action {
            integration: "jira",
            operation: "create-issue",
        },
        account,
        "write",
        vec![
            ("project", written("OPS")),
            ("type", written("Bug")),
            ("summary", written("Disk full on db-2")),
            ("description", written("The nightly backup stopped.")),
        ],
    );
    let comment = action(
        Action {
            integration: "jira",
            operation: "comment-on-issue",
        },
        account,
        "communicate",
        vec![
            ("issue", read("jira-create-issue.json.key")),
            ("body", written("Freed 40 GB; watching it.")),
        ],
    );
    chain(vec![create, comment])
}

/// Jira received the issue's fields nested where it reads them and the
/// comment on OPS-12, both signed with the token kept from connecting and
/// neither carrying the grant.
fn check_issue_and_comment(atlassian: &CannedApp) {
    let issue = only_call(atlassian, "POST", ISSUES);
    let comment = only_call(atlassian, "POST", COMMENTS);
    for call in [&issue, &comment] {
        assert_eq!(
            call.header("authorization"),
            Some(format!("Bearer {ISSUED}").as_str())
        );
        no_secret_leaked(&call.body, &[GRANT]);
    }
    assert_eq!(
        issue.json(),
        json!({ "fields": {
            "project": { "key": "OPS" },
            "issuetype": { "name": "Bug" },
            "summary": "Disk full on db-2",
            "description": "The nightly backup stopped."
        } })
    );
    assert_eq!(
        comment.json(),
        json!({ "body": "Freed 40 GB; watching it." })
    );
}

/// The Atlassian stand-in: it issues tokens and grants, lists Acme's site,
/// and answers Acme's Jira through the gateway, a new issue with `issue`.
async fn atlassian_answering(issue: Canned) -> CannedApp {
    CannedApp::start([
        (
            TOKEN_PATH,
            Canned::json(
                &json!({ "access_token": ISSUED, "refresh_token": GRANT, "expires_in": 3600 }),
            ),
        ),
        (
            RESOURCES,
            Canned::json(&json!([
                { "id": "acme-cloud", "url": "https://acme.atlassian.net", "name": "acme" }
            ])),
        ),
        (MYSELF, Canned::json(&json!({ "accountId": "tess" }))),
        (ISSUES, issue),
        (COMMENTS, Canned::json(&json!({ "id": "10001" }))),
    ])
    .await
    .expect("the Atlassian stand-in starts")
}

/// The pasted account's user on Acme's own site.
const SITE_USER: &str = "tess@acme.test";

/// The pasted account's API token: a sentence, so no scanner takes it for
/// a key.
const SITE_TOKEN: &str = "acme pasted jira token";

/// Tess pastes a user and token for Acme's own Jira site, which the
/// deployment lists, and the account is tried there with them. Ann
/// publishes the workflow that creates a bug in OPS and comments on it;
/// Tess runs it. The site receives the issue, then the comment on the key
/// it answered with, each carrying the user and token as a basic
/// credential, the issue's fields nested where Jira reads them, and
/// nothing else about the token anywhere.
#[tokio::test]
async fn a_run_reaches_a_pasted_jira_site_with_its_user_and_token() {
    let site = pasted_site_answering().await;
    let stack = Stack::start(
        Profile::standard()
            .with("OUTBOUND_DELIVERY_CA_FILE", site.authority_file())
            .with("JIRA_SITES", &site.host_and_port()),
    )
    .await
    .expect("the stack starts");
    let world = World::new(&stack).await;
    let origin = site.url_on(&stack, "");
    let credential = json!({
        "site": origin,
        "user": SITE_USER,
        "token": SITE_TOKEN
    })
    .to_string();
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!("{SITE_USER}:{SITE_TOKEN}"))
    );

    let account = account_at(&world, "jira", &credential).await;
    let probe = site.received_at("GET", SITE_MYSELF);
    assert_eq!(probe.len(), 1, "the account was tried once");
    assert_eq!(probe[0].header("authorization"), Some(basic.as_str()));

    ran(&world, issue_graph(&account), "succeeded").await;

    let issues = site.received_at("POST", SITE_ISSUES);
    assert_eq!(issues.len(), 1, "one issue was created");
    assert_eq!(issues[0].header("authorization"), Some(basic.as_str()));
    assert_eq!(
        issues[0].json(),
        json!({ "fields": {
            "project": { "key": "OPS" },
            "issuetype": { "name": "Bug" },
            "summary": "Disk full on db-2",
            "description": "The nightly backup stopped."
        } })
    );
    let comments = site.received_at("POST", SITE_COMMENTS);
    assert_eq!(comments.len(), 1, "one comment was posted");
    assert_eq!(comments[0].header("authorization"), Some(basic.as_str()));
    assert_eq!(
        comments[0].json(),
        json!({ "body": "Freed 40 GB; watching it." })
    );
    for arrival in site.received() {
        no_secret_leaked(&arrival.body, &[SITE_TOKEN]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Where the pasted site proves the account: who it is.
const SITE_MYSELF: &str = "/rest/api/2/myself";

/// Where an issue is created on the pasted site.
const SITE_ISSUES: &str = "/rest/api/2/issue";

/// Where the comment goes on the pasted site.
const SITE_COMMENTS: &str = "/rest/api/2/issue/OPS-12/comment";

/// A stand-in for Acme's own Jira site.
async fn pasted_site_answering() -> OutsideReceiver {
    OutsideReceiver::start(
        "jira.acme.example",
        [
            (SITE_MYSELF, Canned::json(&json!({ "accountId": "tess" }))),
            (
                SITE_ISSUES,
                Canned::json(&json!({ "id": "10012", "key": "OPS-12" })),
            ),
            (SITE_COMMENTS, Canned::json(&json!({ "id": "10001" }))),
        ],
    )
    .await
}

/// The standard deployment with the platform's Atlassian app at
/// `atlassian`, its gateway there too.
fn profile(atlassian: &CannedApp) -> Profile {
    let base = atlassian.url();
    Profile::standard()
        .with("JIRA_CLIENT_ID", CLIENT_ID)
        .with("JIRA_CLIENT_SECRET", "acme platform atlassian app words")
        .with("JIRA_AUTHORIZE_URL", &format!("{base}/authorize"))
        .with("JIRA_TOKEN_URL", &format!("{base}{TOKEN_PATH}"))
        .with("JIRA_GATEWAY_URL", &format!("{base}/"))
}
