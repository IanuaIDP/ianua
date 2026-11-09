//! What a workflow's builder is shown: every integration installed with
//! its title, description, icon and own picture, and every operation with
//! what it does, what each input means and what it gives back.

use ianua_scenarios::api::workflows;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::workflows::{Integration, Operation};
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;

/// The integration identities and icons the builder advertises.
const INSTALLED: &[(&str, &str, &str)] = &[
    ("github", "GitHub", "github"),
    ("slack", "Slack", "slack"),
    ("jira", "Jira", "jira"),
    ("azure-devops", "Azure DevOps", "azure-devops"),
    ("mailgun", "Mailgun", "mailgun"),
    ("twilio", "Twilio", "twilio"),
    ("google-calendar", "Google Calendar", "google-calendar"),
    ("google-sheets", "Google Sheets", "google-sheets"),
    ("gmail", "Gmail", "gmail"),
    ("gitlab", "GitLab", "gitlab"),
    ("linear", "Linear", "linear"),
    ("asana", "Asana", "asana"),
    ("trello", "Trello", "trello"),
    ("clickup", "ClickUp", "clickup"),
    ("teams", "Microsoft Teams", "teams"),
    ("discord", "Discord", "discord"),
    ("pagerduty", "PagerDuty", "pagerduty"),
    ("notion", "Notion", "notion"),
    ("airtable", "Airtable", "airtable"),
    ("hubspot", "HubSpot", "hubspot"),
    ("stripe", "Stripe", "stripe"),
    ("salesforce", "Salesforce", "salesforce"),
    ("telegram", "Telegram", "telegram"),
    ("http", "HTTP request", "http"),
];

/// Tess opens the workflow builder. It lists every outside service the
/// build installs and the HTTP request step, each with a title, a
/// description and an icon. GitHub's
/// "open an issue" says what each of its inputs means and that it gives
/// back the issue's number at `json.number`, which a later comment step
/// reads; every operation explains every input it takes. Each integration's
/// own picture is served to anyone, so nothing in it can run. Sam, from another
/// company, and nobody signed in are refused the catalog.
#[tokio::test]
async fn the_builder_is_shown_each_integration_and_what_its_steps_do() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    let integrations = workflows::integrations(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let operations = workflows::operations(world.tenant())
        .send(world.admin().client())
        .await
        .ok();

    check_integrations(&integrations);
    check_operations(&operations);
    check_pictures(&world, &integrations).await;
    refuse_catalog_readers(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Installed integrations have the expected labels, icons and descriptions.
fn check_integrations(integrations: &[Integration]) {
    for &(key, title, icon) in INSTALLED {
        let listed = integrations
            .iter()
            .find(|integration| integration.key == key)
            .unwrap_or_else(|| panic!("{key} is listed"));
        assert_eq!(listed.title, title);
        assert_eq!(listed.icon, icon);
        assert!(!listed.description.is_empty(), "{key} says what it is for");
    }
}

/// The GitHub and Slack operations expose their expected inputs and result paths.
fn check_operations(operations: &[Operation]) {
    let open = operation(operations, "github", "create-issue");
    assert_eq!(open.title, "Open an issue");
    assert_eq!(open.effect, "write");
    let repository = open
        .inputs
        .iter()
        .find(|input| input.name == "repository")
        .expect("the repository input is listed");
    assert!(repository.required && repository.description.contains("owner/name"));
    assert!(
        open.outputs
            .iter()
            .any(|output| output.path == "json.number"),
        "opening an issue gives back its number"
    );
    let post = operation(operations, "slack", "post-message");
    assert!(post.outputs.iter().any(|output| output.path == "json.ts"));
    check_input_descriptions(operations);
}

/// Every operation has a title and explains every input it accepts.
fn check_input_descriptions(operations: &[Operation]) {
    for listed in operations {
        assert!(!listed.title.is_empty(), "{} has a title", listed.operation);
        assert!(
            listed
                .inputs
                .iter()
                .all(|input| !input.description.is_empty()),
            "{}.{} explains every input",
            listed.integration,
            listed.operation
        );
    }
}

/// Only built-in integrations omit pictures; published SVGs are readable with restrictive policy.
async fn check_pictures(world: &World<'_>, integrations: &[Integration]) {
    for listed in integrations {
        let built_in = ["http", "memory", "apps", "ianua"].contains(&listed.key.as_str());
        assert_eq!(
            listed.picture.is_none(),
            built_in,
            "only {} carries no picture of its own",
            listed.key
        );
        let Some(address) = &listed.picture else {
            continue;
        };
        let picture: Answer<String> = world.anonymous().client().get(address).await;
        assert_eq!(picture.status(), Status::OK, "{} has a picture", listed.key);
        assert_eq!(picture.header("content-type"), Some("image/svg+xml"));
        assert_eq!(
            picture.header("content-security-policy"),
            Some("default-src 'none'; sandbox"),
            "nothing in {}'s picture runs",
            listed.key
        );
        assert!(picture.exchange().response_body().starts_with("<svg"));
    }
}

/// A stranger and an anonymous visitor cannot read this tenant's catalog.
async fn refuse_catalog_readers(world: &World<'_>) {
    Matrix::new(
        "reading the catalog",
        workflows::integrations(world.tenant()).call(),
    )
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
}

/// The operation `operation` of `integration` in `operations`.
fn operation<'a>(operations: &'a [Operation], integration: &str, operation: &str) -> &'a Operation {
    operations
        .iter()
        .find(|listed| listed.integration == integration && listed.operation == operation)
        .unwrap_or_else(|| panic!("{integration}.{operation} is listed"))
}
