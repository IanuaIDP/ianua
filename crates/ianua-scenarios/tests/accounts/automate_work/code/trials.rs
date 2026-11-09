//! Trying a sandbox version on sample input: Ann checks her code before it
//! goes in a workflow. A worker runs it in a real container, as a code step
//! would, and she reads back what it gave, or the error it raised. Only
//! those who may change workflows try a version, and nobody reads another
//! company's trial.

use ianua_scenarios::api::sandboxes;
use ianua_scenarios::expect::{Matrix, eventually_paced};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sandboxes::{NewTrial, Trial};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::code::registry::{Fingerprints, registry};
use crate::code::running::{CONTAINER_PATIENCE, Readied, Recipe, readied};

/// Python that makes a slug of the title it is handed, or raises when it
/// is handed none.
const SLUG: &str = "import re\n\n\
def main(input):\n\
\tif not input.get('title'):\n\
\t\traise ValueError('no title to make a slug of')\n\
\treturn {'slug': re.sub(r'[^a-z0-9]+', '-', input['title'].lower()).strip('-')}\n";

/// Ann's slug version.
fn slugs() -> Recipe<'static> {
    Recipe {
        name: "Slugs",
        language: "python",
        runtime: "python-3.13",
        code: SLUG,
        packages: &[],
        run_seconds: 20,
        allowed_hosts: &[],
    }
}

/// The stack running code through the container command.
async fn stack_running_code(npm_url: &str) -> Stack {
    let profile = Profile::standard()
        .with("NPM_REGISTRY_URL", npm_url)
        .with("SANDBOX_CONTAINER_COMMAND", "docker");
    Stack::start(profile).await.expect("the stack starts")
}

/// Tess tries `version` on `input`; the trial once it ended.
async fn tried(world: &World<'_>, version: &Readied, input: serde_json::Value) -> Trial {
    let answer = sandboxes::start_trial(
        world.tenant(),
        &version.sandbox_id,
        &version.version_id,
        &NewTrial { input },
    )
    .send(world.admin().client())
    .await;
    assert_eq!(answer.status(), Status::ACCEPTED, "{}", answer.summary());
    let started = answer.ok();
    assert_eq!(started.status, "running");
    eventually_paced("the trial to end", CONTAINER_PATIENCE, || async {
        let trial = sandboxes::trial(world.tenant(), &version.sandbox_id, &started.id)
            .send(world.admin().client())
            .await
            .ok();
        (trial.status != "running").then_some(trial)
    })
    .await
}

/// Tess tries Ann's slug version on a title. The trial answers at once as
/// running, and once a worker ran it in a container, it succeeded with the
/// slug of that title.
#[tokio::test]
async fn a_version_is_tried_on_sample_input() {
    let npm = registry(&[], Fingerprints::True).await;
    let stack = stack_running_code(&npm.url()).await;
    let world = World::new(&stack).await;
    let version = readied(&world, &slugs()).await;

    let trial = tried(&world, &version, json!({"title": "Fix Login Page"})).await;

    assert_eq!(trial.status, "succeeded", "{:?}", trial.failure);
    assert_eq!(trial.output, Some(json!({"slug": "fix-login-page"})));

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess tries the version on input with no title. The code raises, and the
/// trial failed with the end of the error it raised, as a code step would.
#[tokio::test]
async fn a_trial_shows_the_error_the_code_raised() {
    let npm = registry(&[], Fingerprints::True).await;
    let stack = stack_running_code(&npm.url()).await;
    let world = World::new(&stack).await;
    let version = readied(&world, &slugs()).await;

    let trial = tried(&world, &version, json!({})).await;

    assert_eq!(trial.status, "failed");
    let failure = trial.failure.expect("a failure");
    assert_eq!(failure.code, "code_raised");
    assert!(
        failure.detail.contains("no title to make a slug of"),
        "{}",
        failure.detail
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max lacks workflow editing rights, Sam belongs to another company, and
/// an anonymous visitor has no session. All are refused a trial of Ann's
/// version; Sam cannot read Tess's trial either.
#[tokio::test]
async fn only_those_who_may_change_workflows_try_a_version() {
    let npm = registry(&[], Fingerprints::True).await;
    let stack = stack_running_code(&npm.url()).await;
    let world = World::new(&stack).await;
    let version = readied(&world, &slugs()).await;
    let input = NewTrial {
        input: json!({"title": "Fix Login Page"}),
    };
    let trial = tried(&world, &version, json!({"title": "Fix Login Page"})).await;

    refuse_trial_starters(&world, &version, &input).await;
    Matrix::new(
        "reading the trial",
        sandboxes::trial(world.tenant(), &version.sandbox_id, &trial.id).call(),
    )
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .run()
    .await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// A member, another tenant's administrator and an anonymous caller cannot start this trial.
async fn refuse_trial_starters(world: &World<'_>, version: &Readied, input: &NewTrial) {
    Matrix::new(
        "trying the version",
        sandboxes::start_trial(
            world.tenant(),
            &version.sandbox_id,
            &version.version_id,
            input,
        )
        .call(),
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
}
