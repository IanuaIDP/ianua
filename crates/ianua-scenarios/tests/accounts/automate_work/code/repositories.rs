//! Code from and to a company's repository: Tess imports a file of the
//! team's GitHub repository into a sandbox version, which keeps the exact
//! commit the branch pointed to, then pushes a copy of the version back to
//! a folder on a branch. A stand-in for GitHub's API shows what arrived.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_scenarios::api::sandboxes;
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sandboxes::{
    Import, ImportedFrom, ImportedSandboxVersion, NewPush, NewSandbox, SandboxVersion,
};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::account_at;

/// The token the team's GitHub account holds: a sentence, so no scanner
/// takes it for a key.
const TOKEN: &str = "acme github token for sandbox code";

/// The commit `main` points to.
const MAIN: &str = "1b2c3d4e5f60718293a4b5c6d7e8f90112233445";

/// The commit each pushed file becomes.
const PUSHED: &str = "99aa88bb77cc66dd55ee44ff3300221100998877";

/// The code in the repository.
const TIDY: &str = "def main(input):\n\treturn {'title': input['title'].strip()}\n";

/// The stand-in GitHub: whose the token is, the commit `main` points to,
/// the file, and the two files a push writes, each already there.
async fn github() -> CannedApp {
    let file = json!({ "content": STANDARD.encode(TIDY), "sha": "blob-of-tidy" });
    let written = json!({ "sha": "blob-before", "commit": { "sha": PUSHED } });
    CannedApp::start([
        ("/user", Canned::json(&json!({ "login": "acme-bot" }))),
        (
            "/repos/acme/web/commits/main",
            Canned::json(&json!({ "sha": MAIN })),
        ),
        (
            "/repos/acme/web/contents/scripts/tidy.py",
            Canned::json(&file),
        ),
        (
            "/repos/acme/web/contents/sandboxes/tidy/main.py",
            Canned::json(&written),
        ),
        (
            "/repos/acme/web/contents/sandboxes/tidy/requirements.txt",
            Canned::json(&written),
        ),
    ])
    .await
    .expect("the GitHub stand-in starts")
}

/// Tess imports `scripts/tidy.py` from `main` of acme/web through the
/// team's GitHub account. GitHub is asked which commit `main` points to,
/// then for the file, and the version keeps its text and that commit.
/// Pushing the version to `sandboxes/tidy` on `ianua/tidy` writes its code
/// as `main.py` and its pins as `requirements.txt`, each replacing the
/// version there, and the trail records the push with the commit it
/// became. The token reaches only GitHub, never the trail.
#[tokio::test]
async fn a_version_is_imported_from_a_repository_and_pushed_back() {
    let github = github().await;
    let profile = Profile::standard().with("GITHUB_API_URL", &github.url());
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "github", TOKEN).await;
    let sandbox_id = create_sandbox(&world).await;
    let import = import_file(&account, "scripts/tidy.py");
    let saved = sandboxes::save_imported_version(world.tenant(), &sandbox_id, &import)
        .send(world.admin().client())
        .await;
    assert_eq!(saved.status(), Status::CREATED, "{}", saved.summary());
    let version = saved.ok();
    check_imported_version(&version);
    push_version(&world, &sandbox_id, &version.id, &account).await;
    check_repository_writes(&github);
    check_push_trail(&world).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann creates the Python sandbox that receives imported code.
async fn create_sandbox(world: &World<'_>) -> String {
    let made = NewSandbox {
        name: "Tidy titles".to_owned(),
        language: "python".to_owned(),
    };
    sandboxes::create(world.tenant(), &made)
        .send(world.owner().client())
        .await
        .ok()
        .id
}

/// The import reads one file at main with the scenario's fixed runtime and resource limits.
fn import_file(account: &str, path: &str) -> ImportedSandboxVersion {
    ImportedSandboxVersion {
        runtime: "python-3.13".to_owned(),
        import: Import {
            account_id: account.to_owned(),
            repository: "acme/web".to_owned(),
            path: path.to_owned(),
            at: "main".to_owned(),
        },
        packages: Vec::new(),
        run_seconds: 20,
        memory_mib: 128,
    }
}

/// The imported version retains the source text and the immutable commit main resolved to.
fn check_imported_version(version: &SandboxVersion) {
    assert_eq!(version.code, TIDY);
    assert_eq!(
        version.imported_from,
        Some(ImportedFrom {
            integration: "github".to_owned(),
            repository: "acme/web".to_owned(),
            path: "scripts/tidy.py".to_owned(),
            commit: MAIN.to_owned(),
        })
    );
}

/// Tess pushes the imported version into the dedicated branch and folder.
async fn push_version(world: &World<'_>, sandbox_id: &str, version_id: &str, account: &str) {
    let push = NewPush {
        account_id: account.to_owned(),
        repository: "acme/web".to_owned(),
        branch: "ianua/tidy".to_owned(),
        folder: "sandboxes/tidy".to_owned(),
    };

    let pushed = sandboxes::push_version(world.tenant(), sandbox_id, version_id, &push)
        .send(world.admin().client())
        .await;

    assert_eq!(pushed.status(), Status::OK, "{}", pushed.summary());
}

/// GitHub receives one replacement commit for the code and one for the package pins.
fn check_repository_writes(github: &CannedApp) {
    let writes: Vec<_> = github
        .received()
        .into_iter()
        .filter(|call| call.method == "PUT")
        .collect();
    assert_eq!(writes.len(), 2, "one commit per file");
    assert_eq!(
        writes[0].path,
        "/repos/acme/web/contents/sandboxes/tidy/main.py"
    );
    let code = writes[0].json();
    assert_eq!(code["branch"], "ianua/tidy");
    assert_eq!(code["sha"], "blob-before", "the file there is replaced");
    assert_eq!(
        STANDARD.decode(code["content"].as_str().unwrap()).unwrap(),
        TIDY.as_bytes()
    );
    assert_eq!(
        writes[1].path,
        "/repos/acme/web/contents/sandboxes/tidy/requirements.txt"
    );
    for call in github.received() {
        assert_eq!(
            call.header("authorization"),
            Some(format!("Bearer {TOKEN}").as_str())
        );
    }
}

/// One push is audited with its commit and no workflow audit details expose the account token.
async fn check_push_trail(world: &World<'_>) {
    let recorded = world
        .trail()
        .entries("workflows.sandbox_version_pushed")
        .await;
    assert_eq!(recorded.len(), 1, "the push is recorded once");
    assert_eq!(recorded[0].details["commit"], PUSHED);
    for entry in world.trail().entries("workflows.").await {
        no_secret_leaked(&entry.details.to_string(), &[TOKEN]);
    }
}

/// Tess cannot import a file missing from `main`. The save returns not found,
/// and the sandbox's latest version remains zero.
#[tokio::test]
async fn an_import_of_a_missing_file_saves_nothing() {
    let github = github().await;
    let profile = Profile::standard().with("GITHUB_API_URL", &github.url());
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let account = account_at(&world, "github", TOKEN).await;
    let sandbox_id = create_sandbox(&world).await;
    let import = import_file(&account, "scripts/gone.py");

    let saved = sandboxes::save_imported_version(world.tenant(), &sandbox_id, &import)
        .send(world.admin().client())
        .await;

    assert_eq!(saved.status(), Status::NOT_FOUND, "{}", saved.summary());
    let detail = sandboxes::get(world.tenant(), &sandbox_id)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(detail.sandbox.latest_version, 0);

    stack.stop().await.expect("the stack stops cleanly");
}
