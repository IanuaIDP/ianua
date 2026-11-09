//! Sandboxes: Ann makes one for JavaScript and Tess saves a version that
//! pins two packages. A stand-in npm registry shows what was fetched: each
//! package once, checked against the fingerprint it published, and a
//! package they need but nobody pinned is named, never fetched. A
//! registry whose fingerprint does not match fails the version, naming
//! the package.

use ianua_scenarios::api::sandboxes;
use ianua_scenarios::expect::eventually;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::CannedApp;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sandboxes::{NewSandbox, NewSandboxVersion, Pin, SandboxVersion};
use ianua_scenarios::world::World;

use crate::code::registry::{Fingerprints, Package, metadata_path, registry, tarball_path};

/// `trim`, which needs nothing.
const TRIM: Package = Package {
    name: "trim",
    version: "1.0.0",
    files: &[
        (
            "package.json",
            r#"{"name":"trim","version":"1.0.0","main":"index.js"}"#,
        ),
        ("index.js", "module.exports = (text) => text.trim();"),
    ],
    needs: &[],
};

/// `@acme/pad`, which says it needs `left-pad`.
const PAD: Package = Package {
    name: "@acme/pad",
    version: "2.0.0",
    files: &[
        (
            "package.json",
            r#"{"name":"@acme/pad","version":"2.0.0","main":"index.js"}"#,
        ),
        ("index.js", "module.exports = (text) => ` ${text} `;"),
    ],
    needs: &["left-pad"],
};

/// Ann makes a JavaScript sandbox; its id.
async fn made(world: &World<'_>) -> String {
    let sandbox = NewSandbox {
        name: "Clean issue titles".to_owned(),
        language: "javascript".to_owned(),
    };
    sandboxes::create(world.tenant(), &sandbox)
        .send(world.owner().client())
        .await
        .ok()
        .id
}

/// Tess saves the next version of `sandbox_id`, pinning `packages`.
async fn saved(world: &World<'_>, sandbox_id: &str, packages: &[&Package]) -> SandboxVersion {
    let version = NewSandboxVersion {
        runtime: "node-22".to_owned(),
        code: "const trim = require('trim');\nmodule.exports = (item) => trim(item.title);\n"
            .to_owned(),
        packages: packages
            .iter()
            .map(|package| Pin {
                name: package.name.to_owned(),
                version: package.version.to_owned(),
            })
            .collect(),
        run_seconds: 10,
        memory_mib: 128,
        allowed_hosts: Vec::new(),
    };
    let answer = sandboxes::save_version(world.tenant(), sandbox_id, &version)
        .send(world.admin().client())
        .await;
    assert_eq!(answer.status(), Status::CREATED);
    answer.ok()
}

/// Waits until the newest version of `sandbox_id` is no longer building.
async fn built(world: &World<'_>, sandbox_id: &str) -> SandboxVersion {
    eventually("the version's bundle to be built", || async {
        let detail = sandboxes::get(world.tenant(), sandbox_id)
            .send(world.admin().client())
            .await
            .ok();
        let newest = detail.versions.items.into_iter().next()?;
        (newest.build.status != "building").then_some(newest)
    })
    .await
}

/// Ann makes a JavaScript sandbox and Tess saves version 1 pinning `trim`
/// and `@acme/pad`, under Node 22. It answers as building, keeping the
/// exact image Node 22 is offered in, named by its content. The build job
/// fetches each package's metadata and tarball once, and the version
/// becomes ready with a SHA-256 of its bundle. `left-pad`, which
/// `@acme/pad` needs but nobody pinned, is named as unlisted and was
/// never fetched. The trail records the sandbox made, the version saved
/// and the bundle built.
#[tokio::test]
async fn a_saved_version_is_built_from_the_packages_it_pins() {
    let npm = registry(&[TRIM, PAD], Fingerprints::True).await;
    let profile = Profile::standard().with("NPM_REGISTRY_URL", &npm.url());
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let sandbox_id = made(&world).await;

    let saved = saved(&world, &sandbox_id, &[&TRIM, &PAD]).await;
    let version = built(&world, &sandbox_id).await;
    check_saved_runtime(&world, &saved).await;
    check_built_bundle(&saved, &version);
    check_package_fetches(&npm);
    let trail = world.trail();
    for recorded in [
        "workflows.sandbox_created",
        "workflows.sandbox_version_saved",
        "workflows.sandbox_version_built",
    ] {
        assert_eq!(trail.count(recorded).await, 1, "{recorded}");
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// The saved version is initially building on the exact offered Node image.
async fn check_saved_runtime(world: &World<'_>, saved: &SandboxVersion) {
    assert_eq!((saved.number, saved.build.status.as_str()), (1, "building"));
    assert_eq!(saved.runtime, "node-22");
    let offered = sandboxes::runtimes(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let node_22 = offered
        .iter()
        .find(|offered| offered.runtime == "node-22")
        .expect("Node 22 is offered");
    assert_eq!(saved.image, node_22.image);
    assert!(saved.image.contains("@sha256:"), "{}", saved.image);
}

/// The same version becomes ready with a nonempty hashed bundle and its missing dependency named.
fn check_built_bundle(saved: &SandboxVersion, version: &SandboxVersion) {
    assert_eq!(version.id, saved.id);
    assert_eq!(version.build.status, "ready", "{:?}", version.build);
    let digest = version
        .build
        .digest
        .as_ref()
        .expect("a ready bundle has a digest");
    assert_eq!(digest.len(), 64);
    assert!(version.build.bytes.is_some_and(|bytes| bytes > 0));
    assert_eq!(version.build.unlisted, ["left-pad"]);
}

/// Each pinned package is fetched once and the unlisted dependency is never requested.
fn check_package_fetches(npm: &CannedApp) {
    for package in [&TRIM, &PAD] {
        assert_eq!(
            npm.asked_for(&metadata_path(package)),
            1,
            "{}",
            package.name
        );
        assert_eq!(npm.asked_for(&tarball_path(package)), 1, "{}", package.name);
    }
    assert!(
        npm.received()
            .iter()
            .all(|asked| !asked.path.contains("left-pad")),
        "an unlisted package is never fetched"
    );
}

/// The registry's fingerprint does not match its tarball, so Tess's version fails as
/// `fingerprint_mismatch`, naming `trim`, keeps no bundle, and the trail
/// records the failure.
#[tokio::test]
async fn a_package_that_does_not_match_its_fingerprint_fails_the_version() {
    let npm = registry(&[TRIM], Fingerprints::Tampered).await;
    let profile = Profile::standard().with("NPM_REGISTRY_URL", &npm.url());
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let sandbox_id = made(&world).await;

    saved(&world, &sandbox_id, &[&TRIM]).await;
    let version = built(&world, &sandbox_id).await;

    assert_eq!(version.build.status, "failed");
    assert_eq!(
        version.build.failure.as_deref(),
        Some("fingerprint_mismatch")
    );
    assert_eq!(version.build.detail.as_deref(), Some("trim"));
    assert!(
        version.build.digest.is_none(),
        "a failed version keeps no bundle"
    );
    assert_eq!(
        world
            .trail()
            .count("workflows.sandbox_version_failed")
            .await,
        1
    );

    stack.stop().await.expect("the stack stops cleanly");
}
