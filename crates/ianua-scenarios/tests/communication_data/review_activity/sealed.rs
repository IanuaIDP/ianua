//! A sealed export of the tenant's audit log: an auditor outside the
//! platform checks the file with nothing but the tenant's published keys.

use ianua_scenarios::api::{Request, Text, audit, oauth};
use ianua_scenarios::expect::{eventually, verified_rs256};
use ianua_scenarios::net::Call;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::audit::{AuditExport, ExportAsked};
use ianua_scenarios::world::World;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::support::invited;

/// The type a seal carries, so no token passes for one.
const SEAL_TYPE: &str = "ianua-audit-seal+jwt";

/// Tess invites Uma, then exports Acme's invitations as JSON for an outside
/// auditor. The export comes with the file's SHA-256 and a seal. The auditor
/// downloads the file and takes its SHA-256 themself, fetches Acme's keys
/// from its discovery document, and checks the seal: typed as a seal,
/// signed by a published key, issued by Acme, naming this export, the
/// file's digest and how many records it holds. One byte added to the
/// file gives another digest, which the seal does not name.
#[tokio::test]
async fn an_auditor_checks_a_sealed_export_against_the_published_keys() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    invited(&world, "uma").await;
    let (id, ready) = written_export(&world).await;
    let file = downloaded(&world, &ready).await;
    let digest = hex(&Sha256::digest(file.as_bytes()));
    assert_eq!(
        ready.sha256.as_deref(),
        Some(digest.as_str()),
        "the export names the file's digest"
    );
    let claims = checked_seal(&world, &ready).await;
    assert_seal_names(&claims, &id, &digest, &ready);
    let tampered = format!("{file} ");
    assert_ne!(
        hex(&Sha256::digest(tampered.as_bytes())),
        digest,
        "a changed file no longer matches the seal"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The file `ready`'s link downloads, as the auditor receives it.
async fn downloaded(world: &World<'_>, ready: &AuditExport) -> String {
    let link = ready
        .download_url
        .clone()
        .expect("a ready export has a link");
    Request::<Text>::text(Call::get(&link))
        .send_text(world.admin().client())
        .await
        .ok()
}

/// The seal names export `id`, the file's `digest`, its record count and
/// its format.
fn assert_seal_names(claims: &Value, id: &str, digest: &str, ready: &AuditExport) {
    assert_eq!(claims["jti"], id, "the seal names this export");
    assert_eq!(
        claims["audit_export"]["sha256"], digest,
        "the seal names the file's digest"
    );
    assert_eq!(
        claims["audit_export"]["rows"],
        ready.rows.expect("a ready export counts its rows")
    );
    assert_eq!(claims["audit_export"]["format"], "json");
}

/// Tess's JSON export of the invitations, once the worker has written and
/// sealed it, with its id.
async fn written_export(world: &World<'_>) -> (String, AuditExport) {
    let asked = ExportAsked {
        format: "json".to_owned(),
        event_type: Some("identity.user_invited".to_owned()),
    };
    let export = audit::request_tenant_export(world.tenant(), &asked)
        .send(world.admin().client())
        .await
        .ok();
    let ready = eventually("the worker to write and seal the export", || async {
        let standing = audit::tenant_export(world.tenant(), &export.id)
            .send(world.admin().client())
            .await
            .ok();
        (standing.status == "ready").then_some(standing)
    })
    .await;
    (export.id, ready)
}

/// The claims of `ready`'s seal, checked as an auditor checks them: against
/// the keys Acme's discovery document points to, issued by Acme.
async fn checked_seal(world: &World<'_>, ready: &AuditExport) -> Value {
    let discovery = oauth::discovery(world.tenant())
        .send(world.anonymous().client())
        .await
        .ok();
    let published = oauth::keys(&discovery.jwks_uri)
        .send(world.anonymous().client())
        .await
        .ok();
    let seal = ready.seal.as_deref().expect("a tenant's export is sealed");
    let claims =
        verified_rs256(&published, seal, SEAL_TYPE).expect("a published key verifies the seal");
    assert_eq!(
        claims["iss"], discovery.issuer,
        "the seal is issued by Acme"
    );
    claims
}

/// `bytes` in lower-case hex, as `sha256sum` prints a digest.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
