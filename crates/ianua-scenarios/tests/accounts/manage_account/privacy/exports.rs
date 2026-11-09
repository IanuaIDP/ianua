//! Pat's export of her own data: she asks for it, the worker builds it,
//! and she downloads it once through a signed link, with no secret of hers
//! in it. Even Tess, who asked for one on Pat's behalf, cannot download it;
//! nor can Uma or anybody signed out. A link expires within minutes, the
//! export itself after its download window, and Pat can always ask again.

use std::time::Duration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::account;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{eventually, no_secret_leaked};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::account::ExportRequest;
use ianua_scenarios::world::World;
use serde_json::Value;

use crate::support::{invited_and_signed_in, tenant_records};

/// How far the clock moves for the worker's next build round, and for a
/// download link to expire: five minutes and a second.
const NEXT_ROUND: Duration = Duration::from_secs(301);

/// How far the clock moves to pass an export's download window: eight
/// days, past its seven.
const PAST_WINDOW: Duration = Duration::from_secs(8 * 86_400);

/// The standard profile with a worker that sweeps every second, so a due
/// export is built at once.
fn sweeping_profile() -> Profile {
    Profile::standard().with("WORKER_SWEEP_TICK_SECONDS", "1")
}

/// Pat asks for an export of each kind, `access` and `portability`, and
/// downloads each file once. Each file is hers: it names the export and
/// its kind, carries her profile and consents, and her sessions only in
/// the `access` export, with no secret of hers in it. Each link answers
/// once and then nothing. Both builds and both downloads are recorded.
#[tokio::test]
async fn pat_downloads_each_kind_of_export_once_with_no_secret_in_it() {
    let clock = Clock::controlled();
    let stack = Stack::start(sweeping_profile())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    for scope in ["access", "portability"] {
        download_kind_once(&world, &clock, scope).await;
    }

    assert_eq!(
        tenant_records(&world, "identity.data_export_ready", &[]).await,
        2,
        "both builds are recorded"
    );
    assert_eq!(
        tenant_records(&world, "identity.data_export_downloaded", &[]).await,
        2,
        "both downloads are recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Build and download one requested export, then prove the same link cannot be reused.
async fn download_kind_once(world: &World<'_>, clock: &Clock, scope: &str) {
    let pat = invited_and_signed_in(world, &format!("pat-{scope}")).await;
    let request = account::export(world.tenant(), pat.id(), &kind(scope))
        .send(pat.client())
        .await
        .ok();
    built(world, &pat, clock, &request.id).await;
    let link = account::download(world.tenant(), &request.id)
        .send(pat.client())
        .await
        .ok();
    let file = pat.client().get::<Value>(&link.url).await.ok();
    check_export_contents(&file, &pat, &request.id, scope);
    let secrets = pat.secrets();
    let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
    no_secret_leaked(&file.to_string(), &secrets);
    pat.client()
        .get::<Value>(&link.url)
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// Each export identifies its request and kind, includes Pat's profile and consents, and scopes sessions.
fn check_export_contents(file: &Value, pat: &Person, id: &str, scope: &str) {
    assert_eq!(
        file["export"]["id"], id,
        "the {scope} file names its export"
    );
    assert_eq!(
        file["export"]["scope"], scope,
        "the {scope} file names its kind"
    );
    assert!(
        file["profile"].to_string().contains(pat.email()),
        "the {scope} file carries Pat's profile"
    );
    assert!(
        file.get("consents").is_some(),
        "the {scope} file carries Pat's consents"
    );
    assert_eq!(
        file.get("sessions").is_some(),
        scope == "access",
        "only the access file carries Pat's sessions"
    );
}

/// Tess asks for an export of Pat's data, and the worker builds it.
/// Uma, Tess and anonymous callers cannot obtain its download link, and
/// Uma cannot list Pat's exports. Pat lists her
/// exports, sees the one staff asked for, and downloads it.
#[tokio::test]
async fn even_tess_who_asked_for_pats_export_cannot_download_it() {
    let clock = Clock::controlled();
    let stack = Stack::start(sweeping_profile())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    let uma = invited_and_signed_in(&world, "uma").await;

    let request = account::export(world.tenant(), pat.id(), &kind("access"))
        .send(world.admin().client())
        .await
        .ok();
    built(&world, &pat, &clock, &request.id).await;
    refuse_export_callers(&world, &pat, &uma, &request.id).await;
    download_staff_export(&world, &pat, &request.id).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma, the requesting administrator and anonymous callers cannot obtain Pat's download.
async fn refuse_export_callers(world: &World<'_>, pat: &Person, uma: &Person, id: &str) {
    account::download(world.tenant(), id)
        .send(uma.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    account::download(world.tenant(), id)
        .send(world.admin().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    account::download(world.tenant(), id)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    account::exports(world.tenant(), pat.id())
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Pat can identify the staff-requested export and download its profile data herself.
async fn download_staff_export(world: &World<'_>, pat: &Person, id: &str) {
    let listed = account::exports(world.tenant(), pat.id())
        .send(pat.client())
        .await
        .ok();
    let staffs = listed
        .iter()
        .any(|export| export.id == id && export.asked_by == "staff" && export.scope == "access");
    assert!(staffs, "Pat sees the access export staff asked for");
    let link = account::download(world.tenant(), id)
        .send(pat.client())
        .await
        .ok();
    let file = pat.client().get::<Value>(&link.url).await.ok();
    assert!(file.get("profile").is_some(), "Pat downloads her own data");
}

/// Pat's export is built and she takes a download link. Five minutes and
/// a second later that link is refused, but a fresh link downloads the
/// file. Past the export's download window, a fresh link is
/// refused and the worker marks the export expired. Pat signs in again
/// and asks for a new export.
#[tokio::test]
async fn a_download_link_expires_before_the_export_does() {
    let clock = Clock::controlled();
    let stack = Stack::start(sweeping_profile())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;

    let request = account::export(world.tenant(), pat.id(), &kind("portability"))
        .send(pat.client())
        .await
        .ok();
    built(&world, &pat, &clock, &request.id).await;
    check_expired_link(&world, &pat, &clock, &request.id).await;
    clock.advance(PAST_WINDOW);
    pat.sign_in(&stack).await;
    check_expired_export(&world, &pat, &request.id).await;
    account::export(world.tenant(), pat.id(), &kind("portability"))
        .send(pat.client())
        .await
        .ok();
    stack.stop().await.expect("the stack stops cleanly");
}

/// The old link expires while a freshly issued link still downloads the ready export.
async fn check_expired_link(world: &World<'_>, pat: &Person, clock: &Clock, id: &str) {
    let old = account::download(world.tenant(), id)
        .send(pat.client())
        .await
        .ok();

    clock.advance(NEXT_ROUND);
    pat.client()
        .get::<Value>(&old.url)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let fresh = account::download(world.tenant(), id)
        .send(pat.client())
        .await
        .ok();
    let file = pat.client().get::<Value>(&fresh.url).await.ok();
    assert!(
        file.get("profile").is_some(),
        "a fresh link downloads the file"
    );
}

/// Past the download window, a fresh link is refused and the worker marks the export expired.
async fn check_expired_export(world: &World<'_>, pat: &Person, id: &str) {
    account::download(world.tenant(), id)
        .send(pat.client())
        .await
        .refused(Status::CONFLICT, "conflict");
    eventually("the worker to mark the export expired", || async {
        let exports = account::exports(world.tenant(), pat.id())
            .send(pat.client())
            .await
            .ok();
        exports
            .iter()
            .any(|export| export.id == id && export.status == "expired")
            .then_some(())
    })
    .await;
}

/// Moves the clock to the worker's next build round and waits until
/// `holder` sees export `id` ready through their own API.
async fn built(world: &World<'_>, holder: &Person, clock: &Clock, id: &str) {
    clock.advance(NEXT_ROUND);
    eventually("the worker to build the export", || async {
        let exports = account::exports(world.tenant(), holder.id())
            .send(holder.client())
            .await
            .ok();
        exports
            .iter()
            .any(|export| export.id == id && export.status == "ready")
            .then_some(())
    })
    .await;
}

/// An export of kind `scope`: `access` or `portability`.
fn kind(scope: &str) -> ExportRequest {
    ExportRequest {
        scope: scope.to_owned(),
    }
}
