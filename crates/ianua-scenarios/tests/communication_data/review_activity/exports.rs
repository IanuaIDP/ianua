//! An export of the tenant's audit log: asked for only by someone who may
//! export it, written in full by the worker, and downloaded once through a
//! signed link, every step on record.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{Request, Text, audit};
use ianua_scenarios::expect::eventually;
use ianua_scenarios::net::Call;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::audit::{AuditExport, ExportAsked};
use ianua_scenarios::world::World;

use crate::support::{invited, invitee, log_reader};

/// The record an invitation leaves.
const INVITED: &str = "identity.user_invited";

/// The columns a CSV export is written in.
const HEADER: &str =
    "id,event_type,actor,tenant,target_id,ip_address,occurred_at,acted_through,through_id";

/// Tess invites Uma and Wes. Vic may read the log but not export it, and
/// Max may do neither: both are refused an export. Tess asks for a CSV of
/// the invitations; the worker writes it, and Vic may not even see where
/// it stands. The file downloads once through its link: it holds the CSV
/// header and both invitations, as many rows as the export says. The
/// same link then gives nothing. The request and the download are on
/// record.
#[tokio::test]
async fn only_someone_who_may_export_gets_the_file_and_only_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = invited(&world, "uma").await;
    let wes = invited(&world, "wes").await;
    let vic = log_reader(&world).await;
    let asked = ExportAsked {
        format: "csv".to_owned(),
        event_type: Some(INVITED.to_owned()),
    };
    refuse_unprivileged_exports(&world, &vic, &asked).await;
    let ready = request_export(&world, &vic, &asked).await;
    let link = download_link(&ready);
    let file = Request::<Text>::text(Call::get(&link))
        .send_text(world.admin().client())
        .await
        .ok();
    let rows = csv_rows(&file, &ready);
    assert_invitations(&world, &[&uma, &wes], &rows).await;
    assert_link_spent(&world, &link).await;
    assert_export_records(&world).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Reading the log grants neither Vic nor Max permission to export it.
async fn refuse_unprivileged_exports(world: &World<'_>, vic: &Person, asked: &ExportAsked) {
    audit::tenant_log(world.tenant(), INVITED)
        .send(vic.client())
        .await
        .ok();
    for (client, who) in [
        (vic.client(), "Vic, who only reads"),
        (world.member().client(), "Max"),
    ] {
        let refused = audit::request_tenant_export(world.tenant(), asked)
            .send(client)
            .await;
        assert_eq!(
            refused.status(),
            Status::FORBIDDEN,
            "{who} may not export: {}",
            refused.summary()
        );
    }
}

/// Tess's export becomes ready while its status remains hidden from Vic.
async fn request_export(world: &World<'_>, vic: &Person, asked: &ExportAsked) -> AuditExport {
    let export = audit::request_tenant_export(world.tenant(), asked)
        .send(world.admin().client())
        .await
        .ok();
    audit::tenant_export(world.tenant(), &export.id)
        .send(vic.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    eventually("the worker to write the export", || async {
        let standing = audit::tenant_export(world.tenant(), &export.id)
            .send(world.admin().client())
            .await
            .ok();
        (standing.status == "ready").then_some(standing)
    })
    .await
}

/// The CSV starts with its columns and holds the advertised number of rows.
fn csv_rows<'a>(file: &'a str, ready: &AuditExport) -> Vec<&'a str> {
    let mut lines = file.lines();
    assert_eq!(
        lines.next(),
        Some(HEADER),
        "the file starts with its columns"
    );
    let rows: Vec<&str> = lines.filter(|line| !line.is_empty()).collect();
    assert_eq!(
        u64::try_from(rows.len()).ok(),
        ready.rows,
        "the file holds as many rows as the export says"
    );
    rows
}

/// Each invited person's audit record appears in the downloaded CSV.
async fn assert_invitations(world: &World<'_>, people: &[&Person], rows: &[&str]) {
    let invitations = audit::tenant_log(world.tenant(), INVITED)
        .send(world.admin().client())
        .await
        .ok();
    for person in people {
        let record = invitations
            .items
            .iter()
            .find(|entry| invitee(entry).as_deref() == Some(person.id()))
            .expect("the invitation is on record");
        assert!(
            rows.iter()
                .any(|row| row.starts_with(&format!("{},", record.id))),
            "the file holds {}'s invitation",
            person.email()
        );
    }
}

/// Downloading the same signed link again yields no successful response.
async fn assert_link_spent(world: &World<'_>, link: &str) {
    let again = Request::<Text>::text(Call::get(link))
        .send_text(world.admin().client())
        .await;
    assert!(
        !again.status().is_success(),
        "the link gives nothing a second time: {}",
        again.summary()
    );
}

/// Requesting and downloading the export both leave their audit records.
async fn assert_export_records(world: &World<'_>) {
    for event in [
        "tenant.audit_log_export_requested",
        "tenant.audit_log_export_downloaded",
    ] {
        let recorded = audit::tenant_log(world.tenant(), event)
            .send(world.admin().client())
            .await
            .ok();
        assert!(!recorded.items.is_empty(), "{event} is on record");
    }
}

/// The signed link a ready export hands out.
fn download_link(ready: &AuditExport) -> String {
    ready
        .download_url
        .clone()
        .expect("a ready export hands out a link")
}
