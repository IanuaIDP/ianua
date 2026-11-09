//! The log of a whole company: one read across its tenants and its own
//! records, narrowed to a tenant or to who did it, holding nothing of any
//! other company, and exported only by someone who may.

use ianua_scenarios::api::{Request, TenantPath, Text, audit, people, roles, tenants};
use ianua_scenarios::expect::{Matrix, eventually};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::audit::{AuditEntry, AuditExport, ExportAsked};
use ianua_scenarios::wire::organization::OrgRole;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::world::{MEMBER_ROLE, World};

use crate::support::{invited, invitee};

/// The record a tenant invitation leaves.
const INVITED: &str = "identity.user_invited";

/// The record an invitation to the company leaves.
const MEMBER_INVITED: &str = "organization.org_user_invited";

/// The columns a CSV export is written in.
const HEADER: &str =
    "id,event_type,actor,tenant,target_id,ip_address,occurred_at,acted_through,through_id";

/// Tess invites Uma into Acme's tenant, Ann invites Bea to the company and
/// Sam invites someone into Globex. Ann's log holds Uma's invitation, under
/// the tenant it happened in, and Bea's, and nothing of Sam's. Narrowed to
/// the tenant it holds no company record; narrowed to Tess it holds Uma's
/// invitation, narrowed to Ann it does not; narrowed to Globex's tenant it
/// holds nothing of Globex's.
#[tokio::test]
async fn ann_reads_one_log_for_her_company_narrowed_by_tenant_and_by_who_did_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = invited(&world, "uma").await;
    world
        .colleague("bea", "Bea Billing", OrgRole::Billing)
        .await;
    let theirs = invited_at_globex(&world).await;
    let tenant = tenant_id(world.tenant(), world.owner().client()).await;

    let read = log(&world, &[("event_type", INVITED)]).await;
    let uma_s = read
        .iter()
        .find(|entry| invitee(entry).as_deref() == Some(uma.id()))
        .expect("Uma's invitation is in the company's log");
    assert_eq!(
        uma_s.tenant_id.as_deref(),
        Some(tenant.as_str()),
        "the record names the tenant it happened in"
    );
    assert_nothing_of(&read, &theirs);
    assert_company_records(&world, &tenant).await;
    assert_who_did_it(&world, uma.id()).await;
    let twin = tenant_id(world.twin(), world.stranger().client()).await;
    let globex = log(&world, &[("event_type", INVITED), ("tenant_id", &twin)]).await;
    assert_nothing_of(&globex, &theirs);

    stack.stop().await.expect("the stack stops cleanly");
}

/// Bea, who runs the bill, Sam from the other company and nobody signed in
/// read no log of Acme's. Ann does.
#[tokio::test]
async fn nobody_without_the_right_reads_the_company_s_log() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut bea = world
        .colleague("bea", "Bea Billing", OrgRole::Billing)
        .await;
    bea.sign_in(&stack).await;

    Matrix::new(
        "reading the company's log",
        audit::organization_log_where(world.org(), &[("limit", "1")]).call(),
    )
    .allowed(world.owner().client())
    .refused(bea.client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess invites Uma. Ann asks for a CSV of the company's invitations while
/// Bea and Sam are refused one, and neither may see where hers stands. The
/// worker writes it: the file starts with its columns, holds as many rows
/// as the export says, Uma's invitation among them, and downloads once.
/// Asking and downloading are on the company's record.
#[tokio::test]
async fn only_someone_who_may_export_gets_the_company_s_file_and_only_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = invited(&world, "uma").await;
    let mut bea = world
        .colleague("bea", "Bea Billing", OrgRole::Billing)
        .await;
    bea.sign_in(&stack).await;
    let asked = ExportAsked {
        format: "csv".to_owned(),
        event_type: Some(INVITED.to_owned()),
    };
    let seen = world.trail().ids().await;

    for who in [bea.client(), world.stranger().client()] {
        audit::request_organization_export(world.org(), &asked)
            .send(who)
            .await
            .refused(Status::FORBIDDEN, "forbidden");
    }
    let export = audit::request_organization_export(world.org(), &asked)
        .send(world.owner().client())
        .await
        .ok();
    for who in [bea.client(), world.stranger().client()] {
        audit::organization_export(world.org(), &export.id)
            .send(who)
            .await
            .refused(Status::FORBIDDEN, "forbidden");
    }
    let ready = written(&world, &export.id).await;

    let link = ready
        .download_url
        .clone()
        .expect("a ready export hands out a link");
    let file = Request::<Text>::text(Call::get(&link))
        .send_text(world.owner().client())
        .await
        .ok();
    assert_file(&world, &file, &ready, uma.id()).await;
    let again = Request::<Text>::text(Call::get(&link))
        .send_text(world.owner().client())
        .await;
    assert!(
        !again.status().is_success(),
        "the link gives nothing a second time: {}",
        again.summary()
    );
    world
        .trail()
        .recorded_after(&seen, "organization.audit_log_export_requested")
        .await;
    world
        .trail()
        .recorded_after(&seen, "organization.audit_log_export_downloaded")
        .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The id of the person Sam invites into Globex's tenant.
async fn invited_at_globex(world: &World<'_>) -> String {
    let sam = world.stranger().client();
    let listed = roles::list(world.twin()).send(sam).await.ok();
    let member = listed
        .items
        .into_iter()
        .find(|role| role.name == MEMBER_ROLE)
        .expect("every tenant has its Member role");
    let invitation = InviteUser {
        email: world.address("globex-newcomer"),
        display_name: "Globex Newcomer".to_owned(),
        role_id: member.id,
    };
    people::invite(world.twin(), &invitation)
        .send(sam)
        .await
        .ok()
        .id
}

/// The id of `tenant`, as `reader` reads it.
async fn tenant_id(tenant: &TenantPath, reader: &Client) -> String {
    tenants::get(tenant).send(reader).await.ok().id
}

/// The company's log as Ann reads it through `filters`, at its longest
/// page.
async fn log(world: &World<'_>, filters: &[(&str, &str)]) -> Vec<AuditEntry> {
    let mut asked = filters.to_vec();
    asked.push(("limit", "100"));
    audit::organization_log_where(world.org(), &asked)
        .send(world.owner().client())
        .await
        .ok()
        .items
}

/// None of `read` is the invitation of `theirs`.
fn assert_nothing_of(read: &[AuditEntry], theirs: &str) {
    assert!(
        read.iter()
            .all(|entry| invitee(entry).as_deref() != Some(theirs)),
        "nothing of Globex's is in Acme's log"
    );
}

/// The company's own invitation is in its log, and gone once the log is
/// narrowed to the tenant.
async fn assert_company_records(world: &World<'_>, tenant: &str) {
    let company = log(world, &[("event_type", MEMBER_INVITED)]).await;
    assert!(!company.is_empty(), "Ann's invitation of Bea is in the log");
    let narrowed = log(
        world,
        &[("event_type", MEMBER_INVITED), ("tenant_id", tenant)],
    )
    .await;
    assert!(
        narrowed.is_empty(),
        "the tenant's log holds no company record"
    );
}

/// Narrowed to Tess the log holds Uma's invitation, narrowed to Ann it
/// does not.
async fn assert_who_did_it(world: &World<'_>, uma: &str) {
    let tess = format!("org_user:{}", world.admin().id());
    let by_tess = log(world, &[("event_type", INVITED), ("actor", &tess)]).await;
    assert!(
        by_tess
            .iter()
            .any(|entry| invitee(entry).as_deref() == Some(uma)),
        "Tess invited Uma"
    );
    let ann = format!("org_user:{}", world.owner().id());
    let by_ann = log(world, &[("event_type", INVITED), ("actor", &ann)]).await;
    assert!(
        by_ann
            .iter()
            .all(|entry| invitee(entry).as_deref() != Some(uma)),
        "Ann did not invite Uma"
    );
}

/// The export once the worker has written it, as Ann reads it.
async fn written(world: &World<'_>, export_id: &str) -> AuditExport {
    eventually("the worker to write the company's export", || async {
        let standing = audit::organization_export(world.org(), export_id)
            .send(world.owner().client())
            .await
            .ok();
        (standing.status == "ready").then_some(standing)
    })
    .await
}

/// `file` starts with its columns, holds as many rows as `ready` says, and
/// Uma's invitation record among them.
async fn assert_file(world: &World<'_>, file: &str, ready: &AuditExport, uma: &str) {
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
    let invitations = log(world, &[("event_type", INVITED)]).await;
    let record = invitations
        .iter()
        .find(|entry| invitee(entry).as_deref() == Some(uma))
        .expect("Uma's invitation is on record");
    assert!(
        rows.iter()
            .any(|row| row.starts_with(&format!("{},", record.id))),
        "the file holds Uma's invitation"
    );
}
