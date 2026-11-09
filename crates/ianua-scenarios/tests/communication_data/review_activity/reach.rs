//! How far a member reads the company's log: its own records and those of
//! the tenants they reach, on a page, in the calendar and in a file. Asked
//! for a tenant out of reach, the log reads as if it held nothing, and a
//! file holding more than its reader reaches is not there for them.

use ianua_scenarios::actors::Member;
use ianua_scenarios::api::{
    Request, TenantPath, Text, activity, audit, organizations, people, roles, tenants,
};
use ianua_scenarios::expect::eventually;
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::audit::{AuditEntry, AuditExport, ExportAsked};
use ianua_scenarios::wire::organization::{OrgRole, PlanChoice};
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::tenants::{NewTenant, TenantStatus};
use ianua_scenarios::world::{MEMBER_ROLE, World};

use crate::support::{invited, invitee};

/// The record a tenant invitation leaves.
const INVITED: &str = "identity.user_invited";

/// The record an invitation to the company leaves.
const MEMBER_INVITED: &str = "organization.org_user_invited";

/// The slug of the tenant Max is not let into.
const STAGING: &str = "staging";

/// The category an invitation is counted under.
const IDENTITY: &str = "Identity";

/// Tess invites Uma into the tenant, and Ann invites Vic to the company as
/// a viewer. Vic reads the company's own invitation and no tenant's, even
/// asking for that tenant by name. His calendar counts no identity change
/// while Ann's counts Uma's.
#[tokio::test]
async fn vic_the_viewer_reads_the_company_s_records_and_no_tenant_s() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = invited(&world, "uma").await;
    let vic = viewer(&world).await;
    let tenant = tenant_id(world.tenant(), world.owner().client()).await;
    let owner_s = log(&world, world.owner().client(), &[("event_type", INVITED)]).await;
    assert!(holds(&owner_s, uma.id()), "Ann reads Uma's invitation");

    assert!(
        !log(&world, vic.client(), &[("event_type", MEMBER_INVITED)])
            .await
            .is_empty(),
        "Vic reads the company's own records"
    );
    assert!(
        log(&world, vic.client(), &[("event_type", INVITED)])
            .await
            .is_empty(),
        "Vic reads no tenant's records"
    );
    assert!(
        log(&world, vic.client(), &[("tenant_id", &tenant)])
            .await
            .is_empty(),
        "naming the tenant reads as if it held nothing"
    );
    assert_calendars(&world, vic.client()).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Acme has a second tenant Max is not let into. Tess invites Uma into the
/// one he reaches and Ann invites Zed into the other. Ann reads both
/// invitations. Max reads Uma's and not Zed's, and asking for the other
/// tenant by name reads as if it held nothing.
#[tokio::test]
async fn max_reads_the_tenant_he_reaches_and_not_the_other() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let staging = staging_tenant(&world).await;
    let uma = invited(&world, "uma").await;
    let zed = invited_to_staging(&world, &staging).await;
    world.owner_mut().sign_in(&stack).await;
    let everything = log(&world, world.owner().client(), &[("event_type", INVITED)]).await;
    assert!(holds(&everything, uma.id()) && holds(&everything, &zed));
    let max = world.member().client();

    let read = log(&world, max, &[("event_type", INVITED)]).await;
    let named = log(&world, max, &[("tenant_id", &staging.id)]).await;

    assert!(holds(&read, uma.id()), "Max reads the tenant he reaches");
    assert!(!holds(&read, &zed), "Max reads nothing of the other");
    assert!(named.is_empty(), "the other reads as if it held nothing");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max's file of the company's invitations holds Uma's and not Zed's. Vic's
/// holds the company's own and none of a tenant's. The file Ann asked for
/// holds both: it is there for her, and Max and Vic are told there is no
/// such export, though each may export the log.
#[tokio::test]
async fn an_export_holds_only_what_its_asker_reaches_and_shows_no_wider_file() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let staging = staging_tenant(&world).await;
    let uma = invited(&world, "uma").await;
    let zed = invited_to_staging(&world, &staging).await;
    world.owner_mut().sign_in(&stack).await;
    let vic = viewer(&world).await;
    let max = world.member().client();
    let owner_s = log(&world, world.owner().client(), &[("event_type", INVITED)]).await;

    let (_, of_max) = written(&world, max, INVITED).await;
    let file = downloaded(&of_max, max).await;
    assert!(
        names(&file, &owner_s, uma.id()),
        "his file holds his tenant"
    );
    assert!(!names(&file, &owner_s, &zed), "and none of the other");

    let (_, of_vic) = written(&world, vic.client(), INVITED).await;
    assert_eq!(of_vic.rows, Some(0), "Vic's file holds no tenant's records");
    let (_, company) = written(&world, vic.client(), MEMBER_INVITED).await;
    assert!(
        company.rows.is_some_and(|rows| rows >= 1),
        "Vic's file holds the company's own records"
    );

    let (ann_s, of_ann) = written(&world, world.owner().client(), INVITED).await;
    assert!(of_ann.rows >= Some(2), "Ann's file holds both tenants'");
    for reader in [max, vic.client()] {
        audit::organization_export(world.org(), &ann_s)
            .send(reader)
            .await
            .refused(Status::NOT_FOUND, "not_found");
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// Vic, invited by Ann as a viewer and signed in.
async fn viewer(world: &World<'_>) -> Member {
    let mut vic = world.colleague("vic", "Vic Viewer", OrgRole::Viewer).await;
    vic.sign_in(world.stack()).await;
    vic
}

/// The second tenant of Acme, and Ann signed in to act in it: that
/// sign-in ends the session she held before, so she signs in again to
/// read the company's log.
struct Staging {
    /// Where its endpoints are.
    path: TenantPath,
    /// Its id, as the log's `tenant_id` filter takes it.
    id: String,
    /// Ann, landed in it.
    ann: Member,
}

/// Acme's second tenant, made by Ann on a plan with room for it and set up
/// once this returns.
async fn staging_tenant(world: &World<'_>) -> Staging {
    let ann = world.owner().client();
    let business = PlanChoice {
        plan: "Business".to_owned(),
    };
    organizations::choose_plan(world.org(), &business)
        .send(ann)
        .await
        .ok();
    let form = NewTenant {
        slug: STAGING.to_owned(),
        display_name: "Staging Team".to_owned(),
        contact_email: world.address("staging-contact"),
        timezone: "Europe/Berlin".to_owned(),
        locale: "en-US".to_owned(),
    };
    let id = tenants::create(world.org(), &form).send(ann).await.ok().id;
    let path = world.org().tenant(STAGING);
    eventually("the second tenant's setup to finish", || async {
        let read = tenants::get(&path).send(ann).await.ok();
        (read.status == TenantStatus::Active && read.setup.state == "over").then_some(())
    })
    .await;
    let client = Client::new(world.stack(), "Ann, in staging").expect("a client");
    let mut ann = Member::new(
        client,
        world.owner().account().clone(),
        world.owner().password(),
    );
    ann.land_in(STAGING);
    ann.sign_in(world.stack()).await;
    Staging { path, id, ann }
}

/// The id of Zed, whom Ann invites into `staging`.
async fn invited_to_staging(world: &World<'_>, staging: &Staging) -> String {
    let ann = staging.ann.client();
    let listed = roles::list(&staging.path).send(ann).await.ok();
    let member = listed
        .items
        .into_iter()
        .find(|role| role.name == MEMBER_ROLE)
        .expect("every tenant has its Member role");
    let invitation = InviteUser {
        email: world.address("zed"),
        display_name: "Zed Staging".to_owned(),
        role_id: member.id,
    };
    people::invite(&staging.path, &invitation)
        .send(ann)
        .await
        .ok()
        .id
}

/// The id of `tenant`, as `reader` reads it.
async fn tenant_id(tenant: &TenantPath, reader: &Client) -> String {
    tenants::get(tenant).send(reader).await.ok().id
}

/// The company's log as `reader` reads it through `filters`, at its
/// longest page.
async fn log(world: &World<'_>, reader: &Client, filters: &[(&str, &str)]) -> Vec<AuditEntry> {
    let mut asked = filters.to_vec();
    asked.push(("limit", "100"));
    audit::organization_log_where(world.org(), &asked)
        .send(reader)
        .await
        .ok()
        .items
}

/// Whether `read` holds the invitation of the person `id`.
fn holds(read: &[AuditEntry], id: &str) -> bool {
    read.iter()
        .any(|entry| invitee(entry).as_deref() == Some(id))
}

/// Ann's calendar counts Uma's invitation today; `vic`'s counts no
/// identity change at all.
async fn assert_calendars(world: &World<'_>, vic: &Client) {
    let ann = world.owner().client();
    let counted = eventually("Ann's calendar to count the invitation", || async {
        let calendar = activity::organization(world.org(), &[])
            .send(ann)
            .await
            .ok();
        (calendar.count_on(&calendar.to, IDENTITY) >= 1).then_some(calendar)
    })
    .await;
    let vics = activity::organization(world.org(), &[])
        .send(vic)
        .await
        .ok();
    assert_eq!(
        vics.count_on(&counted.to, IDENTITY),
        0,
        "Vic's calendar counts no tenant's identity change"
    );
}

/// An export of the records of `event_type` `who` asked for, once the
/// worker wrote it, with its id.
async fn written(world: &World<'_>, who: &Client, event_type: &str) -> (String, AuditExport) {
    let asked = ExportAsked {
        format: "csv".to_owned(),
        event_type: Some(event_type.to_owned()),
    };
    let id = audit::request_organization_export(world.org(), &asked)
        .send(who)
        .await
        .ok()
        .id;
    let ready = eventually("the worker to write the export", || async {
        let standing = audit::organization_export(world.org(), &id)
            .send(who)
            .await
            .ok();
        (standing.status == "ready").then_some(standing)
    })
    .await;
    (id, ready)
}

/// The file `ready`'s link gives `who`.
async fn downloaded(ready: &AuditExport, who: &Client) -> String {
    let link = ready
        .download_url
        .clone()
        .expect("a ready export hands out a link");
    Request::<Text>::text(Call::get(&link))
        .send_text(who)
        .await
        .ok()
}

/// Whether the CSV `file` holds the invitation of the person `id`, whose
/// record is among `records`.
fn names(file: &str, records: &[AuditEntry], id: &str) -> bool {
    let record = records
        .iter()
        .find(|entry| invitee(entry).as_deref() == Some(id))
        .expect("the invitation is on record");
    file.lines()
        .any(|row| row.starts_with(&format!("{},", record.id)))
}
