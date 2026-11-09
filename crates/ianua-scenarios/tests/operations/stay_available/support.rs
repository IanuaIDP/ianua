//! What the recovery scenarios share: Ann's second tenant, `staging`, the
//! room on her plan for it, waiting for its setup, Ann signed in to it,
//! and reading what its setup made and recorded, so a scenario can say
//! the setup was done once whatever stopped it on the way.

use std::time::{Duration, Instant};

use ianua_scenarios::actors::Member;
use ianua_scenarios::api::{TenantPath, audit, crypto, organizations, roles, tenants};
use ianua_scenarios::expect::{Waiting, eventually_paced};
use ianua_scenarios::net::Client;
use ianua_scenarios::wire::organization::PlanChoice;
use ianua_scenarios::wire::tenants::{NewTenant, TenantStatus};
use ianua_scenarios::world::{ADMIN_ROLE, MEMBER_ROLE, World};

/// The slug of Ann's second tenant.
pub(crate) const STAGING: &str = "staging";

/// The record each role a setup seeds leaves.
const ROLE_CREATED: &str = "authorization.role_created";

/// The record the setup's first signing key leaves.
const KEY_CREATED: &str = "crypto.key_created";

/// The record the setup's last step leaves, putting the tenant in use.
const STATUS_CHANGED: &str = "tenant.status_changed";

/// The record a new tenant leaves in its organization.
pub(crate) const TENANT_CREATED: &str = "organization.tenant_created";

/// How Ann waits for a setup: once a second, as a dashboard asks, for at
/// most two minutes, longer than a setup recovered by the worker's sweeps
/// takes.
const AS_A_DASHBOARD_ASKS: Waiting = Waiting {
    patience: Duration::from_secs(120),
    every: Duration::from_secs(1),
};

/// The form for `staging` on the platform's own infrastructure, with a
/// contact address of this world.
fn staging_form(world: &World<'_>) -> NewTenant {
    NewTenant {
        slug: STAGING.to_owned(),
        display_name: "Staging Team".to_owned(),
        contact_email: world.address("tenant-contact"),
        timezone: "Europe/Berlin".to_owned(),
        locale: "en-US".to_owned(),
    }
}

/// Ann moves her organization to the Business plan, which admits more
/// than the one tenant the Free plan does.
pub(crate) async fn room_for_another_tenant(world: &World<'_>) {
    let business = PlanChoice {
        plan: "Business".to_owned(),
    };
    organizations::choose_plan(world.org(), &business)
        .send(world.owner().client())
        .await
        .ok();
}

/// Ann makes `staging`; its id.
pub(crate) async fn staging_made(world: &World<'_>) -> String {
    tenants::create(world.org(), &staging_form(world))
        .send(world.owner().client())
        .await
        .ok()
        .id
}

/// The tenant `id` read as `staging` by Ann, as provisioning or active,
/// failing at once when a setup step failed.
async fn setup_over(world: &World<'_>, id: &str) -> bool {
    let read = tenants::get(&world.org().tenant(STAGING))
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(read.id, id, "the tenant read is the one Ann made");
    assert!(
        read.setup.failed_step.is_none(),
        "no setup step failed: {:?}",
        read.setup
    );
    read.status == TenantStatus::Active && read.setup.state == "over"
}

/// Waits until the setup of `staging`, made as `id`, is over and it is
/// in use.
pub(crate) async fn once_set_up(world: &World<'_>, id: &str) {
    eventually_paced("staging's completed setup", AS_A_DASHBOARD_ASKS, || async {
        setup_over(world, id).await.then_some(())
    })
    .await;
}

/// Asserts `staging`, made as `id`, is still being set up.
pub(crate) async fn still_provisioning(world: &World<'_>, id: &str, why: &str) {
    assert!(!setup_over(world, id).await, "{why}");
}

/// Ann signed in again on a new client, landing in `staging`.
pub(crate) async fn ann_in_staging(world: &World<'_>) -> Member {
    let client = Client::new(world.stack(), "Ann, in staging").expect("a client");
    let mut ann = Member::new(
        client,
        world.owner().account().clone(),
        world.owner().password(),
    );
    ann.land_in(STAGING);
    ann.sign_in(world.stack()).await;
    ann
}

/// Asserts `staging` holds exactly what one setup makes: the `Admin` and
/// `Member` roles once each and one signing key in use, as Ann reads them.
pub(crate) async fn assert_made_once(staging: &TenantPath, ann: &Member) {
    let seeded = roles::list(staging).send(ann.client()).await.ok();
    for name in [ADMIN_ROLE, MEMBER_ROLE] {
        assert_eq!(
            seeded.items.iter().filter(|role| role.name == name).count(),
            1,
            "the setup seeded the {name} role once"
        );
    }
    let keys = crypto::keys(staging).send(ann.client()).await.ok();
    assert_eq!(
        keys.keys
            .iter()
            .filter(|key| key.status == "Active")
            .count(),
        1,
        "the setup made one signing key in use: {:?}",
        keys.keys
    );
}

/// How many records of exactly `event_type` the organization's trail
/// holds for the tenant `tenant_id`, as `reader` reads it.
pub(crate) async fn recorded_for(
    world: &World<'_>,
    reader: &Client,
    tenant_id: &str,
    event_type: &str,
) -> usize {
    audit::organization_log(world.org(), event_type)
        .send(reader)
        .await
        .ok()
        .items
        .iter()
        .filter(|entry| entry.event_type == event_type)
        .filter(|entry| entry.tenant_id.as_deref() == Some(tenant_id))
        .count()
}

/// Asserts the trail holds exactly the records one setup of `staging`,
/// made as `tenant_id`, leaves: two seeded roles, one signing key and one
/// move into use, none written twice by a recovery.
pub(crate) async fn assert_recorded_once(world: &World<'_>, reader: &Client, tenant_id: &str) {
    for (event_type, once) in [(ROLE_CREATED, 2), (KEY_CREATED, 1), (STATUS_CHANGED, 1)] {
        assert_eq!(
            recorded_for(world, reader, tenant_id, event_type).await,
            once,
            "staging's setup recorded {event_type} as often as one setup does"
        );
    }
}

/// Waits out `duration` on the real clock while the worker relays, polls
/// and sweeps, for work that must not come, or must have had its chance.
pub(crate) async fn watched_for(duration: Duration) {
    let since = Instant::now();
    eventually_paced(
        "the watch on the real clock",
        Waiting {
            patience: duration * 2,
            every: Duration::from_millis(250),
        },
        || async { (since.elapsed() > duration).then_some(()) },
    )
    .await;
}
