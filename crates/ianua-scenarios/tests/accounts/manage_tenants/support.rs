//! What the tenant scenarios share: the form for a second tenant, room on
//! the plan for it, waiting for its setup, Pat signed in to the first
//! tenant, Ann signing in again, and the moves a tenant makes through its
//! life.

use std::time::Duration;

use ianua_scenarios::actors::{Member, Person};
use ianua_scenarios::api::{Request, TenantPath, organizations, people, tenants};
use ianua_scenarios::expect::eventually_within;
use ianua_scenarios::net::Client;
use ianua_scenarios::wire::organization::PlanChoice;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::tenants::{NewTenant, TenantStatus};
use ianua_scenarios::world::{MEMBER_ROLE, World};

/// How long a new tenant's setup may take on a busy four-core machine.
const SETUP_PATIENCE: Duration = Duration::from_secs(60);

/// The form for a tenant called `slug` on the platform's own
/// infrastructure, with a contact address of this world.
pub(crate) fn new_tenant(world: &World<'_>, slug: &str) -> NewTenant {
    NewTenant {
        slug: slug.to_owned(),
        display_name: format!("{slug} Team"),
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

/// Waits until the setup of `tenant`, made as `id`, is over and it is
/// active. Fails at once when a setup step failed.
pub(crate) async fn once_set_up(world: &World<'_>, tenant: &TenantPath, id: &str) {
    eventually_within(
        "the new tenant's completed setup",
        SETUP_PATIENCE,
        || async {
            let read = tenants::get(tenant).send(world.owner().client()).await.ok();
            assert_eq!(read.id, id, "the tenant read is the one made");
            assert!(
                read.setup.failed_step.is_none(),
                "no setup step failed: {:?}",
                read.setup
            );
            (read.status == TenantStatus::Active && read.setup.state == "over").then_some(())
        },
    )
    .await;
}

/// Pat, invited by Tess into the first tenant, who accepted from the
/// mailed link and signed in, with a live session that reads her own
/// record.
pub(crate) async fn pat_in_the_tenant(world: &World<'_>) -> Person {
    let mut pat = world.newcomer("pat", "Pat Holder");
    let invitation = people::invite(
        world.tenant(),
        &InviteUser {
            email: pat.email().to_owned(),
            display_name: pat.account().display_name.clone(),
            role_id: world.role_id(MEMBER_ROLE).await,
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    pat.record_invitation(&invitation.id);
    pat.accept_invitation(world.stack()).await;
    pat.sign_in(world.stack()).await;
    people::me(world.tenant()).send(pat.client()).await.ok();
    pat
}

/// Ann signed in again on a new client, landing in the tenant `slug`.
pub(crate) async fn ann_landing_in(world: &World<'_>, slug: &str) -> Member {
    let client = Client::new(world.stack(), &format!("Ann, in {slug}")).expect("a client");
    let mut ann = Member::new(
        client,
        world.owner().account().clone(),
        world.owner().password(),
    );
    ann.land_in(slug);
    ann.sign_in(world.stack()).await;
    ann
}

/// Ann signed in again on a new client, landing in no tenant: her first
/// session is long over once the clock moved past the archive grace, and
/// the tenant she used to land in is put away.
pub(crate) async fn ann_signed_in_again(world: &World<'_>) -> Member {
    let mut account = world.owner().account().clone();
    account.landing = None;
    let client = Client::new(world.stack(), "Ann, after the archive grace").expect("a client");
    let mut ann = Member::new(client, account, world.owner().password());
    ann.sign_in(world.stack()).await;
    ann
}

/// A move a tenant makes through its life.
#[derive(Clone, Copy)]
pub(crate) enum Move {
    /// Stopped for now.
    Suspend,
    /// Back in use after a suspension.
    Reactivate,
    /// Put away, restorable while its grace runs.
    Archive,
    /// Back in use from the archive.
    Restore,
    /// Gone, once its grace has passed.
    Delete,
}

impl Move {
    /// The move in words, for a matrix's name.
    pub(crate) fn what(self) -> &'static str {
        match self {
            Self::Suspend => "suspending the tenant",
            Self::Reactivate => "reactivating the tenant",
            Self::Archive => "archiving the tenant",
            Self::Restore => "restoring the tenant",
            Self::Delete => "deleting the tenant",
        }
    }
}

/// The request that makes `change` on `tenant`.
pub(crate) fn moved(tenant: &TenantPath, change: Move) -> Request<()> {
    match change {
        Move::Suspend => tenants::suspend(tenant),
        Move::Reactivate => tenants::reactivate(tenant),
        Move::Archive => tenants::archive(tenant),
        Move::Restore => tenants::restore(tenant),
        Move::Delete => tenants::delete(tenant),
    }
}
