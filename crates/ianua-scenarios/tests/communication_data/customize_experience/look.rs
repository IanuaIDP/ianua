//! Tess gives the tenant its colour and the name its mail is sent under,
//! and reads them back; an empty change saves nothing. A colour that is
//! not one is refused. Uma, Max, Sam and nobody signed in change nothing,
//! and nothing is recorded for them.

use ianua_scenarios::api::branding;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::branding::BrandingChange;
use ianua_scenarios::world::World;

use crate::support::person;

/// The record a saved branding leaves.
const BRANDING_UPDATED: &str = "branding.updated";

/// The colour Tess picks.
const ACME_BLUE: &str = "#0A84FF";

/// The name Tess sends the tenant's mail under.
const SENDER: &str = "Acme Accounts";

/// Acme's colour and sender name.
fn acme_look() -> BrandingChange {
    BrandingChange {
        primary_color: Some(ACME_BLUE.to_owned()),
        email_from_name: Some(SENDER.to_owned()),
    }
}

/// The tenant starts on the platform's look. Tess saves Acme's colour and
/// sender name in one change, recorded once, and reads both back. An
/// empty change saves and records nothing.
#[tokio::test]
async fn tess_gives_the_tenant_its_colour_and_sender_name() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();

    let before = branding::get(world.tenant()).send(tess).await.ok();
    assert_eq!(before.primary_color, None, "the platform's colour at first");
    let seen = world.trail().ids().await;
    let saves_before = world.trail().count(BRANDING_UPDATED).await;
    branding::change(world.tenant(), &acme_look())
        .send(tess)
        .await
        .ok();
    let after = branding::get(world.tenant()).send(tess).await.ok();
    assert_eq!(after.primary_color.as_deref(), Some(ACME_BLUE));
    assert_eq!(after.email_from_name.as_deref(), Some(SENDER));
    world.trail().recorded_after(&seen, BRANDING_UPDATED).await;
    assert_eq!(
        world.trail().count(BRANDING_UPDATED).await,
        saves_before + 1,
        "one save is one record, however many parts it changed"
    );

    branding::change(world.tenant(), &BrandingChange::default())
        .send(tess)
        .await
        .ok();
    assert_eq!(
        world.trail().count(BRANDING_UPDATED).await,
        saves_before + 1,
        "an empty change records nothing"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess types a colour that is not one and is refused; the tenant keeps
/// the platform's colour and nothing is recorded.
#[tokio::test]
async fn a_colour_that_is_not_one_is_refused() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let seen = world.trail().ids().await;
    let not_a_colour = BrandingChange {
        primary_color: Some("blue-ish".to_owned()),
        email_from_name: None,
    };

    branding::change(world.tenant(), &not_a_colour)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let look = branding::get(world.tenant()).send(tess).await.ok();
    assert_eq!(look.primary_color, None);
    world.trail().nothing_after(&seen, BRANDING_UPDATED).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma, an ordinary user of the tenant, Max, a member with no
/// administrator's rights, Sam from the other company and nobody signed
/// in may not change the tenant's look. It stays the platform's and
/// nothing is recorded.
#[tokio::test]
async fn nobody_without_the_right_changes_the_tenant_s_look() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = person(&world, "uma").await;
    let seen = world.trail().ids().await;

    Matrix::new(
        "changing the tenant's look",
        branding::change(world.tenant(), &acme_look()).call(),
    )
    .refused(uma.client(), Status::FORBIDDEN, "forbidden")
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;

    let look = branding::get(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(look.primary_color, None);
    world.trail().nothing_after(&seen, BRANDING_UPDATED).await;

    stack.stop().await.expect("the stack stops cleanly");
}
