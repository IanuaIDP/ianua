//! Pat fills her language and time zone from the lists the platform
//! offers, which anyone may read before signing in; a time zone not on
//! the list is refused and her choice stays. Max does the same on his
//! organization's plane.

use ianua_scenarios::api::{account, reference};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::account::Preferences;
use ianua_scenarios::world::World;

use crate::support::invited_and_signed_in;

/// The language Pat picks, when the list offers it.
const JAPANESE: &str = "ja-JP";

/// The time zone Pat picks, when the list offers it.
const TOKYO: &str = "Asia/Tokyo";

/// A place no time zone is named after.
const NOWHERE: &str = "Mars/Olympus_Mons";

/// Nobody signed in reads the languages and time zones on offer: Japanese
/// and Tokyo among them, nowhere on Mars. Pat picks both, and her account
/// reads them. She then names the time zone on Mars and is refused, and
/// her choice stays. Max picks the same on his own plane.
#[tokio::test]
async fn pat_and_max_pick_a_language_and_time_zone_from_the_lists_on_offer() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;

    let anyone = world.anonymous().client();
    let locales = reference::locales().send(anyone).await.ok();
    let zones = reference::timezones().send(anyone).await.ok();
    assert!(
        locales.iter().any(|tag| tag == JAPANESE),
        "Japanese is offered"
    );
    assert!(zones.iter().any(|zone| zone == TOKYO), "Tokyo is offered");
    assert!(zones.iter().all(|zone| zone != NOWHERE));

    let picked = Preferences {
        locale: Some(JAPANESE.to_owned()),
        timezone: Some(TOKYO.to_owned()),
        ..Preferences::default()
    };
    let tenant = account::Plane::Tenant(world.tenant());
    account::preferences(tenant, &picked)
        .send(pat.client())
        .await
        .ok();
    let unlisted = Preferences {
        timezone: Some(NOWHERE.to_owned()),
        ..Preferences::default()
    };
    account::preferences(tenant, &unlisted)
        .send(pat.client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let own = account::me(tenant).send(pat.client()).await.ok();
    assert_eq!(own.locale.as_deref(), Some(JAPANESE));
    assert_eq!(
        own.timezone.as_deref(),
        Some(TOKYO),
        "the refused zone changed nothing"
    );

    let member = account::Plane::Member(world.org());
    account::preferences(member, &picked)
        .send(world.member().client())
        .await
        .ok();
    let max = account::me(member).send(world.member().client()).await.ok();
    assert_eq!(max.timezone.as_deref(), Some(TOKYO));

    stack.stop().await.expect("the stack stops cleanly");
}
