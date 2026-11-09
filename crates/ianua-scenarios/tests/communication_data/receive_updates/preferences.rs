//! How notices reach a person, chosen per category. Pat turns off
//! notices about roles, on record, yet is still told when Tess gives her
//! one: what changes her own account always reaches her. Ann turns the
//! same category off for her company inbox and hears nothing more of it.
//! Nobody else changes either choice.

use ianua_scenarios::api::notifications;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::notifications::{Preference, PreferencesChange};
use ianua_scenarios::world::World;

use crate::support::{
    AUTHORIZATION, fresh_tenant_notice, give_role, member_ids, person, reader_role, tenant_ids,
};

/// The record a tenant user's changed choice leaves.
const CHOSEN: &str = "notifications.preferences_updated";

/// The record a member's changed choice leaves.
const MEMBER_CHOSEN: &str = "notifications.member_preferences_updated";

/// Notices about roles and groups switched off.
fn roles_off() -> PreferencesChange {
    PreferencesChange {
        preferences: vec![Preference {
            category: AUTHORIZATION.to_owned(),
            channel: "Disabled".to_owned(),
        }],
    }
}

/// The channel `preferences` names for `category`, if any.
fn channel_of<'p>(preferences: &'p [Preference], category: &str) -> Option<&'p str> {
    preferences
        .iter()
        .find(|preference| preference.category == category)
        .map(|preference| preference.channel.as_str())
}

/// Pat reads her choices: notices about roles reach her in the app, as
/// nobody chose otherwise. She switches them off; the answer and a fresh
/// read both say so, and the change is on record. Tess then gives her a
/// role, and Pat is told anyway, because a change to what her own account
/// may do reaches her whatever she chose.
#[tokio::test]
async fn pat_switches_off_notices_about_roles_but_still_hears_of_her_own() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let role = reader_role(&world).await;
    let trail_before = world.trail().ids().await;

    let chosen = notifications::preferences(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert_eq!(
        channel_of(&chosen, AUTHORIZATION),
        Some("InApp"),
        "notices about roles reach Pat in the app until she chooses"
    );
    let changed = notifications::change_preferences(world.tenant(), &roles_off())
        .send(pat.client())
        .await
        .ok();
    assert_eq!(channel_of(&changed, AUTHORIZATION), Some("Disabled"));
    let chosen = notifications::preferences(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert_eq!(
        channel_of(&chosen, AUTHORIZATION),
        Some("Disabled"),
        "Pat's choice is kept"
    );
    world.trail().recorded_after(&trail_before, CHOSEN).await;

    let seen = tenant_ids(world.tenant(), pat.client()).await;
    give_role(&world, &pat, &role).await;
    fresh_tenant_notice(world.tenant(), pat.client(), &seen, AUTHORIZATION).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann switches off notices about roles for her company inbox; the change
/// is on record. Tess gives Pat a role: Pat is told in her tenant, so the
/// notices went out, but Ann's inbox holds nothing new about it.
#[tokio::test]
async fn ann_switches_off_notices_about_roles_and_hears_no_more_of_them() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let role = reader_role(&world).await;
    let ann = world.owner().client();
    let trail_before = world.trail().ids().await;

    let changed = notifications::change_member_preferences(world.org(), &roles_off())
        .send(ann)
        .await
        .ok();
    assert_eq!(channel_of(&changed, AUTHORIZATION), Some("Disabled"));
    let chosen = notifications::member_preferences(world.org())
        .send(ann)
        .await
        .ok();
    assert_eq!(
        channel_of(&chosen, AUTHORIZATION),
        Some("Disabled"),
        "Ann's choice is kept"
    );
    world
        .trail()
        .recorded_after(&trail_before, MEMBER_CHOSEN)
        .await;

    let ann_seen = member_ids(world.org(), ann).await;
    let pat_seen = tenant_ids(world.tenant(), pat.client()).await;
    give_role(&world, &pat, &role).await;
    fresh_tenant_notice(world.tenant(), pat.client(), &pat_seen, AUTHORIZATION).await;
    let inbox = notifications::member_inbox(world.org())
        .send(ann)
        .await
        .ok();
    assert!(
        inbox
            .items
            .iter()
            .filter(|notice| !ann_seen.contains(&notice.id))
            .all(|notice| notice.category != AUTHORIZATION),
        "Ann hears nothing more about roles"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Sam, from the other company, and nobody signed in cannot read or
/// change Pat's choices or Ann's; neither choice changes and nothing is
/// recorded.
#[tokio::test]
async fn nobody_else_changes_how_pat_or_ann_are_told() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let trail_before = world.trail().ids().await;

    for call in [
        notifications::change_preferences(world.tenant(), &roles_off()).call(),
        notifications::change_member_preferences(world.org(), &roles_off()).call(),
    ] {
        Matrix::new("changing how someone else is told", call)
            .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
            .refused(
                world.anonymous().client(),
                Status::UNAUTHORIZED,
                "unauthenticated",
            )
            .run()
            .await;
    }

    let chosen = notifications::preferences(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert_eq!(channel_of(&chosen, AUTHORIZATION), Some("InApp"));
    let chosen = notifications::member_preferences(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_ne!(channel_of(&chosen, AUTHORIZATION), Some("Disabled"));
    world.trail().nothing_after(&trail_before, CHOSEN).await;
    world
        .trail()
        .nothing_after(&trail_before, MEMBER_CHOSEN)
        .await;

    stack.stop().await.expect("the stack stops cleanly");
}
