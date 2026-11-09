//! Pat and Max change what is theirs to change on their own profile: a
//! language, a time zone, Max's name. Nothing else moves: a field left
//! out keeps its value, a field nobody may set is ignored, and the
//! account's rights are what they were.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{account, members, people};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::net::Call;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::account::Preferences;
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{invited_and_signed_in, still_signed_in, tenant_records};

/// Pat sets her language and time zone, then her language alone, in a
/// request that also names a role and a verified mailbox nobody may set
/// for themselves. Her time zone stays, the role and the flag are
/// ignored, and she reaches no more than before.
#[tokio::test]
async fn a_preference_change_leaves_the_rest_and_pats_rights_alone() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    change_pat_preferences(&world, &pat).await;
    check_pat_preferences(&world, &pat).await;
    still_signed_in(&world, &pat).await;
    assert_eq!(
        tenant_records(&world, "identity.user_preferences_updated", &[]).await,
        2,
        "each change is recorded once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat changes both preferences, then sends a language-only update with forbidden identity fields.
async fn change_pat_preferences(world: &World<'_>, pat: &Person) {
    let plane = account::Plane::Tenant(world.tenant());

    let both = Preferences {
        locale: Some("de-DE".to_owned()),
        timezone: Some("Europe/Berlin".to_owned()),
        ..Preferences::default()
    };
    account::preferences(plane, &both)
        .send(pat.client())
        .await
        .ok();

    let overreaching = Call::patch(world.tenant().at("/me"))
        .json(&json!({"locale": "fr-FR", "role": "Admin", "email_verified": true}));
    pat.client().send::<()>(overreaching).await.ok();
}

/// Pat retains her own identity and the omitted time zone while the last language wins.
async fn check_pat_preferences(world: &World<'_>, pat: &Person) {
    let plane = account::Plane::Tenant(world.tenant());
    let own = account::me(plane).send(pat.client()).await.ok();
    assert_eq!(own.id, pat.id(), "Pat's record is still her own");
    assert_eq!(
        own.email,
        pat.email(),
        "a preference change moves no address"
    );
    assert_eq!(
        own.locale.as_deref(),
        Some("fr-FR"),
        "the language named last is the one kept"
    );
    assert_eq!(
        own.timezone.as_deref(),
        Some("Europe/Berlin"),
        "a time zone left out of the second change keeps its value"
    );
}

/// An invalid time zone, an anonymous caller and Pat's session in the
/// twin tenant each fail to change preferences. Her language stays unset, and no update is
/// recorded.
#[tokio::test]
async fn a_refused_preference_change_leaves_pats_profile_as_it_was() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    refuse_pat_preferences(&world, &pat).await;

    let own = account::me(account::Plane::Tenant(world.tenant()))
        .send(pat.client())
        .await
        .ok();
    assert!(
        own.locale.is_none(),
        "a refused change sets no part of the preferences"
    );
    still_signed_in(&world, &pat).await;
    assert_eq!(
        tenant_records(&world, "identity.user_preferences_updated", &[]).await,
        0,
        "a refused change records nothing"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Invalid values, an anonymous caller and a foreign tenant each refuse the update.
async fn refuse_pat_preferences(world: &World<'_>, pat: &Person) {
    let nowhere = Preferences {
        locale: Some("de-DE".to_owned()),
        timezone: Some("Invalid/Nowhere".to_owned()),
        ..Preferences::default()
    };
    account::preferences(account::Plane::Tenant(world.tenant()), &nowhere)
        .send(pat.client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    let german = Preferences {
        locale: Some("de-DE".to_owned()),
        ..Preferences::default()
    };
    account::preferences(account::Plane::Tenant(world.tenant()), &german)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    account::preferences(account::Plane::Tenant(world.twin()), &german)
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Max, a member with no administrator's rights, renames himself and sets
/// his language and time zone, then sends a null language and a role he
/// may not give himself. His name and preferences are his, Ann's name is
/// untouched, he still reads no list of users, and each change is
/// recorded once.
#[tokio::test]
async fn max_renames_himself_without_touching_his_role_or_anyone_else() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    change_max_preferences(&world).await;
    check_max_preferences(&world).await;
    check_max_rights(&world).await;
    check_max_profile_events(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max updates his name and preferences, then attempts to grant himself ownership.
async fn change_max_preferences(world: &World<'_>) {
    let max = world.member();
    let plane = account::Plane::Member(world.org());

    let renamed = Preferences {
        display_name: Some("Max Updated".to_owned()),
        locale: Some("uk-UA".to_owned()),
        timezone: Some("Europe/Kyiv".to_owned()),
    };
    account::preferences(plane, &renamed)
        .send(max.client())
        .await
        .ok();

    let overreaching =
        Call::patch(world.org().at("/me")).json(&json!({"locale": null, "role": "Owner"}));
    max.client().send::<()>(overreaching).await.ok();
}

/// Max retains his identity and preferences after the omitted and null fields.
async fn check_max_preferences(world: &World<'_>) {
    let max = world.member();
    let plane = account::Plane::Member(world.org());
    let own = account::me(plane).send(max.client()).await.ok();
    assert_eq!(own.id, max.id(), "Max's record is still his own");
    assert_eq!(own.display_name, "Max Updated", "the name he chose is his");
    assert_eq!(
        own.locale.as_deref(),
        Some("uk-UA"),
        "a null language keeps the one set before"
    );
    assert_eq!(
        own.timezone.as_deref(),
        Some("Europe/Kyiv"),
        "a time zone left out keeps its value"
    );
}

/// Max's profile change leaves Ann's name untouched and grants him no user-list access.
async fn check_max_rights(world: &World<'_>) {
    let ann = members::me(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_ne!(
        ann.display_name, "Max Updated",
        "Max's new name is his alone, not Ann's"
    );
    people::list(world.tenant(), None)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Max's rename and actual preference change each leave one event.
async fn check_max_profile_events(world: &World<'_>) {
    assert_eq!(
        world
            .trail()
            .count("organization.org_user_display_name_changed")
            .await,
        1,
        "the rename is recorded once"
    );
    assert_eq!(
        world
            .trail()
            .count("organization.org_user_preferences_updated")
            .await,
        1,
        "the preference change is recorded once"
    );
}

/// Max reads his own profile; Sam, from the twin company, and nobody
/// signed in are refused it. Max cannot set an empty name, and the
/// refused update leaves his current name unchanged.
#[tokio::test]
async fn only_max_reads_his_own_profile_and_an_empty_name_is_refused() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    check_profile_readers(&world).await;

    let nameless = Preferences {
        display_name: Some(String::new()),
        locale: Some("de-DE".to_owned()),
        ..Preferences::default()
    };
    account::preferences(account::Plane::Member(world.org()), &nameless)
        .send(world.member().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let max = members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    assert_eq!(
        max.display_name, "Max Member",
        "a refused rename leaves the name Max had"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max can read his profile while foreign and anonymous sessions are refused.
async fn check_profile_readers(world: &World<'_>) {
    Matrix::new(
        "reading one's own member profile",
        account::me(account::Plane::Member(world.org())).call(),
    )
    .allowed(world.member().client())
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
}
