//! Ann hands her company on to Uma: both become what the handover makes
//! them, an administrator and the owner, and every session either held
//! ends. Ownership goes only from an owner, only to an active colleague
//! who is not one yet; a locked co-owner leaves Ann the last active
//! owner, who cannot step down; her API key, however broad, hands
//! nothing on.
//!
//! - `last_owner`: two owners stepping down at the same moment leave one.
//! - `races`: two handovers at the same moment choose one heir whole.
//! - `rollback`: a handover whose record cannot be written changes
//!   nothing, and succeeds once retried.

mod last_owner;
mod races;
mod rollback;

use ianua_scenarios::actors::Member;
use ianua_scenarios::api::{api_keys, members};
use ianua_scenarios::expect::{Matrix, Trail};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::{ChangeMemberStatus, ChangeRole, NewOrgApiKey, OrgRole};
use ianua_scenarios::world::World;

use crate::support::{another, listed};

/// The audit record a handover leaves.
const OWNERSHIP_TRANSFERRED: &str = "organization.ownership_transferred";

/// The audit record a changed organization role leaves.
const ROLE_CHANGED: &str = "organization.org_user_role_changed";

/// The audit record a changed standing leaves.
const STATUS_CHANGED: &str = "organization.org_user_status_changed";

/// The audit record a removed member leaves.
const DELETED: &str = "organization.org_user_deleted";

/// Ann and Uma are each signed in on two browsers, the second having
/// replaced the first. Ann hands ownership to Uma from her second
/// browser: all four browsers are out at once. Signed in afresh, Ann is
/// an administrator and Uma the owner: Ann can no longer make Max an
/// owner, Uma cannot lock herself as the last active owner, the handover
/// is recorded under Ann beside two role changes, and Uma makes Max an
/// owner. Uma is still nobody in Sam's company.
#[tokio::test]
async fn a_handover_changes_both_roles_and_ends_both_members_sessions() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let mut uma = world.colleague("uma", "Uma Heir", OrgRole::Member).await;
    uma.sign_in(&stack).await;
    let ann_second = another(&world, world.owner()).await;
    let uma_second = another(&world, &uma).await;
    transfer_and_end_sessions(&world, &uma, &ann_second, &uma_second).await;
    world.owner_mut().sign_in(&stack).await;
    uma.sign_in(&stack).await;
    check_handover_roles(&world, &uma).await;
    refuse_former_owner(&world, &uma).await;
    check_handover_audit(&world, &uma).await;
    promote_as_new_owner(&world, &uma).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The handover invalidates both members' original and replacement browsers.
async fn transfer_and_end_sessions(
    world: &World<'_>,
    uma: &Member,
    ann_second: &Member,
    uma_second: &Member,
) {
    members::transfer_ownership(world.org(), uma.id())
        .send(ann_second.client())
        .await
        .ok();
    for browser in [
        world.owner().client(),
        ann_second.client(),
        uma.client(),
        uma_second.client(),
    ] {
        members::me(world.org())
            .send(browser)
            .await
            .refused(Status::UNAUTHORIZED, "unauthenticated");
    }
}

/// Fresh sessions show Ann as administrator and Uma as the new owner.
async fn check_handover_roles(world: &World<'_>, uma: &Member) {
    let ann = members::me(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        ann.role,
        Some(OrgRole::Admin),
        "Ann is an administrator after the handover"
    );
    let own = members::me(world.org()).send(uma.client()).await.ok();
    assert_eq!(own.role, Some(OrgRole::Owner), "Uma owns the company now");
}

/// Ann cannot promote owners after handing over, and Uma cannot lock herself as the sole owner.
async fn refuse_former_owner(world: &World<'_>, uma: &Member) {
    members::change_role(
        world.org(),
        world.member().id(),
        &ChangeRole {
            role: OrgRole::Owner,
        },
    )
    .send(world.owner().client())
    .await
    .refused(Status::FORBIDDEN, "forbidden");
    members::change_status(
        world.org(),
        uma.id(),
        &ChangeMemberStatus {
            status: "Locked".to_owned(),
        },
    )
    .send(uma.client())
    .await
    .refused(Status::CONFLICT, "conflict");
}

/// The handover records Ann as actor and both resulting role changes.
async fn check_handover_audit(world: &World<'_>, uma: &Member) {
    let trail = Trail::of_organization(uma.client(), world.org().slug());
    let handovers = trail.entries(OWNERSHIP_TRANSFERRED).await;
    let [handover] = handovers.as_slice() else {
        panic!("one handover is recorded, not {}", handovers.len());
    };
    assert!(
        handover.actor.contains(world.owner().email()),
        "the handover is recorded under Ann"
    );
    assert_eq!(
        trail.count(ROLE_CHANGED).await,
        2,
        "the handover records both role changes"
    );
}

/// Uma can promote Max after becoming owner but remains outside Sam's company.
async fn promote_as_new_owner(world: &World<'_>, uma: &Member) {
    members::change_role(
        world.org(),
        world.member().id(),
        &ChangeRole {
            role: OrgRole::Owner,
        },
    )
    .send(uma.client())
    .await
    .ok();
    members::me(world.stranger().org())
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Ann cannot transfer ownership to herself, another owner, an inactive
/// colleague or Sam from another company. Max, Tess, Sam and anonymous
/// callers cannot transfer it to Max either.
/// After each refusal Ann is still the owner on the session she holds;
/// no handover is recorded, the deactivated colleague is still a member,
/// and Max is still in.
#[tokio::test]
async fn ownership_goes_only_from_an_owner_to_an_active_colleague_who_is_none_yet() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let coowner = world
        .colleague("coowner", "Other Owner", OrgRole::Owner)
        .await;
    let inactive = world
        .colleague("inactive", "Inactive Colleague", OrgRole::Member)
        .await;
    members::change_status(
        world.org(),
        inactive.id(),
        &ChangeMemberStatus {
            status: "Deactivated".to_owned(),
        },
    )
    .send(world.owner().client())
    .await
    .ok();
    refuse_ineligible_heirs(&world, &coowner, &inactive).await;
    refuse_handover_callers(&world).await;
    check_refused_handover(&world, &inactive).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Self, existing owner, inactive member and foreign member are all refused without ending Ann's session.
async fn refuse_ineligible_heirs(world: &World<'_>, coowner: &Member, inactive: &Member) {
    for (heir, status, code) in [
        (
            world.owner().id(),
            Status::UNPROCESSABLE_ENTITY,
            "domain_error",
        ),
        (coowner.id(), Status::CONFLICT, "conflict"),
        (inactive.id(), Status::CONFLICT, "conflict"),
        (world.stranger().id(), Status::NOT_FOUND, "not_found"),
    ] {
        members::transfer_ownership(world.org(), heir)
            .send(world.owner().client())
            .await
            .refused(status, code);
        assert_eq!(
            listed(world, world.owner().id()).await.role,
            Some(OrgRole::Owner),
            "Ann is still the owner after the refused handover to {heir}"
        );
        members::me(world.org())
            .send(world.owner().client())
            .await
            .ok();
    }
}

/// Non-owners and anonymous callers cannot transfer company ownership.
async fn refuse_handover_callers(world: &World<'_>) {
    Matrix::new(
        "handing ownership on",
        members::transfer_ownership(world.org(), world.member().id()).call(),
    )
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.admin().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
}

/// Refused handovers record nothing, preserve the inactive member's role and leave Max signed in.
async fn check_refused_handover(world: &World<'_>, inactive: &Member) {
    assert_eq!(
        world.trail().count(OWNERSHIP_TRANSFERRED).await,
        0,
        "no refused handover is recorded"
    );
    assert_eq!(
        listed(world, inactive.id()).await.role,
        Some(OrgRole::Member),
        "the deactivated colleague is still a member"
    );
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
}

/// After locking the other owner, Ann cannot lock, deactivate, demote or
/// remove herself. As the last active owner she
/// is refused each time, stays the active owner on the session she
/// holds, and nothing is recorded.
#[tokio::test]
async fn a_locked_co_owner_leaves_ann_the_last_active_owner_who_cannot_step_down() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let coowner = world
        .colleague("coowner", "Other Owner", OrgRole::Owner)
        .await;
    members::change_status(
        world.org(),
        coowner.id(),
        &ChangeMemberStatus {
            status: "Locked".to_owned(),
        },
    )
    .send(world.owner().client())
    .await
    .ok();
    let statuses_before = world.trail().count(STATUS_CHANGED).await;
    refuse_last_owner_changes(&world).await;
    check_last_owner_unchanged(&world, statuses_before).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The last active owner cannot disable, demote or remove herself.
async fn refuse_last_owner_changes(world: &World<'_>) {
    for status in ["Locked", "Deactivated"] {
        members::change_status(
            world.org(),
            world.owner().id(),
            &ChangeMemberStatus {
                status: status.to_owned(),
            },
        )
        .send(world.owner().client())
        .await
        .refused(Status::CONFLICT, "conflict");
    }
    members::change_role(
        world.org(),
        world.owner().id(),
        &ChangeRole {
            role: OrgRole::Admin,
        },
    )
    .send(world.owner().client())
    .await
    .refused(Status::CONFLICT, "conflict");
    members::remove(world.org(), world.owner().id())
        .send(world.owner().client())
        .await
        .refused(Status::CONFLICT, "conflict");
}

/// Refusals leave all audit counts unchanged and Ann active as owner on her current session.
async fn check_last_owner_unchanged(world: &World<'_>, statuses_before: usize) {
    assert_eq!(
        world.trail().count(STATUS_CHANGED).await,
        statuses_before,
        "no refused change of standing is recorded"
    );
    assert_eq!(
        world.trail().count(ROLE_CHANGED).await,
        0,
        "no refused demotion is recorded"
    );
    assert_eq!(
        world.trail().count(DELETED).await,
        0,
        "no refused removal is recorded"
    );
    let ann = members::me(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(ann.role, Some(OrgRole::Owner), "Ann is still the owner");
    assert_eq!(ann.status, "Active", "Ann is still active");
}

/// Ann's API key with every scope can list the team but cannot transfer
/// ownership to Max. Max remains a member, Ann stays the owner on the session
/// she holds, and no handover is recorded.
#[tokio::test]
async fn an_owners_api_key_cannot_hand_ownership_on() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let automation = team_automation(&world).await;

    members::list(world.org(), None)
        .send(&automation)
        .await
        .ok();
    members::transfer_ownership(world.org(), world.member().id())
        .send(&automation)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    check_key_handover_refused(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Creates Ann's automation client with every organization API-key scope.
async fn team_automation(world: &World<'_>) -> Client {
    let made = api_keys::create_for_organization(
        world.org(),
        &NewOrgApiKey {
            name: "Team automation".to_owned(),
            scopes: vec!["org:*:*".to_owned()],
        },
    )
    .send(world.owner().client())
    .await
    .ok();
    let mut automation = Client::new(world.stack(), "Ann's team automation").expect("a client");
    automation.authorize(&made.raw_key);
    automation
}

/// The API-key refusal leaves Max a member and Ann signed in as owner without a handover event.
async fn check_key_handover_refused(world: &World<'_>) {
    assert_eq!(
        listed(world, world.member().id()).await.role,
        Some(OrgRole::Member),
        "Max is still a member"
    );
    let ann = members::me(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(ann.role, Some(OrgRole::Owner), "Ann is still the owner");
    assert_eq!(
        world.trail().count(OWNERSHIP_TRANSFERRED).await,
        0,
        "no refused handover is recorded"
    );
}
