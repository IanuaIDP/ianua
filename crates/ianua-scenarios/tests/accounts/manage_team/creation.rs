//! Ann creates a colleague's account herself, password and all, instead
//! of inviting them: Uma gets the default role and an unproved mailbox,
//! proves it once from the mail and signs in to Ann's company alone.
//! Tess, Max, Sam and nobody signed in create nobody; a weak password or
//! an address already on the team creates nobody; Uma as an administrator
//! creates colleagues up to Admin, and only Ann creates an owner or a
//! billing contact.

use std::time::Duration;

use ianua_scenarios::actors::Member;
use ianua_scenarios::api::members;
use ianua_scenarios::expect::{Matrix, no_secret_leaked};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::{CreateMember, OrgRole};
use ianua_scenarios::wire::people::LinkToken;
use ianua_scenarios::world::World;

use crate::support::{account, listed, provisioned, recorded};

/// How long a mailbox is watched for a mail that must not come.
const QUIET: Duration = Duration::from_secs(1);

/// Ann creates Uma's account with a password and no role chosen. Uma is a
/// member, active, with an unproved mailbox. The mailed link proves it
/// once and is dead after; Uma then signs in with the password Ann chose,
/// is a member with a proved mailbox, and is nobody in Sam's company. The
/// creation is in the trail, with neither password nor token in it.
#[tokio::test]
async fn a_provisioned_member_proves_the_mailbox_and_signs_in_as_offered() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    let form = account(&world, "uma");
    let made = members::create(world.org(), &form)
        .send(world.owner().client())
        .await
        .ok();
    check_provisioned_member(&world, &made.id).await;
    let proof = verify_mailbox_once(&world, &form.email).await;
    let mut uma = provisioned(&world, made.id, &form);
    uma.sign_in(&stack).await;
    check_provisioned_sign_in(&world, &uma, &form, &proof).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A newly provisioned account defaults to an active member with an unproved mailbox.
async fn check_provisioned_member(world: &World<'_>, id: &str) {
    let seat = listed(world, id).await;
    assert_eq!(
        seat.role,
        Some(OrgRole::Member),
        "a colleague created with no role chosen is a member"
    );
    assert_eq!(seat.status, "Active", "Uma is active from the start");
    assert!(!seat.email_verified, "Uma's mailbox is not proved yet");
}

/// The mailed verification token proves the new mailbox once and refuses reuse.
async fn verify_mailbox_once(world: &World<'_>, email: &str) -> LinkToken {
    let mail = world.stack().mailbox().next_for(email).await;
    let proof = LinkToken {
        token: mail.token_in("/verify-email"),
    };
    members::verify_email(world.org(), &proof)
        .send(world.anonymous().client())
        .await
        .ok();
    members::verify_email(world.org(), &proof)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    proof
}

/// Uma signs in with her verified member role, stays outside Sam's company and exposes no secrets.
async fn check_provisioned_sign_in(
    world: &World<'_>,
    uma: &Member,
    form: &CreateMember,
    proof: &LinkToken,
) {
    let own = members::me(world.org()).send(uma.client()).await.ok();
    assert!(own.email_verified, "the mailed link proved Uma's mailbox");
    assert_eq!(own.role, Some(OrgRole::Member), "Uma signs in as a member");
    members::me(world.stranger().org())
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let record = recorded(
        world,
        "organization.org_user_created",
        uma.id(),
        world.owner().email(),
    )
    .await;
    no_secret_leaked(&record.details.to_string(), &[&form.password, &proof.token]);
    no_secret_leaked(&format!("{own:?}"), &[&form.password, &proof.token]);
}

/// Tess, Max, Sam and an anonymous caller cannot create a colleague.
/// Their attempts leave no account, mail or creation record; Ann then creates
/// the same colleague from the same form.
#[tokio::test]
async fn nobody_without_the_right_creates_a_colleague() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let form = account(&world, "uma");
    let before = world.trail().count("organization.org_user_created").await;
    refuse_creation_callers(&world, &form).await;
    check_refused_creation(&world, &form, before).await;

    members::create(world.org(), &form)
        .send(world.owner().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Creating colleagues is refused to tenant admins, members, strangers and anonymous callers.
async fn refuse_creation_callers(world: &World<'_>, form: &CreateMember) {
    Matrix::new(
        "creating a colleague",
        members::create(world.org(), form).call(),
    )
    .refused(world.admin().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
}

/// Refused creation leaves no account, audit record or mailbox delivery.
async fn check_refused_creation(world: &World<'_>, form: &CreateMember, before: usize) {
    let found = members::list(world.org(), Some(&form.email))
        .send(world.owner().client())
        .await
        .ok();
    assert!(
        found.items.is_empty(),
        "a refused creation leaves no account behind"
    );
    assert_eq!(
        world.trail().count("organization.org_user_created").await,
        before,
        "a refused creation records no creation"
    );
    world
        .stack()
        .mailbox()
        .nothing_for(&form.email, QUIET)
        .await;
}

/// A weak password prevents Ann from creating Uma or recording a creation.
/// Correcting it succeeds; submitting the same form again is refused for
/// the taken address. The team holds one Uma and one creation record, and
/// Max's session remains usable.
#[tokio::test]
async fn a_weak_password_or_a_taken_address_creates_nobody() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut form = account(&world, "uma");
    let password = std::mem::replace(&mut form.password, "abc".to_owned());
    let before = world.trail().count("organization.org_user_created").await;
    refuse_weak_password(&world, &form, before).await;
    form.password = password;
    check_duplicate_address(&world, &form, before).await;
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// The weak password refuses creation without adding an account or audit record.
async fn refuse_weak_password(world: &World<'_>, form: &CreateMember, before: usize) {
    members::create(world.org(), form)
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let found = members::list(world.org(), Some(&form.email))
        .send(world.owner().client())
        .await
        .ok();
    assert!(
        found.items.is_empty(),
        "a creation refused for its password leaves no account behind"
    );
    assert_eq!(
        world.trail().count("organization.org_user_created").await,
        before,
        "a creation refused for its password records no creation"
    );
}

/// A corrected form creates one account; reusing its address leaves that account and record alone.
async fn check_duplicate_address(world: &World<'_>, form: &CreateMember, before: usize) {
    let made = members::create(world.org(), form)
        .send(world.owner().client())
        .await
        .ok();
    members::create(world.org(), form)
        .send(world.owner().client())
        .await
        .refused(Status::CONFLICT, "conflict");
    let matching = members::list(world.org(), Some(&form.email))
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        matching.items.len(),
        1,
        "the team holds one account at Uma's address"
    );
    assert_eq!(
        matching.items[0].id, made.id,
        "the one account is the one the corrected form made"
    );
    assert_eq!(
        world.trail().count("organization.org_user_created").await,
        before + 1,
        "one creation is recorded"
    );
}

/// Uma, an administrator of Ann's company, creates a viewer, a member and
/// an administrator, but is refused an owner and a billing contact, and
/// nothing of those is kept; Ann creates both. Every colleague created
/// has exactly the role on the form and an unproved mailbox, and each
/// creation is recorded under who made it. Uma's refused attempts mail
/// nothing, so they do not hold back Ann's mail to the same addresses.
#[tokio::test]
async fn only_an_owner_creates_an_owner_or_a_billing_contact() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut uma = world
        .colleague("uma", "Uma Administrator", OrgRole::Admin)
        .await;
    uma.sign_in(&stack).await;
    let before = world.trail().count("organization.org_user_created").await;

    for role in [
        OrgRole::Viewer,
        OrgRole::Member,
        OrgRole::Admin,
        OrgRole::Owner,
        OrgRole::Billing,
    ] {
        create_with_role(&world, &uma, role).await;
    }
    assert_eq!(
        world.trail().count("organization.org_user_created").await,
        before + 5,
        "five creations are recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Protected roles require Ann; other roles permit Uma, and the created account keeps the offered role.
async fn create_with_role(world: &World<'_>, uma: &Member, role: OrgRole) {
    let mut form = account(world, &format!("created-{role:?}"));
    form.role = Some(role);
    let creator = match role {
        OrgRole::Owner | OrgRole::Billing => {
            refused_to_uma(world, uma, &form).await;
            world.owner()
        }
        OrgRole::Viewer | OrgRole::Member | OrgRole::Admin => uma,
    };
    let made = members::create(world.org(), &form)
        .send(creator.client())
        .await
        .ok();
    assert_created_role(world, &made.id, role).await;
    recorded(
        world,
        "organization.org_user_created",
        &made.id,
        creator.email(),
    )
    .await;
}

/// The new colleague keeps the requested role and has not yet proved their mailbox.
async fn assert_created_role(world: &World<'_>, id: &str, role: OrgRole) {
    let seat = listed(world, id).await;
    assert_eq!(
        seat.role,
        Some(role),
        "the colleague created as {role:?} has that role"
    );
    assert!(
        !seat.email_verified,
        "the colleague created as {role:?} has an unproved mailbox"
    );
}

/// Uma is refused creating the colleague on `form`, and nothing of them
/// is kept.
async fn refused_to_uma(world: &World<'_>, uma: &Member, form: &CreateMember) {
    members::create(world.org(), form)
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let found = members::list(world.org(), Some(&form.email))
        .send(world.owner().client())
        .await
        .ok();
    assert!(
        found.items.is_empty(),
        "a creation refused to an administrator leaves no account behind"
    );
}
