//! A directory of the tenant's company, linked over SCIM 2.0, makes Pat:
//! her mailbox is not taken as proved on the directory's word, she proves
//! it herself, sets a password and signs in, and the directory's later
//! deactivation ends that session. The directory's token is rotated and
//! the link switched off, each time killing the old client. Only Tess
//! sets the link up, and no status read shows a token.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{directory, members, people, registration};
use ianua_scenarios::expect::{Matrix, no_secret_leaked};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::directory::{DirectoryPatch, DirectorySettings, DirectoryUser};
use ianua_scenarios::wire::people::LinkToken;
use ianua_scenarios::world::World;

/// The password Pat sets through the reset link, once her mailbox is
/// proved: a sentence, so no scanner takes it for a key.
const PATS_PASSWORD: &str = "Gentle orchard silver sentence 9471!";

/// The most mails passed over before the verification link, so a missing
/// link fails rather than reading forever.
const PASSED_OVER: usize = 10;

/// The directory, as a client of its own: Tess switches the link on, gives
/// the directory the token shown that once, and has the people it makes
/// active at once and deactivated, not deleted, when it removes them.
async fn linked_directory(world: &World<'_>) -> Client {
    let token = directory::enable(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let mut client = Client::new(world.stack(), "the directory").expect("a client");
    client.authorize(
        token
            .bearer_token
            .as_deref()
            .expect("the first setup shows its token"),
    );
    let settings = DirectorySettings {
        default_role_id: None,
        auto_activate: true,
        deactivate_on_remove: true,
    };
    directory::replace_settings(world.tenant(), &settings)
        .send(world.admin().client())
        .await
        .ok();
    client
}

/// The token of the verification link mailed to `email`, passing over any
/// other mail that came first: the mailbox's own proof, not the
/// directory's word.
async fn verification_link(world: &World<'_>, email: &str) -> LinkToken {
    for _ in 0..=PASSED_OVER {
        let mail = world.stack().mailbox().next_for(email).await;
        if mail
            .links()
            .iter()
            .any(|link| link.path().ends_with("/verify-email"))
        {
            return LinkToken {
                token: mail.token_in("/verify-email"),
            };
        }
    }
    panic!("{email} got {PASSED_OVER} mails before one linking to /verify-email");
}

/// The directory makes Pat, active but with her mailbox unproved. Pat
/// follows the verification link mailed to her, sets her own password
/// through a reset link and signs in, her mailbox now proved. The
/// directory deactivates her: her session is dead and Tess reads her as
/// locked, Sam still reads his own organization, and the status change is
/// recorded as the platform's own doing.
#[tokio::test]
async fn a_person_the_directory_made_proves_her_mailbox_and_is_cut_off_when_it_removes_her() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let directory = linked_directory(&world).await;
    let mut pat = world.newcomer("pat", "Pat Holder");

    create_directory_person(&world, &directory, &mut pat).await;
    prove_mailbox(&world, &mut pat).await;
    deactivate_person(&world, &directory, &pat).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// SCIM creates an active person whose mailbox is still unproved.
async fn create_directory_person(world: &World<'_>, directory: &Client, pat: &mut Person) {
    let user = DirectoryUser {
        user_name: pat.email().to_owned(),
        display_name: pat.account().display_name.clone(),
        active: true,
        external_id: "external-pat".to_owned(),
    };
    let made = directory::create_user(world.tenant(), &user)
        .send(directory)
        .await
        .ok();
    pat.record_invitation(&made.id);
    let unproved = people::get(world.tenant(), &made.id)
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        !unproved.email_verified,
        "the directory's word proves no mailbox"
    );
    assert_eq!(unproved.status, "Active", "Pat is active at once");
}

/// Pat proves her mailbox, resets her password and signs in with verified email.
async fn prove_mailbox(world: &World<'_>, pat: &mut Person) {
    let stack = world.stack();
    let proof = verification_link(world, pat.email()).await;
    registration::verify(world.tenant(), &proof)
        .send(world.anonymous().client())
        .await
        .ok();
    let reset = pat.reset_link(stack).await;
    pat.confirm_reset(&reset, PATS_PASSWORD).await.ok();
    pat.sign_in(stack).await;
    let me = people::me(world.tenant()).send(pat.client()).await.ok();
    assert!(me.email_verified, "Pat proved her mailbox herself");
}

/// Directory deactivation ends Pat's session while Sam retains access and the system is audited.
async fn deactivate_person(world: &World<'_>, directory: &Client, pat: &Person) {
    directory::patch_user(world.tenant(), pat.id(), &DirectoryPatch::deactivation())
        .send(directory)
        .await
        .ok();
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let locked = people::get(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(locked.status, "Locked", "the directory locked Pat");
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();
    let records = world.trail().entries("identity.user_status_changed").await;
    assert!(
        records
            .iter()
            .any(|entry| entry.actor.contains("System") || entry.actor.contains("system")),
        "the lock is recorded as the platform's own doing"
    );
}

/// The directory lists the tenant's people with its token. Tess rotates
/// the token: the old one is refused and the new one lists. Tess switches
/// the link off: the new one is refused too. The link's status shows no
/// token.
#[tokio::test]
async fn a_rotated_token_and_a_link_switched_off_kill_the_old_directory_client() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let old = linked_directory(&world).await;
    directory::list_users(world.tenant()).send(&old).await.ok();

    let current = rotate_directory_token(&world, &old).await;
    disable_directory(&world, &current).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Rotation disables the old token, enables the replacement and keeps status free of secrets.
async fn rotate_directory_token(world: &World<'_>, old: &Client) -> Client {
    let rotated = directory::rotate_token(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let raw = rotated
        .bearer_token
        .expect("a rotation shows the new token");
    let mut current =
        Client::new(world.stack(), "the directory, after the rotation").expect("a client");
    current.authorize(&raw);
    let denied = directory::list_users(world.tenant()).send(old).await;
    assert_eq!(
        denied.status(),
        Status::UNAUTHORIZED,
        "the old token is dead: {}",
        denied.summary()
    );
    directory::list_users(world.tenant())
        .send(&current)
        .await
        .ok();

    let status = directory::status(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let whole_status = serde_json::to_string(&status).expect("the status writes as JSON");
    no_secret_leaked(&whole_status, &[&raw]);
    current
}

/// Switching the link off refuses the token that worked after rotation.
async fn disable_directory(world: &World<'_>, current: &Client) {
    directory::disable(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let disabled = directory::list_users(world.tenant()).send(current).await;
    assert_eq!(
        disabled.status(),
        Status::UNAUTHORIZED,
        "a link switched off takes no token: {}",
        disabled.summary()
    );
}

/// Max, Sam and an anonymous visitor cannot switch the directory link on
/// or get a token, and the link stays unset. Tess sets it up, the
/// directory lists people, and one link is recorded as switched on.
#[tokio::test]
async fn only_the_tenants_administrator_links_a_directory() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    refuse_directory_setup(&world).await;
    let directory = linked_directory(&world).await;
    directory::list_users(world.tenant())
        .send(&directory)
        .await
        .ok();
    assert_eq!(
        world.trail().count("federation.scim_enabled").await,
        1,
        "one link is recorded as switched on"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Refused setup attempts neither configure the directory nor reveal a token.
async fn refuse_directory_setup(world: &World<'_>) {
    Matrix::new(
        "switching the directory link on",
        directory::enable(world.tenant()).call(),
    )
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
    let status = directory::status(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert!(!status.configured, "no refused attempt set the link up");
}
