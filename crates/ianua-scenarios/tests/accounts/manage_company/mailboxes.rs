//! What a company's mailboxes prove: another proof asked for by someone
//! signed in to nothing, an address Ann moves for a colleague, a welcome
//! mail, and the links a member's own move leaves behind. Asking never
//! tells whether an address is registered, and a proof goes only to the
//! address on the account.

use std::time::Duration;

use ianua_scenarios::actors::Member;
use ianua_scenarios::api::{account, audit, members};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Matrix, no_secret_leaked};
use ianua_scenarios::mail::Mail;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::account::EmailChange;
use ianua_scenarios::wire::organization::{
    ChangeMemberEmail, CreateMember, Member as ListedMember, MemberAddress, OrgRole,
};
use ianua_scenarios::wire::people::LinkToken;
use ianua_scenarios::world::World;

use crate::support::{QUIET, bob_signed_in, colleague_signed_in};

/// The password Ann chooses for Uma: a sentence, so no scanner takes it
/// for a key.
const PASSWORD: &str = "Separate golden orchard meadow 7814!";

/// How long a move's link lasts in the expiry scenario, on the
/// controlled clock.
const LINK_LIFETIME: Duration = Duration::from_secs(5);

/// One second past that.
const PAST_THE_LINK: Duration = Duration::from_secs(6);

/// The most mails passed over before the one awaited, so a missing link
/// fails rather than reading forever.
const PASSED_OVER: usize = 10;

/// The record of another confirmation link going out.
const VERIFICATION_SENT: &str = "organization.org_verification_email_sent";

/// The record of an address Ann changed for a colleague.
const EMAIL_CHANGED: &str = "organization.org_user_email_changed";

/// The record of a welcome mailed.
const WELCOME_SENT: &str = "organization.org_welcome_email_sent";

/// The subject of the mail that follows a proved mailbox.
const ACCOUNT_READY: &str = "Your account is ready";

/// The record of a move's link replaced.
const MOVE_LINK_RESENT: &str = "identity.management_email_change_link_resent";

/// The next mail to `email` that links to `path`.
///
/// # Panics
///
/// When none comes among the next few mails.
async fn mail_linking_to(world: &World<'_>, email: &str, path: &str) -> Mail {
    for _ in 0..=PASSED_OVER {
        let mail = world.stack().mailbox().next_for(email).await;
        if mail.links().iter().any(|link| link.path().ends_with(path)) {
            return mail;
        }
    }
    panic!("{email} got {PASSED_OVER} mails before one linking to {path}");
}

/// The member `id` as Ann's team list shows them.
///
/// # Panics
///
/// When the list cannot be read, or the member is not on it.
async fn listed(world: &World<'_>, id: &str) -> ListedMember {
    let found = members::list(world.org(), None)
        .send(world.owner().client())
        .await
        .ok()
        .items
        .into_iter()
        .find(|member| member.id == id);
    let Some(member) = found else {
        panic!("the member {id} is on the team list");
    };
    member
}

/// Uma's account, made by Ann, with an unproved mailbox and the first
/// proof read and thrown away. Answers Uma's id and address.
async fn create_uma(world: &World<'_>) -> (String, String) {
    let email = world.address("uma");
    let made = members::create(
        world.org(),
        &CreateMember {
            email: email.clone(),
            display_name: "Uma Colleague".to_owned(),
            password: PASSWORD.to_owned(),
            role: None,
        },
    )
    .send(world.owner().client())
    .await
    .ok();
    mail_linking_to(world, &email, "/verify-email").await;
    (made.id, email)
}

/// Uma asks for another proof of her mailbox, nobody signed in: a new
/// link comes and proves it, and she is told her account is ready. Asking
/// for a stranger's address answers the same and mails nothing, a
/// malformed address is refused, and asking for an address already proved
/// mails nothing.
#[tokio::test]
async fn another_proof_goes_only_to_the_address_on_the_account() {
    let stack = Stack::start(
        Profile::standard()
            .with("MAIL_RESEND_COOLDOWN_SECONDS", "0")
            .with("MAIL_COOLDOWN_SECONDS", "0"),
    )
    .await
    .expect("the stack starts");
    let world = World::new(&stack).await;
    let (id, email) = create_uma(&world).await;
    let before = world.trail().count(VERIFICATION_SENT).await;
    let uma = MemberAddress {
        email: email.clone(),
    };

    members::send_verification(world.org(), &uma)
        .send(world.anonymous().client())
        .await
        .ok();
    let mail = mail_linking_to(&world, &email, "/verify-email").await;
    members::verify_email(
        world.org(),
        &LinkToken {
            token: mail.token_in("/verify-email"),
        },
    )
    .send(world.anonymous().client())
    .await
    .ok();
    assert!(
        listed(&world, &id).await.email_verified,
        "her mailbox is proved"
    );
    assert_eq!(
        stack.mailbox().next_for(&email).await.subject(),
        ACCOUNT_READY,
        "proving her mailbox tells her the account is ready"
    );

    answer_the_same_for_nobody(&world).await;
    members::send_verification(world.org(), &uma)
        .send(world.anonymous().client())
        .await
        .ok();
    stack.mailbox().nothing_for(&email, QUIET).await;
    assert_eq!(
        world.trail().count(VERIFICATION_SENT).await,
        before + 1,
        "one link went out for the one who could be helped"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// A stranger's address and a malformed one answer without mailing
/// anybody.
async fn answer_the_same_for_nobody(world: &World<'_>) {
    let nobody = world.address("nobody");
    members::send_verification(
        world.org(),
        &MemberAddress {
            email: nobody.clone(),
        },
    )
    .send(world.anonymous().client())
    .await
    .ok();
    world.stack().mailbox().nothing_for(&nobody, QUIET).await;
    members::send_verification(
        world.org(),
        &MemberAddress {
            email: "not an address".to_owned(),
        },
    )
    .send(world.anonymous().client())
    .await
    .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
}

/// A second request inside the wait mails nothing and records nothing,
/// and the answer is the same as for a first.
#[tokio::test]
async fn a_second_request_inside_the_wait_mails_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let (_id, email) = create_uma(&world).await;
    let before = world.trail().count(VERIFICATION_SENT).await;

    members::send_verification(
        world.org(),
        &MemberAddress {
            email: email.clone(),
        },
    )
    .send(world.anonymous().client())
    .await
    .ok();

    stack.mailbox().nothing_for(&email, QUIET).await;
    assert_eq!(
        world.trail().count(VERIFICATION_SENT).await,
        before,
        "nothing new went out"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// With no company named, the proof goes to every account at the
/// address that still needs one. A stranger's address answers the same,
/// and a malformed one is refused.
#[tokio::test]
async fn another_proof_is_asked_for_with_no_company_named() {
    let stack = Stack::start(
        Profile::standard()
            .with("MAIL_RESEND_COOLDOWN_SECONDS", "0")
            .with("MAIL_COOLDOWN_SECONDS", "0"),
    )
    .await
    .expect("the stack starts");
    let world = World::new(&stack).await;
    let (_id, email) = create_uma(&world).await;
    let before = world.trail().count(VERIFICATION_SENT).await;

    members::send_verification_anywhere(&MemberAddress {
        email: email.clone(),
    })
    .send(world.anonymous().client())
    .await
    .ok();
    mail_linking_to(&world, &email, "/verify-email").await;
    assert_eq!(
        world.trail().count(VERIFICATION_SENT).await,
        before + 1,
        "the link is recorded"
    );

    let nobody = world.address("nobody");
    members::send_verification_anywhere(&MemberAddress {
        email: nobody.clone(),
    })
    .send(world.anonymous().client())
    .await
    .ok();
    stack.mailbox().nothing_for(&nobody, QUIET).await;
    members::send_verification_anywhere(&MemberAddress {
        email: "not an address".to_owned(),
    })
    .send(world.anonymous().client())
    .await
    .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann moves Max to a new address. He reads it unproved; the link mailed
/// there proves it. The change and the link are recorded, and Ann's own
/// address is as it was.
#[tokio::test]
async fn ann_moves_max_to_a_new_address_and_it_proves_itself_from_the_new_mailbox() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let new_address = world.address("max-new");
    let before = world.trail().count(VERIFICATION_SENT).await;

    members::change_email(
        world.org(),
        world.member().id(),
        &ChangeMemberEmail {
            email: new_address.clone(),
        },
    )
    .send(world.owner().client())
    .await
    .ok();

    let max = listed(&world, world.member().id()).await;
    assert_eq!(max.email, new_address, "Max is at the new address");
    assert!(!max.email_verified, "it is not proved yet");
    let mail = mail_linking_to(&world, &new_address, "/verify-email").await;
    members::verify_email(
        world.org(),
        &LinkToken {
            token: mail.token_in("/verify-email"),
        },
    )
    .send(world.anonymous().client())
    .await
    .ok();
    assert!(
        listed(&world, world.member().id()).await.email_verified,
        "the new address is proved"
    );
    assert_eq!(
        world.trail().count(EMAIL_CHANGED).await,
        1,
        "the move is recorded once"
    );
    assert_eq!(
        world.trail().count(VERIFICATION_SENT).await,
        before + 1,
        "the link is recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Moving a colleague takes the right to change members and an address
/// nobody else in the company holds. Tess, Max, Sam and nobody signed in
/// cannot move Uma; Ann cannot move herself this way; Uma as an
/// administrator cannot move Ann, an owner; nobody can take Tess's
/// address, move a stranger, or use a broken address. Nothing is recorded.
#[tokio::test]
async fn moving_a_colleague_takes_the_right_and_an_address_nobody_holds() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = colleague_signed_in(&world, "uma", OrgRole::Admin).await;
    let move_to_new = ChangeMemberEmail {
        email: world.address("moved"),
    };

    refuse_without_the_right(&world, &uma, &move_to_new).await;
    refuse_bad_targets(&world).await;

    assert_eq!(
        world.trail().count(EMAIL_CHANGED).await,
        0,
        "no refused move is recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Who may not move whom.
async fn refuse_without_the_right(
    world: &World<'_>,
    uma: &Member,
    move_to_new: &ChangeMemberEmail,
) {
    Matrix::new(
        "moving Uma to a new mailbox",
        members::change_email(world.org(), uma.id(), move_to_new).call(),
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
    members::change_email(world.org(), world.owner().id(), move_to_new)
        .send(world.owner().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    members::change_email(world.org(), world.owner().id(), move_to_new)
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// A taken address, someone not of the company and a broken address are
/// refused.
async fn refuse_bad_targets(world: &World<'_>) {
    members::change_email(
        world.org(),
        world.member().id(),
        &ChangeMemberEmail {
            email: world.admin().email().to_owned(),
        },
    )
    .send(world.owner().client())
    .await
    .refused(Status::CONFLICT, "conflict");
    members::change_email(
        world.org(),
        world.stranger().id(),
        &ChangeMemberEmail {
            email: world.address("elsewhere"),
        },
    )
    .send(world.owner().client())
    .await
    .refused(Status::NOT_FOUND, "not_found");
    members::change_email(
        world.org(),
        world.member().id(),
        &ChangeMemberEmail {
            email: "not an address".to_owned(),
        },
    )
    .send(world.owner().client())
    .await
    .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
}

/// Ann welcomes Uma, whose account she just made: a mail reaches Uma with
/// a way to sign in and no secret, and the welcome is recorded once.
/// Someone not of the company is no error: nothing is mailed and nothing
/// is recorded. Tess, Max, Sam and nobody signed in send no welcome.
#[tokio::test]
async fn ann_welcomes_a_colleague_she_made_an_account_for() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let (id, email) = create_uma(&world).await;

    members::welcome(world.org(), &id)
        .send(world.owner().client())
        .await
        .ok();

    let mail = world.stack().mailbox().next_for(&email).await;
    assert!(!mail.links().is_empty(), "the mail says where to sign in");
    no_secret_leaked(&format!("{:?}{:?}", mail.text(), mail.html()), &[PASSWORD]);
    assert_eq!(
        welcomes_of(&world, &id).await,
        1,
        "the welcome is recorded once"
    );

    members::welcome(world.org(), world.stranger().id())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        welcomes_of(&world, world.stranger().id()).await,
        0,
        "nobody was welcomed for someone not of the company"
    );

    Matrix::new(
        "welcoming a colleague",
        members::welcome(world.org(), &id).call(),
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
    assert_eq!(
        welcomes_of(&world, &id).await,
        1,
        "no refused welcome is recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// How many welcome records name the member `id`: setup's own sign-ups
/// leave welcome records of their own.
async fn welcomes_of(world: &World<'_>, id: &str) -> usize {
    world
        .trail()
        .entries(WELCOME_SENT)
        .await
        .iter()
        .filter(|entry| entry.event_type == WELCOME_SENT && entry.details["org_user"]["id"] == id)
        .count()
}

/// The links a move of Max's left: the proof mailed to the new address
/// and the warning mailed to the old one, with the address moved to.
async fn max_moves_mailbox(world: &World<'_>, name: &str) -> (LinkToken, String) {
    let address = world.address(name);
    let change = EmailChange {
        new_email: address.clone(),
        password: world.member().password().to_owned(),
        code: None,
    };
    account::change_email(account::Plane::Member(world.org()), &change)
        .send(world.member().client())
        .await
        .ok();
    let mail = mail_linking_to(world, &address, "/confirm-email-change").await;
    (
        LinkToken {
            token: mail.token_in("/confirm-email-change"),
        },
        address,
    )
}

/// What the link `proof` of a move is worth, read by nobody signed in.
async fn move_status(world: &World<'_>, proof: &LinkToken) -> String {
    account::email_status(account::Plane::Member(world.org()), proof)
        .send(world.anonymous().client())
        .await
        .ok()
        .status
}

/// Max's move leaves a link that reads as usable, however often it is
/// read; confirmed, it reads as used. A link nobody sent reads invalid,
/// and an empty one is refused.
#[tokio::test]
async fn a_moves_link_is_read_without_being_spent() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let (proof, _address) = max_moves_mailbox(&world, "max-new").await;

    assert_eq!(
        move_status(&world, &proof).await,
        "Valid",
        "the link is usable"
    );
    assert_eq!(
        move_status(&world, &proof).await,
        "Valid",
        "reading spends nothing"
    );

    let invented = LinkToken {
        token: "an invented move link".to_owned(),
    };
    assert_eq!(
        move_status(&world, &invented).await,
        "Invalid",
        "a link nobody sent reads invalid"
    );
    account::email_status(
        account::Plane::Member(world.org()),
        &LinkToken {
            token: String::new(),
        },
    )
    .send(world.anonymous().client())
    .await
    .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    account::confirm_email(account::Plane::Member(world.org()), &proof)
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(
        move_status(&world, &proof).await,
        "AlreadyUsed",
        "confirming spends it"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max's link runs out: it reads expired and confirms nothing. With it
/// he asks for another, nobody signed in: a new link reaches the address
/// the move waits on, the old one is dead, and the new one confirms the
/// move. Asked of Sam's company, or with an invented link, nothing is
/// found. The replacement is recorded once, with no link in the record.
#[tokio::test]
async fn an_expired_move_link_is_replaced_and_only_the_new_one_confirms() {
    let clock = Clock::controlled();
    let stack = Stack::start(
        Profile::standard()
            .with(
                "EMAIL_CHANGE_TTL_SECONDS",
                &LINK_LIFETIME.as_secs().to_string(),
            )
            .with("MAIL_COOLDOWN_SECONDS", "0"),
    )
    .await
    .expect("the stack starts");
    let world = World::new(&stack).await;
    let (old, address) = max_moves_mailbox(&world, "max-new").await;
    let plane = account::Plane::Member(world.org());

    clock.advance(PAST_THE_LINK);
    assert_eq!(
        move_status(&world, &old).await,
        "Expired",
        "the link ran out"
    );
    account::confirm_email(plane, &old)
        .send(world.anonymous().client())
        .await
        .refused(Status::GONE, "link_expired");
    refuse_replacements_nobody_asked_for(&world).await;

    account::resend_email(plane, &old)
        .send(world.anonymous().client())
        .await
        .ok();
    let mail = mail_linking_to(&world, &address, "/confirm-email-change").await;
    let fresh = LinkToken {
        token: mail.token_in("/confirm-email-change"),
    };
    assert_ne!(fresh.token, old.token, "a new link is mailed");

    account::confirm_email(plane, &old)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    account::confirm_email(plane, &fresh)
        .send(world.anonymous().client())
        .await
        .ok();

    let bob = bob_signed_in(&stack).await;
    let records = audit::platform_log_where(&[("event_type", MOVE_LINK_RESENT)])
        .send(&bob)
        .await
        .ok()
        .items;
    let [record] = records.as_slice() else {
        panic!("one {MOVE_LINK_RESENT} is recorded, not {}", records.len());
    };
    no_secret_leaked(&record.details.to_string(), &[&old.token, &fresh.token]);

    stack.stop().await.expect("the stack stops cleanly");
}

/// A replacement asked from a link nobody sent is not found, and records
/// nothing.
async fn refuse_replacements_nobody_asked_for(world: &World<'_>) {
    let invented = LinkToken {
        token: "an invented move link".to_owned(),
    };
    account::resend_email(account::Plane::Member(world.org()), &invented)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert_eq!(
        world.trail().count(MOVE_LINK_RESENT).await,
        0,
        "no refused replacement is recorded"
    );
}
