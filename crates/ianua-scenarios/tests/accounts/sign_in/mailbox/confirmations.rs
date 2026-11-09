//! The link mailed to Ann to confirm a sign-in from a device she never
//! remembered: it finishes the one sign-in it was mailed for, once, and
//! only while it is fresh. Mallory, who got hold of Ann's password, gets
//! a waiting sign-in that no made-up or borrowed link finishes.

use std::time::Duration;

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{OrgPath, members, sessions};
use ianua_scenarios::expect::{Trail, assert_clean_refusal, no_secret_leaked};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sign_in::{ConfirmSignIn, Owed, PasswordSignIn, Session, SignedIn};

use crate::support::{mail_linking_to, past_lifetime};

/// How long a confirmation link is worth something in the expiry
/// scenario: short enough to wait for on the real clock, which the API,
/// database and cache share.
const CONFIRMATION_LIFETIME_SECONDS: u64 = 2;

/// Ann's phone session and its proof deliberately paired with the waiting laptop first.
struct PhoneSignIn {
    /// The separate browser whose session will eventually be confirmed.
    client: Client,
    /// The phone's pending session credentials.
    session: Session,
    /// The phone's proof paired with the laptop's session credential.
    crossed: ConfirmSignIn,
}

/// Mallory, who got hold of Ann's password, signs in from her own device:
/// the sign-in waits for Ann's mailbox, reads nothing meanwhile, and no
/// token Mallory makes up finishes it. Ann, mailed about a sign-in she
/// never made, leaves that link alone and signs in herself: her own link
/// finishes her own sign-in, once; used again it answers that nothing is
/// owed, and in Mallory's hands it finishes nothing.
#[tokio::test]
async fn a_waiting_sign_in_is_finished_only_by_its_own_link() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    ann.signed_in(&stack).await;

    let mut mallory = Client::new(&stack, "Mallory, with Ann's password").expect("a client");
    let waiting = assert_attacker_waits(&stack, &ann, &mut mallory, &org).await;
    let own_link = confirm_owner_once(&stack, &mut ann, &org).await;
    assert_spent_link_refused(&org, &mallory, &waiting, &own_link).await;

    let trail = Trail::of_organization(ann.client(), &founded.org_slug);
    let confirmed = trail.recorded("organization.org_mfa_verified").await;
    no_secret_leaked(
        &confirmed.details.to_string(),
        &[
            &own_link.token,
            &own_link.refresh_token,
            &waiting.refresh_token,
        ],
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Knowing Ann's password still leaves Mallory waiting, and a fabricated mailbox proof is refused.
async fn assert_attacker_waits(
    stack: &Stack,
    ann: &Founder,
    mallory: &mut Client,
    org: &OrgPath,
) -> Session {
    let answer = sessions::member_sign_in(&PasswordSignIn::of(ann.email(), FOUNDER_PASSWORD))
        .send(mallory)
        .await
        .ok();
    let SignedIn::Authenticated(waiting) = answer else {
        panic!("Ann is in one organization, so no choice is offered");
    };
    assert_eq!(
        waiting.owed(),
        Owed::MailedConfirmation,
        "a device Ann never remembered waits for her mailbox"
    );
    mallory.authorize(&waiting.refresh_token);
    members::me(org)
        .send(mallory)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let about_mallory = mail_linking_to(stack, ann.email(), "/confirm-sign-in").await;
    assert_eq!(
        about_mallory.recipient(),
        ann.email(),
        "the link for Mallory's sign-in goes to Ann's mailbox"
    );
    assert_fabricated_proof(mallory, &waiting).await;
    waiting
}

/// A fabricated mailbox token cannot finish the session opened with Ann's password.
async fn assert_fabricated_proof(mallory: &Client, waiting: &Session) {
    let made_up = ConfirmSignIn {
        token: "a-token-mallory-made-up".to_owned(),
        refresh_token: waiting.refresh_token.clone(),
    };
    sessions::confirm_member_sign_in(&made_up)
        .send(mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// Ann's own mailbox proof confirms her own waiting session once.
async fn confirm_owner_once(stack: &Stack, ann: &mut Founder, org: &OrgPath) -> ConfirmSignIn {
    let own = ann.password_sign_in().await;
    assert_eq!(
        own.owed(),
        Owed::MailedConfirmation,
        "Ann's own device, never remembered, waits for her mailbox too"
    );
    let own_mail = mail_linking_to(stack, ann.email(), "/confirm-sign-in").await;
    let own_link = ConfirmSignIn {
        token: own_mail.token_in("/confirm-sign-in"),
        refresh_token: own.refresh_token.clone(),
    };
    sessions::confirm_member_sign_in(&own_link)
        .send(ann.client())
        .await
        .ok();
    ann.client_mut().authorize(&own.refresh_token);
    members::me(org).send(ann.client()).await.ok();
    sessions::confirm_member_sign_in(&own_link)
        .send(ann.client())
        .await
        .refused(Status::CONFLICT, "conflict");
    own_link
}

/// Ann's consumed proof cannot finish Mallory's pending session or grant account access.
async fn assert_spent_link_refused(
    org: &OrgPath,
    mallory: &Client,
    waiting: &Session,
    own_link: &ConfirmSignIn,
) {
    let anns_link_in_mallorys_hands = ConfirmSignIn {
        token: own_link.token.clone(),
        refresh_token: waiting.refresh_token.clone(),
    };
    let replayed = sessions::confirm_member_sign_in(&anns_link_in_mallorys_hands)
        .send(mallory)
        .await;
    assert_clean_refusal("Ann's spent link on Mallory's waiting sign-in", &replayed);
    members::me(org)
        .send(mallory)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Ann's password is accepted on her laptop and then on her phone, and
/// each sign-in waits for the link mailed for it. The phone's link, tried
/// on the laptop's sign-in, finishes nothing, and the phone still reads
/// nothing. On the phone's own sign-in the same link finishes it: the
/// phone reads Ann's record, and the laptop's waiting sign-in is ended.
#[tokio::test]
async fn an_unused_confirmation_link_cannot_finish_another_session() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let on_laptop = ann.password_sign_in().await;
    assert_eq!(
        on_laptop.owed(),
        Owed::MailedConfirmation,
        "the laptop, never remembered, waits for Ann's mailbox"
    );
    mail_linking_to(&stack, ann.email(), "/confirm-sign-in").await;

    let phone = begin_phone_sign_in(&stack, &ann, &on_laptop).await;
    assert_phone_link_binding(&mut ann, &org, &on_laptop, phone).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The phone receives its own waiting session and proof, initially paired with the laptop token.
async fn begin_phone_sign_in(stack: &Stack, ann: &Founder, on_laptop: &Session) -> PhoneSignIn {
    let mut phone = Client::new(stack, "Ann, on her phone").expect("a client");
    let answer = sessions::member_sign_in(&PasswordSignIn::of(ann.email(), FOUNDER_PASSWORD))
        .send(&phone)
        .await
        .ok();
    let SignedIn::Authenticated(on_phone) = answer else {
        panic!("Ann is in one organization, so no choice is offered");
    };
    assert_eq!(
        on_phone.owed(),
        Owed::MailedConfirmation,
        "the phone, never remembered, waits for Ann's mailbox too"
    );
    let phones_mail = mail_linking_to(stack, ann.email(), "/confirm-sign-in").await;
    phone.authorize(&on_phone.refresh_token);

    let crossed = ConfirmSignIn {
        token: phones_mail.token_in("/confirm-sign-in"),
        refresh_token: on_laptop.refresh_token.clone(),
    };
    PhoneSignIn {
        client: phone,
        session: on_phone,
        crossed,
    }
}

/// A cross-session attempt preserves the proof, which then admits the phone and ends the laptop.
async fn assert_phone_link_binding(
    ann: &mut Founder,
    org: &OrgPath,
    on_laptop: &Session,
    phone: PhoneSignIn,
) {
    let PhoneSignIn {
        client: phone,
        session: on_phone,
        crossed,
    } = phone;
    assert_crossed_link_refused(ann, org, &phone, &crossed).await;

    let rightful = ConfirmSignIn {
        refresh_token: on_phone.refresh_token.clone(),
        ..crossed
    };
    sessions::confirm_member_sign_in(&rightful)
        .send(&phone)
        .await
        .ok();
    assert_eq!(
        members::me(org).send(&phone).await.ok().email,
        ann.email(),
        "the phone's own link finishes the phone's sign-in"
    );
    ann.client_mut().authorize(&on_laptop.refresh_token);
    members::me(org)
        .send(ann.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// A phone's proof paired with the laptop token finishes neither session.
async fn assert_crossed_link_refused(
    ann: &Founder,
    org: &OrgPath,
    phone: &Client,
    crossed: &ConfirmSignIn,
) {
    sessions::confirm_member_sign_in(crossed)
        .send(ann.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    members::me(org)
        .send(phone)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Ann signs in and her confirmation link is mailed, but she follows it
/// only once it has expired: it leaves her sign-in waiting, and her
/// browser reads nothing. She signs in again, follows the fresh link, and
/// is in.
#[tokio::test]
async fn an_expired_confirmation_link_leaves_the_session_waiting() {
    let stack = Stack::start(Profile::standard().with(
        "AUTH_SIGN_IN_CONFIRMATION_TTL_SECONDS",
        &CONFIRMATION_LIFETIME_SECONDS.to_string(),
    ))
    .await
    .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let waiting = ann.password_sign_in().await;
    assert_eq!(
        waiting.owed(),
        Owed::MailedConfirmation,
        "a device Ann never remembered waits for her mailbox"
    );
    let mail = mail_linking_to(&stack, ann.email(), "/confirm-sign-in").await;
    ann.client_mut().authorize(&waiting.refresh_token);
    let stale = ConfirmSignIn {
        token: mail.token_in("/confirm-sign-in"),
        refresh_token: waiting.refresh_token,
    };

    assert_expired_confirmation(&ann, &org, &stale).await;

    let fresh = ann.signed_in(&stack).await;
    ann.client_mut().authorize(&fresh.refresh_token);
    members::me(&org).send(ann.client()).await.ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Expiry refuses the issued proof and leaves the authorized browser unable to read its account.
async fn assert_expired_confirmation(ann: &Founder, org: &OrgPath, stale: &ConfirmSignIn) {
    past_lifetime(Duration::from_secs(CONFIRMATION_LIFETIME_SECONDS)).await;
    sessions::confirm_member_sign_in(stale)
        .send(ann.client())
        .await
        .refused(Status::GONE, "link_expired");
    members::me(org)
        .send(ann.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}
