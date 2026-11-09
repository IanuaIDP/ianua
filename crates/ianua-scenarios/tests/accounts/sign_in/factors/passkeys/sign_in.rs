//! Ann signs in with her passkey: naming her address, or with the key
//! alone, which names its own account; with an authenticator app set up
//! too, no code is asked. Each answer opens a session that owes nothing
//! and ends her earlier one, and is good once; two browsers sending the
//! same answer at once open one session.

use ianua_scenarios::api::{OrgPath, member_factors, members, sessions};
use ianua_scenarios::authenticators::SoftPasskey;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Trail, no_secret_leaked};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::PasskeyAnswerBody;
use ianua_scenarios::wire::sign_in::{Owed, Session};

use crate::factors::passkeys::{
    PasskeyHolder, answer, challenge, enrolled, enrolled_with_authenticator, signed_in,
};
use crate::support::session_won_once;

/// Ann types her address and signs the challenge for it: the session owes
/// no password, mailbox or code, reads her account and ends the one she
/// held. The same answer sent again is refused and ends nothing. The
/// record holds no token.
#[tokio::test]
async fn an_address_and_a_passkey_sign_in_with_no_password_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let PasskeyHolder { ann, org, mut key } = enrolled(&stack).await;
    let mut browser = Client::new(&stack, "Ann, using a passkey").expect("a client");

    let signed = answer(&mut key, challenge(&browser, ann.email()).await);
    let session = signed_in(&browser, &signed).await;
    assert_eq!(
        session.owed(),
        Owed::Nothing,
        "a passkey sign-in owes nothing more"
    );
    assert_eq!(
        session.org_slug,
        org.slug(),
        "the session is in Ann's organization"
    );
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(&org).send(&browser).await.ok().email,
        ann.email(),
        "the session reads Ann's account"
    );
    members::me(&org)
        .send(ann.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    assert_replay_preserves_session(&browser, &org, &signed, &session).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann types no address: the key she picks names her account and
/// organization by itself. The session owes nothing, reads her account
/// and ends the one she held; the same answer sent again is refused.
#[tokio::test]
async fn a_discoverable_passkey_names_its_own_account_without_an_email() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let PasskeyHolder { ann, org, mut key } = enrolled(&stack).await;
    let mut browser = Client::new(&stack, "Ann, using a passkey").expect("a client");

    let signed = discoverable_answer(&browser, &mut key).await;
    let session = signed_in(&browser, &signed).await;
    assert_eq!(
        session.owed(),
        Owed::Nothing,
        "a passkey sign-in owes nothing more"
    );
    assert_eq!(
        session.org_slug,
        org.slug(),
        "the key names Ann's organization"
    );
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(&org).send(&browser).await.ok().email,
        ann.email(),
        "the key names Ann's account"
    );
    members::me(&org)
        .send(ann.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    assert_replay_preserves_session(&browser, &org, &signed, &session).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann set up an authenticator app before adding her passkey. The passkey
/// already proves she holds it and is present, so her sign-in with it
/// owes no code from the app: it reads her account at once, ends the
/// session she held, and is good once. The application clock moves to the
/// fresh code that proves her when the key is added.
#[tokio::test]
async fn a_passkey_owes_no_code_even_with_an_authenticator_set_up() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let PasskeyHolder { ann, org, mut key } = enrolled_with_authenticator(&stack).await;
    let mut browser = Client::new(&stack, "Ann, using a passkey").expect("a client");

    let signed = answer(&mut key, challenge(&browser, ann.email()).await);
    let session = signed_in(&browser, &signed).await;
    assert_eq!(
        session.owed(),
        Owed::Nothing,
        "the passkey stands for the authenticator's code too"
    );
    assert_eq!(
        session.org_slug,
        org.slug(),
        "the session is in Ann's organization"
    );
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(&org).send(&browser).await.ok().email,
        ann.email(),
        "the session reads Ann's account"
    );
    members::me(&org)
        .send(ann.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    assert_replay_preserves_session(&browser, &org, &signed, &session).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Two of Ann's browsers send the same signed answer at the same moment.
/// One opens a session, which stays usable after the other is refused,
/// and it is the only live session.
#[tokio::test]
async fn simultaneous_passkey_answers_open_only_one_session() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let PasskeyHolder { ann, org, mut key } = enrolled(&stack).await;
    let mut browser = Client::new(&stack, "Ann, sending a passkey answer").expect("a client");
    let duplicate = Client::new(&stack, "Ann's other tab, sending it too").expect("a client");

    let signed = answer(&mut key, challenge(&browser, ann.email()).await);
    let first = member_factors::confirm_passkey_sign_in(&signed);
    let second = member_factors::confirm_passkey_sign_in(&signed);
    let (first, second) = tokio::join!(first.send(&browser), second.send(&duplicate));
    let session = session_won_once(
        [first, second],
        Status::UNPROCESSABLE_ENTITY,
        "domain_error",
    );

    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(&org).send(&browser).await.ok().email,
        ann.email(),
        "the one session opened reads Ann's account"
    );
    assert_only_session(&browser, &org, &session).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The key signs a discoverable challenge without supplying an account address.
async fn discoverable_answer(browser: &Client, key: &mut SoftPasskey) -> PasskeyAnswerBody {
    let begun = member_factors::begin_discoverable_sign_in()
        .send(browser)
        .await
        .ok();
    answer(key, begun)
}

/// Reusing the answer is refused without ending the session, whose login
/// record contains no refresh token.
async fn assert_replay_preserves_session(
    browser: &Client,
    org: &OrgPath,
    signed: &PasskeyAnswerBody,
    session: &Session,
) {
    member_factors::confirm_passkey_sign_in(signed)
        .send(browser)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    members::me(org).send(browser).await.ok();
    let record = Trail::of_organization(browser, org.slug())
        .recorded("organization.org_login_succeeded")
        .await;
    no_secret_leaked(&record.details.to_string(), &[&session.refresh_token]);
}

/// The simultaneous answers leave exactly the winning session active.
async fn assert_only_session(browser: &Client, org: &OrgPath, session: &Session) {
    let active = sessions::member_sessions(org).send(browser).await.ok();
    assert_eq!(
        active.items.len(),
        1,
        "the refused duplicate opened no second session"
    );
    assert_eq!(
        active.items[0].session_id, session.session_id,
        "the one live session is the one the answer opened"
    );
}
