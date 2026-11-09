//! Passkey answers the platform refuses: Mallory's phishing page relaying
//! Ann's ceremony, a copy of her key whose sign count did not go up, a
//! key Ann removed answering a challenge issued before, Bob's key from
//! another company answering a challenge for Ann's address, Ann's own
//! signature moved to another challenge, and a key added to her account
//! without her password. After each, the right key still signs in.

use ianua_scenarios::actors::Founder;
use ianua_scenarios::api::{OrgPath, member_factors, members};
use ianua_scenarios::authenticators::SoftPasskey;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::PasskeyAnswerBody;
use ianua_scenarios::wire::sign_in::{ConfirmMemberPasskey, MemberProof};
use url::Url;

use crate::factors::passkeys::{
    PasskeyHolder, answer, challenge, enrolled, registered_key, signed_in,
};
use crate::support::WRONG_GUESS;

/// Ann's passkey answer from Mallory's phishing page is refused because
/// it names that page's origin, and the browser reads
/// nothing. The same key, answering a fresh challenge from the real page,
/// signs Ann in.
#[tokio::test]
async fn a_member_passkey_from_a_phishing_origin_is_refused() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let PasskeyHolder { ann, org, mut key } = enrolled(&stack).await;
    let mut browser = Client::new(&stack, "Ann, on Mallory's phishing page").expect("a client");
    let phishing = Url::parse("https://login.phish.example/").expect("a URL");

    let begun = challenge(&browser, ann.email()).await;
    let relayed = answer(&mut key.on_page(&phishing), begun);
    member_factors::confirm_passkey_sign_in(&relayed)
        .send(&browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    members::me(&org)
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    let fresh = answer(&mut key, challenge(&browser, ann.email()).await);
    let session = signed_in(&browser, &fresh).await;
    browser.authorize(&session.refresh_token);
    members::me(&org).send(&browser).await.ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// After Ann's passkey signs in, a copy repeating its sign count is
/// refused as a cloned key;
/// the session the original opened goes on, and the original, counting
/// on, still signs in.
#[tokio::test]
async fn a_member_passkey_repeating_its_sign_count_is_refused() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let PasskeyHolder { ann, org, mut key } = enrolled(&stack).await;
    let mut browser = Client::new(&stack, "Ann, using a passkey").expect("a client");

    let good = answer(&mut key, challenge(&browser, ann.email()).await);
    let first = signed_in(&browser, &good).await;

    let begun = challenge(&browser, ann.email()).await;
    let copied = key.sign_in_repeating_count(&begun.challenge);
    let copied = PasskeyAnswerBody {
        ceremony_id: begun.ceremony_id,
        response: copied.response,
        credential_id: copied.credential_id,
    };
    member_factors::confirm_passkey_sign_in(&copied)
        .send(&browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    browser.authorize(&first.refresh_token);
    members::me(&org).send(&browser).await.ok();

    let fresh = answer(&mut key, challenge(&browser, ann.email()).await);
    let session = signed_in(&browser, &fresh).await;
    browser.authorize(&session.refresh_token);
    members::me(&org).send(&browser).await.ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Answering an outstanding challenge after Ann removes her passkey is
/// refused. The key is gone from her list, the answer grants no access
/// to her account; the session she removed it from goes on, and her
/// password still signs her in.
#[tokio::test]
async fn a_removed_passkey_cannot_finish_an_outstanding_sign_in() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let PasskeyHolder { ann, org, mut key } = enrolled(&stack).await;
    let browser = Client::new(&stack, "Ann, on another browser").expect("a client");

    let pending = answer(&mut key, challenge(&browser, ann.email()).await);
    remove_only_passkey(&ann, &org).await;

    member_factors::confirm_passkey_sign_in(&pending)
        .send(&browser)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    members::me(&org)
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    members::me(&org).send(ann.client()).await.ok();
    let session = ann.signed_in(&stack).await;
    members::me(&org)
        .header(
            "authorization",
            &format!("Bearer {}", session.refresh_token),
        )
        .send(ann.client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Bob's Globex passkey is refused when it answers a challenge for Ann's
/// address, and the browser cannot read an account. Bob's key signs Bob in,
/// to Globex only, and Ann's key signs
/// Ann in to Acme.
#[tokio::test]
async fn another_members_passkey_cannot_answer_an_email_challenge() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let PasskeyHolder { ann, org, mut key } = enrolled(&stack).await;
    let mut bob = Founder::named(&stack, "Bob");
    let founded = bob.founded(&stack, "Globex").await;
    let other = OrgPath::new(&founded.org_slug);
    let session = bob.signed_in(&stack).await;
    bob.client_mut().authorize(&session.refresh_token);
    let mut bobs_key = registered_key(&stack, &bob, &other, None).await;
    let mut browser = Client::new(&stack, "Bob, naming Ann's address").expect("a client");

    let crossed = answer(&mut bobs_key, challenge(&browser, ann.email()).await);
    assert_answer_grants_no_access(&browser, &org, &crossed).await;

    sign_in_as_bob(&mut browser, &bob, &other, &mut bobs_key).await;
    members::me(&org)
        .send(&browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let anns_answer = answer(&mut key, challenge(ann.client(), ann.email()).await);
    let anns_session = signed_in(ann.client(), &anns_answer).await;
    assert_eq!(
        anns_session.org_slug,
        org.slug(),
        "Ann's key signs Ann in to Acme"
    );
    members::me(&other).send(&browser).await.ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann's signature is refused when sent with another challenge's ceremony
/// identifier. The browser reads nothing, and the
/// ceremony it named is spent by the refusal; the signature sent for the
/// ceremony it was made for still opens Ann's account.
#[tokio::test]
async fn a_passkey_answer_cannot_be_moved_to_another_challenge() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let PasskeyHolder { ann, org, mut key } = enrolled(&stack).await;
    let mut browser = Client::new(&stack, "Ann, with two sign-in tabs").expect("a client");

    let first = challenge(&browser, ann.email()).await;
    let second = challenge(&browser, ann.email()).await;
    let original = answer(&mut key, first);
    let substituted = PasskeyAnswerBody {
        ceremony_id: second.ceremony_id.clone(),
        ..original.clone()
    };
    assert_answer_grants_no_access(&browser, &org, &substituted).await;

    let spent = answer(&mut key, second);
    member_factors::confirm_passkey_sign_in(&spent)
        .send(&browser)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    let session = signed_in(&browser, &original).await;
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(&org).send(&browser).await.ok().email,
        ann.email(),
        "the signature opens the account for the ceremony it was made for"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory cannot add a passkey with Ann's session and a wrong password.
/// Ann's list is unchanged and her session goes on. Ann
/// adds a key with the right password, and it signs her in.
#[tokio::test]
async fn adding_a_passkey_needs_the_right_password() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let PasskeyHolder { ann, org, .. } = enrolled(&stack).await;
    let before = member_factors::passkeys(&org).send(ann.client()).await.ok();

    refuse_unproved_key(&stack, &ann, &org).await;
    let after = member_factors::passkeys(&org).send(ann.client()).await.ok();
    assert_eq!(
        after.passkeys.len(),
        before.passkeys.len(),
        "the refused key was not added"
    );
    assert_eq!(
        after.passkeys[0].id, before.passkeys[0].id,
        "Ann's own key is still listed"
    );
    members::me(&org).send(ann.client()).await.ok();

    let mut proved = registered_key(&stack, &ann, &org, None).await;
    let mut browser = Client::new(&stack, "Ann, using her new key").expect("a client");
    let own = answer(&mut proved, challenge(&browser, ann.email()).await);
    let session = signed_in(&browser, &own).await;
    browser.authorize(&session.refresh_token);
    members::me(&org).send(&browser).await.ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Removing Ann's only passkey leaves her registered-key list empty.
async fn remove_only_passkey(ann: &Founder, org: &OrgPath) {
    let listed = member_factors::passkeys(org).send(ann.client()).await.ok();
    assert_eq!(
        listed.passkeys.len(),
        1,
        "Ann has the one passkey she added"
    );
    member_factors::remove_passkey(org, &listed.passkeys[0].id)
        .send(ann.client())
        .await
        .ok();
    let left = member_factors::passkeys(org).send(ann.client()).await.ok();
    assert!(
        left.passkeys.is_empty(),
        "the removed passkey is gone from Ann's list"
    );
}

/// Bob's own address accepts his key and opens his Globex account.
async fn sign_in_as_bob(
    browser: &mut Client,
    bob: &Founder,
    other: &OrgPath,
    key: &mut SoftPasskey,
) {
    let own = answer(key, challenge(browser, bob.email()).await);
    let session = signed_in(browser, &own).await;
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(other).send(browser).await.ok().email,
        bob.email(),
        "Bob's key signs Bob in to Globex"
    );
}

/// An answer that does not match its challenge is refused and grants no account access.
async fn assert_answer_grants_no_access(
    browser: &Client,
    org: &OrgPath,
    signed: &PasskeyAnswerBody,
) {
    member_factors::confirm_passkey_sign_in(signed)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    members::me(org)
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// A valid registration response cannot add Mallory's key with a wrong password.
async fn refuse_unproved_key(stack: &Stack, ann: &Founder, org: &OrgPath) {
    let mallorys_key = SoftPasskey::new(&stack.app_url());
    let begun = member_factors::begin_passkey(org)
        .send(ann.client())
        .await
        .ok();
    let attested = mallorys_key.register(&begun.challenge);
    let confirm = ConfirmMemberPasskey {
        ceremony_id: begun.ceremony_id,
        response: attested.response,
        passkey_name: "An unproved key".to_owned(),
        proof: Some(MemberProof {
            password: WRONG_GUESS.to_owned(),
            code: None,
        }),
    };
    member_factors::confirm_passkey(org, &confirm)
        .send(ann.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}
