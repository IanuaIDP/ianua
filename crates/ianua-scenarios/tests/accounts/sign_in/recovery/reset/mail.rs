//! Ann forgets her password. Mallory asks for Ann's reset and is answered
//! as anyone is, but the link lands in Ann's mailbox; it is worth
//! something until Ann spends it, once, on a password that meets the
//! rules, and then every session she held is dead. With an authenticator
//! app set up, the link alone replaces nothing: the reset needs the app's
//! code, and the new password still owes it at sign-in.

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{OrgPath, member_factors, members, sessions};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Trail, no_secret_leaked};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{BREACHED_PASSWORDS, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::FactorCode;
use ianua_scenarios::wire::sign_in::{
    ConfirmMemberPasswordReset, MemberPasswordResetFor, Owed, PasswordSignIn, ResetLinkToken,
    SignedIn,
};

use crate::support::{mail_linking_to, settled_sign_in};

/// The password Ann chooses after forgetting the first: a sentence, so no
/// scanner takes it for a key.
const NEW_PASSWORD: &str = "Scenario replaced lantern meadow 9317";

/// Ann is signed in. Mallory asks for a reset link to Ann's address and
/// is answered as anyone is; the link lands in Ann's mailbox, and reads
/// as valid. Mallory's made-up token sets nothing. Ann sets a breached
/// password and is refused, then a good one: the link now reads as used,
/// the session she held is dead, her old password opens nothing and her
/// new one signs her in. The spent link sets nothing more, and the trail
/// holds no password or token.
#[tokio::test]
async fn a_forgotten_password_is_reset_by_mail_and_every_session_ends() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let before = ann.signed_in(&stack).await;
    ann.client_mut().authorize(&before.refresh_token);

    let mallory = Client::new(&stack, "Mallory, asking for Ann's reset").expect("a client");
    let token = request_founder_reset(&stack, &ann, &mallory).await;
    reject_fabricated_token(&mallory).await;
    let browser = Client::new(&stack, "Ann, resetting her password").expect("a client");
    let good = replace_unbreached_password(&browser, &token).await;
    sign_in_after_reset(&stack, &mut ann, &org, &browser).await;
    sessions::confirm_member_password_reset(&good)
        .send(&mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");

    assert_reset_record(&ann, &org, &token).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann's password-change record contains neither password nor the reset token.
async fn assert_reset_record(ann: &Founder, org: &OrgPath, token: &str) {
    let trail = Trail::of_organization(ann.client(), org.slug());
    let changed = trail
        .recorded("organization.org_user_password_changed")
        .await;
    no_secret_leaked(
        &changed.details.to_string(),
        &[FOUNDER_PASSWORD, NEW_PASSWORD, token],
    );
}

/// A public reset request mails Ann alone and produces a valid link.
async fn request_founder_reset(stack: &Stack, ann: &Founder, mallory: &Client) -> String {
    let for_ann = MemberPasswordResetFor {
        email: ann.email().to_owned(),
    };
    sessions::request_member_password_reset(&for_ann)
        .send(mallory)
        .await
        .ok();
    let mail = mail_linking_to(stack, ann.email(), "/reset-password").await;
    assert_eq!(
        mail.recipient(),
        ann.email(),
        "the link reaches Ann's mailbox alone"
    );
    let token = mail.token_in("/reset-password");
    let asked = ResetLinkToken {
        token: token.clone(),
    };
    let worth = sessions::member_reset_link_status(&asked)
        .send(mallory)
        .await
        .ok();
    assert_eq!(worth.status, "Valid", "a fresh link reads as valid");
    token
}

/// A fabricated token cannot set the chosen password.
async fn reject_fabricated_token(mallory: &Client) {
    let made_up = ConfirmMemberPasswordReset {
        token: "a-token-mallory-made-up".to_owned(),
        password: NEW_PASSWORD.to_owned(),
        mfa_code: None,
    };
    sessions::confirm_member_password_reset(&made_up)
        .send(mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// A breached password is refused; the accepted replacement spends the same reset link.
async fn replace_unbreached_password(browser: &Client, token: &str) -> ConfirmMemberPasswordReset {
    let breached = ConfirmMemberPasswordReset {
        token: token.to_owned(),
        password: BREACHED_PASSWORDS[0].to_owned(),
        mfa_code: None,
    };
    sessions::confirm_member_password_reset(&breached)
        .send(browser)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let good = ConfirmMemberPasswordReset {
        token: token.to_owned(),
        password: NEW_PASSWORD.to_owned(),
        mfa_code: None,
    };
    sessions::confirm_member_password_reset(&good)
        .send(browser)
        .await
        .ok();
    let worth = sessions::member_reset_link_status(&ResetLinkToken {
        token: token.to_owned(),
    })
    .send(browser)
    .await
    .ok();
    assert_eq!(worth.status, "AlreadyUsed", "the spent link reads as used");
    good
}

/// The previous session and password stop working, while the new password opens Ann's account.
async fn sign_in_after_reset(stack: &Stack, ann: &mut Founder, org: &OrgPath, browser: &Client) {
    members::me(org)
        .send(ann.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    sessions::member_sign_in(&PasswordSignIn::of(ann.email(), FOUNDER_PASSWORD))
        .send(browser)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let after = settled_sign_in(
        stack,
        browser,
        &PasswordSignIn::of(ann.email(), NEW_PASSWORD),
    )
    .await;
    ann.client_mut().authorize(&after.refresh_token);
    members::me(org).send(ann.client()).await.ok();
}

/// Ann set up an authenticator app, then forgets her password. The
/// mailed link alone does not replace it: without a code the reset is
/// refused, and so is a wrong code. With the code from her phone the
/// password is set, and signing in with it still asks for the code. The
/// application clock advances to each fresh code without changing its rules.
#[tokio::test]
async fn a_reset_with_an_authenticator_app_needs_its_code() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let first = ann.signed_in(&stack).await;
    let mut phone = ann.set_up_authenticator(&founded.org_slug, &first).await;

    let for_ann = MemberPasswordResetFor {
        email: ann.email().to_owned(),
    };
    sessions::request_member_password_reset(&for_ann)
        .send(ann.client())
        .await
        .ok();
    let mail = mail_linking_to(&stack, ann.email(), "/reset-password").await;
    let token = mail.token_in("/reset-password");
    let browser = Client::new(&stack, "Ann, resetting her password").expect("a client");
    reset_with_phone(&browser, token, &mut phone).await;
    sign_in_with_phone(&stack, &ann, &org, &mut phone).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Missing and wrong codes fail before a current authenticator code permits the reset.
async fn reset_with_phone(browser: &Client, token: String, phone: &mut TotpApp) {
    let without_a_code = ConfirmMemberPasswordReset {
        token,
        password: NEW_PASSWORD.to_owned(),
        mfa_code: None,
    };
    sessions::confirm_member_password_reset(&without_a_code)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "step_up_required");
    let wrong_code = ConfirmMemberPasswordReset {
        mfa_code: Some("000000".to_owned()),
        ..without_a_code.clone()
    };
    sessions::confirm_member_password_reset(&wrong_code)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let with_the_code = ConfirmMemberPasswordReset {
        mfa_code: Some(phone.code().await),
        ..without_a_code
    };
    sessions::confirm_member_password_reset(&with_the_code)
        .send(browser)
        .await
        .ok();
}

/// The reset password still owes a factor, and its answer opens the founder's account.
async fn sign_in_with_phone(stack: &Stack, ann: &Founder, org: &OrgPath, phone: &mut TotpApp) {
    let mut tablet = Client::new(stack, "Ann, on her tablet").expect("a client");
    let answer = sessions::member_sign_in(&PasswordSignIn::of(ann.email(), NEW_PASSWORD))
        .send(&tablet)
        .await
        .ok();
    let SignedIn::Authenticated(waiting) = answer else {
        panic!("Ann is in one organization, so no choice is offered");
    };
    assert_eq!(
        waiting.owed(),
        Owed::FactorCode,
        "the new password still owes the phone's code"
    );
    tablet.authorize(&waiting.refresh_token);
    let code = FactorCode {
        code: phone.code().await,
    };
    member_factors::verify(org, &code).send(&tablet).await.ok();
    members::me(org).send(&tablet).await.ok();
}
