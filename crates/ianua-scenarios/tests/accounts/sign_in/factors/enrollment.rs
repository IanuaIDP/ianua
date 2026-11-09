//! A factor Acme requires of everyone: Ann, who proved her password and
//! her mailbox, reads nothing until the authenticator app or passkey she
//! sets up is confirmed, from the very sign-in that owed it. And a
//! self-hosted installation with no mail server still asks its owner for
//! a factor rather than letting her in on the password alone.

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{OrgPath, member_factors, members, organizations, sessions};
use ianua_scenarios::authenticators::{SoftPasskey, TotpApp};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Install, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::ConfirmFactor;
use ianua_scenarios::wire::organization::ReplaceOrgSignInSettings;
use ianua_scenarios::wire::sign_in::{
    ConfirmMemberPasskey, ConfirmSignIn, MemberProof, Owed, PasswordSignIn, Session, SignedIn,
};
use serde_json::json;

use crate::support::{QUIET, mail_linking_to};

/// Ann cannot read her account with password and mailbox proof alone
/// after setting Acme's two-factor baseline. Starting the authenticator
/// setup opens nothing either; the first
/// code from the app finishes that same sign-in, which then reads her
/// account.
#[tokio::test]
async fn a_required_authenticator_lets_nobody_in_until_its_code_is_confirmed() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let before = ann.signed_in(&stack).await;
    ann.client_mut().authorize(&before.refresh_token);
    require_factor(&ann, &org).await;

    let mut browser = Client::new(&stack, "Ann, setting up her factor").expect("a client");
    let waiting = owing_a_factor(&stack, &browser, ann.email()).await;
    browser.authorize(&waiting.refresh_token);
    reads_nothing(&browser, &org).await;

    let begun = member_factors::begin_required_totp(&org)
        .send(&browser)
        .await
        .ok();
    reads_nothing(&browser, &org).await;

    confirm_required_totp(&browser, &org, &waiting.session_id, &begun.otpauth_uri).await;
    assert_eq!(
        members::me(&org).send(&browser).await.ok().email,
        ann.email(),
        "the sign-in that owed the factor reads Ann's account once it is confirmed"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The first authenticator code completes the required enrollment and supplies recovery codes.
async fn confirm_required_totp(browser: &Client, org: &OrgPath, session_id: &str, otpauth: &str) {
    let mut phone = TotpApp::scanning(otpauth);
    let confirm = ConfirmFactor {
        code: phone.code().await,
        session_id: Some(session_id.to_owned()),
    };
    let printout = member_factors::confirm_totp(org, &confirm)
        .send(browser)
        .await
        .ok();
    assert!(
        !printout.recovery_codes.is_empty(),
        "a confirmed authenticator comes with recovery codes"
    );
}

/// Starting passkey setup does not complete Ann's required enrollment.
/// Her sign-in reads nothing until the attestation is accepted; the same
/// sign-in then reads her account without signing in again.
#[tokio::test]
async fn a_required_passkey_lets_nobody_in_until_it_is_attested() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let before = ann.signed_in(&stack).await;
    ann.client_mut().authorize(&before.refresh_token);
    require_factor(&ann, &org).await;

    let mut browser = Client::new(&stack, "Ann, setting up her passkey").expect("a client");
    let waiting = owing_a_factor(&stack, &browser, ann.email()).await;
    browser.authorize(&waiting.refresh_token);
    reads_nothing(&browser, &org).await;

    enroll_required_passkey(&stack, &browser, &org).await;
    assert_eq!(
        members::me(&org).send(&browser).await.ok().email,
        ann.email(),
        "the sign-in that owed the factor reads Ann's account once the passkey is attested"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The required passkey opens no access until its attestation is accepted on the waiting session.
async fn enroll_required_passkey(stack: &Stack, browser: &Client, org: &OrgPath) {
    let key = SoftPasskey::new(&stack.app_url());
    let begun = member_factors::begin_required_passkey(org)
        .send(browser)
        .await
        .ok();
    reads_nothing(browser, org).await;

    let registered = key.register(&begun.challenge);
    let confirm = ConfirmMemberPasskey {
        ceremony_id: begun.ceremony_id,
        response: registered.response,
        passkey_name: "Ann's required key".to_owned(),
        proof: None,
    };
    member_factors::confirm_passkey(org, &confirm)
        .send(browser)
        .await
        .ok();
}

/// On a fresh self-hosted installation without mail, Ann cannot sign in
/// with the installer's password alone. She reads nothing and cannot start
/// a factor setup
/// from it, and no mail goes out meanwhile.
#[tokio::test]
async fn a_deployment_without_mail_still_requires_a_factor() {
    let stack = Stack::start(Profile::without_mail().with("DEPLOYMENT", "self_hosted"))
        .await
        .expect("the stack starts");
    let email = format!("ann@{}", stack.base_domain());
    let install = Install {
        organization_name: "Acme".to_owned(),
        tenant_name: "Main".to_owned(),
        owner_email: email.clone(),
        owner_name: "Ann".to_owned(),
        owner_password: FOUNDER_PASSWORD.to_owned(),
    };
    stack
        .install(&install)
        .await
        .expect("the organization is installed");
    let org = OrgPath::new("acme");

    let browser = Client::new(&stack, "Ann, without a mail server").expect("a client");
    sessions::member_sign_in(&PasswordSignIn::of(&email, FOUNDER_PASSWORD))
        .send(&browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    reads_nothing(&browser, &org).await;
    member_factors::begin_required_totp(&org)
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    stack.mailbox().nothing_for(&email, QUIET).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann raises Acme's baseline to two factors and allows the authenticator
/// app, leaving every other sign-in setting as it was, with her password
/// typed again.
async fn require_factor(ann: &Founder, org: &OrgPath) {
    let mut settings = organizations::sign_in_settings(org)
        .send(ann.client())
        .await
        .ok();
    settings.rest.get_mut("step_up").expect("step-up policy")["baseline_aal"] = json!("Aal2");
    settings
        .rest
        .insert("second_factors".to_owned(), json!(["Totp"]));
    let replace = ReplaceOrgSignInSettings {
        settings,
        proof: MemberProof {
            password: FOUNDER_PASSWORD.to_owned(),
            code: None,
        },
    };
    organizations::replace_sign_in_settings(org, &replace)
        .send(ann.client())
        .await
        .ok();
}

/// The session Ann's password opens through `browser`, confirmed from her
/// mailbox, still owing the factor Acme now requires.
async fn owing_a_factor(stack: &Stack, browser: &Client, email: &str) -> Session {
    let answer = sessions::member_sign_in(&PasswordSignIn::of(email, FOUNDER_PASSWORD))
        .send(browser)
        .await
        .ok();
    let SignedIn::Authenticated(session) = answer else {
        panic!("Ann is in one organization, so no choice is offered");
    };
    assert_eq!(
        session.owed(),
        Owed::MailedConfirmation,
        "a browser Ann never remembered waits for her mailbox first"
    );
    let mail = mail_linking_to(stack, email, "/confirm-sign-in").await;
    let confirm = ConfirmSignIn {
        token: mail.token_in("/confirm-sign-in"),
        refresh_token: session.refresh_token.clone(),
    };
    let confirmed = sessions::confirm_member_sign_in(&confirm)
        .send(browser)
        .await
        .ok();
    assert!(
        confirmed.mfa_enrollment_required,
        "the mailed link leaves Ann owing the factor Acme requires"
    );
    session
}

/// The sign-in `browser` carries reads nothing of Ann's account.
async fn reads_nothing(browser: &Client, org: &OrgPath) {
    members::me(org)
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}
