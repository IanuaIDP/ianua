//! Ann, without her phone, types a printed recovery code: it finishes one
//! sign-in and is spent, while the next code on the printout still works.
//! Bob, who founded another company with the same password, cannot use
//! Ann's code on his own sign-in, and his refusal does not spend it. Two
//! of Ann's browsers sending one code at once finish the sign-in once.

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{OrgPath, member_factors, members, sessions};
use ianua_scenarios::authenticators::{RecoveryCodes, TotpApp};
use ianua_scenarios::expect::{Trail, no_secret_leaked};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::factors::ConfirmFactor;
use ianua_scenarios::wire::sign_in::{
    MemberFactorSetup, MemberProof, MemberRecoveryCode, Owed, PasswordSignIn, Session, SignedIn,
};
use ianua_scenarios::wire::{Answer, Status};

use crate::recovery::codes::support::recovered_session;

/// A founder signed in to their company with the recovery printout from enrollment.
struct RecoveryOwner {
    founder: Founder,
    org: OrgPath,
    codes: RecoveryCodes,
}

/// Founds the company, authorizes its founder, and enrolls their authenticator app.
async fn recovery_owner(stack: &Stack, name: &str, company: &str) -> RecoveryOwner {
    let mut founder = Founder::named(stack, name);
    let founded = founder.founded(stack, company).await;
    let org = OrgPath::new(&founded.org_slug);
    let session = founder.signed_in(stack).await;
    founder.client_mut().authorize(&session.refresh_token);
    let codes = recovery_codes(&founder, &org).await;
    RecoveryOwner {
        founder,
        org,
        codes,
    }
}

/// Ann set up an authenticator app and kept its printout. Without her
/// phone she signs in and types a printed code, which lets her in. On her
/// next sign-in the same code opens nothing, while the next code on the
/// printout lets her in. The record holds no code.
#[tokio::test]
async fn a_recovery_code_stands_in_for_the_lost_phone_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = recovery_owner(&stack, "Ann", "Acme").await;

    let spent = MemberRecoveryCode {
        code: ann.codes.take(),
    };
    let mut browser = Client::new(&stack, "Ann, without her phone").expect("a client");
    let waiting = waiting_for_factor(&browser, ann.founder.email()).await;
    browser.authorize(&waiting.refresh_token);
    members::me(&ann.org)
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    recovered_session(&browser, &ann.org, &spent).await;

    let next = waiting_for_factor(&browser, ann.founder.email()).await;
    browser.authorize(&next.refresh_token);
    refused_code(&browser, &ann.org, &spent).await;
    let unused = MemberRecoveryCode {
        code: ann.codes.take(),
    };
    recovered_session(&browser, &ann.org, &unused).await;

    let record = Trail::of_organization(&browser, ann.org.slug())
        .recorded("organization.org_mfa_verified")
        .await;
    let secrets: Vec<&str> = ann.codes.all().iter().map(String::as_str).collect();
    no_secret_leaked(&record.details.to_string(), &secrets);

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann and Bob, who founded Globex with the same password, each hold a
/// printout. Bob types one of Ann's codes on his own sign-in: it is
/// refused and he reads nothing; his own code lets him in, to Globex
/// only. Ann's code, unspent by the refusal, still lets Ann in. The
/// record holds neither code.
#[tokio::test]
async fn another_members_recovery_code_is_refused_without_spending_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = recovery_owner(&stack, "Ann", "Acme").await;
    let mut bob = recovery_owner(&stack, "Bob", "Globex").await;

    let mut browser = Client::new(&stack, "Bob, with Ann's recovery code").expect("a client");
    let waiting = waiting_for_factor(&browser, bob.founder.email()).await;
    browser.authorize(&waiting.refresh_token);
    let anns_code = MemberRecoveryCode {
        code: ann.codes.take(),
    };
    refused_code(&browser, &bob.org, &anns_code).await;

    let bobs_code = MemberRecoveryCode {
        code: bob.codes.take(),
    };
    recovered_session(&browser, &bob.org, &bobs_code).await;
    members::me(&ann.org)
        .send(&browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let waiting = waiting_for_factor(ann.founder.client(), ann.founder.email()).await;
    ann.founder.client_mut().authorize(&waiting.refresh_token);
    recovered_session(ann.founder.client(), &ann.org, &anns_code).await;
    members::me(&bob.org).send(&browser).await.ok();

    assert_codes_hidden(&ann, &anns_code, &bobs_code).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann's recorded factor answer exposes neither her own code nor Bob's.
async fn assert_codes_hidden(
    ann: &RecoveryOwner,
    anns_code: &MemberRecoveryCode,
    bobs_code: &MemberRecoveryCode,
) {
    let record = Trail::of_organization(ann.founder.client(), ann.org.slug())
        .recorded("organization.org_mfa_verified")
        .await;
    no_secret_leaked(
        &record.details.to_string(),
        &[&anns_code.code, &bobs_code.code],
    );
}

/// Two of Ann's browsers send the same recovery code at the same moment.
/// One is accepted and the sign-in reads her account; the other is
/// refused. On her next sign-in the code is spent, and the next one on
/// the printout lets her in.
#[tokio::test]
async fn simultaneous_recovery_codes_finish_the_session_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = recovery_owner(&stack, "Ann", "Acme").await;

    let code = MemberRecoveryCode {
        code: ann.codes.take(),
    };
    let mut browser = Client::new(&stack, "Ann, sending a recovery code").expect("a client");
    let waiting = waiting_for_factor(&browser, ann.founder.email()).await;
    browser.authorize(&waiting.refresh_token);
    redeem_twice(&browser, &ann.org, &code).await;

    let next = waiting_for_factor(&browser, ann.founder.email()).await;
    browser.authorize(&next.refresh_token);
    refused_code(&browser, &ann.org, &code).await;
    let unused = MemberRecoveryCode {
        code: ann.codes.take(),
    };
    recovered_session(&browser, &ann.org, &unused).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// One concurrent redemption succeeds; its duplicate fails and the session remains usable.
async fn redeem_twice(browser: &Client, org: &OrgPath, code: &MemberRecoveryCode) {
    let first = member_factors::redeem_recovery_code(org, code);
    let second = member_factors::redeem_recovery_code(org, code);
    let (first, second) = tokio::join!(first.send(browser), second.send(browser));
    let mut answers = [first, second];
    answers.sort_by_key(Answer::status);
    let [accepted, refused] = answers;
    assert!(
        !accepted.ok().mfa_enrollment_required,
        "the accepted code leaves no new factor owed"
    );
    match refused.status() {
        Status::FORBIDDEN => {
            refused.refused(Status::FORBIDDEN, "forbidden");
        }
        Status::CONFLICT => {
            refused.refused(Status::CONFLICT, "conflict");
        }
        _ => panic!(
            "the second send of one code is refused, not {}",
            refused.summary()
        ),
    }
    members::me(org).send(browser).await.ok();
}

/// A refused printed code leaves the waiting session unable to read its member.
async fn refused_code(browser: &Client, org: &OrgPath, code: &MemberRecoveryCode) {
    member_factors::redeem_recovery_code(org, code)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    members::me(org)
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// The printout `ann` is shown once when she sets up an authenticator app
/// from her client, with her password typed again.
async fn recovery_codes(ann: &Founder, org: &OrgPath) -> RecoveryCodes {
    let setup = MemberFactorSetup {
        proof: MemberProof {
            password: FOUNDER_PASSWORD.to_owned(),
            code: None,
        },
    };
    let begun = member_factors::begin_totp(org, &setup)
        .send(ann.client())
        .await
        .ok();
    let mut phone = TotpApp::scanning(&begun.otpauth_uri);
    let confirm = ConfirmFactor {
        code: phone.code().await,
        session_id: None,
    };
    let shown = member_factors::confirm_totp(org, &confirm)
        .send(ann.client())
        .await
        .ok();
    RecoveryCodes::printed(shown.recovery_codes)
}

/// The session the founder's password opens for `email` through
/// `client`, still owing the factor they set up.
async fn waiting_for_factor(client: &Client, email: &str) -> Session {
    let answer = sessions::member_sign_in(&PasswordSignIn::of(email, FOUNDER_PASSWORD))
        .send(client)
        .await
        .ok();
    let SignedIn::Authenticated(waiting) = answer else {
        panic!("a founder of one organization is offered no choice");
    };
    assert_eq!(
        waiting.owed(),
        Owed::FactorCode,
        "a browser never remembered is asked for the factor"
    );
    waiting
}
