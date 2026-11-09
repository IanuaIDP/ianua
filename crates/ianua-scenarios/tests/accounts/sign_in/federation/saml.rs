//! Ann signs in through Acme's SAML provider. A trusted assertion opens
//! her account once; replay is refused while that session remains usable.
//! Wrong audience, issuer, recipient, request, time or signature claims
//! are refused without a successful sign-in record, and a fresh valid
//! assertion still signs her in and records that success once. Another
//! tab's binding is also refused: the returning browser stays signed out
//! while Ann's existing session remains usable.

use ianua_scenarios::api::members;
use ianua_scenarios::net::Client;
use ianua_scenarios::providers::saml::{Claim, Provider, SignIn};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;

use super::{Company, accepted, begin, configured, finish, refused, successful_sign_ins};

/// Ann signs in with a correctly signed assertion. Replaying the same
/// answer is refused, and the session it opened still
/// reads Ann's account.
#[tokio::test]
async fn saml_signs_in_once_and_refuses_replay() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let provider = Provider::new();
    let company = configured(&stack, provider.config()).await;
    let mut browser = Client::new(&stack, "Ann, returning from SAML").expect("a client");

    let begun = begin(&browser, &company.org).await;
    let sign_in = SignIn {
        email: company.ann.email(),
        begun,
        claim: Claim::Correct,
    };
    let callback = provider.callback(&stack, sign_in);
    accepted(&mut browser, &company, &callback).await;

    finish(&callback)
        .send(&browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    members::me(&company.org).send(&browser).await.ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// An assertion signed for another service is refused without a successful
/// sign-in record; a fresh assertion for this service still signs Ann in.
#[tokio::test]
async fn saml_refuses_a_signed_assertion_for_another_audience() {
    invalid_claim(Claim::WrongAudience).await;
}

/// An assertion naming another issuer is refused despite a trusted
/// signature; Ann's session and a fresh sign-in remain usable.
#[tokio::test]
async fn saml_refuses_a_signed_assertion_from_another_issuer() {
    invalid_claim(Claim::WrongIssuer).await;
}

/// A signed recipient mismatch is refused even when the unsigned envelope
/// names the platform; Ann's existing session remains usable.
#[tokio::test]
async fn saml_checks_the_signed_recipient_inside_the_response() {
    invalid_claim(Claim::WrongRecipient).await;
}

/// An assertion for another request is refused despite an envelope naming
/// this sign-in; a fresh matching assertion still works.
#[tokio::test]
async fn saml_checks_the_signed_request_inside_the_response() {
    invalid_claim(Claim::WrongRequest).await;
}

/// An assertion expired by five minutes is refused without a successful
/// sign-in record; a fresh assertion still works.
#[tokio::test]
async fn saml_refuses_an_expired_assertion() {
    invalid_claim(Claim::Expired).await;
}

/// An assertion issued beyond permitted clock drift is refused while
/// Ann's existing session and a correctly dated assertion remain usable.
#[tokio::test]
async fn saml_refuses_an_assertion_issued_in_the_future() {
    invalid_claim(Claim::FutureIssued).await;
}

/// Matching claims signed with an unregistered key are refused; a fresh
/// assertion from Acme's provider still signs Ann in.
#[tokio::test]
async fn saml_refuses_an_assertion_signed_with_another_key() {
    invalid_claim(Claim::WrongSignature).await;
}

/// Unsigned claims are refused without a successful sign-in record;
/// Ann's session and a fresh signed assertion still work.
#[tokio::test]
async fn saml_refuses_an_unsigned_assertion() {
    invalid_claim(Claim::Unsigned).await;
}

/// Ann's first assertion is refused with her second sign-in's binding,
/// as from the wrong tab. The browser stays signed out, and the session
/// she already held still works.
#[tokio::test]
async fn saml_refuses_another_browsers_binding() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let provider = Provider::new();
    let company = configured(&stack, provider.config()).await;
    let browser = Client::new(&stack, "Ann, returning to the wrong tab").expect("a client");

    let own = begin(&browser, &company.org).await;
    let other = begin(&browser, &company.org).await;
    let sign_in = SignIn {
        email: company.ann.email(),
        begun: own,
        claim: Claim::Correct,
    };
    let mut callback = provider.callback(&stack, sign_in);
    callback.binding = other.binding;
    refused(&browser, &company, &callback).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// An assertion changed as `claim` says is refused as forbidden: the
/// browser stays signed out, Ann's own session still works, and no
/// sign-in is recorded. A fresh, correctly signed assertion then signs
/// her in, recorded once, read through the new session since signing in
/// ends her earlier one.
async fn invalid_claim(claim: Claim) {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let provider = Provider::new();
    let company = configured(&stack, provider.config()).await;
    let mut browser = Client::new(&stack, "Ann, with mismatched SAML claims").expect("a client");
    let before = successful_sign_ins(company.ann.client(), &company).await;

    let begun = begin(&browser, &company.org).await;
    let sign_in = SignIn {
        email: company.ann.email(),
        begun,
        claim,
    };
    let callback = provider.callback(&stack, sign_in);
    refused(&browser, &company, &callback).await;
    assert_eq!(
        successful_sign_ins(company.ann.client(), &company).await,
        before,
        "a refused assertion records no sign-in"
    );

    sign_in_afresh(&provider, &stack, &mut browser, &company).await;
    assert_eq!(
        successful_sign_ins(&browser, &company).await,
        before + 1,
        "the fresh sign-in is recorded once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// A fresh, correctly signed assertion opens Ann's account on the returning browser.
async fn sign_in_afresh(
    provider: &Provider,
    stack: &Stack,
    browser: &mut Client,
    company: &Company,
) {
    let begun = begin(browser, &company.org).await;
    let sign_in = SignIn {
        email: company.ann.email(),
        begun,
        claim: Claim::Correct,
    };
    let callback = provider.callback(stack, sign_in);
    accepted(browser, company, &callback).await;
}
