//! Ann signing in through Acme's own OIDC provider, a real HTTPS server
//! with its own key: the platform finds it by discovery, exchanges the
//! code with PKCE and the client secret, and checks the signed ID token.
//! A token wrong in any signed claim, signed with another key or not at
//! all, or naming an address the provider cannot vouch for, grants
//! nothing; nor does a state no sign-in is waiting for, a provider that
//! failed or was switched off mid-sign-in, or an address Acme never let
//! in. After every refusal Ann's own session still works and a fresh,
//! correct answer still signs her in, recorded once.

use ianua_scenarios::api::{members, organizations};
use ianua_scenarios::net::Client;
use ianua_scenarios::providers::oidc::{Claim, Provider};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::federation::Callback;
use ianua_scenarios::wire::organization::{ChangeIdentityProvider, SwitchIdentityProvider};

use super::{
    Company, ProviderAnswer, accepted, begin, configured, finish, founder_proof, refused,
    successful_sign_ins, unchanged_access,
};

/// What the platform tells a browser whose token failed any check: the
/// same words whichever check it was.
const UNVERIFIED: &str = "The identity provider's answer could not be verified";

/// Ann signs in through Acme's provider, whose client secret holds spaces
/// and punctuation: discovery, the code exchange and the signed ID token
/// open her account, and the provider sees one exchange. Replaying the same
/// answer is refused without reaching the
/// provider, and the session it opened still reads Ann's account.
#[tokio::test]
async fn oidc_signs_in_once_and_refuses_callback_replay() {
    let provider = Provider::start().await;
    let stack = stack(&provider).await;
    let company = configured(&stack, provider.config()).await;
    let mut browser = Client::new(&stack, "Ann, returning from OIDC").expect("a client");

    let begun = begin(&browser, &company.org).await;
    let callback = provider.callback(begun, company.ann.email(), Claim::Correct);
    accepted(&mut browser, &company, &callback).await;
    assert_eq!(
        provider.exchanges(),
        1,
        "the sign-in exchanged its code once"
    );

    finish(&callback)
        .send(&browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    assert_eq!(
        provider.exchanges(),
        1,
        "a replay never reaches the provider"
    );
    members::me(&company.org).send(&browser).await.ok();

    stack.stop().await.expect("the stack stops cleanly");
    provider.stop().await;
}

/// A token signed by Acme's provider but naming another issuer is fetched
/// and refused; Ann's existing session and a fresh sign-in still work.
#[tokio::test]
async fn oidc_refuses_a_signed_token_from_another_issuer() {
    invalid_claim(Claim::WrongIssuer).await;
}

/// A token Acme's provider signs for another client is fetched and refused;
/// Ann's session still works and a fresh answer signs her in.
#[tokio::test]
async fn oidc_refuses_a_signed_token_for_another_audience() {
    invalid_claim(Claim::WrongAudience).await;
}

/// A correctly signed token carrying another sign-in's nonce is refused
/// without ending Ann's session or recording a successful sign-in.
#[tokio::test]
async fn oidc_refuses_a_signed_token_with_another_nonce() {
    invalid_claim(Claim::WrongNonce).await;
}

/// An expired token grants no access and records no successful sign-in;
/// a fresh answer still signs Ann in.
#[tokio::test]
async fn oidc_refuses_an_expired_token() {
    invalid_claim(Claim::Expired).await;
}

/// A token dated further ahead than clock drift permits is refused.
/// Ann's session survives, and a correctly dated answer signs her in.
#[tokio::test]
async fn oidc_refuses_a_token_issued_in_the_future() {
    invalid_claim(Claim::FutureIssued).await;
}

/// An unexpired token issued too long ago is refused without recording a
/// successful sign-in. A fresh token still signs Ann in.
#[tokio::test]
async fn oidc_refuses_a_token_issued_too_long_ago() {
    invalid_claim(Claim::OldIssued).await;
}

/// Matching claims signed with an unregistered key are refused without a
/// successful sign-in record; Acme's provider still signs Ann in.
#[tokio::test]
async fn oidc_refuses_a_token_signed_with_another_key() {
    invalid_claim(Claim::WrongSignature).await;
}

/// An unsigned token, `alg: none`, grants no access despite matching
/// claims. A signed answer still signs Ann in.
#[tokio::test]
async fn oidc_refuses_an_unsigned_token() {
    invalid_claim(Claim::Unsigned).await;
}

/// A provider without email authority is refused when it names Ann's
/// address without verifying it. Her session
/// survives and no sign-in is recorded. A fresh answer naming a verified
/// address signs her in, recorded once.
#[tokio::test]
async fn oidc_requires_email_proof_from_a_provider_without_email_authority() {
    let provider = Provider::start().await;
    let stack = stack(&provider).await;
    let company = configured(&stack, provider.config()).await;
    let untrusted = ChangeIdentityProvider {
        email_trust: Some("Unverified".to_owned()),
        proof: founder_proof(),
    };
    organizations::change_identity_provider(&company.org, &untrusted)
        .send(company.ann.client())
        .await
        .ok();
    let mut browser = Client::new(&stack, "Ann, without provider email proof").expect("a client");
    let before = successful_sign_ins(company.ann.client(), &company).await;

    let begun = begin(&browser, &company.org).await;
    let callback = provider.callback(begun, company.ann.email(), Claim::UnverifiedEmail);
    refused(&browser, &company, &callback).await;
    assert_eq!(
        successful_sign_ins(company.ann.client(), &company).await,
        before,
        "an unproved address records no sign-in"
    );

    signs_in_afresh(&provider, &mut browser, &company, before).await;

    stack.stop().await.expect("the stack stops cleanly");
    provider.stop().await;
}

/// When the provider refuses to exchange the code, the answer grants
/// nothing, even partly, and handed back again it is still refused. Once
/// the provider issues tokens again, a fresh sign-in works, recorded once.
#[tokio::test]
async fn a_failed_provider_exchange_can_be_followed_by_a_fresh_sign_in() {
    let provider = Provider::start().await;
    let stack = stack(&provider).await;
    let company = configured(&stack, provider.config()).await;
    let mut browser = Client::new(&stack, "Ann, after a failed exchange").expect("a client");
    let before = successful_sign_ins(company.ann.client(), &company).await;

    let begun = begin(&browser, &company.org).await;
    let callback = provider.callback(begun, company.ann.email(), Claim::Correct);
    provider.discard_grant();
    finish(&callback)
        .send(&browser)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    refused(&browser, &company, &callback).await;
    assert_eq!(
        provider.exchanges(),
        1,
        "the failed exchange reached the provider once"
    );
    assert_eq!(
        successful_sign_ins(company.ann.client(), &company).await,
        before,
        "a failed exchange records no sign-in"
    );

    signs_in_afresh(&provider, &mut browser, &company, before).await;

    stack.stop().await.expect("the stack stops cleanly");
    provider.stop().await;
}

/// Ann begins a sign-in and then switches Acme's provider off. The arriving
/// answer is refused without a code exchange or successful sign-in record.
/// She switches it on again; the old answer is still refused, spent by
/// its first try, but a fresh sign-in works, recorded once.
#[tokio::test]
async fn a_provider_disabled_during_sign_in_cannot_finish_the_old_flow() {
    let provider = Provider::start().await;
    let stack = stack(&provider).await;
    let company = configured(&stack, provider.config()).await;
    let mut browser =
        Client::new(&stack, "Ann, returning after provider shutdown").expect("a client");
    let before = successful_sign_ins(company.ann.client(), &company).await;

    let begun = begin(&browser, &company.org).await;
    let callback = provider.callback(begun, company.ann.email(), Claim::Correct);
    switch_provider(&company, "Disabled").await;
    refused(&browser, &company, &callback).await;
    assert_eq!(
        provider.exchanges(),
        0,
        "a switched-off provider is never asked"
    );
    assert_eq!(
        successful_sign_ins(company.ann.client(), &company).await,
        before,
        "the refused answer records no sign-in"
    );

    switch_provider(&company, "Active").await;
    refused(&browser, &company, &callback).await;
    signs_in_afresh(&provider, &mut browser, &company, before).await;
    assert_eq!(
        provider.exchanges(),
        1,
        "only the fresh sign-in reached the provider"
    );

    stack.stop().await.expect("the stack stops cleanly");
    provider.stop().await;
}

/// A provider answer for an unknown member is refused. No member is made
/// and no successful sign-in is recorded; Ann still
/// signs in with her own address, recorded once.
#[tokio::test]
async fn a_provider_cannot_create_membership_for_an_unknown_email() {
    let provider = Provider::start().await;
    let stack = stack(&provider).await;
    let company = configured(&stack, provider.config()).await;
    let mut browser = Client::new(&stack, "Someone Acme never invited").expect("a client");
    let stranger = format!("unknown@{}", stack.base_domain());
    let before = successful_sign_ins(company.ann.client(), &company).await;

    let begun = begin(&browser, &company.org).await;
    let callback = provider.callback(begun, &stranger, Claim::Correct);
    refused(&browser, &company, &callback).await;
    let listed = members::list(&company.org, Some(&stranger))
        .send(company.ann.client())
        .await
        .ok();
    assert!(
        listed.items.is_empty(),
        "no member is made for the stranger"
    );
    assert_eq!(
        successful_sign_ins(company.ann.client(), &company).await,
        before,
        "the stranger's answer records no sign-in"
    );

    signs_in_afresh(&provider, &mut browser, &company, before).await;

    stack.stop().await.expect("the stack stops cleanly");
    provider.stop().await;
}

/// An answer with an unknown state is refused before any code reaches
/// the provider. The browser stays signed out, and Ann's own session
/// still works.
#[tokio::test]
async fn oidc_refuses_invalid_state_before_exchanging_the_code() {
    let provider = Provider::start().await;
    let stack = stack(&provider).await;
    let company = configured(&stack, provider.config()).await;
    let browser = Client::new(&stack, "Ann, with another flow's state").expect("a client");

    let begun = begin(&browser, &company.org).await;
    let mut callback = provider.callback(begun, company.ann.email(), Claim::Correct);
    let ProviderAnswer::Oidc { state, .. } = &mut callback.answer else {
        panic!("an OIDC provider answers with a state and a code");
    };
    *state = "state-of-another-request".to_owned();
    refused(&browser, &company, &callback).await;
    assert_eq!(
        provider.exchanges(),
        0,
        "an unknown state is refused before the code is exchanged"
    );

    stack.stop().await.expect("the stack stops cleanly");
    provider.stop().await;
}

/// The token `claim` makes wrong is fetched through the real exchange and
/// refused with the same words whatever was wrong; Ann's session still
/// works and nothing is recorded. The provider saw one exchange, so the
/// token's own check refused it, not an earlier gate. A fresh, correct
/// answer then signs Ann in, recorded once.
async fn invalid_claim(claim: Claim) {
    let provider = Provider::start().await;
    let stack = stack(&provider).await;
    let company = configured(&stack, provider.config()).await;
    let mut browser = Client::new(&stack, "Ann, with mismatched OIDC claims").expect("a client");
    let before = successful_sign_ins(company.ann.client(), &company).await;

    let begun = begin(&browser, &company.org).await;
    let callback = provider.callback(begun, company.ann.email(), claim);
    assert_token_refused(&provider, &browser, &company, &callback).await;
    assert_eq!(
        successful_sign_ins(company.ann.client(), &company).await,
        before,
        "a refused token records no sign-in"
    );

    signs_in_afresh(&provider, &mut browser, &company, before).await;
    assert_eq!(
        provider.exchanges(),
        2,
        "the fresh sign-in fetched its own token"
    );

    stack.stop().await.expect("the stack stops cleanly");
    provider.stop().await;
}

/// The fetched token fails verification without changing either browser's access.
async fn assert_token_refused(
    provider: &Provider,
    browser: &Client,
    company: &Company,
    callback: &Callback,
) {
    let problem = finish(callback)
        .send(browser)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    assert_eq!(
        problem.message(),
        UNVERIFIED,
        "the refusal does not say which check failed"
    );
    unchanged_access(browser, company).await;
    assert_eq!(
        provider.exchanges(),
        1,
        "the signed token was fetched and checked"
    );
}

/// A fresh, correct answer from `provider` signs Ann in on `browser`, and
/// the trail then holds one sign-in more than `before`. The count is read
/// through the new session, since signing in ends Ann's earlier one.
async fn signs_in_afresh(
    provider: &Provider,
    browser: &mut Client,
    company: &Company,
    before: usize,
) {
    let begun = begin(browser, &company.org).await;
    let callback = provider.callback(begun, company.ann.email(), Claim::Correct);
    accepted(browser, company, &callback).await;
    assert_eq!(
        successful_sign_ins(browser, company).await,
        before + 1,
        "the fresh sign-in is recorded once"
    );
}

/// Switches Acme's provider to `status`, `Active` or `Disabled`, with
/// Ann's session and her password typed again.
async fn switch_provider(company: &Company, status: &str) {
    let switch = SwitchIdentityProvider {
        status: status.to_owned(),
        proof: founder_proof(),
    };
    organizations::switch_identity_provider(&company.org, &switch)
        .send(company.ann.client())
        .await
        .ok();
}

/// The platform started with this provider's certificate as the authority
/// its OIDC client trusts. Discovery and the code exchange still go
/// through the real HTTPS client; the certificate file lives as long as
/// `provider`, past the start that reads it.
async fn stack(provider: &Provider) -> Stack {
    Stack::start(Profile::standard().with("OIDC_PROVIDER_CA_FILE", provider.authority_file()))
        .await
        .expect("the stack trusts its configured provider authority")
}
