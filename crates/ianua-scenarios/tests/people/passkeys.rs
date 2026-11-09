//! Passkey answers the platform refuses: Pat's, relayed from a phishing
//! page on another origin, and one from a copy of Pat's key whose sign
//! count did not go up.

use ianua_scenarios::actors::{Person, SignedInWith};
use ianua_scenarios::api::factors;
use ianua_scenarios::authenticators::SoftPasskey;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::PasskeyAnswerBody;
use ianua_scenarios::world::World;
use url::Url;

use crate::support::invitation_of;

/// A phishing page relays Pat's passkey ceremony. The answer names
/// the phishing page's origin, so adding the passkey from there is refused,
/// and so is signing in with a passkey answering from there.
#[tokio::test]
async fn a_passkey_answering_from_another_origin_is_refused() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = joined_and_signed_in(&world).await;
    let phishing = Url::parse("https://login.phish.example/").expect("a URL");

    let real = SoftPasskey::new(&stack.app_url());
    let relayed = pat.registration_answer(&real.on_page(&phishing)).await;
    pat.confirm_registration(&relayed, "Relayed")
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    pat.add_passkey(&stack, "Pat's laptop").await;
    let (ceremony_id, challenge) = pat.passkey_challenge().await;
    let Some(passkey) = pat.passkey() else {
        panic!("Pat just added a passkey, so holds one");
    };
    let answer = passkey.on_page(&phishing).sign_in(&challenge);
    let body = PasskeyAnswerBody {
        ceremony_id,
        response: answer.response,
        credential_id: answer.credential_id,
    };
    factors::confirm_passkey_sign_in(pat.tenant(), &body)
        .send(world.anonymous().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    stack.stop().await.expect("the stack stops cleanly");
}

/// A copy of Pat's passkey tries to sign in after the original did, with a
/// count that did not go up. The platform takes it for a cloned key and
/// refuses it, while the original, counting on, still signs in.
#[tokio::test]
async fn a_passkey_repeating_its_sign_count_is_refused() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = joined_and_signed_in(&world).await;
    pat.add_passkey(&stack, "Pat's laptop").await;
    assert_eq!(
        pat.sign_in_with_passkey().await,
        SignedInWith::Passkey,
        "Pat's passkey signs in on its own"
    );
    refuse_copied_count(&world, &mut pat).await;
    assert_eq!(
        pat.sign_in_with_passkey().await,
        SignedInWith::Passkey,
        "the original key, counting on, still signs in"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// A copied key's repeated sign count is refused on a fresh sign-in challenge.
async fn refuse_copied_count(world: &World<'_>, pat: &mut Person) {
    let (ceremony_id, challenge) = pat.passkey_challenge().await;
    let Some(passkey) = pat.passkey() else {
        panic!("Pat just added a passkey, so holds one");
    };
    let copied = passkey.sign_in_repeating_count(&challenge);
    let body = PasskeyAnswerBody {
        ceremony_id,
        response: copied.response,
        credential_id: copied.credential_id,
    };
    factors::confirm_passkey_sign_in(pat.tenant(), &body)
        .send(world.anonymous().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Pat, invited by Tess with the `Member` role, joined and signed in with
/// the password.
async fn joined_and_signed_in(world: &World<'_>) -> Person {
    let mut pat = world.newcomer("pat", "Pat Person");
    invitation_of(world, &mut pat, &mut Vec::new()).await;
    pat.accept_invitation(world.stack()).await;
    assert_eq!(
        pat.sign_in(world.stack()).await,
        SignedInWith::Password,
        "Pat, with no factor yet, signs in with the password alone"
    );
    pat
}
