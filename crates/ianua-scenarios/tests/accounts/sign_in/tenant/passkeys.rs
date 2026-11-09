//! Pat's passkey beyond the plain sign-in the people scenarios cover: one
//! that signs her in naming nobody, one added while a sign-in waits for
//! the factor it owes, and one renamed by her alone.

use ianua_scenarios::api::{factors, people, tenants};
use ianua_scenarios::authenticators::{PasskeyAnswer, SoftPasskey};
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::{ConfirmWaitingPasskey, PasskeyAnswerBody, RenamePasskey};
use ianua_scenarios::wire::sign_in::Owed;
use ianua_scenarios::wire::tenants::{MfaPolicy, PasswordAgain, ReplaceSignInSettings};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::tenant::support::{device, person, sign_in_owing};

/// The name Pat lists her passkey under.
const LAPTOP: &str = "Pat's laptop";

/// The record a registered passkey leaves.
const REGISTERED: &str = "authentication.passkey_registered";

/// The record a renamed passkey leaves.
const RENAMED: &str = "authentication.passkey_renamed";

/// The body sending `answer` for the ceremony `ceremony_id`.
fn answer_body(ceremony_id: &str, answer: &PasskeyAnswer) -> PasskeyAnswerBody {
    PasskeyAnswerBody {
        ceremony_id: ceremony_id.to_owned(),
        response: answer.response.clone(),
        credential_id: answer.credential_id.clone(),
    }
}

/// Pat's own client, on a discoverable sign-in naming nobody: her passkey
/// answers the challenge and she reads as herself. The same answer sent
/// again is refused, and Mallory's unregistered key is refused as
/// unknown.
#[tokio::test]
async fn pat_signs_in_with_her_passkey_naming_nobody() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    pat.add_passkey(&stack, LAPTOP).await;
    let Some(passkey) = pat.passkey() else {
        panic!("Pat just added a passkey");
    };
    let mut passkey = passkey.clone();

    let mut browser = device(&stack, "Pat, naming nobody");
    let begun = factors::begin_discoverable_sign_in(world.tenant())
        .send(&browser)
        .await
        .ok();
    let answer = passkey.sign_in(&begun.challenge);
    let body = answer_body(&begun.ceremony_id, &answer);
    let session = factors::confirm_passkey_sign_in(world.tenant(), &body)
        .send(&browser)
        .await
        .ok();
    assert_eq!(
        session.owed(),
        Owed::Nothing,
        "the passkey proves Pat on its own"
    );
    browser.authorize(&session.refresh_token);
    let own = people::me(world.tenant()).send(&browser).await.ok();
    assert_eq!(own.id, pat.id(), "the passkey names Pat alone");

    factors::confirm_passkey_sign_in(world.tenant(), &body)
        .send(&device(&stack, "Pat, sending it twice"))
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    refuse_an_unknown_key(&world, &stack).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A key the tenant never saw, answering a discoverable challenge, is
/// refused as unknown.
async fn refuse_an_unknown_key(world: &World<'_>, stack: &Stack) {
    let browser = device(stack, "Mallory, with a key nobody registered");
    let begun = factors::begin_discoverable_sign_in(world.tenant())
        .send(&browser)
        .await
        .ok();
    let mut stranger = SoftPasskey::new(&stack.app_url());
    let answer = stranger.sign_in(&begun.challenge);
    factors::confirm_passkey_sign_in(world.tenant(), &answer_body(&begun.ceremony_id, &answer))
        .send(&browser)
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// Ann requires a second factor. Pat signs in on a new browser and owes a
/// factor to set up, the tenant's policy asking it of her and nothing about
/// that browser, so no mail comes first; that sign-in reads nothing.
/// She adds a passkey on that waiting sign-in, with no password
/// typed again: it answers the factor she owed, the browser now reads
/// her account, and the registration is recorded once without the
/// attestation. Uma, signed in as herself and owing nothing, cannot start
/// that step on her own session.
#[tokio::test]
async fn a_waiting_sign_in_adds_a_passkey_as_the_factor_it_owes() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    factors::begin_waiting_passkey(world.tenant())
        .send(uma.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    factor_required(&world).await;

    let waiting = sign_in_owing(&world, &pat, "Pat, owing a factor", Owed::FactorEnrolment).await;
    people::me(world.tenant())
        .send(&waiting.client)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    let key = SoftPasskey::new(&stack.app_url());
    let begun = factors::begin_waiting_passkey(world.tenant())
        .send(&waiting.client)
        .await
        .ok();
    let registered = key.register(&begun.challenge);
    let confirm = ConfirmWaitingPasskey {
        ceremony_id: begun.ceremony_id,
        response: registered.response.clone(),
        passkey_name: LAPTOP.to_owned(),
    };
    factors::confirm_waiting_passkey(world.tenant(), &confirm)
        .send(&waiting.client)
        .await
        .ok();
    let own = people::me(world.tenant()).send(&waiting.client).await.ok();
    assert_eq!(own.id, pat.id(), "the new passkey lets Pat in as herself");
    let trail = world.trail();
    let recorded = trail.recorded(REGISTERED).await;
    no_secret_leaked(&recorded.details.to_string(), &[&registered.response]);
    assert_eq!(trail.count(REGISTERED).await, 1, "one passkey is recorded");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat renames her passkey and it lists under the new name, a change
/// that is on record. A blank name is refused. Uma cannot rename Pat's
/// passkey, which reads to her as not there, and nobody signed in cannot
/// either.
#[tokio::test]
async fn pat_renames_her_passkey_and_nobody_else_can() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    pat.add_passkey(&stack, LAPTOP).await;
    let listed = factors::passkeys(world.tenant())
        .send(pat.client())
        .await
        .ok();
    let passkey_id = listed.passkeys[0].id.clone();

    let renamed = RenamePasskey {
        name: "Pat's old laptop".to_owned(),
    };
    factors::rename_passkey(world.tenant(), &passkey_id, &renamed)
        .send(pat.client())
        .await
        .ok();
    let now = factors::passkeys(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert_eq!(
        now.passkeys[0].name, renamed.name,
        "the new name is what lists"
    );
    world.trail().recorded(RENAMED).await;

    let blank = RenamePasskey {
        name: String::new(),
    };
    factors::rename_passkey(world.tenant(), &passkey_id, &blank)
        .send(pat.client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    factors::rename_passkey(world.tenant(), &passkey_id, &renamed)
        .send(uma.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    factors::rename_passkey(world.tenant(), &passkey_id, &renamed)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Makes a second factor required in the tenant, with a baseline of a
/// second factor, as Ann with her password typed again.
async fn factor_required(world: &World<'_>) {
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    settings.mfa_policy = MfaPolicy::Required;
    let Some(step_up) = settings.rest.get_mut("step_up") else {
        panic!("the tenant's sign-in settings hold a step-up policy");
    };
    step_up["baseline_aal"] = json!("Aal2");
    let replace = ReplaceSignInSettings {
        settings,
        proof: PasswordAgain {
            password: world.owner().password().to_owned(),
            code: None,
        },
    };
    tenants::replace_sign_in_settings(world.tenant(), &replace)
        .send(world.owner().client())
        .await
        .ok();
}
