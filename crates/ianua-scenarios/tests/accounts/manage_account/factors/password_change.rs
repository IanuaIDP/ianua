//! A temporary password Tess set for Pat: it opens nothing on its own,
//! the replacement Pat must choose takes a code from her phone, happens
//! once, and leaves neither the temporary nor the old password able to
//! sign in.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{factors, people, sessions};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::SessionCode;
use ianua_scenarios::wire::sign_in::Owed;
use ianua_scenarios::wire::tenant_sign_in::{TenantPasswordSignIn, TenantSession, TenantSignedIn};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;
use serde_json::{Value, json};

use crate::support::{device, invited_and_signed_in, tenant_records};

/// The password Tess sets for Pat: a sentence, so no scanner takes it for
/// a key.
const TEMPORARY_PASSWORD: &str = "Temporary golden orchard meadow 7159!";

/// The password Pat replaces it with.
const REPLACEMENT_PASSWORD: &str = "Replacement mountain lantern meadow 8236!";

/// Tess sets a temporary password for Pat, who has an authenticator:
/// Pat's session is out. On a new browser the temporary password opens no
/// session but a change owed with her own factor, reading nothing.
/// Changing the password without a factor code is refused. With a code from her phone
/// the change finishes, the sign-in reads her record, and the spent
/// change token is refused. Neither her old password nor the temporary
/// one signs in, and the reset is recorded once with no password or
/// token in it.
#[tokio::test]
async fn tess_sets_a_temporary_password_that_pat_replaces_only_with_her_phone() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;
    pat.set_up_authenticator().await;
    let mut phone = pat.lose_phone();
    reset_as_tess(&world, &pat).await;
    let mut browser = device(&stack, "Pat replacing the temporary password");
    let token = begin_password_replacement(&world, &pat, &browser).await;
    let change = replace_password(&world, &mut browser, &mut phone, &token).await;
    check_completed_replacement(&world, &pat, &browser, &change).await;
    refuse_previous_passwords(&world, &pat).await;
    assert_eq!(
        tenant_records(
            &world,
            "authentication.password_reset_completed",
            &[TEMPORARY_PASSWORD, REPLACEMENT_PASSWORD, &token]
        )
        .await,
        1,
        "the reset is recorded once"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess's temporary reset immediately revokes Pat's existing session.
async fn reset_as_tess(world: &World<'_>, pat: &Person) {
    let by_tess = format!("/users/{}/reset-password", pat.id());
    let reset =
        Call::post(world.tenant().at(&by_tess)).json(&json!({"password": TEMPORARY_PASSWORD}));
    world.admin().client().send::<IgnoredAny>(reset).await.ok();
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// The temporary password opens only a replacement challenge requiring Pat's own factor.
async fn begin_password_replacement(world: &World<'_>, pat: &Person, browser: &Client) -> String {
    let temporary = TenantPasswordSignIn {
        email: pat.email().to_owned(),
        password: TEMPORARY_PASSWORD.to_owned(),
        fingerprint_hash: None,
    };
    let answer = sessions::sign_in(world.tenant(), &temporary)
        .send(browser)
        .await
        .ok();
    let TenantSignedIn::PasswordChangeRequired(due) = answer else {
        panic!("a password Tess set must change before a session opens");
    };
    assert_eq!(due.proof, "own_factor", "the change takes Pat's factor");
    let Some(token) = due.change_token else {
        panic!("a change proved by Pat's own factor carries its token");
    };
    people::me(world.tenant())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    token
}

/// Require Pat's phone code before completing the password replacement and any remaining factor.
async fn replace_password(
    world: &World<'_>,
    browser: &mut Client,
    phone: &mut TotpApp,
    token: &str,
) -> Value {
    let path = world.tenant().at("/login/password-change");
    let mut change = json!({"change_token": token, "new_password": REPLACEMENT_PASSWORD});
    browser
        .send::<IgnoredAny>(Call::post(&path).json(&change))
        .await
        .refused(Status::FORBIDDEN, "step_up_required");

    change["code"] = json!(phone.code().await);
    let answer = browser
        .send::<TenantSignedIn>(Call::post(&path).json(&change))
        .await
        .ok();
    let TenantSignedIn::Session(session) = answer else {
        panic!("the replacement finishes the password step");
    };
    browser.authorize(&session.refresh_token);
    settle_remaining_factor(world, browser, phone, session).await;
    change
}

/// Complete an additional factor challenge if the replacement session still owes one.
async fn settle_remaining_factor(
    world: &World<'_>,
    browser: &Client,
    phone: &mut TotpApp,
    session: TenantSession,
) {
    if session.owed() == Owed::FactorCode {
        let code = SessionCode {
            session_id: session.session_id,
            code: phone.code().await,
        };
        factors::verify(world.tenant(), &code)
            .send(browser)
            .await
            .ok();
    }
}

/// The replacement session reads Pat while its spent change token cannot be reused.
async fn check_completed_replacement(
    world: &World<'_>,
    pat: &Person,
    browser: &Client,
    change: &Value,
) {
    let own = people::me(world.tenant()).send(browser).await.ok();
    assert_eq!(own.id, pat.id(), "the replaced password signs Pat in");
    browser
        .send::<IgnoredAny>(Call::post(world.tenant().at("/login/password-change")).json(change))
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// Neither Pat's original password nor Tess's temporary password authenticates after replacement.
async fn refuse_previous_passwords(world: &World<'_>, pat: &Person) {
    for password in [pat.password(), TEMPORARY_PASSWORD] {
        let dead = TenantPasswordSignIn {
            email: pat.email().to_owned(),
            password: password.to_owned(),
            fingerprint_hash: None,
        };
        sessions::sign_in(world.tenant(), &dead)
            .send(world.anonymous().client())
            .await
            .refused(Status::NOT_FOUND, "not_found");
    }
}
