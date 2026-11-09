//! Pat signs in on a protected app's own host and still owes the code
//! from her phone. Ann raises the tenant's baseline meanwhile: the code
//! no longer suffices, and nothing reaches the upstream. Ann lowers it
//! again, and the same browser finishes with the next code and reaches
//! the app with a signed assertion and no cookie or token of its own.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{app_sign_in, audit, tenants};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::AssertionCheck;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::app_sign_in::{AppFactorCode, AppLogIn};
use ianua_scenarios::wire::tenants::{PasswordAgain, ReplaceSignInSettings};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{Application, invited};

/// Pat, with an authenticator app, signs in on the protected app's host
/// and owes its code. Ann raises the tenant's baseline to AAL3 before she
/// types it. The code cannot finish a sign-in below that baseline:
/// the app answers nothing to her cookie, the upstream saw no request and
/// no code was recorded as verified. Ann lowers the baseline to AAL2: the
/// next code finishes the sign-in, the one request that reaches the app
/// carries the gateway's verified assertion naming Pat, no cookie and no
/// token, and one verified code is recorded.
#[tokio::test]
async fn a_sign_in_waiting_for_a_code_obeys_a_baseline_raised_meanwhile() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let app = Application::protected(&world).await;
    let mut pat = invited(&world, "pat", "Pat Holder").await;
    pat.sign_in(&stack).await;
    pat.set_up_authenticator().await;
    let mut phone = pat.lose_phone();
    begin_app_sign_in(&app, &pat).await;
    let before = raise_baseline(&world, &app, &pat, &mut phone).await;
    baseline(&world, "Aal2").await;
    complete_app_sign_in(&app, &pat, &mut phone).await;
    check_forwarded_identity(&app, &pat);
    assert_eq!(
        codes_verified(&world).await,
        before + 1,
        "one verified code is recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Raising the baseline refuses the pending sign-in without verifying a phone code.
async fn raise_baseline(
    world: &World<'_>,
    app: &Application,
    pat: &Person,
    phone: &mut TotpApp,
) -> usize {
    baseline(world, "Aal3").await;
    let before = codes_verified(world).await;
    app.upstream.forget();
    refuse_below_baseline(app, pat, phone).await;
    assert_eq!(
        codes_verified(world).await,
        before,
        "no code was recorded as verified"
    );
    before
}

/// Pat's password starts a pending app sign-in that still requires her phone code.
async fn begin_app_sign_in(app: &Application, pat: &Person) {
    let log_in = AppLogIn {
        email: pat.email().to_owned(),
        password: pat.password().to_owned(),
    };
    let waiting = app_sign_in::log_in(&app.host, &log_in)
        .send(pat.client())
        .await
        .ok();
    assert!(waiting.mfa_required, "the sign-in owes Pat's code");
    assert!(!waiting.signed_in, "Pat is not in before the code");
}

/// Pat's code cannot finish below the new baseline, and her cookie forwards no request.
async fn refuse_below_baseline(app: &Application, pat: &Person, phone: &mut TotpApp) {
    let code = AppFactorCode {
        code: phone.code().await,
    };
    let refused = app_sign_in::answer_factor(&app.host, &code)
        .send(pat.client())
        .await;
    assert_eq!(
        refused.status(),
        Status::FORBIDDEN,
        "a code below the raised baseline is refused: {}",
        refused.summary()
    );
    app.visit("/app/account")
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert!(
        app.upstream.arrivals().is_empty(),
        "nothing reached the app"
    );
}

/// The next phone code finishes the pending sign-in after the baseline is lowered.
async fn complete_app_sign_in(app: &Application, pat: &Person, phone: &mut TotpApp) {
    let next = AppFactorCode {
        code: phone.code().await,
    };
    let completed = app_sign_in::answer_factor(&app.host, &next)
        .send(pat.client())
        .await
        .ok();
    assert!(completed.signed_in, "the next code finishes the sign-in");
    app.visit("/app/account").send(pat.client()).await.ok();
}

/// Only the completed request reaches the upstream, with Pat's assertion but no browser secrets.
fn check_forwarded_identity(app: &Application, pat: &Person) {
    let arrivals = app.upstream.arrivals();
    let [arrival] = arrivals.as_slice() else {
        panic!("only the finished sign-in's request reaches the app");
    };
    let AssertionCheck::Verified { caller } = &arrival.assertion else {
        panic!("the app verifies the gateway's signature on the assertion");
    };
    assert_eq!(caller.sub, pat.id(), "the assertion names Pat");
    assert!(
        !arrival.has_header("cookie"),
        "Pat's cookie stays at the gateway"
    );
    assert!(
        !arrival.has_header("authorization"),
        "no token of Pat's reaches the app"
    );
}

/// How many codes the tenant's trail records as verified.
async fn codes_verified(world: &World<'_>) -> usize {
    audit::tenant_log(world.tenant(), "authentication.mfa_verified")
        .send(world.admin().client())
        .await
        .ok()
        .items
        .len()
}

/// Ann sets the tenant's baseline and its sensitive floor to `required`,
/// such as `Aal3`, proving herself with her password.
async fn baseline(world: &World<'_>, required: &str) {
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    let step_up = settings
        .rest
        .get_mut("step_up")
        .expect("the tenant has a step-up policy");
    step_up["baseline_aal"] = json!(required);
    step_up["sensitive_aal"] = json!(required);
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
