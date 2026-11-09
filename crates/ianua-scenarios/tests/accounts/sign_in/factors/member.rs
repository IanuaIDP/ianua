//! Max, the member with no administrator's rights, and his second factor:
//! the authenticator app he sets up and the printout it comes with, a
//! sign-in of his that waits for the code, the code that finishes it, the
//! policy Ann sets that requires a factor of everyone, and the colleagues
//! whose access a step about Max must leave alone.

use ianua_scenarios::api::{member_factors, members, organizations, sessions};
use ianua_scenarios::authenticators::{RecoveryCodes, TotpApp};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::net::Client;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::{ConfirmFactor, FactorCode};
use ianua_scenarios::wire::organization::ReplaceOrgSignInSettings;
use ianua_scenarios::wire::sign_in::{
    MemberFactorSetup, MemberProof, Owed, PasswordSignIn, Session, SignedIn,
};
use ianua_scenarios::world::World;
use serde_json::json;

/// Max's authenticator app and the printout shown once when he confirmed
/// it.
pub(crate) struct Enrolled {
    /// The app whose codes finish his sign-ins and prove him again.
    pub(crate) phone: TotpApp,
    /// The printout, each code crossed out as he uses it.
    pub(crate) codes: RecoveryCodes,
}

/// Max's phone and printout once he set up an authenticator app from the
/// session he holds, typing his password again to begin; the session he
/// set it up from still reads his account.
///
/// # Panics
///
/// When the setup or its confirmation is refused, or his session no
/// longer reads his account.
pub(crate) async fn enrolled(world: &World<'_>) -> Enrolled {
    let setup = MemberFactorSetup {
        proof: MemberProof {
            password: world.member().password().to_owned(),
            code: None,
        },
    };
    let begun = member_factors::begin_totp(world.org(), &setup)
        .send(world.member().client())
        .await
        .ok();
    let mut phone = TotpApp::scanning(&begun.otpauth_uri);
    let confirm = ConfirmFactor {
        code: phone.code().await,
        session_id: None,
    };
    let shown = member_factors::confirm_totp(world.org(), &confirm)
        .send(world.member().client())
        .await
        .ok();
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
    Enrolled {
        phone,
        codes: RecoveryCodes::printed(shown.recovery_codes),
    }
}

/// The session Max's `password` opens through `browser`, which the
/// browser now carries: it owes the code from his phone and reads nothing
/// yet.
///
/// # Panics
///
/// When the sign-in is refused, offers a choice, owes something else, or
/// already reads his account.
pub(crate) async fn waiting(world: &World<'_>, browser: &mut Client, password: &str) -> Session {
    let sign_in = PasswordSignIn::of(world.member().email(), password);
    let answer = sessions::member_sign_in(&sign_in).send(browser).await.ok();
    let SignedIn::Authenticated(session) = answer else {
        panic!("Max is in one organization, so no choice is offered");
    };
    assert_eq!(
        session.owed(),
        Owed::FactorCode,
        "a sign-in from a browser Max never remembered owes his phone's code"
    );
    browser.authorize(&session.refresh_token);
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    session
}

/// Max types the code `phone` shows now for the sign-in `browser`
/// carries, which then reads his account.
///
/// # Panics
///
/// When the code is refused, or the account read is not Max's.
pub(crate) async fn answered(world: &World<'_>, browser: &Client, phone: &mut TotpApp) {
    let code = FactorCode {
        code: phone.code().await,
    };
    member_factors::verify(world.org(), &code)
        .send(browser)
        .await
        .ok();
    assert_eq!(
        members::me(world.org()).send(browser).await.ok().email,
        world.member().email(),
        "the code finishes Max's own sign-in"
    );
}

/// Ann and Tess still read their accounts, Sam from the twin company
/// reads nothing in Ann's and everything in his own, and nobody signed in
/// reads nothing: a step about Max's factor touched nobody else.
///
/// # Panics
///
/// When any of them is answered otherwise.
pub(crate) async fn others_keep_access(world: &World<'_>) {
    Matrix::new(
        "the others reading their own accounts",
        members::me(world.org()).call(),
    )
    .allowed(world.owner().client())
    .allowed(world.admin().client())
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();
}

/// Ann requires a second factor of every member of Acme, an authenticator
/// app, and raises the baseline to two factors; every other sign-in
/// setting stays as it was.
///
/// # Panics
///
/// When the settings cannot be read or the change is refused.
pub(crate) async fn require_factor(world: &World<'_>) {
    let mut settings = organizations::sign_in_settings(world.org())
        .send(world.owner().client())
        .await
        .ok();
    settings
        .rest
        .insert("mfa_policy".to_owned(), json!("Required"));
    settings
        .rest
        .insert("second_factors".to_owned(), json!(["Totp"]));
    settings.rest.get_mut("step_up").expect("step-up policy")["baseline_aal"] = json!("Aal2");
    let replace = ReplaceOrgSignInSettings {
        settings,
        proof: MemberProof {
            password: world.owner().password().to_owned(),
            code: None,
        },
    };
    organizations::replace_sign_in_settings(world.org(), &replace)
        .send(world.owner().client())
        .await
        .ok();
}
