//! The device a member remembers: only a sign-in that proved a second
//! factor may remember one; from then on the password alone opens a
//! session there, while any other device is still asked for the factor;
//! and a device forgotten is asked again at once.

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{OrgPath, members, sessions};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Trail, no_secret_leaked};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sign_in::{
    ForgetDevice, Owed, PasswordSignIn, RememberDevice, Session, SignedIn,
};

use crate::support::WRONG_GUESS;

/// Ann, signed in with her password and her mailbox alone, cannot
/// remember her laptop: that would let whoever holds the password skip a
/// factor she adds later. With an authenticator app set up and its code
/// proved, she remembers it, and from then on her password alone signs
/// her in there, while Mallory with the same password on another device
/// is asked for the code. Every sign-in ends the sessions before it,
/// Mallory's included, so Ann signs in from her laptop once more, and
/// forgets it: it is listed as forgotten, cannot be forgotten twice, and
/// her next sign-in from it is asked for the code again. The application
/// clock advances to the fresh code used to prove the laptop.
#[tokio::test]
async fn a_remembered_device_skips_the_factor_until_it_is_forgotten() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);

    let password_only = ann.signed_in(&stack).await;
    ann.remember_device(&founded.org_slug, &password_only)
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let mut phone = ann
        .set_up_authenticator(&founded.org_slug, &password_only)
        .await;
    let proved = ann.signed_in_with(&stack, &mut phone).await;
    let remembered = ann.remember_device(&founded.org_slug, &proved).await.ok();
    ann.client_mut().authorize(&proved.refresh_token);
    assert_trusted_laptop(&ann, &org, &remembered.device_id).await;
    assert_other_device_owes_code(&stack, &ann).await;
    forget_laptop_once(&mut ann, &org, &remembered.device_id).await;
    let secrets: [&str; 3] = [phone.secret(), &proved.refresh_token, FOUNDER_PASSWORD];
    assert_device_audits(&ann, &org, &secrets).await;

    let asked_again = ann.password_sign_in().await;
    assert_eq!(
        asked_again.owed(),
        Owed::FactorCode,
        "the forgotten laptop is asked for the code again"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann lists exactly the named laptop she just trusted.
async fn assert_trusted_laptop(ann: &Founder, org: &OrgPath, device_id: &str) {
    let listed = sessions::member_devices(org).send(ann.client()).await.ok();
    let [laptop] = listed.devices.as_slice() else {
        panic!(
            "Ann remembered one device, {} are listed",
            listed.devices.len()
        );
    };
    assert_eq!(
        laptop.id, device_id,
        "the device listed is the one Ann remembered"
    );
    assert_eq!(
        laptop.name, "Founder's laptop",
        "the laptop is listed under its name"
    );
    assert_eq!(laptop.status, "trusted", "the laptop is listed as trusted");
}

/// Ann's remembered laptop skips the factor, while the same password on Mallory's browser does not.
async fn assert_other_device_owes_code(stack: &Stack, ann: &Founder) {
    let from_laptop = ann.password_sign_in().await;
    assert_eq!(
        from_laptop.owed(),
        Owed::Nothing,
        "the remembered laptop is asked for nothing more"
    );
    let mallory = Client::new(stack, "Mallory, with Ann's password").expect("a client");
    let elsewhere = sessions::member_sign_in(&PasswordSignIn::of(ann.email(), FOUNDER_PASSWORD))
        .send(&mallory)
        .await
        .ok();
    let SignedIn::Authenticated(elsewhere) = elsewhere else {
        panic!("Ann is in one organization, so no choice is offered");
    };
    assert_eq!(
        elsewhere.owed(),
        Owed::FactorCode,
        "another device is asked for the code"
    );
}

/// The still-trusted laptop signs in before its device record is revoked exactly once.
async fn forget_laptop_once(ann: &mut Founder, org: &OrgPath, device_id: &str) {
    let again = ann.password_sign_in().await;
    assert_eq!(
        again.owed(),
        Owed::Nothing,
        "the remembered laptop is still asked for nothing more"
    );
    ann.client_mut().authorize(&again.refresh_token);
    let forget = ForgetDevice {
        device_id: device_id.to_owned(),
    };
    sessions::forget_device(org, &forget)
        .send(ann.client())
        .await
        .ok();
    sessions::forget_device(org, &forget)
        .send(ann.client())
        .await
        .refused(Status::CONFLICT, "conflict");
    let listed = sessions::member_devices(org).send(ann.client()).await.ok();
    assert!(
        listed
            .devices
            .iter()
            .all(|device| device.status == "revoked"),
        "the laptop is listed as forgotten"
    );
}

/// Trusting and forgetting the laptop leave audit records without authentication secrets.
async fn assert_device_audits(ann: &Founder, org: &OrgPath, secrets: &[&str]) {
    let trail = Trail::of_organization(ann.client(), org.slug());
    let trusted = trail.recorded("organization.org_device_trusted").await;
    let revoked = trail.recorded("organization.org_device_revoked").await;
    for record in [trusted, revoked] {
        no_secret_leaked(&record.details.to_string(), secrets);
    }
}

/// Ann, her authenticator proved, remembers her browser by the secret it
/// keeps. From that browser a wrong guess at her password is refused, the
/// secret notwithstanding, and her session is untouched; with a secret
/// nobody remembered and her right password, the sign-in still owes the
/// code and reads nothing. The remembered secret with the right password
/// is asked for nothing more, and the record of the trust holds neither
/// the secret nor the password. The clock is controlled so the
/// authenticator shows a fresh code.
#[tokio::test]
async fn a_device_secret_needs_the_right_password_and_must_be_remembered() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let first = ann.signed_in(&stack).await;
    let mut phone = ann.set_up_authenticator(&founded.org_slug, &first).await;
    let proved = ann.signed_in_with(&stack, &mut phone).await;
    ann.client_mut().authorize(&proved.refresh_token);
    let secret = "ab".repeat(32);
    remember_browser(&ann, &org, &secret).await;

    let mut browser = Client::new(&stack, "Ann's remembered browser").expect("a client");
    assert_invalid_device_proofs(&ann, &org, &mut browser, &secret).await;

    let trusted = session_from_device(&browser, ann.email(), &secret).await;
    assert_eq!(
        trusted.owed(),
        Owed::Nothing,
        "the remembered secret with the right password is asked for nothing more"
    );
    browser.authorize(&trusted.refresh_token);
    members::me(&org).send(&browser).await.ok();
    let record = Trail::of_organization(&browser, org.slug())
        .recorded("organization.org_device_trusted")
        .await;
    no_secret_leaked(&record.details.to_string(), &[&secret, FOUNDER_PASSWORD]);

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann stores the chosen browser secret after proving her authenticator.
async fn remember_browser(ann: &Founder, org: &OrgPath, secret: &str) {
    sessions::remember_device(
        org,
        &RememberDevice {
            fingerprint_hash: secret.to_owned(),
            device_name: "Ann's browser".to_owned(),
        },
    )
    .send(ann.client())
    .await
    .ok();
}

/// A trusted secret cannot rescue a wrong password, and an unknown secret cannot skip the factor.
async fn assert_invalid_device_proofs(
    ann: &Founder,
    org: &OrgPath,
    browser: &mut Client,
    secret: &str,
) {
    sessions::member_sign_in(&PasswordSignIn::of(ann.email(), WRONG_GUESS).from_device(secret))
        .send(browser)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    members::me(org).send(ann.client()).await.ok();
    let made_up = session_from_device(browser, ann.email(), &"cd".repeat(32)).await;
    assert_eq!(
        made_up.owed(),
        Owed::FactorCode,
        "a secret nobody remembered is asked for the code"
    );
    browser.authorize(&made_up.refresh_token);
    members::me(org)
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// The session opened by Ann's password and the browser's device secret.
async fn session_from_device(client: &Client, email: &str, secret: &str) -> Session {
    let SignedIn::Authenticated(session) =
        sessions::member_sign_in(&PasswordSignIn::of(email, FOUNDER_PASSWORD).from_device(secret))
            .send(client)
            .await
            .ok()
    else {
        panic!("Ann belongs to one organization, so no choice is offered");
    };
    session
}
