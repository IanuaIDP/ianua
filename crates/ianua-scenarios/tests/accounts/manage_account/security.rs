//! Pat changing what she signs in with: her password, with every other
//! device put out and this one kept, and nothing moved by a refused
//! change; her authenticator turned off; a passkey removed, which Uma
//! could not remove; and a new printout of recovery codes that retires
//! the old one.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{factors, people, sessions};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{BREACHED_PASSWORDS, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::{
    FactorCode, PasskeyAnswerBody, Proof, RegenerateRecoveryCodes, SessionCode,
};
use ianua_scenarios::wire::sign_in::Owed;
use ianua_scenarios::wire::tenant_sign_in::{
    ChangePassword, ConfirmPasswordReset, TenantPasswordSignIn, TenantSignedIn,
};
use ianua_scenarios::world::World;

use crate::support::{
    SignedDevice, device, invited_and_signed_in, still_signed_in, tenant_records,
};

/// The password Pat changes to: a sentence, so no scanner takes it for a
/// key.
const NEW_PASSWORD: &str = "Different Orchard Lantern 7482!";

/// A password nobody ever set, which a dead reset link would have set.
const UNUSED_PASSWORD: &str = "Unused Quiet Meadow 6753!";

/// A wrong guess at Pat's current password.
const WRONG_PASSWORD: &str = "Wrong Quiet Meadow 7654!";

/// Pat, signed in on an old device too and holding a reset link she asked
/// for, changes her password from her own device. Her own device goes on;
/// the old device is out, the old password signs in no more, and the
/// reset link is dead. A fresh device signs in with the new password, and
/// the change is recorded once with no password or link in it.
#[tokio::test]
async fn pat_changes_her_password_and_her_other_device_is_out() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;
    let (old_device, _) = pat.on_another_device(&stack, "Pat's old device").await;
    let reset = pat.reset_link(&stack).await;
    people::me(world.tenant()).send(&old_device).await.ok();
    change_with_device_check(&world, &pat, &old_device).await;
    refuse_old_proofs(&world, &pat, &reset).await;
    fresh_password_sign_in(&world, &pat).await;
    assert_eq!(
        tenant_records(
            &world,
            "authentication.password_changed",
            &[NEW_PASSWORD, &reset, pat.password()]
        )
        .await,
        1,
        "the change is recorded once"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Changing Pat's password keeps the requesting session and ends her other device.
async fn change_with_device_check(world: &World<'_>, pat: &Person, old_device: &Client) {
    let change = ChangePassword {
        old_password: pat.password().to_owned(),
        new_password: NEW_PASSWORD.to_owned(),
        mfa_code: None,
    };
    sessions::change_password(world.tenant(), &change)
        .send(pat.client())
        .await
        .ok();
    still_signed_in(world, pat).await;
    people::me(world.tenant())
        .send(old_device)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// The password change invalidates both the old password and the pending reset link.
async fn refuse_old_proofs(world: &World<'_>, pat: &Person, reset: &str) {
    let old_password = TenantPasswordSignIn {
        email: pat.email().to_owned(),
        password: pat.password().to_owned(),
        fingerprint_hash: None,
    };
    sessions::sign_in(world.tenant(), &old_password)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let by_dead_link = ConfirmPasswordReset {
        token: reset.to_owned(),
        new_password: UNUSED_PASSWORD.to_owned(),
        mfa_code: None,
    };
    sessions::confirm_password_reset(world.tenant(), &by_dead_link)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// A fresh browser signs into Pat's existing account with her replacement password.
async fn fresh_password_sign_in(world: &World<'_>, pat: &Person) {
    let mut fresh = Person::new(
        device(world.stack(), "Pat with the new password"),
        pat.account().clone(),
        NEW_PASSWORD,
    );
    fresh.record_invitation(pat.id());
    fresh.sign_in(world.stack()).await;
    still_signed_in(world, &fresh).await;
}

/// A wrong current password, one-letter replacement and breached password
/// each prevent Pat's password change. Every change is
/// refused; her other device and her own stay signed in, her password
/// still signs in, and nothing is recorded.
#[tokio::test]
async fn a_refused_password_change_leaves_every_device_signed_in() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;
    let (other, _) = pat.on_another_device(&stack, "Pat's other device").await;
    refuse_password_changes(&world, &pat, &other).await;
    pat.sign_in(&stack).await;
    assert_eq!(
        tenant_records(&world, "authentication.password_changed", &[pat.password()]).await,
        0,
        "a refused change records nothing"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Incorrect proof and weak replacements leave both existing devices usable.
async fn refuse_password_changes(world: &World<'_>, pat: &Person, other: &Client) {
    let wrong_current = ChangePassword {
        old_password: WRONG_PASSWORD.to_owned(),
        new_password: NEW_PASSWORD.to_owned(),
        mfa_code: None,
    };
    sessions::change_password(world.tenant(), &wrong_current)
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    for replacement in ["x", BREACHED_PASSWORDS[0]] {
        let too_weak = ChangePassword {
            old_password: pat.password().to_owned(),
            new_password: replacement.to_owned(),
            mfa_code: None,
        };
        sessions::change_password(world.tenant(), &too_weak)
            .send(pat.client())
            .await
            .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
        people::me(world.tenant()).send(other).await.ok();
        still_signed_in(world, pat).await;
    }
}

/// Pat, with her authenticator set up and signed in on another device
/// with its code, turns the authenticator off with a fresh code. The
/// other device is out, the factor is off, and her next sign-in works on
/// the password alone. Turning it off is recorded once.
#[tokio::test]
async fn pat_turns_off_her_authenticator_and_signs_in_with_the_password_alone() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;
    pat.set_up_authenticator().await;
    let (other, _) = pat
        .on_another_device(&stack, "Pat's device signed in with a code")
        .await;
    let mut phone = pat.lose_phone();

    let code = FactorCode {
        code: phone.code().await,
    };
    disable_factor(&world, &pat, &other, &code).await;
    pat.sign_in(&stack).await;
    still_signed_in(&world, &pat).await;
    assert_eq!(
        tenant_records(&world, "authentication.mfa_unenrolled", &[]).await,
        1,
        "turning the factor off is recorded once"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Disabling the authenticator ends the other device and reports the factor disabled.
async fn disable_factor(world: &World<'_>, pat: &Person, other: &Client, code: &FactorCode) {
    factors::disable(world.tenant(), code)
        .send(pat.client())
        .await
        .ok();
    people::me(world.tenant())
        .send(other)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let status = factors::status(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert!(!status.enabled, "the authenticator is off");
}

/// Pat adds a passkey on her laptop. Uma cannot remove it by its id
/// because it is not hers. Pat removes it: her list is empty, the
/// passkey's answer to a sign-in challenge is refused, and her password
/// still signs her in. Uma's session goes on.
#[tokio::test]
async fn a_removed_passkey_signs_in_no_more_and_uma_cannot_remove_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;
    let uma = invited_and_signed_in(&world, "uma").await;
    pat.add_passkey(&stack, "Laptop").await;
    remove_owned_passkey(&world, &pat, &uma).await;
    refuse_removed_passkey(&world, &mut pat).await;
    pat.sign_in(&stack).await;
    still_signed_in(&world, &pat).await;
    still_signed_in(&world, &uma).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma cannot remove Pat's key; Pat's own removal leaves her registration list empty.
async fn remove_owned_passkey(world: &World<'_>, pat: &Person, uma: &Person) {
    let keys = factors::passkeys(world.tenant())
        .send(pat.client())
        .await
        .ok();
    let key = &keys.passkeys[0];

    factors::remove_passkey(world.tenant(), &key.id)
        .send(uma.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    factors::remove_passkey(world.tenant(), &key.id)
        .send(pat.client())
        .await
        .ok();
    let left = factors::passkeys(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert!(left.passkeys.is_empty(), "Pat's passkey list is empty");
}

/// The removed key's valid answer cannot authenticate against its deleted registration.
async fn refuse_removed_passkey(world: &World<'_>, pat: &mut Person) {
    let (ceremony_id, challenge) = pat.passkey_challenge().await;
    let Some(passkey) = pat.passkey() else {
        panic!("Pat still holds the key itself, only its registration is gone");
    };
    let answer = passkey
        .on_page(&world.stack().app_url())
        .sign_in(&challenge);
    let body = PasskeyAnswerBody {
        ceremony_id,
        response: answer.response,
        credential_id: answer.credential_id,
    };
    factors::confirm_passkey_sign_in(world.tenant(), &body)
        .send(pat.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// Pat, with her authenticator set up, asks for a new printout of recovery
/// codes. A wrong password is refused even with a valid factor code.
/// With her password and a fresh code she gets codes none of which was on
/// the old printout. On a new browser her sign-in owes the code: an old
/// code is refused and reads nothing, a new one lets her in as herself.
#[tokio::test]
async fn a_new_printout_retires_the_old_codes() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;
    pat.set_up_authenticator().await;
    let Some(printout) = pat.recovery_codes() else {
        panic!("setting up the authenticator printed recovery codes");
    };
    let old = printout.all().to_vec();
    let mut phone = pat.lose_phone();
    refuse_wrong_printout_password(&world, &pat, &mut phone).await;
    let new = replace_printout(&world, &pat, &mut phone, &old).await;
    let waiting = pending_recovery_sign_in(&world, &pat).await;
    refuse_old_recovery_code(&world, &waiting, &old[0]).await;
    accept_new_recovery_code(&world, &pat, &waiting, &new[0]).await;
    still_signed_in(&world, &pat).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// A valid phone code does not excuse an incorrect password when replacing recovery codes.
async fn refuse_wrong_printout_password(world: &World<'_>, pat: &Person, phone: &mut TotpApp) {
    let wrong_password = RegenerateRecoveryCodes {
        proof: Proof::Password {
            password: WRONG_PASSWORD.to_owned(),
            code: Some(phone.code().await),
        },
    };
    factors::regenerate_recovery_codes(world.tenant(), &wrong_password)
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Correct password and fresh factor proof produce codes absent from the old printout.
async fn replace_printout(
    world: &World<'_>,
    pat: &Person,
    phone: &mut TotpApp,
    old: &[String],
) -> Vec<String> {
    let proved = RegenerateRecoveryCodes {
        proof: Proof::Password {
            password: pat.password().to_owned(),
            code: Some(phone.code().await),
        },
    };
    let shown = factors::regenerate_recovery_codes(world.tenant(), &proved)
        .send(pat.client())
        .await
        .ok();
    assert!(
        !shown.recovery_codes.is_empty(),
        "the new printout holds codes"
    );
    assert!(
        shown.recovery_codes.iter().all(|code| !old.contains(code)),
        "no code of the new printout was on the old one"
    );
    shown.recovery_codes
}

/// A new browser authenticates the password but still owes a factor before account access.
async fn pending_recovery_sign_in(world: &World<'_>, pat: &Person) -> SignedDevice {
    let mut browser = device(world.stack(), "Pat with the new printout");
    let sign_in = TenantPasswordSignIn {
        email: pat.email().to_owned(),
        password: pat.password().to_owned(),
        fingerprint_hash: None,
    };
    let answer = sessions::sign_in(world.tenant(), &sign_in)
        .send(&browser)
        .await
        .ok();
    let TenantSignedIn::Session(waiting) = answer else {
        panic!("Pat chose her own password, so none must change");
    };
    assert_eq!(
        waiting.owed(),
        Owed::FactorCode,
        "a new browser owes the code"
    );
    browser.authorize(&waiting.refresh_token);
    SignedDevice {
        client: browser,
        session: waiting,
    }
}

/// The retired recovery code cannot complete the session or permit an account read.
async fn refuse_old_recovery_code(world: &World<'_>, waiting: &SignedDevice, code: &str) {
    let old_code = SessionCode {
        session_id: waiting.session.session_id.clone(),
        code: code.to_owned(),
    };
    factors::redeem_recovery_code(world.tenant(), &old_code)
        .send(&waiting.client)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    people::me(world.tenant())
        .send(&waiting.client)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// A replacement recovery code completes the pending session as Pat's own account.
async fn accept_new_recovery_code(
    world: &World<'_>,
    pat: &Person,
    waiting: &SignedDevice,
    code: &str,
) {
    let new_code = SessionCode {
        session_id: waiting.session.session_id.clone(),
        code: code.to_owned(),
    };
    factors::redeem_recovery_code(world.tenant(), &new_code)
        .send(&waiting.client)
        .await
        .ok();
    let own = people::me(world.tenant()).send(&waiting.client).await.ok();
    assert_eq!(own.id, pat.id(), "the new code lets Pat in as herself");
}
