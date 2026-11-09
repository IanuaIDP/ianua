//! Pat's remembered laptop in the tenant: once her factor is proved she
//! remembers it and its secret skips the code, until she forgets it; a
//! session on the password alone remembers nothing, Uma neither forgets
//! Pat's laptop nor signs in with its secret.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{people, sessions};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sign_in::{
    DeviceRemembered, Devices, ForgetDevice, Owed, RememberDevice,
};
use ianua_scenarios::wire::tenant_sign_in::{TenantPasswordSignIn, TenantSession, TenantSignedIn};
use ianua_scenarios::world::World;

use crate::support::{device, invited_and_signed_in, still_signed_in, tenant_records};

/// Pat, with her authenticator set up and proved, remembers her laptop.
/// The laptop, sending its secret, signs in on the password alone and
/// reads her record. She forgets the laptop: the next sign-in with the
/// same secret owes the code again and reads nothing until it is given.
/// Both the remembering and the forgetting are recorded, with no secret
/// in either.
#[tokio::test]
async fn a_remembered_laptop_skips_the_code_until_pat_forgets_it() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;
    pat.set_up_authenticator().await;
    pat.sign_in(&stack).await;

    let secret = "4e".repeat(32);
    let remembered = remember_laptop(&world, &pat, &secret).await;
    check_remembered_sign_in(&world, &pat, &secret).await;
    forget_and_check(&world, &pat, remembered.device_id, &secret).await;
    still_signed_in(&world, &pat).await;
    assert_eq!(
        tenant_records(&world, "authentication.device_trusted", &[&secret]).await,
        1,
        "remembering the laptop is recorded once"
    );
    assert_eq!(
        tenant_records(&world, "authentication.device_revoked", &[&secret]).await,
        1,
        "forgetting the laptop is recorded once"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Remember Pat's laptop and verify its name and trusted status in her device list.
async fn remember_laptop(world: &World<'_>, pat: &Person, secret: &str) -> DeviceRemembered {
    let remember = RememberDevice {
        fingerprint_hash: secret.to_owned(),
        device_name: "My laptop".to_owned(),
    };
    let remembered = pat
        .client()
        .post::<DeviceRemembered>(&world.tenant().at("/auth/device/trust/add"), &remember)
        .await
        .ok();
    let listed = pat
        .client()
        .get::<Devices>(&world.tenant().at("/auth/device/trust"))
        .await
        .ok();
    assert!(
        listed
            .devices
            .iter()
            .any(|entry| entry.id == remembered.device_id
                && entry.name == "My laptop"
                && entry.status == "trusted"),
        "the laptop is listed under its name as trusted"
    );
    remembered
}

/// A remembered laptop reaches Pat's record without another factor challenge.
async fn check_remembered_sign_in(world: &World<'_>, pat: &Person, secret: &str) {
    let mut laptop = device(world.stack(), "Pat's remembered laptop");
    let skipped = signed_in_with_secret(world, pat, &laptop, secret).await;
    assert_eq!(
        skipped.owed(),
        Owed::Nothing,
        "the remembered laptop is asked for no code"
    );
    laptop.authorize(&skipped.refresh_token);
    let own = people::me(world.tenant()).send(&laptop).await.ok();
    assert_eq!(own.id, pat.id(), "the laptop reads Pat's own record");
}

/// Revoking the laptop makes its next session owe a factor and denies account reads.
async fn forget_and_check(world: &World<'_>, pat: &Person, device_id: String, secret: &str) {
    let forget = ForgetDevice { device_id };
    pat.client()
        .post::<()>(&world.tenant().at("/auth/device/trust/revoke"), &forget)
        .await
        .ok();
    let mut forgotten = device(world.stack(), "Pat's laptop after she forgot it");
    let waiting = signed_in_with_secret(world, pat, &forgotten, secret).await;
    assert_eq!(
        waiting.owed(),
        Owed::FactorCode,
        "a forgotten laptop owes the code again"
    );
    forgotten.authorize(&waiting.refresh_token);
    people::me(world.tenant())
        .send(&forgotten)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Pat cannot remember her laptop with password proof alone. After proving
/// her factor she can remember it, but Uma cannot revoke that trust or use
/// its secret to skip her own factor. Pat's laptop remains trusted and her
/// session stays usable.
#[tokio::test]
async fn only_pat_with_her_factor_proved_remembers_or_forgets_her_laptop() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;
    let mut uma = invited_and_signed_in(&world, "uma").await;
    let secret = "5f".repeat(32);
    let remember = RememberDevice {
        fingerprint_hash: secret.clone(),
        device_name: "My laptop".to_owned(),
    };
    refuse_password_only(&world, &pat, &remember).await;
    pat.set_up_authenticator().await;
    pat.sign_in(&stack).await;
    let remembered = pat
        .client()
        .post::<DeviceRemembered>(&world.tenant().at("/auth/device/trust/add"), &remember)
        .await
        .ok();
    refuse_other_holder(&world, &mut uma, &remembered, &secret).await;
    check_remaining_trust(&world, &pat, &remembered.device_id).await;
    still_signed_in(&world, &pat).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Password proof alone cannot create a trusted device or leave a device entry.
async fn refuse_password_only(world: &World<'_>, pat: &Person, remember: &RememberDevice) {
    pat.client()
        .post::<DeviceRemembered>(&world.tenant().at("/auth/device/trust/add"), remember)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let listed = pat
        .client()
        .get::<Devices>(&world.tenant().at("/auth/device/trust"))
        .await
        .ok();
    assert!(
        listed.devices.is_empty(),
        "a session on the password alone remembers nothing"
    );
}

/// Uma can neither revoke Pat's laptop nor use its secret to satisfy her own factor.
async fn refuse_other_holder(
    world: &World<'_>,
    uma: &mut Person,
    remembered: &DeviceRemembered,
    secret: &str,
) {
    let forget = ForgetDevice {
        device_id: remembered.device_id.clone(),
    };
    uma.client()
        .post::<()>(&world.tenant().at("/auth/device/trust/revoke"), &forget)
        .await
        .refused(Status::NOT_FOUND, "not_found");

    uma.set_up_authenticator().await;
    let browser = device(world.stack(), "Uma with Pat's copied laptop secret");
    let umas = signed_in_with_secret(world, uma, &browser, secret).await;
    assert_eq!(
        umas.owed(),
        Owed::FactorCode,
        "Pat's laptop secret remembers nothing for Uma"
    );
}

/// The refused cross-holder revocation leaves Pat's laptop trusted.
async fn check_remaining_trust(world: &World<'_>, pat: &Person, device_id: &str) {
    let listed = pat
        .client()
        .get::<Devices>(&world.tenant().at("/auth/device/trust"))
        .await
        .ok();
    assert!(
        listed
            .devices
            .iter()
            .any(|entry| entry.id == device_id && entry.status == "trusted"),
        "Pat's laptop is still listed as trusted"
    );
}

/// The session `holder`'s password opens through `browser`, which sends
/// `secret` as the laptop's own, with whatever the sign-in still owes left
/// unanswered, so the step reads what a remembered secret is worth.
///
/// # Panics
///
/// When the sign-in is refused, or the password must change first.
async fn signed_in_with_secret(
    world: &World<'_>,
    holder: &Person,
    browser: &Client,
    secret: &str,
) -> TenantSession {
    let sign_in = TenantPasswordSignIn {
        email: holder.email().to_owned(),
        password: holder.password().to_owned(),
        fingerprint_hash: Some(secret.to_owned()),
    };
    let answer = sessions::sign_in(world.tenant(), &sign_in)
        .send(browser)
        .await
        .ok();
    let TenantSignedIn::Session(session) = answer else {
        panic!(
            "{} chose their own password, so none must change",
            holder.email()
        );
    };
    session
}
