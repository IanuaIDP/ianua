//! What a remembered device's secret is worth: Max's obey his company's
//! limit on devices and stop counting when he changes his password; Ann's
//! laptop is trusted for a day, to the second; and Ann's secret, used in
//! a sign-in as Bob, skips none of Bob's factors.

use std::time::Duration;

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{OrgPath, members, sessions};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Trail, no_secret_leaked};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::ChangeMemberPassword;
use ianua_scenarios::wire::sign_in::{
    ForgetDevice, Owed, PasswordSignIn, RememberDevice, Session, SignedIn,
};
use ianua_scenarios::world::World;

use crate::factors::member::{answered, enrolled, others_keep_access, waiting};

/// The seconds in the one day a company in these scenarios trusts a
/// remembered device for, so the boundaries are stated as offsets from it.
const DAY_SECONDS: u64 = 86_400;

/// The password Max changes to after remembering his laptop: a sentence,
/// so no scanner takes it for a key.
const NEW_PASSWORD: &str = "Scenario orchard mountain harbour 8291";

/// Max's company lets a member remember one device. Max remembers his
/// first laptop; remembering a second is refused and leaves one trust
/// record, and from the second his password still owes the code. Once he
/// forgets the first, the second is remembered and his password alone
/// signs him in from it: two devices were trusted and one forgotten, and
/// his colleagues keep their access. The clock is controlled so the
/// authenticator shows fresh codes.
#[tokio::test]
async fn a_device_limit_refuses_trust_until_an_existing_device_is_forgotten() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().with("AUTH_MAX_TRUSTED_DEVICES_PER_USER", "1"))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut factor = enrolled(&world).await;
    let mut browser = Client::new(&stack, "Max, with two laptops").expect("a client");
    waiting(&world, &mut browser, world.member().password()).await;
    answered(&world, &browser, &mut factor.phone).await;
    let first = "12".repeat(32);
    let second = "34".repeat(32);

    let device_id = fill_device_limit(&world, &browser, &first, &second).await;
    let from_second =
        PasswordSignIn::of(world.member().email(), world.member().password()).from_device(&second);
    let pending = from_device(&browser, &from_second).await;
    assert_eq!(
        pending.owed(),
        Owed::FactorCode,
        "the device the company would not remember is asked for the code"
    );
    browser.authorize(&pending.refresh_token);
    answered(&world, &browser, &mut factor.phone).await;

    forget_first_device(&world, &browser, device_id).await;
    trust_second_device(&world, &mut browser, &second, &from_second).await;
    assert_replacement_records(&world).await;
    others_keep_access(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max remembers the first laptop and the second reaches the device limit,
/// leaving only the first trust in the audit trail.
async fn fill_device_limit(
    world: &World<'_>,
    browser: &Client,
    first: &str,
    second: &str,
) -> String {
    let device = sessions::remember_device(world.org(), &remember(first))
        .send(browser)
        .await
        .ok();
    let refused = sessions::remember_device(world.org(), &remember(second))
        .send(browser)
        .await
        .refused(Status::CONFLICT, "conflict");
    assert_eq!(
        refused.message(),
        "Maximum trusted devices reached",
        "the refusal names the limit"
    );
    let trail = world.trail();
    assert_eq!(
        trail.count("organization.org_device_trusted").await,
        1,
        "the refused device records no trust"
    );
    device.device_id
}

/// Forgetting the first laptop releases the company's only available device slot.
async fn forget_first_device(world: &World<'_>, browser: &Client, device_id: String) {
    sessions::forget_device(world.org(), &ForgetDevice { device_id })
        .send(browser)
        .await
        .ok();
}

/// With a free slot the second laptop is remembered, and its secret removes the
/// factor challenge while restoring authenticated access.
async fn trust_second_device(
    world: &World<'_>,
    browser: &mut Client,
    second: &str,
    from_second: &PasswordSignIn,
) {
    sessions::remember_device(world.org(), &remember(second))
        .send(browser)
        .await
        .ok();
    let trusted = from_device(browser, from_second).await;
    assert_eq!(
        trusted.owed(),
        Owed::Nothing,
        "the second laptop, remembered once there is room, is asked for nothing more"
    );
    browser.authorize(&trusted.refresh_token);
    members::me(world.org()).send(browser).await.ok();
}

/// Replacing the first laptop records two successful trusts and one revocation.
async fn assert_replacement_records(world: &World<'_>) {
    let trail = world.trail();
    assert_eq!(
        trail.count("organization.org_device_trusted").await,
        2,
        "two devices were trusted in all"
    );
    assert_eq!(
        trail.count("organization.org_device_revoked").await,
        1,
        "one device was forgotten"
    );
}

/// Max remembers his laptop, then changes his password: the session that
/// changed it is ended, and from the laptop the new password still owes
/// the code, reading nothing until it is given. Proving the phone, he
/// remembers the laptop anew, and his password alone signs him in from
/// it. His colleagues keep their access, and the one change recorded
/// holds no password and no device secret. The clock is controlled so the
/// authenticator shows fresh codes.
#[tokio::test]
async fn a_password_change_invalidates_previously_remembered_device_trust() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut factor = enrolled(&world).await;
    let mut browser =
        Client::new(&stack, "Max, replacing a compromised password").expect("a client");
    waiting(&world, &mut browser, world.member().password()).await;
    answered(&world, &browser, &mut factor.phone).await;
    let old_secret = "56".repeat(32);
    sessions::remember_device(world.org(), &remember(&old_secret))
        .send(&browser)
        .await
        .ok();

    replace_password_and_challenge(&world, &mut browser, &old_secret).await;
    answered(&world, &browser, &mut factor.phone).await;

    let new_secret = "78".repeat(32);
    remember_after_password_change(&world, &mut browser, &new_secret).await;
    others_keep_access(&world).await;
    assert_password_record(&world, &old_secret, &new_secret).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Changing Max's password ends the current session, and the previous device
/// secret cannot bypass his factor with the replacement password.
async fn replace_password_and_challenge(world: &World<'_>, browser: &mut Client, old_secret: &str) {
    change_password_ending_session(world, browser).await;
    let pending = from_device(
        browser,
        &PasswordSignIn::of(world.member().email(), NEW_PASSWORD).from_device(old_secret),
    )
    .await;
    assert_eq!(
        pending.owed(),
        Owed::FactorCode,
        "the laptop remembered under the old password is asked for the code"
    );
    browser.authorize(&pending.refresh_token);
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Max changes his password and the browser that made the change immediately loses access.
async fn change_password_ending_session(world: &World<'_>, browser: &Client) {
    members::change_password(
        world.org(),
        &ChangeMemberPassword {
            old_password: world.member().password().to_owned(),
            new_password: NEW_PASSWORD.to_owned(),
        },
    )
    .send(browser)
    .await
    .ok();
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Max remembers the laptop after proving his factor again, and its new secret
/// lets the replacement password open his account without another challenge.
async fn remember_after_password_change(world: &World<'_>, browser: &mut Client, new_secret: &str) {
    sessions::remember_device(world.org(), &remember(new_secret))
        .send(browser)
        .await
        .ok();
    let trusted = from_device(
        browser,
        &PasswordSignIn::of(world.member().email(), NEW_PASSWORD).from_device(new_secret),
    )
    .await;
    assert_eq!(
        trusted.owed(),
        Owed::Nothing,
        "the laptop remembered anew is asked for nothing more"
    );
    browser.authorize(&trusted.refresh_token);
    members::me(world.org()).send(browser).await.ok();
}

/// The single password change exposes neither the password nor either device
/// secret in its audit record.
async fn assert_password_record(world: &World<'_>, old_secret: &str, new_secret: &str) {
    let changes = world
        .trail()
        .entries("organization.org_user_password_changed")
        .await;
    let [change] = changes.as_slice() else {
        panic!("one password change is recorded, not {}", changes.len());
    };
    no_secret_leaked(
        &format!("{change:?}"),
        &[NEW_PASSWORD, old_secret, new_secret],
    );
}

/// Ann remembers her laptop, which her company trusts for a day, and
/// signs in from it with her password alone. A day and a second later the
/// laptop is asked for the code again and reads nothing until the app
/// answers, and then she is in. One trust was recorded, and no
/// forgetting. The clock is controlled so the authenticator shows fresh
/// codes and the day passes at once.
#[tokio::test]
async fn an_unused_device_expires_and_requires_the_factor_again() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().with("AUTH_DEVICE_TRUST_DAYS", "1"))
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let initial = ann.signed_in(&stack).await;
    let mut phone = ann.set_up_authenticator(&founded.org_slug, &initial).await;
    let proved = ann.signed_in_with(&stack, &mut phone).await;
    ann.remember_device(&founded.org_slug, &proved).await.ok();

    let trusted = ann.password_sign_in().await;
    assert_eq!(
        trusted.owed(),
        Owed::Nothing,
        "the remembered laptop is asked for nothing more"
    );

    clock.advance(Duration::from_secs(DAY_SECONDS + 1));
    assert_expired_device(&mut ann, &org).await;
    let completed = ann.signed_in_with(&stack, &mut phone).await;
    ann.client_mut().authorize(&completed.refresh_token);
    members::me(&org).send(ann.client()).await.ok();

    assert_expiry_records(&ann, &org).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// After the trust deadline Ann's laptop owes her factor and its pending session
/// cannot read her member record.
async fn assert_expired_device(ann: &mut Founder, org: &OrgPath) {
    let expired = ann.password_sign_in().await;
    assert_eq!(
        expired.owed(),
        Owed::FactorCode,
        "a day and a second later the laptop is asked for the code again"
    );
    ann.client_mut().authorize(&expired.refresh_token);
    members::me(org)
        .send(ann.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Expiring the laptop's single trust produces no device-forgetting record.
async fn assert_expiry_records(ann: &Founder, org: &OrgPath) {
    let trail = Trail::of_organization(ann.client(), org.slug());
    assert_eq!(
        trail.count("organization.org_device_trusted").await,
        1,
        "the laptop was trusted once"
    );
    assert_eq!(
        trail.count("organization.org_device_revoked").await,
        0,
        "an expired trust is no forgetting"
    );
}

/// Ann signs in from her remembered laptop one second before its day of
/// trust ends: her password alone signs her in.
#[tokio::test]
async fn device_trust_works_one_second_before_its_deadline() {
    device_trust_at(DAY_SECONDS - 1, TrustAt::Kept).await;
}

/// Ann signs in from her remembered laptop at the very second its day of
/// trust ends: her password alone still signs her in, the cutoff being
/// inclusive.
#[tokio::test]
async fn device_trust_still_works_at_its_inclusive_cutoff() {
    device_trust_at(DAY_SECONDS, TrustAt::Kept).await;
}

/// One second past its day of trust, Ann's laptop cannot skip her
/// authenticator. It is asked for the code, reads nothing until the app
/// answers, and no second trust is recorded.
#[tokio::test]
async fn device_trust_requires_the_factor_one_second_after_its_deadline() {
    device_trust_at(DAY_SECONDS + 1, TrustAt::Expired).await;
}

/// Whether a remembered laptop still skips the authenticator at a given
/// age.
#[derive(Clone, Copy)]
enum TrustAt {
    /// The password alone signs in.
    Kept,
    /// The code is asked for again.
    Expired,
}

/// The elapsed trust time and the corresponding factor requirement.
struct TrustBoundary {
    /// Seconds since the device was remembered.
    age: u64,
    /// Whether the device still skips the factor.
    at: TrustAt,
}

/// Ann remembers her laptop after proving her authenticator, then signs
/// in from it `age` seconds later with her password alone: `at` says
/// whether that is enough. Either way she reads her record in the end,
/// and the laptop was trusted once.
async fn device_trust_at(age: u64, at: TrustAt) {
    let _setup_clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().with("AUTH_DEVICE_TRUST_DAYS", "1"))
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let initial = ann.signed_in(&stack).await;
    let mut phone = ann.set_up_authenticator(&founded.org_slug, &initial).await;
    let proved = ann.signed_in_with(&stack, &mut phone).await;
    let clock = Clock::fixed();
    ann.remember_device(&founded.org_slug, &proved).await.ok();

    clock.advance(Duration::from_secs(age));
    let session = ann.password_sign_in().await;
    ann.client_mut().authorize(&session.refresh_token);
    assert_trust_boundary(&ann, &org, &session, TrustBoundary { age, at }).await;
    if matches!(at, TrustAt::Expired) {
        let completed = ann.signed_in_with(&stack, &mut phone).await;
        ann.client_mut().authorize(&completed.refresh_token);
    }
    assert_trusted_account(&ann, &org).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann can read her account after the boundary check, with exactly one device trust recorded.
async fn assert_trusted_account(ann: &Founder, org: &OrgPath) {
    members::me(org).send(ann.client()).await.ok();
    assert_eq!(
        Trail::of_organization(ann.client(), org.slug())
            .count("organization.org_device_trusted")
            .await,
        1,
        "the laptop was trusted once"
    );
}

/// Ann's factor requirement follows the trust cutoff, and an expired device's
/// pending session cannot read her account before the factor is proved.
async fn assert_trust_boundary(
    ann: &Founder,
    org: &OrgPath,
    session: &Session,
    boundary: TrustBoundary,
) {
    let TrustBoundary { age, at } = boundary;
    match at {
        TrustAt::Kept => assert_eq!(
            session.owed(),
            Owed::Nothing,
            "{age} seconds on, the laptop is asked for nothing more"
        ),
        TrustAt::Expired => {
            assert_eq!(
                session.owed(),
                Owed::FactorCode,
                "{age} seconds on, the laptop is asked for the code again"
            );
            members::me(org)
                .send(ann.client())
                .await
                .refused(Status::UNAUTHORIZED, "unauthenticated");
        }
    }
}

/// Ann and Bob each founded a company and set up an authenticator, and
/// Ann remembered her laptop. Someone knowing Bob's password signs in as
/// Bob from a device claiming the secret of Ann's laptop: the sign-in
/// still owes Bob's code and reads nothing, and Bob signs in with his own
/// app. Ann's laptop still signs her in with her password alone, one
/// trust is recorded at Acme and none at Globex. The clock is controlled
/// so the authenticators show fresh codes.
#[tokio::test]
async fn a_device_secret_cannot_be_reused_for_another_account() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let secret = "9a".repeat(32);
    let mut acme = remember_anns_laptop(&stack, &secret).await;
    let mut bob = Founder::named(&stack, "Bob");
    let globex = bob.founded(&stack, "Globex").await;
    let first = bob.signed_in(&stack).await;
    let mut bobs_phone = bob.set_up_authenticator(&globex.org_slug, &first).await;

    assert_borrowed_secret(&stack, &bob, &globex.org_slug, &secret).await;
    finish_bobs_sign_in(&stack, &mut bob, &globex.org_slug, &mut bobs_phone).await;
    assert_anns_laptop(&mut acme.ann, &secret).await;
    assert_account_trust_records(&acme, &bob, &globex.org_slug).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann and the company in which her laptop was remembered.
struct RememberedAccount {
    /// Ann, signed in with her authenticator.
    ann: Founder,
    /// Her company's slug for checking its separate audit trail.
    org_slug: String,
}

/// Ann proves her authenticator and remembers a chosen device secret in Acme.
async fn remember_anns_laptop(stack: &Stack, secret: &str) -> RememberedAccount {
    let mut ann = Founder::named(stack, "Ann");
    let acme = ann.founded(stack, "Acme").await;
    let initial = ann.signed_in(stack).await;
    let mut phone = ann.set_up_authenticator(&acme.org_slug, &initial).await;
    let proved = ann.signed_in_with(stack, &mut phone).await;
    ann.client_mut().authorize(&proved.refresh_token);
    sessions::remember_device(&OrgPath::new(&acme.org_slug), &remember(secret))
        .send(ann.client())
        .await
        .ok();
    RememberedAccount {
        ann,
        org_slug: acme.org_slug,
    }
}

/// A stranger supplies Ann's device secret with Bob's password, but still owes
/// Bob's factor and cannot read his member record.
async fn assert_borrowed_secret(stack: &Stack, bob: &Founder, org_slug: &str, secret: &str) {
    let mut stranger = Client::new(stack, "Someone reusing Ann's device secret").expect("a client");
    let pending = from_device(
        &stranger,
        &PasswordSignIn::of(bob.email(), FOUNDER_PASSWORD).from_device(secret),
    )
    .await;
    assert_eq!(
        pending.owed(),
        Owed::FactorCode,
        "Ann's laptop's secret skips none of Bob's factors"
    );
    stranger.authorize(&pending.refresh_token);
    members::me(&OrgPath::new(org_slug))
        .send(&stranger)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Bob signs in with his own authenticator and reads his member record.
async fn finish_bobs_sign_in(
    stack: &Stack,
    bob: &mut Founder,
    org_slug: &str,
    phone: &mut TotpApp,
) {
    let completed = bob.signed_in_with(stack, phone).await;
    bob.client_mut().authorize(&completed.refresh_token);
    members::me(&OrgPath::new(org_slug))
        .send(bob.client())
        .await
        .ok();
}

/// Ann's own secret still removes her factor challenge after its misuse for Bob.
async fn assert_anns_laptop(ann: &mut Founder, secret: &str) {
    let valid = from_device(
        ann.client(),
        &PasswordSignIn::of(ann.email(), FOUNDER_PASSWORD).from_device(secret),
    )
    .await;
    assert_eq!(
        valid.owed(),
        Owed::Nothing,
        "Ann's own laptop is still asked for nothing more"
    );
    ann.client_mut().authorize(&valid.refresh_token);
}

/// The two companies retain separate trust histories: one device for Ann and
/// none for Bob after the attempted cross-account reuse.
async fn assert_account_trust_records(acme: &RememberedAccount, bob: &Founder, globex: &str) {
    assert_eq!(
        Trail::of_organization(acme.ann.client(), &acme.org_slug)
            .count("organization.org_device_trusted")
            .await,
        1,
        "one trust is recorded at Acme"
    );
    assert_eq!(
        Trail::of_organization(bob.client(), globex)
            .count("organization.org_device_trusted")
            .await,
        0,
        "no trust is recorded at Globex"
    );
}

/// The request remembering the device whose browser keeps `secret`.
fn remember(secret: &str) -> RememberDevice {
    RememberDevice {
        fingerprint_hash: secret.to_owned(),
        device_name: "Personal laptop".to_owned(),
    }
}

/// The session the password sign-in `request`, from a device keeping a
/// secret, opens through `browser`, whatever it still owes.
async fn from_device(browser: &Client, request: &PasswordSignIn) -> Session {
    let answer = sessions::member_sign_in(request).send(browser).await.ok();
    let SignedIn::Authenticated(session) = answer else {
        panic!("the account is in one organization, so no choice is offered");
    };
    session
}
