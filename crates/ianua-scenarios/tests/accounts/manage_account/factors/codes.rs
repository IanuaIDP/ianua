//! Pat's factors delivered to her: a code mailed to her, and a code
//! texted to her phone number, each received where it was sent and proved
//! there before it counts, and then answering only the sign-in it was
//! sent for: not from nobody signed in, not from Uma's session.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{factors, people, sessions, tenants};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::{ConfirmFactor, SessionCode};
use ianua_scenarios::wire::sign_in::Owed;
use ianua_scenarios::wire::tenant_sign_in::{TenantPasswordSignIn, TenantSession, TenantSignedIn};
use ianua_scenarios::wire::tenants::{PasswordAgain, ReplaceSignInSettings};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;
use serde_json::json;

use crate::support::{SignedDevice, device, invited_and_signed_in, tenant_records};

/// Pat's phone number: one of the numbers set aside for testing, which
/// no carrier serves.
const PHONE_NUMBER: &str = "+15005550009";

/// The most mails passed over before the one carrying a code, so a
/// missing code fails rather than reading forever.
const PASSED_OVER: usize = 10;

/// Where a code is delivered.
#[derive(Clone, Copy)]
enum Delivery {
    /// To Pat's mailbox.
    Mail,
    /// To Pat's phone, as a text.
    Text,
}

/// Pat sets up a mailed code: the first code, received in her mailbox,
/// confirms it. On a new browser her sign-in owes a code and reads
/// nothing; she has one sent and receives it. An anonymous visitor and Uma
/// cannot use that code. On Pat's own browser it lets her in, and the
/// setup is recorded once with no code in it.
#[tokio::test]
async fn a_mailed_code_proves_the_mailbox_and_answers_only_its_own_sign_in() {
    let stack = Stack::start(sending_codes_at_once())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    let uma = invited_and_signed_in(&world, "uma").await;
    sent_factors_offered(&world).await;
    enroll_delivered_factor(&world, &pat, Delivery::Mail).await;
    let waiting = pending_sign_in(&world, &pat, "Pat with a mailed code").await;
    let answer = request_sign_in_code(&world, &pat, &waiting, Delivery::Mail).await;
    refuse_other_callers(&world, &uma, &answer).await;
    factors::verify(world.tenant(), &answer)
        .send(&waiting.client)
        .await
        .ok();
    let own = people::me(world.tenant()).send(&waiting.client).await.ok();
    assert_eq!(own.id, pat.id(), "the mailed code lets Pat in as herself");
    assert_eq!(
        tenant_records(&world, "authentication.mfa_enrolled", &[&answer.code]).await,
        1,
        "the setup is recorded once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat sets up a texted code, naming her number: the first code, texted
/// to it, confirms it. On a new browser her sign-in owes a code and
/// reads nothing; she has one sent and receives it on her phone. An anonymous
/// visitor and Uma cannot use that code. On Pat's own browser it lets
/// her in, and the setup is recorded once with no code in it.
#[tokio::test]
async fn a_texted_code_proves_the_number_and_answers_only_its_own_sign_in() {
    let stack = Stack::start(sending_codes_at_once())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    let uma = invited_and_signed_in(&world, "uma").await;
    sent_factors_offered(&world).await;
    enroll_delivered_factor(&world, &pat, Delivery::Text).await;
    let waiting = pending_sign_in(&world, &pat, "Pat with a texted code").await;
    let answer = request_sign_in_code(&world, &pat, &waiting, Delivery::Text).await;
    refuse_other_callers(&world, &uma, &answer).await;
    factors::verify(world.tenant(), &answer)
        .send(&waiting.client)
        .await
        .ok();
    let own = people::me(world.tenant()).send(&waiting.client).await.ok();
    assert_eq!(own.id, pat.id(), "the texted code lets Pat in as herself");
    assert_eq!(
        tenant_records(&world, "authentication.mfa_enrolled", &[&answer.code]).await,
        1,
        "the setup is recorded once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Prove the destination with its first delivered code before using it as a sign-in factor.
async fn enroll_delivered_factor(world: &World<'_>, pat: &Person, delivery: Delivery) {
    pat.client()
        .send::<IgnoredAny>(enrolment(world, pat.password(), delivery))
        .await
        .ok();
    let first = received(world.stack(), delivery, pat.email()).await;
    let confirm = ConfirmFactor {
        code: first,
        session_id: None,
    };
    factors::confirm_totp(world.tenant(), &confirm)
        .send(pat.client())
        .await
        .ok();
}

/// A new browser owes the delivered code and cannot read Pat before answering it.
async fn pending_sign_in(world: &World<'_>, pat: &Person, label: &str) -> SignedDevice {
    let mut browser = device(world.stack(), label);
    let waiting = owing_a_code(world, &browser, pat.email(), pat.password()).await;
    browser.authorize(&waiting.refresh_token);
    people::me(world.tenant())
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    SignedDevice {
        client: browser,
        session: waiting,
    }
}

/// Ask for the pending session's code and read it from the configured delivery destination.
async fn request_sign_in_code(
    world: &World<'_>,
    pat: &Person,
    waiting: &SignedDevice,
    delivery: Delivery,
) -> SessionCode {
    waiting
        .client
        .send::<IgnoredAny>(send_code(world, &waiting.session.session_id))
        .await
        .ok();
    let code = received(world.stack(), delivery, pat.email()).await;
    SessionCode {
        session_id: waiting.session.session_id.clone(),
        code,
    }
}

/// Neither an anonymous caller nor Uma can use Pat's session-bound code.
async fn refuse_other_callers(world: &World<'_>, uma: &Person, answer: &SessionCode) {
    factors::verify(world.tenant(), answer)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    factors::verify(world.tenant(), answer)
        .send(uma.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// The standard profile with no wait between one sent code and the next,
/// so the code sent for the sign-in follows the one that proved the
/// destination at once.
fn sending_codes_at_once() -> Profile {
    Profile::standard().with("MFA_SENT_CODE_RESEND_SECONDS", "0")
}

/// Offers the tenant's users mailed and texted codes beside the
/// authenticator app, in its sign-in settings, as Ann.
async fn sent_factors_offered(world: &World<'_>) {
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    settings.rest.insert(
        "second_factors".to_owned(),
        json!(["Totp", "EmailCode", "SmsCode"]),
    );
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

/// `POST …/auth/mfa/enroll/code`: Pat sets up a code sent by `delivery`,
/// proving who she is with `password`, naming her number for a text.
fn enrolment(world: &World<'_>, password: &str, delivery: Delivery) -> Call {
    let mut body = json!({
        "method": method(delivery),
        "proof": {"kind": "password", "password": password},
    });
    if matches!(delivery, Delivery::Text) {
        body["phone_number"] = json!(PHONE_NUMBER);
    }
    Call::post(world.tenant().at("/auth/mfa/enroll/code")).json(&body)
}

/// The name the API gives a factor delivered by `delivery`.
fn method(delivery: Delivery) -> &'static str {
    match delivery {
        Delivery::Mail => "email_code",
        Delivery::Text => "sms_code",
    }
}

/// `POST …/auth/mfa/send-code`: the waiting sign-in `session_id` asks for
/// its code to be sent.
fn send_code(world: &World<'_>, session_id: &str) -> Call {
    Call::post(world.tenant().at("/auth/mfa/send-code")).json(&json!({"session_id": session_id}))
}

/// The session the password of `email` opens through `browser`, a device
/// never remembered, so it owes the code from the factor set up.
///
/// # Panics
///
/// When the sign-in is refused, the password must change first, or it
/// owes anything but a code.
async fn owing_a_code(
    world: &World<'_>,
    browser: &Client,
    email: &str,
    password: &str,
) -> TenantSession {
    let sign_in = TenantPasswordSignIn {
        email: email.to_owned(),
        password: password.to_owned(),
        fingerprint_hash: None,
    };
    let answer = sessions::sign_in(world.tenant(), &sign_in)
        .send(browser)
        .await
        .ok();
    let TenantSignedIn::Session(session) = answer else {
        panic!("{email} chose their own password, so none must change");
    };
    assert_eq!(
        session.owed(),
        Owed::FactorCode,
        "a device never remembered is asked for the code"
    );
    session
}

/// The next code delivered by `delivery` for Pat: from the text to her
/// number, or from the next mail to `email` carrying a code, passing over
/// a welcome or a notice.
///
/// # Panics
///
/// When no code comes, or ten mails came without one.
async fn received(stack: &Stack, delivery: Delivery, email: &str) -> String {
    match delivery {
        Delivery::Text => stack.texts().next_for(PHONE_NUMBER).await.code(),
        Delivery::Mail => mailed_code(stack, email).await,
    }
}

/// The code in the next mail to `email` whose subject speaks of a code.
async fn mailed_code(stack: &Stack, email: &str) -> String {
    for _ in 0..=PASSED_OVER {
        let mail = stack.mailbox().next_for(email).await;
        if mail.subject().to_ascii_lowercase().contains("code") {
            return mail.code();
        }
    }
    panic!("{email} got {PASSED_OVER} mails and none carried a code");
}
