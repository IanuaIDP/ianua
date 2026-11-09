//! What the tenant sign-in scenarios share: Pat invited and signed in, a
//! device of its own, a sign-in still waiting for her second factor, and
//! mailed or texted codes offered, set up and read where they arrive.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{factors, people, sessions, tenants};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::factors::ConfirmFactor;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::sign_in::Owed;
use ianua_scenarios::wire::tenant_sign_in::{TenantPasswordSignIn, TenantSession, TenantSignedIn};
use ianua_scenarios::wire::tenants::{PasswordAgain, ReplaceSignInSettings};
use ianua_scenarios::world::{MEMBER_ROLE, World};
use serde::de::IgnoredAny;
use serde_json::json;

/// A phone number set aside for testing, which no carrier serves.
pub(super) const PHONE_NUMBER: &str = "+15005550009";

/// How many mails are passed over before the one carrying a code, so a
/// missing code fails rather than reading forever.
const PASSED_OVER: usize = 10;

/// Where a code a factor sends arrives.
#[derive(Clone, Copy)]
pub(super) enum Delivery {
    /// To the person's mailbox.
    Mail,
    /// To their phone, as a text.
    Text,
}

/// Someone at an address unique to this world for `name`, invited by Tess
/// with the tenant's `Member` role, who accepted from the mailed link and
/// signed in.
///
/// # Panics
///
/// When the invitation, the acceptance or the sign-in is refused.
pub(super) async fn person(world: &World<'_>, name: &str) -> Person {
    let mut person = world.newcomer(name, &format!("{name} Tenant Holder"));
    let invitation = InviteUser {
        email: person.email().to_owned(),
        display_name: person.account().display_name.clone(),
        role_id: world.role_id(MEMBER_ROLE).await,
    };
    let invited = people::invite(world.tenant(), &invitation)
        .send(world.admin().client())
        .await
        .ok();
    person.record_invitation(&invited.id);
    person.accept_invitation(world.stack()).await;
    person.sign_in(world.stack()).await;
    person
}

/// A device of its own for `why`, nobody signed in on it.
///
/// # Panics
///
/// When the client cannot be built.
pub(super) fn device(stack: &Stack, why: &str) -> Client {
    Client::new(stack, why).expect("a device of its own")
}

/// A sign-in on a new device, waiting for what `password` opened: the
/// device and the session it holds.
pub(super) struct WaitingSignIn {
    /// The device, sending the session's token.
    pub(super) client: Client,
    /// The session, holding its token, so never printed.
    pub(super) session: TenantSession,
}

/// The sign-in `pat`'s `password` opens on a new device for `why`, which
/// owes `owed` and is held there.
///
/// # Panics
///
/// When the sign-in is refused or owes anything else.
pub(super) async fn sign_in_owing(
    world: &World<'_>,
    pat: &Person,
    why: &str,
    owed: Owed,
) -> WaitingSignIn {
    let mut client = device(world.stack(), why);
    let session = opened_session(world, &client, pat.email(), pat.password()).await;
    assert_eq!(session.owed(), owed, "the sign-in owes what it should");
    client.authorize(&session.refresh_token);
    WaitingSignIn { client, session }
}

/// The session `email`'s `password` opens through `client`.
///
/// # Panics
///
/// When the sign-in is refused, or the password must change first.
pub(super) async fn opened_session(
    world: &World<'_>,
    client: &Client,
    email: &str,
    password: &str,
) -> TenantSession {
    let sign_in = TenantPasswordSignIn {
        email: email.to_owned(),
        password: password.to_owned(),
        fingerprint_hash: None,
    };
    let answer = sessions::sign_in(world.tenant(), &sign_in)
        .send(client)
        .await
        .ok();
    let TenantSignedIn::Session(session) = answer else {
        panic!("{email} chose their own password, so none must change");
    };
    session
}

/// Offers the tenant's users mailed and texted codes beside the
/// authenticator app, as Ann with her password typed again.
///
/// # Panics
///
/// When the settings cannot be read or replaced.
pub(super) async fn sent_factors_offered(world: &World<'_>) {
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

/// Sets up a factor sent by `delivery` for `pat` and confirms it with its
/// first code, which comes where it was sent.
///
/// # Panics
///
/// When setting up or confirming is refused, or no code comes.
pub(super) async fn enroll_delivered_factor(world: &World<'_>, pat: &Person, delivery: Delivery) {
    pat.client()
        .send::<IgnoredAny>(enrolment(world, pat.password(), delivery))
        .await
        .ok();
    let code = received(world.stack(), delivery, pat.email()).await;
    let confirm = ConfirmFactor {
        code,
        session_id: None,
    };
    factors::confirm_totp(world.tenant(), &confirm)
        .send(pat.client())
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

/// The next code delivered by `delivery` for the person at `email`: from
/// the text to [`PHONE_NUMBER`], or from the next mail carrying a code.
///
/// # Panics
///
/// When no code comes.
pub(super) async fn received(stack: &Stack, delivery: Delivery, email: &str) -> String {
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
