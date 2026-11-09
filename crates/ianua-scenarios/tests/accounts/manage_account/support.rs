//! What the account scenarios share: Pat and Uma invited into the tenant
//! and signed in, a session of theirs on another device settled from the
//! mailbox, the two links a move to another mailbox sends, reading past
//! the notices to the mail with the link awaited, and the checks after a
//! change that a person is still signed in and that the tenant's audit log
//! holds the records expected, with no secret in them.

use std::time::{Duration, Instant};

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{account, audit, people, sessions};
use ianua_scenarios::expect::{eventually, no_secret_leaked};
use ianua_scenarios::mail::Mail;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::account::EmailChange;
use ianua_scenarios::wire::people::{InviteUser, LinkToken};
use ianua_scenarios::wire::sign_in::Owed;
use ianua_scenarios::wire::tenant_sign_in::{
    ConfirmTenantSignIn, TenantPasswordSignIn, TenantSession, TenantSignedIn,
};
use ianua_scenarios::world::{MEMBER_ROLE, World};

/// The most mails passed over before the one awaited, so a missing link
/// fails rather than reading forever.
const PASSED_OVER: usize = 10;

/// A move to another mailbox still pending: the address moved to, and the
/// two links the platform mailed, one to each mailbox.
pub(crate) struct EmailProofs {
    /// The address moved to, not the person's until confirmed.
    pub(crate) address: String,
    /// The link mailed to the new mailbox, which confirms the move.
    pub(crate) confirm: LinkToken,
    /// The link mailed to the old mailbox, which calls the move off.
    pub(crate) cancel: LinkToken,
}

/// A session a person opened on another device, with its token, which a
/// step needs to prove that session's account.
pub(crate) struct SignedDevice {
    /// The device, sending the session's token.
    pub(crate) client: Client,
    /// The session, holding its token, so never printed.
    pub(crate) session: TenantSession,
}

/// Someone at an address unique to this world for `name`, invited by
/// Tess with the tenant's `Member` role, who accepts from the mailed
/// link and signs in on a device of their own.
///
/// # Panics
///
/// When the invitation, the acceptance or the sign-in is refused.
pub(crate) async fn invited_and_signed_in(world: &World<'_>, name: &str) -> Person {
    let mut person = world.newcomer(name, &format!("{name} Account Holder"));
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

/// The session `person`'s password opens on a device of their own they
/// never used, settled from their mailbox when the platform asks, so it
/// owes nothing more.
///
/// # Panics
///
/// When the sign-in is refused, or owes a second factor they never set up.
pub(crate) async fn signed_in_elsewhere(world: &World<'_>, person: &Person) -> SignedDevice {
    let why = format!("{} on another device", person.account().display_name);
    let mut client = device(world.stack(), &why);
    let sign_in = TenantPasswordSignIn {
        email: person.email().to_owned(),
        password: person.password().to_owned(),
        fingerprint_hash: None,
    };
    let answer = sessions::sign_in(person.tenant(), &sign_in)
        .send(&client)
        .await
        .ok();
    let TenantSignedIn::Session(session) = answer else {
        panic!(
            "{} chose their own password, so none must change",
            person.email()
        );
    };
    client.authorize(&session.refresh_token);
    settle_device_sign_in(world, &client, person, &session).await;
    SignedDevice { client, session }
}

/// A new device settles a mailed challenge but refuses unexpected factor requirements.
async fn settle_device_sign_in(
    world: &World<'_>,
    client: &Client,
    person: &Person,
    session: &TenantSession,
) {
    match session.owed() {
        Owed::Nothing => {}
        Owed::MailedConfirmation => confirmed_from_mailbox(world, client, person, session).await,
        Owed::FactorEnrolment | Owed::FactorCode => {
            panic!(
                "{} set up no second factor, yet owes {:?}",
                person.email(),
                session.owed()
            )
        }
    }
}

/// Confirms `person`'s waiting `session` on `client` with the link mailed
/// to them, after which it owes nothing more.
async fn confirmed_from_mailbox(
    world: &World<'_>,
    client: &Client,
    person: &Person,
    session: &TenantSession,
) {
    let mail = mail_linking_to(world.stack(), person.email(), "/confirm-sign-in").await;
    let confirm = ConfirmTenantSignIn {
        link: mail.token_in("/confirm-sign-in"),
        session_token: session.refresh_token.clone(),
    };
    let confirmed = sessions::confirm_sign_in(person.tenant(), &confirm)
        .send(client)
        .await
        .ok();
    assert_eq!(
        confirmed.owed(),
        Owed::Nothing,
        "the mailed link settles everything the sign-in owed"
    );
}

/// The next mail to `email` with a link ending in `path`, passing over
/// any other mail that came first, such as a welcome or a notice.
///
/// # Panics
///
/// When no such mail comes, or more than ten others came before it.
pub(crate) async fn mail_linking_to(stack: &Stack, email: &str, path: &str) -> Mail {
    for _ in 0..=PASSED_OVER {
        let mail = stack.mailbox().next_for(email).await;
        if mail.links().iter().any(|link| link.path().ends_with(path)) {
            return mail;
        }
    }
    panic!("{email} got {PASSED_OVER} mails before one linking to {path}");
}

/// The move `holder` asks for, to an address unique to this world for
/// `name`, proving who they are with their password, with the two links
/// it mailed.
///
/// # Panics
///
/// When the move is refused, or either link does not come.
pub(crate) async fn email_change_requested(
    world: &World<'_>,
    holder: &Person,
    name: &str,
) -> EmailProofs {
    let address = world.address(name);
    let change = EmailChange {
        new_email: address.clone(),
        password: holder.password().to_owned(),
        code: None,
    };
    account::change_email(account::Plane::Tenant(world.tenant()), &change)
        .send(holder.client())
        .await
        .ok();
    email_change_proofs(world.stack(), holder.email(), address).await
}

/// The two links a move from `old` to `address` mailed: the confirmation
/// to the new mailbox and the warning to the old one, each read from its
/// own mail, neither derived from the other.
///
/// # Panics
///
/// When either link does not come.
pub(crate) async fn email_change_proofs(stack: &Stack, old: &str, address: String) -> EmailProofs {
    let confirm = mail_linking_to(stack, &address, "/confirm-email-change").await;
    let cancel = mail_linking_to(stack, old, "/cancel-email-change").await;
    EmailProofs {
        address,
        confirm: LinkToken {
            token: confirm.token_in("/confirm-email-change"),
        },
        cancel: LinkToken {
            token: cancel.token_in("/cancel-email-change"),
        },
    }
}

/// How many records of exactly `event_type` the tenant's audit log holds,
/// read by Tess, failing when any of `secrets` appears in one: a step
/// records what it did, never the password, code or link it was given.
///
/// # Panics
///
/// When the log cannot be read, or a record holds one of `secrets`.
pub(crate) async fn tenant_records(world: &World<'_>, event_type: &str, secrets: &[&str]) -> usize {
    let records = audit::tenant_log(world.tenant(), event_type)
        .send(world.admin().client())
        .await
        .ok();
    for record in &records.items {
        no_secret_leaked(&record.details.to_string(), secrets);
    }
    records
        .items
        .iter()
        .filter(|record| record.event_type == event_type)
        .count()
}

/// `person`'s own session still works, and reaches no more than before: it
/// reads their own record, but not the twin tenant, nor the tenant's list
/// of users, which only an administrator reads.
///
/// # Panics
///
/// When their session is refused, reads someone else, or reaches further.
pub(crate) async fn still_signed_in(world: &World<'_>, person: &Person) {
    let own = people::me(world.tenant()).send(person.client()).await.ok();
    assert_eq!(
        own.id,
        person.id(),
        "{} still reads their own record",
        person.email()
    );
    people::me(world.twin())
        .send(person.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    people::list(world.tenant(), None)
        .send(person.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Waits until a link or secret received now is older than `lifetime`.
/// The real clock keeps the API, database and cache on the same timeline.
pub(crate) async fn past_lifetime(lifetime: Duration) {
    let received = Instant::now();
    eventually("the issued proof's lifetime to pass", || async {
        (received.elapsed() > lifetime).then_some(())
    })
    .await;
}

/// A device of its own for `why`, with its own address and cookies, nobody
/// signed in on it.
///
/// # Panics
///
/// When the client cannot be built.
pub(crate) fn device(stack: &Stack, why: &str) -> Client {
    Client::new(stack, why).expect("a device of its own")
}
