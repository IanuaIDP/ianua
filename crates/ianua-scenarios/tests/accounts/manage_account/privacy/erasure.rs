//! Pat's erasure: asking for it closes her account and ends every session
//! of hers at once. She calls it off with the link mailed to her and signs
//! in afresh; a legal hold keeps her account past its due date until staff
//! lift it; once due, the worker removes her for good, once, even across a
//! restart. Uma cannot erase Pat, nobody signed in can, and staff asking
//! twice start no second erasure.

use std::time::Duration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{account, audit, people, sessions};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{eventually, no_secret_leaked};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::account::ErasureRequest;
use ianua_scenarios::wire::people::LinkToken;
use ianua_scenarios::wire::tenant_sign_in::TenantPasswordSignIn;
use ianua_scenarios::world::World;

use crate::support::{
    invited_and_signed_in, mail_linking_to, past_lifetime, still_signed_in, tenant_records,
};

/// How long the erasure waits before it is due, in days, in the scenarios
/// that let the worker carry it out: one, the shortest the platform takes.
const GRACE_DAYS: &str = "1";

/// How far the clock moves to pass the grace period: two days, well past
/// one, so the worker's next sweep finds the erasure due.
const PAST_GRACE: Duration = Duration::from_secs(2 * 86_400);

/// How often the worker sweeps for due work in these scenarios, in
/// seconds: every second, so a due erasure is carried out at once.
const SWEEP_EVERY: &str = "1";

/// A held erasure and the mailbox proof that can cancel it after release.
struct HeldErasure {
    /// The request staff holds and releases.
    id: String,
    /// The cancellation proof mailed to Pat.
    proof: LinkToken,
}

/// Pat asks to erase her account: her laptop and her phone are signed out
/// at once and her account reads as closing. Her mailed cancellation link
/// is refused in the twin tenant. In her own
/// tenant it calls the erasure off, but her phone stays signed out. She
/// signs in afresh and is herself again; the link, used once, calls off
/// nothing more. The call-off is recorded once, without the link.
#[tokio::test]
async fn pat_calls_off_her_erasure_by_mail_and_her_old_sessions_stay_ended() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;
    let (phone, _) = pat.on_another_device(&stack, "Pat's phone").await;
    close_pat_account(&world, &pat, &phone).await;
    let proof = cancel_from_mailbox(&world, &pat, &phone).await;
    pat.sign_in(&stack).await;
    still_signed_in(&world, &pat).await;
    account::cancel_erasure(world.tenant(), &proof)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    assert_eq!(
        tenant_records(&world, "identity.erasure_cancelled", &[&proof.token]).await,
        1,
        "the call-off is recorded once"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat's erasure request closes her record and immediately ends both existing devices.
async fn close_pat_account(world: &World<'_>, pat: &Person, phone: &Client) {
    account::erase(world.tenant(), pat.id(), &leaving())
        .send(pat.client())
        .await
        .ok();
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    people::me(world.tenant())
        .send(phone)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let record = people::get(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(record.status, "Closing", "Pat's account reads as closing");
}

/// Only Pat's tenant accepts the mailed cancellation, and her old phone session stays ended.
async fn cancel_from_mailbox(world: &World<'_>, pat: &Person, phone: &Client) -> LinkToken {
    let mail = mail_linking_to(world.stack(), pat.email(), "/cancel-erasure").await;
    let proof = LinkToken {
        token: mail.token_in("/cancel-erasure"),
    };
    account::cancel_erasure(world.twin(), &proof)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    account::cancel_erasure(world.tenant(), &proof)
        .send(world.anonymous().client())
        .await
        .ok();
    people::me(world.tenant())
        .send(phone)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    proof
}

/// After Pat requests erasure, Uma cannot place a legal hold because she
/// is not staff, but Ann can. The clock passes the due date and the
/// worker sweeps, but Pat's account still reads as closing. Ann lifts the
/// hold, Pat calls the erasure off with her mailed link, and she signs in
/// afresh.
#[tokio::test]
async fn a_legal_hold_keeps_pats_account_past_its_due_date_until_ann_lifts_it() {
    let clock = Clock::controlled();
    let stack = Stack::start(sweeping_profile())
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;
    let uma = invited_and_signed_in(&world, "uma").await;
    let held = request_and_hold(&world, &pat, &uma).await;
    check_hold_after_due(&mut world, &pat, &clock).await;
    account::release_erasure(world.tenant(), &held.id)
        .send(world.owner().client())
        .await
        .ok();
    account::cancel_erasure(world.tenant(), &held.proof)
        .send(world.anonymous().client())
        .await
        .ok();
    pat.sign_in(&stack).await;
    still_signed_in(&world, &pat).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma cannot place the requested erasure on hold, while Ann can.
async fn request_and_hold(world: &World<'_>, pat: &Person, uma: &Person) -> HeldErasure {
    let request = account::erase(world.tenant(), pat.id(), &leaving())
        .send(pat.client())
        .await
        .ok();
    let mail = mail_linking_to(world.stack(), pat.email(), "/cancel-erasure").await;
    let proof = LinkToken {
        token: mail.token_in("/cancel-erasure"),
    };

    account::hold_erasure(world.tenant(), &request.id)
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    account::hold_erasure(world.tenant(), &request.id)
        .send(world.owner().client())
        .await
        .ok();
    HeldErasure {
        id: request.id,
        proof,
    }
}

/// After time and worker sweeps pass the due date, the held account remains closing.
async fn check_hold_after_due(world: &mut World<'_>, pat: &Person, clock: &Clock) {
    clock.advance(PAST_GRACE);
    let stack = world.stack();
    world.owner_mut().sign_in(stack).await;
    past_lifetime(Duration::from_secs(3)).await;
    let record = people::get(world.tenant(), pat.id())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        record.status, "Closing",
        "the held erasure is not carried out on its date"
    );
}

/// Pat asks to erase her account and the clock passes its due date: the
/// worker removes her account, her password signs nobody in and her old
/// session reads nothing. The API and worker restart and sweep again:
/// the erasure is recorded as done once, and the record names neither
/// Pat's address, nor her password, nor her name.
#[tokio::test]
async fn a_due_erasure_removes_pat_once_even_across_a_restart() {
    let clock = Clock::controlled();
    let stack = Stack::start(sweeping_profile())
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;

    account::erase(world.tenant(), pat.id(), &leaving())
        .send(pat.client())
        .await
        .ok();
    clock.advance(PAST_GRACE);
    world.owner_mut().sign_in(&stack).await;
    await_account_removal(&world, &pat).await;
    refuse_erased_credentials(&world, &pat).await;
    check_erasure_after_restart(&world, &pat).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Wait for the worker to remove the due account as observed through the owner's API.
async fn await_account_removal(world: &World<'_>, pat: &Person) {
    eventually("the worker to remove Pat's account", || async {
        let answer = people::get(world.tenant(), pat.id())
            .send(world.owner().client())
            .await;
        (answer.status() == Status::NOT_FOUND).then_some(())
    })
    .await;
}

/// An erased account authenticates with neither its old password nor its former session.
async fn refuse_erased_credentials(world: &World<'_>, pat: &Person) {
    let sign_in = TenantPasswordSignIn {
        email: pat.email().to_owned(),
        password: pat.password().to_owned(),
        fingerprint_hash: None,
    };
    sessions::sign_in(world.tenant(), &sign_in)
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// A restart and another sweep leave one completed record without Pat's personal details or password.
async fn check_erasure_after_restart(world: &World<'_>, pat: &Person) {
    world
        .stack()
        .restart()
        .await
        .expect("the API and worker restart");
    past_lifetime(Duration::from_secs(2)).await;
    let records = audit::tenant_log(world.tenant(), "identity.erasure_completed")
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        records.items.len(),
        1,
        "the erasure is recorded as done once"
    );
    no_secret_leaked(
        &records.items[0].details.to_string(),
        &[pat.email(), pat.password(), &pat.account().display_name],
    );
}

/// Uma and an anonymous caller cannot erase Pat, whose session stays
/// usable. Tess can request it once, ending Pat's session; a second request
/// is refused. Uma is still
/// herself, and the erasure is recorded once, without Pat's password.
#[tokio::test]
async fn only_staff_or_pat_herself_erase_pat_and_only_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    let uma = invited_and_signed_in(&world, "uma").await;
    refuse_erasure_callers(&world, &pat, &uma).await;
    still_signed_in(&world, &pat).await;
    erase_as_staff_once(&world, &pat).await;
    still_signed_in(&world, &uma).await;
    assert_eq!(
        tenant_records(&world, "identity.erasure_requested", &[pat.password()]).await,
        1,
        "the erasure is recorded once"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Neither Uma nor an anonymous caller can request Pat's erasure.
async fn refuse_erasure_callers(world: &World<'_>, pat: &Person, uma: &Person) {
    account::erase(world.tenant(), pat.id(), &leaving())
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    account::erase(world.tenant(), pat.id(), &leaving())
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Staff can request the erasure once, and Pat's existing session immediately stops working.
async fn erase_as_staff_once(world: &World<'_>, pat: &Person) {
    account::erase(world.tenant(), pat.id(), &leaving())
        .send(world.admin().client())
        .await
        .ok();
    account::erase(world.tenant(), pat.id(), &leaving())
        .send(world.admin().client())
        .await
        .refused(Status::CONFLICT, "conflict");
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// The standard profile with a one-day grace period and a worker that
/// sweeps every second, so a due erasure is carried out at once.
fn sweeping_profile() -> Profile {
    Profile::standard()
        .with("PRIVACY_ERASURE_GRACE_DAYS", GRACE_DAYS)
        .with("WORKER_SWEEP_TICK_SECONDS", SWEEP_EVERY)
}

/// The reason given with each erasure in these scenarios.
fn leaving() -> ErasureRequest {
    ErasureRequest {
        reason: "I am leaving".to_owned(),
    }
}
