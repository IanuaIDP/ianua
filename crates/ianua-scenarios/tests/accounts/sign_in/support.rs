//! What the sign-in scenarios share: a wrong guess, how long a mailbox is
//! watched for a mail that must not come, a password sign-in made by hand
//! and settled from the mailbox, reading past the notices to the mail
//! with the link awaited, which of two racing sign-ins won, a proof's
//! lifetime passed, and the API ready again after a dependency outage.

use std::time::{Duration, Instant};

use ianua_scenarios::api::sessions;
use ianua_scenarios::expect::eventually;
use ianua_scenarios::mail::Mail;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::sign_in::{ConfirmSignIn, Owed, PasswordSignIn, Session, SignedIn};
use ianua_scenarios::wire::{Answer, Status};

/// A wrong guess at a founder's password.
pub(crate) const WRONG_GUESS: &str = "Scenario wrong guess entirely 1234";

/// How long a mailbox is watched for a mail that must not come: two of
/// the worker's one-second polls, though a mail job runs as it is queued.
pub(crate) const QUIET: Duration = Duration::from_secs(2);

/// The most mails passed over before the one awaited, so a missing link
/// fails rather than reading forever.
const PASSED_OVER: usize = 10;

/// The session `sign_in` opens through `client`, confirmed from the
/// mailbox of its address when the platform asks for that, so it owes
/// nothing more.
///
/// # Panics
///
/// When the sign-in is refused, offers a choice, or owes a second factor.
pub(crate) async fn settled_sign_in(
    stack: &Stack,
    client: &Client,
    sign_in: &PasswordSignIn,
) -> Session {
    let answer = sessions::member_sign_in(sign_in).send(client).await.ok();
    let SignedIn::Authenticated(session) = answer else {
        panic!(
            "{} is in one organization, so no choice is offered",
            sign_in.email
        );
    };
    match session.owed() {
        Owed::Nothing => session,
        Owed::MailedConfirmation => {
            confirmed_from_mailbox(stack, client, &sign_in.email, session).await
        }
        Owed::FactorEnrolment | Owed::FactorCode => {
            panic!(
                "{} set up no second factor, yet owes {:?}",
                sign_in.email,
                session.owed()
            )
        }
    }
}

/// The waiting `session` of `email`, confirmed with the link mailed to
/// them.
///
/// # Panics
///
/// When no link comes, or the confirmation is refused.
pub(crate) async fn confirmed_from_mailbox(
    stack: &Stack,
    client: &Client,
    email: &str,
    session: Session,
) -> Session {
    let mail = mail_linking_to(stack, email, "/confirm-sign-in").await;
    let confirm = ConfirmSignIn {
        token: mail.token_in("/confirm-sign-in"),
        refresh_token: session.refresh_token.clone(),
    };
    let confirmed = sessions::confirm_member_sign_in(&confirm)
        .send(client)
        .await
        .ok();
    assert_eq!(
        confirmed.session_id, session.session_id,
        "the mailed link confirms the sign-in it was sent for"
    );
    session
}

/// The next mail to `email` with a link to `path_prefix`, passing over
/// any other mail that came first, such as a welcome or a notice.
///
/// # Panics
///
/// When no such mail comes, or more than ten others came before it.
pub(crate) async fn mail_linking_to(stack: &Stack, email: &str, path_prefix: &str) -> Mail {
    for _ in 0..=PASSED_OVER {
        let mail = stack.mailbox().next_for(email).await;
        if mail
            .links()
            .iter()
            .any(|link| link.path().starts_with(path_prefix))
        {
            return mail;
        }
    }
    panic!("{email} got {PASSED_OVER} mails before one linking to {path_prefix}");
}

/// Exactly one of two competing sign-in answers opens a session; the
/// other has the expected refusal. No session token is printed on failure.
///
/// # Panics
///
/// When both requests succeed, either fails unexpectedly, or a choice is offered.
pub(crate) fn session_won_once(
    mut answers: [Answer<SignedIn>; 2],
    refusal: Status,
    code: &str,
) -> Session {
    answers.sort_by_key(Answer::status);
    let [accepted, rejected] = answers;
    assert_eq!(
        accepted.status(),
        Status::OK,
        "one sign-in succeeds: {}",
        accepted.summary()
    );
    rejected.refused(refusal, code);
    let SignedIn::Authenticated(session) = accepted.ok() else {
        panic!("the proof identifies one account, so no choice is offered");
    };
    session
}

/// Waits until a proof received now is older than the configured lifetime.
/// The real clock keeps the API, database and cache on the same timeline.
pub(crate) async fn past_lifetime(lifetime: Duration) {
    let received = Instant::now();
    eventually("the issued proof's lifetime to pass", || async {
        (received.elapsed() > lifetime).then_some(())
    })
    .await;
}

/// Waits until the API's internal listener reports it ready again, once a
/// dependency the scenario cut is mended.
pub(crate) async fn api_ready_again(stack: &Stack) {
    let probe = format!("http://{}/health/ready", stack.internal_api());
    eventually("the API to report itself ready again", || async {
        let answer = reqwest::get(probe.as_str()).await.ok()?;
        answer.status().is_success().then_some(())
    })
    .await;
}
