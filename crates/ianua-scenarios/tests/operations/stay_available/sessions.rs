//! Ann signing in and out over and over leaves nothing behind in the
//! platform's memory: every session, token check and counter a sign-in
//! makes is given back once it ends.

use ianua_scenarios::actors::Founder;
use ianua_scenarios::api::OrgPath;
use ianua_scenarios::api::sessions::member_sign_out;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::memory::Steady;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::sign_in::SignOut;

/// Sign-ins one address may make a minute here: far above what the rounds
/// need, so the per-address limit never answers instead of the platform.
const SIGN_INS_A_MINUTE: &str = "100000";

/// Ann signs in, sets up an authenticator app, signs in again with its
/// code and remembers her laptop, as the dashboard offers once a second
/// factor was proved, so her later sign-ins from it ask for nothing more
/// than her password. Then she signs in and straight out again a hundred
/// times, after twenty rounds to warm up. What each round leaves held in
/// the platform's memory stays within a few kilobytes: no session, token
/// or counter piles up. The application clock advances only for the
/// initial authenticator proof; the measured rounds run with real time
/// passing normally.
#[tokio::test]
async fn signing_in_and_out_leaves_nothing_behind() {
    let _clock = Clock::controlled();
    let profile = Profile::standard().with("RATE_LIMIT_LOGIN_PER_MINUTE", SIGN_INS_A_MINUTE);
    let stack = Stack::start(profile).await.expect("the stack starts");
    let ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let first = ann.signed_in(&stack).await;
    let mut phone = ann.set_up_authenticator(&founded.org_slug, &first).await;
    let proved = ann.signed_in_with(&stack, &mut phone).await;
    let remembered = ann.remember_device(&founded.org_slug, &proved).await;
    assert!(
        remembered.status().is_success(),
        "Ann remembers her laptop: {}",
        remembered.summary()
    );
    measure_sessions(&ann, &stack, &org).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Repeated complete sessions retain no more than the per-round memory budget.
async fn measure_sessions(ann: &Founder, stack: &Stack, org: &OrgPath) {
    let steady = Steady {
        warm_up: 20,
        rounds: 100,
        per_round: 8 * 1024,
    };
    let per_round = steady
        .holds("signing in and out", move || async move {
            let session = ann.signed_in(stack).await;
            let sign_out = SignOut {
                session_id: session.session_id.clone(),
            };
            let bearer = format!("Bearer {}", session.refresh_token);
            let answer = member_sign_out(org, &sign_out)
                .header("authorization", &bearer)
                .send(ann.client())
                .await;
            assert!(
                answer.status().is_success(),
                "Ann signs out: {}",
                answer.summary()
            );
        })
        .await;
    tracing::info!(per_round, "signing in and out holds this much per round");
}
