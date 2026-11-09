//! The platform builds every address it hands out from its own name,
//! never from the name a request claims: the link mailed to Victor is the
//! platform's even when Mallory sent the request under her own host.

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::onboarding;
use ianua_scenarios::stack::{Profile, Stack};

/// The host Mallory claims.
const MALLORYS_HOST: &str = "evil.example";

/// Mallory asks for a sign-up of Victor's address while claiming her own
/// host, hoping the link mailed to Victor points at her site, where she
/// would catch his token when he clicks. The link Victor gets points at
/// the platform's own address, and nowhere names her host.
#[tokio::test]
async fn a_mailed_link_never_takes_the_host_a_request_claims() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let victor = Founder::named(&stack, "Victor");
    let mallory = Founder::named(&stack, "Mallory");
    let sign_up = victor.sign_up_of("Victor Ltd", FOUNDER_PASSWORD);

    onboarding::sign_up(&sign_up)
        .header("host", MALLORYS_HOST)
        .header("x-forwarded-host", MALLORYS_HOST)
        .send(mallory.client())
        .await
        .ok();

    let mail = stack.mailbox().next_for(victor.email()).await;
    let own = stack.app_url();
    for link in mail.links() {
        assert_eq!(
            link.host_str(),
            own.host_str(),
            "every link in the mail is the platform's own: {link}"
        );
    }
    let text = mail.text().unwrap_or_default();
    let html = mail.html().unwrap_or_default();
    assert!(
        !text.contains(MALLORYS_HOST) && !html.contains(MALLORYS_HOST),
        "the mail nowhere names the host Mallory claimed"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
