//! Ann signing in by a mailed link alone, with no password, once she let
//! her company's members do that: the link works once, ends the session
//! she held before, still owes her authenticator's code when she has one,
//! obeys the methods her company allows at the moment it is followed, and
//! is worth nothing once expired. Mallory, asking for Ann's link, gets
//! nothing from it.

use std::time::Duration;

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{OrgPath, member_factors, members, organizations, sessions};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Trail, no_secret_leaked};
use ianua_scenarios::mail::Mail;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::FactorCode;
use ianua_scenarios::wire::organization::{OrgSignInSettings, ReplaceOrgSignInSettings};
use ianua_scenarios::wire::sign_in::{
    MagicLinkRequest, MagicLinkSignIn, MemberProof, Owed, Session, SignedIn,
};

use crate::mailbox::allow_mailed_links;
use crate::support::{QUIET, mail_linking_to, past_lifetime, session_won_once};

/// How long a mailed link is worth something in the expiry scenario:
/// short enough to wait for on the real clock, which the API, database
/// and cache share.
const LINK_LIFETIME_SECONDS: u64 = 2;

/// Ann lets her company's members sign in by a mailed link. Mallory asks
/// for a link to Ann's address and is answered as anyone is; the link
/// lands in Ann's mailbox and nowhere else, and Ann asking again a moment
/// later gets no second one. Ann follows her link on her phone: she is
/// signed in with no password and owes nothing more, and that sign-in
/// ends the one she held before. The same link again, or one made up,
/// opens nothing.
#[tokio::test]
async fn a_mailed_link_signs_in_without_a_password_and_works_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let session = ann.signed_in(&stack).await;
    ann.client_mut().authorize(&session.refresh_token);
    allow_mailed_links(&ann, &org).await;

    let mallory = Client::new(&stack, "Mallory, asking for Ann's link").expect("a client");
    let mail = request_once_for_owner(&stack, &ann, &mallory).await;

    let mut phone = Client::new(&stack, "Ann, on her phone").expect("a client");
    let follow = MagicLinkSignIn {
        token: mail.token_in("/magic-link"),
        tenant_slug: None,
    };
    let by_link = follow_link(&phone, &follow).await;
    assert_eq!(by_link.owed(), Owed::Nothing, "the link proves the mailbox");
    assert_eq!(
        by_link.org_slug, founded.org_slug,
        "the link signs Ann in to her own company"
    );
    phone.authorize(&by_link.refresh_token);
    assert_replaced_session(&phone, &ann, &org).await;

    assert_spent_and_fabricated(&mallory, &follow).await;
    assert_link_audit(&phone, &org, &follow, &by_link).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The new phone session reads Ann's account while her old browser session has ended.
async fn assert_replaced_session(phone: &Client, ann: &Founder, org: &OrgPath) {
    members::me(org).send(phone).await.ok();
    members::me(org)
        .send(ann.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Mallory's request mails Ann alone, and Ann's immediate repeat produces no second link.
async fn request_once_for_owner(stack: &Stack, ann: &Founder, mallory: &Client) -> Mail {
    let for_ann = MagicLinkRequest {
        email: ann.email().to_owned(),
    };
    sessions::request_magic_link(&for_ann)
        .send(mallory)
        .await
        .ok();
    let mail = mail_linking_to(stack, ann.email(), "/magic-link").await;
    assert_eq!(
        mail.recipient(),
        ann.email(),
        "the link Mallory asked for goes to Ann's mailbox"
    );
    sessions::request_magic_link(&for_ann)
        .send(ann.client())
        .await
        .ok();
    stack.mailbox().nothing_for(ann.email(), QUIET).await;
    mail
}

/// A valid mailed link identifies Ann's sole organization without offering a company choice.
async fn follow_link(browser: &Client, follow: &MagicLinkSignIn) -> Session {
    let answer = sessions::sign_in_by_magic_link(follow)
        .send(browser)
        .await
        .ok();
    let SignedIn::Authenticated(by_link) = answer else {
        panic!("the link names Ann's one organization, so no choice is offered");
    };
    by_link
}

/// Neither a consumed link nor a made-up token opens another session for Mallory.
async fn assert_spent_and_fabricated(mallory: &Client, follow: &MagicLinkSignIn) {
    sessions::sign_in_by_magic_link(follow)
        .send(mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let made_up = MagicLinkSignIn {
        token: "a-token-mallory-made-up".to_owned(),
        tenant_slug: None,
    };
    sessions::sign_in_by_magic_link(&made_up)
        .send(mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// Link requesting and successful login are audited without the mailed or session credentials.
async fn assert_link_audit(
    phone: &Client,
    org: &OrgPath,
    follow: &MagicLinkSignIn,
    by_link: &Session,
) {
    let trail = Trail::of_organization(phone, org.slug());
    trail
        .recorded("organization.org_magic_link_requested")
        .await;
    let signed_in = trail.recorded("organization.org_login_succeeded").await;
    no_secret_leaked(
        &signed_in.details.to_string(),
        &[&follow.token, &by_link.refresh_token],
    );
}

/// Ann, with an authenticator app set up, lets her company sign in by
/// mailed link and follows hers: the link proves her mailbox, but the
/// sign-in still owes the app's code and reads nothing until it is given,
/// and the link followed again opens nothing. With the code she is in,
/// and the record of it holds neither the link's token, the session's,
/// nor the app's secret. The clock is controlled so the app shows a
/// fresh code.
#[tokio::test]
async fn a_mailed_link_with_an_authenticator_still_owes_its_code() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let first = ann.signed_in(&stack).await;
    ann.client_mut().authorize(&first.refresh_token);
    allow_mailed_links(&ann, &org).await;
    let mut authenticator = ann.set_up_authenticator(&founded.org_slug, &first).await;

    let follow = request_link(&stack, &ann).await;
    let mut browser = Client::new(&stack, "Ann, following her link").expect("a client");
    let waiting = begin_factor_link(&mut browser, &org, &follow).await;
    verify_link_factor(&browser, &org, &mut authenticator).await;
    let verified = Trail::of_organization(&browser, &founded.org_slug)
        .recorded("organization.org_mfa_verified")
        .await;
    no_secret_leaked(
        &verified.details.to_string(),
        &[
            &follow.token,
            &waiting.refresh_token,
            authenticator.secret(),
        ],
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann requests the mailbox proof for a subsequent link-only sign-in.
async fn request_link(stack: &Stack, ann: &Founder) -> MagicLinkSignIn {
    sessions::request_magic_link(&MagicLinkRequest {
        email: ann.email().to_owned(),
    })
    .send(ann.client())
    .await
    .ok();
    let mail = mail_linking_to(stack, ann.email(), "/magic-link").await;
    MagicLinkSignIn {
        token: mail.token_in("/magic-link"),
        tenant_slug: None,
    }
}

/// The mailed proof is consumed once but leaves account access waiting for Ann's authenticator.
async fn begin_factor_link(
    browser: &mut Client,
    org: &OrgPath,
    follow: &MagicLinkSignIn,
) -> Session {
    let waiting = follow_link(browser, follow).await;
    assert_eq!(
        waiting.owed(),
        Owed::FactorCode,
        "the link proves the mailbox, and the authenticator's code is still owed"
    );
    browser.authorize(&waiting.refresh_token);
    members::me(org)
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    sessions::sign_in_by_magic_link(follow)
        .send(browser)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    members::me(org)
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    waiting
}

/// The authenticator code admits the session whose mailbox was already proved by the link.
async fn verify_link_factor(browser: &Client, org: &OrgPath, authenticator: &mut TotpApp) {
    let code = FactorCode {
        code: authenticator.code().await,
    };
    member_factors::verify(org, &code).send(browser).await.ok();
    members::me(org).send(browser).await.ok();
}

/// Ann lets her company sign in by mailed link, asks for hers, then takes
/// the method away again before following it: the link is refused and
/// her browser reads nothing. She allows the method once more: the same
/// link, not spent by the refusal, signs her in, once, and the record of
/// a refused sign-in holds neither the link's token nor the session's.
#[tokio::test]
async fn a_mailed_link_obeys_a_method_disabled_after_it_was_sent() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let session = ann.signed_in(&stack).await;
    ann.client_mut().authorize(&session.refresh_token);
    let without_links = organizations::sign_in_settings(&org)
        .send(ann.client())
        .await
        .ok();
    allow_mailed_links(&ann, &org).await;

    let follow = request_link(&stack, &ann).await;
    restore_methods(&ann, &org, without_links).await;
    let mut browser = Client::new(&stack, "Ann, following an earlier link").expect("a client");
    assert_disabled_link(&browser, &org, &follow).await;

    allow_mailed_links(&ann, &org).await;
    let by_link = assert_restored_link(&ann, &org, &mut browser, &follow).await;
    let record = Trail::of_organization(&browser, org.slug())
        .recorded("organization.org_login_failed")
        .await;
    no_secret_leaked(
        &record.details.to_string(),
        &[&follow.token, &by_link.refresh_token],
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann restores the saved method set with her password proof.
async fn restore_methods(ann: &Founder, org: &OrgPath, without_links: OrgSignInSettings) {
    organizations::replace_sign_in_settings(
        org,
        &ReplaceOrgSignInSettings {
            settings: without_links,
            proof: MemberProof {
                password: FOUNDER_PASSWORD.to_owned(),
                code: None,
            },
        },
    )
    .send(ann.client())
    .await
    .ok();
}

/// A mailed proof cannot admit its browser while the method is disabled.
async fn assert_disabled_link(browser: &Client, org: &OrgPath, follow: &MagicLinkSignIn) {
    sessions::sign_in_by_magic_link(follow)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    members::me(org)
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Re-enabling the method admits the preserved proof once and opens Ann's own record.
async fn assert_restored_link(
    ann: &Founder,
    org: &OrgPath,
    browser: &mut Client,
    follow: &MagicLinkSignIn,
) -> Session {
    let by_link = follow_link(browser, follow).await;
    assert_eq!(
        by_link.owed(),
        Owed::Nothing,
        "the link, allowed again, proves the mailbox"
    );
    browser.authorize(&by_link.refresh_token);
    assert_eq!(
        members::me(org).send(browser).await.ok().email,
        ann.email(),
        "the link signs Ann in"
    );
    sessions::sign_in_by_magic_link(follow)
        .send(browser)
        .await
        .refused(Status::NOT_FOUND, "not_found");

    by_link
}

/// Ann opens her mailed link in two browsers at once: one sign-in opens a
/// session and the other is refused. The session she holds reads her
/// record and is the only one live, and the session she held before the
/// link is ended.
#[tokio::test]
async fn simultaneous_mailed_links_open_only_one_session() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let before = ann.signed_in(&stack).await;
    ann.client_mut().authorize(&before.refresh_token);
    allow_mailed_links(&ann, &org).await;

    let follow = request_link(&stack, &ann).await;

    let mut browser = Client::new(&stack, "Ann, opening her mailed link").expect("a client");
    let twin = Client::new(&stack, "Ann, opening the same link again").expect("a client");
    let first = sessions::sign_in_by_magic_link(&follow);
    let second = sessions::sign_in_by_magic_link(&follow);
    let (first, second) = tokio::join!(first.send(&browser), second.send(&twin));
    let session = session_won_once([first, second], Status::NOT_FOUND, "not_found");
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(&org).send(&browser).await.ok().email,
        ann.email(),
        "the sign-in that won reads Ann's record"
    );

    assert_only_winning_session(&browser, &org, &session).await;
    members::me(&org)
        .send(ann.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    stack.stop().await.expect("the stack stops cleanly");
}

/// The concurrent winner is the sole live session left by the shared link.
async fn assert_only_winning_session(browser: &Client, org: &OrgPath, session: &Session) {
    let active = sessions::member_sessions(org).send(browser).await.ok();
    let [only] = active.items.as_slice() else {
        panic!(
            "the link opened one session, {} are live",
            active.items.len()
        );
    };
    assert_eq!(
        only.session_id, session.session_id,
        "the one live session is the one the link opened"
    );
}

/// Ann asks for a mailed link and follows it only once it has expired:
/// it opens nothing and her browser reads nothing, while the session she
/// already held is untouched and the only one live.
#[tokio::test]
async fn an_expired_magic_link_opens_no_session() {
    let stack = Stack::start(Profile::standard().with(
        "EMAIL_MAGIC_LINK_TTL_SECONDS",
        &LINK_LIFETIME_SECONDS.to_string(),
    ))
    .await
    .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let before = ann.signed_in(&stack).await;
    ann.client_mut().authorize(&before.refresh_token);
    allow_mailed_links(&ann, &org).await;

    let follow = request_link(&stack, &ann).await;

    past_lifetime(Duration::from_secs(LINK_LIFETIME_SECONDS)).await;
    let browser = Client::new(&stack, "Ann, opening an old link").expect("a client");
    sessions::sign_in_by_magic_link(&follow)
        .send(&browser)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    members::me(&org)
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    assert_original_session(&ann, &org, &before).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The expired link leaves Ann's original session readable and solely active.
async fn assert_original_session(ann: &Founder, org: &OrgPath, before: &Session) {
    members::me(org).send(ann.client()).await.ok();
    let active = sessions::member_sessions(org).send(ann.client()).await.ok();
    let [only] = active.items.as_slice() else {
        panic!(
            "Ann holds the one session from before, {} are live",
            active.items.len()
        );
    };
    assert_eq!(
        only.session_id, before.session_id,
        "the session Ann held before the link is the one live"
    );
}
