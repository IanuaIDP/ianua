//! A sign-up link over time: one Ann let expire, replaced by a fresh one;
//! a form she sends again inside the mail cooldown, which changes nothing
//! of the first; and one sent after the cooldown, which founds with its
//! own details while the older link can no longer overwrite them.

use std::time::Duration;

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{OrgPath, members, onboarding, sessions};
use ianua_scenarios::mail::Mail;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::onboarding::{Founded, Signup};
use ianua_scenarios::wire::sign_in::PasswordSignIn;

use crate::support::{QUIET, owner_signed_in, past_lifetime, requested, signed_in_with};

/// How long a sign-up link is kept in the expiry scenario: long enough to
/// be mailed and read, short enough to wait out.
const LINK_LIFETIME: Duration = Duration::from_secs(4);

/// The mail cooldown in the resubmission scenario: short enough to wait
/// out, so the second form gets a link of its own.
const COOLDOWN: Duration = Duration::from_secs(1);

/// The password Ann's changed form carries: a sentence, so no scanner
/// takes it for a key.
const CHANGED_PASSWORD: &str = "Different quiet orchard lantern 5729";

/// Ann's four-second sign-up link expires, then returns not found when
/// reused. Her password cannot sign in. A fresh form brings a different
/// link that founds the company, and she reads her verified account.
#[tokio::test]
async fn an_expired_sign_up_link_is_replaced_by_a_fresh_one() {
    let stack = Stack::start(
        Profile::standard()
            .with(
                "EMAIL_ORG_VERIFICATION_TTL_SECONDS",
                &LINK_LIFETIME.as_secs().to_string(),
            )
            .with("MAIL_COOLDOWN_SECONDS", "0"),
    )
    .await
    .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let old = requested(&stack, &ann, "Acme").await;

    past_lifetime(LINK_LIFETIME).await;
    assert_expired_link(&ann, &old).await;

    let fresh = requested(&stack, &ann, "Acme").await;
    assert_ne!(
        old.token_in("/signup/confirm"),
        fresh.token_in("/signup/confirm"),
        "the fresh link carries a token of its own"
    );
    let founded = ann.confirmed_sign_up(&fresh).await.ok();
    owner_signed_in(&stack, &mut ann, &founded).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// An expired proof is consumed on refusal and its unconfirmed account cannot sign in.
async fn assert_expired_link(ann: &Founder, old: &Mail) {
    ann.confirmed_sign_up(old)
        .await
        .refused(Status::GONE, "link_expired");
    ann.confirmed_sign_up(old)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    sessions::member_sign_in(&PasswordSignIn::of(ann.email(), FOUNDER_PASSWORD))
        .send(ann.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// Ann's form waits for its link. Inside the mail cooldown she sends
/// another, with a different company, tenant, name and password: it is
/// answered as any form is, but mails nothing and changes nothing. Her
/// first link founds exactly what she first asked for, the second
/// password opens nothing, and her record carries her first name.
#[tokio::test]
async fn a_form_sent_again_in_the_cooldown_changes_nothing_of_the_first() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let old = requested(&stack, &ann, "Acme").await;

    let mut changed = ann.sign_up_of("Globex", CHANGED_PASSWORD);
    changed.tenant_name = "Sandbox".to_owned();
    changed.admin_display_name = "Changed Owner".to_owned();
    onboarding::sign_up(&changed).send(ann.client()).await.ok();
    stack.mailbox().nothing_for(ann.email(), QUIET).await;

    let founded = ann.confirmed_sign_up(&old).await.ok();
    assert_eq!(founded.org_slug, "acme", "the first form's company");
    assert_eq!(founded.tenant_slug, "production", "the first form's tenant");
    sessions::member_sign_in(&PasswordSignIn::of(ann.email(), &changed.admin_password))
        .send(ann.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    owner_signed_in(&stack, &mut ann, &founded).await;
    let owner = members::me(&OrgPath::new(&founded.org_slug))
        .send(ann.client())
        .await
        .ok();
    assert_eq!(
        owner.display_name, "Acme Owner",
        "the first form's name, not the changed one"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// After the cooldown Ann sends a changed form and gets a link of its
/// own. She opens that one first: the company has the changed tenant, the
/// earlier link can no longer overwrite it, the first password opens
/// nothing, and the changed one signs her in as the owner under her
/// changed name.
#[tokio::test]
async fn a_form_sent_after_the_cooldown_founds_with_its_own_details() {
    let stack = Stack::start(
        Profile::standard().with("MAIL_COOLDOWN_SECONDS", &COOLDOWN.as_secs().to_string()),
    )
    .await
    .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let old = requested(&stack, &ann, "Acme").await;

    past_lifetime(COOLDOWN).await;
    let mut changed = ann.sign_up_of("Acme", CHANGED_PASSWORD);
    changed.tenant_name = "Sandbox".to_owned();
    changed.admin_display_name = "Changed Owner".to_owned();
    onboarding::sign_up(&changed).send(ann.client()).await.ok();
    let fresh = stack.mailbox().next_for(ann.email()).await;

    let founded = ann.confirmed_sign_up(&fresh).await.ok();
    assert_eq!(founded.tenant_slug, "sandbox", "the changed form's tenant");
    ann.confirmed_sign_up(&old)
        .await
        .refused(Status::CONFLICT, "conflict");
    sessions::member_sign_in(&PasswordSignIn::of(ann.email(), FOUNDER_PASSWORD))
        .send(ann.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    assert_changed_owner(&stack, &mut ann, &changed, &founded).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The replacement form's password signs in as the owner under its changed name.
async fn assert_changed_owner(
    stack: &Stack,
    ann: &mut Founder,
    changed: &Signup,
    founded: &Founded,
) {
    let session = signed_in_with(stack, ann, &changed.admin_password).await;
    ann.client_mut().authorize(&session.refresh_token);
    let owner = members::me(&OrgPath::new(&founded.org_slug))
        .send(ann.client())
        .await
        .ok();
    assert_eq!(
        owner.display_name, changed.admin_display_name,
        "the changed form's name"
    );
    assert_eq!(owner.id, founded.admin_user_id, "Ann is the owner founded");
}
