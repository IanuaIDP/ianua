//! Tess writes the tenant's own welcome mail: she previews her draft,
//! saves it, sends herself a test and welcomes Pat, who receives Tess's
//! words; reset, the platform's words are back. A draft that hides the
//! link in markup is refused. Uma, Max, Sam and nobody signed in change
//! no email of the tenant's, and nothing is recorded for what they tried.

use ianua_scenarios::api::{branding, people};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::mail::Mail;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::branding::{EmailWording, PreviewAsked};
use ianua_scenarios::world::World;

use crate::support::person;

/// The email the scenarios write their own version of.
const WELCOME: &str = "Welcome";

/// The record a written or reset email leaves.
const BRANDING_UPDATED: &str = "branding.updated";

/// How every subject of Tess's welcome begins.
const SUBJECT_START: &str = "Welcome aboard Acme";

/// The words of the body only Tess's welcome carries.
const DESK_READY: &str = "your desk is ready";

/// Tess's welcome: the person's name in the subject, her words in both
/// bodies, the link on its own.
fn tess_s_welcome() -> EmailWording {
    EmailWording {
        subject: format!("{SUBJECT_START}, {{{{ user_name }}}}"),
        body_html: format!(
            "<p>Hello {{{{ user_name }}}}, {DESK_READY}.</p><p>{{{{ action_link }}}}</p>"
        ),
        body_text: format!("Hello {{{{ user_name }}}}, {DESK_READY}.\n\n{{{{ action_link }}}}\n"),
    }
}

/// A welcome whose link hides inside a button's address, where a reader
/// cannot see where it goes.
fn hidden_link() -> EmailWording {
    EmailWording {
        subject: "Welcome".to_owned(),
        body_html: "<a href=\"{{ action_link }}\">Start</a>".to_owned(),
        body_text: "Start here:\n\n{{ action_link }}\n".to_owned(),
    }
}

/// The next mail for `address` whose subject begins as Tess's welcome
/// does, passing over up to three others mailed before it.
async fn mail_titled(world: &World<'_>, address: &str) -> Mail {
    for _ in 0..4 {
        let mail = world.stack().mailbox().next_for(address).await;
        if mail.subject().starts_with(SUBJECT_START) {
            return mail;
        }
    }
    panic!("{address} got no mail reading Tess's welcome");
}

/// The saved version, previewed or sent as a test.
fn saved() -> PreviewAsked {
    PreviewAsked { draft: None }
}

/// Tess previews her draft and reads her own words, filled with sample
/// values. She saves it, on record, and finds it among the tenant's own
/// emails. She sends herself a test and receives it at her own address.
/// She welcomes Pat, and Pat receives Tess's words. Tess resets the email,
/// on record: the preview reads the platform's words again and the email
/// is no longer among the tenant's own.
#[tokio::test]
async fn tess_writes_the_welcome_pat_receives() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let tess = world.admin();
    let seen = world.trail().ids().await;

    let draft = PreviewAsked {
        draft: Some(tess_s_welcome()),
    };
    let previewed = branding::preview_email(world.tenant(), WELCOME, &draft)
        .send(tess.client())
        .await
        .ok();
    assert!(previewed.subject.starts_with(SUBJECT_START));
    assert!(previewed.text.contains(DESK_READY));

    branding::write_email(world.tenant(), WELCOME, &tess_s_welcome())
        .send(tess.client())
        .await
        .ok();
    world.trail().recorded_after(&seen, BRANDING_UPDATED).await;
    let own = branding::custom_emails(world.tenant())
        .send(tess.client())
        .await
        .ok();
    assert!(
        own.items
            .iter()
            .any(|email| email.template_type == WELCOME && email.is_custom),
        "the welcome is among the tenant's own emails"
    );

    branding::test_send_email(world.tenant(), WELCOME, &saved())
        .send(tess.client())
        .await
        .ok();
    mail_titled(&world, tess.email()).await;

    people::send_welcome(world.tenant(), pat.id())
        .send(tess.client())
        .await
        .ok();
    let welcome = mail_titled(&world, pat.email()).await;
    assert!(welcome.text().is_some_and(|text| text.contains(DESK_READY)));

    let before_reset = world.trail().ids().await;
    branding::reset_email(world.tenant(), WELCOME)
        .send(tess.client())
        .await
        .ok();
    world
        .trail()
        .recorded_after(&before_reset, BRANDING_UPDATED)
        .await;
    let previewed = branding::preview_email(world.tenant(), WELCOME, &saved())
        .send(tess.client())
        .await
        .ok();
    assert!(
        !previewed.subject.starts_with(SUBJECT_START),
        "the platform's words are back"
    );
    let own = branding::custom_emails(world.tenant())
        .send(tess.client())
        .await
        .ok();
    assert!(own.items.iter().all(|email| email.template_type != WELCOME));

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess drafts a welcome whose link hides in a button's address. Both the
/// preview and the save are refused, the tenant keeps the platform's
/// words, and nothing is recorded.
#[tokio::test]
async fn a_welcome_hiding_its_link_in_markup_is_refused() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin();
    let seen = world.trail().ids().await;

    let draft = PreviewAsked {
        draft: Some(hidden_link()),
    };
    branding::preview_email(world.tenant(), WELCOME, &draft)
        .send(tess.client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    branding::write_email(world.tenant(), WELCOME, &hidden_link())
        .send(tess.client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let own = branding::custom_emails(world.tenant())
        .send(tess.client())
        .await
        .ok();
    assert!(own.items.iter().all(|email| email.template_type != WELCOME));
    world.trail().nothing_after(&seen, BRANDING_UPDATED).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma, an ordinary user of the tenant, Max, a member with no
/// administrator's rights, Sam from the other company and nobody signed
/// in may not write, reset or draft the tenant's welcome. The tenant keeps
/// the platform's words and nothing is recorded.
#[tokio::test]
async fn nobody_without_the_right_rewrites_the_tenant_s_mail() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = person(&world, "uma").await;
    let seen = world.trail().ids().await;
    let draft = PreviewAsked {
        draft: Some(tess_s_welcome()),
    };

    for request in [
        branding::write_email(world.tenant(), WELCOME, &tess_s_welcome()).call(),
        branding::reset_email(world.tenant(), WELCOME).call(),
        branding::preview_email(world.tenant(), WELCOME, &draft).call(),
        branding::test_send_email(world.tenant(), WELCOME, &draft).call(),
    ] {
        Matrix::new("rewriting the tenant's welcome", request)
            .refused(uma.client(), Status::FORBIDDEN, "forbidden")
            .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
            .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
            .refused(
                world.anonymous().client(),
                Status::UNAUTHORIZED,
                "unauthenticated",
            )
            .run()
            .await;
    }

    let own = branding::custom_emails(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert!(own.items.iter().all(|email| email.template_type != WELCOME));
    world.trail().nothing_after(&seen, BRANDING_UPDATED).await;

    stack.stop().await.expect("the stack stops cleanly");
}
