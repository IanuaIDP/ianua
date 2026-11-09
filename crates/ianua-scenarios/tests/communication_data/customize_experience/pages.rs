//! The page a visitor signs in on, at the portal's own address: it wears
//! what Tess chose and reads in the language the browser asks for. Only
//! what is safe of her CSS reaches it.

use ianua_scenarios::api::branding;
use ianua_scenarios::expect::eventually;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::branding::PageLook;
use ianua_scenarios::world::World;

use crate::support::{Portal, claimed_png, png};

/// The colour Tess picks for the buttons, as the platform normalizes it.
const ACME_BLUE: &str = "#0A84FF";

/// The background she picks.
const ACME_NIGHT: &str = "#102030";

/// The sides of her logo, in pixels.
const LOGO_SIDE: u32 = 64;

/// The platform's own colour for buttons, before she chooses.
const PLATFORM_PRIMARY: &str = "--primary: #B1F15E;";

/// What the page says of a slash in an attribute, escaped as all its
/// values are.
const ESCAPED_SLASH: &str = "&#x2f;";

/// CSS asking for one colour and for something loaded from elsewhere.
const CSS_WITH_A_REACH_OUT: &str =
    ".brand { color: red; background-color: url(https://evil.example/x); }";

/// What is left of it on the page.
const CSS_AS_DRAWN: &str = ".brand { color: red; }";

/// Pages and how each should read, for the browser that asks in the first
/// value: the page's language and the words at its top.
const LANGUAGES: [(Option<&str>, &str, &str); 5] = [
    (None, "en", "Welcome back"),
    (Some("de-DE,de;q=0.9,en;q=0.8"), "de", "Willkommen zurück"),
    (Some("fr"), "fr", "Heureux de vous revoir"),
    (Some("sw, de;q=0.8"), "de", "Willkommen zurück"),
    (Some("sw"), "en", "Welcome back"),
];

/// Visitors to Tess's portal first see the platform's look. She uploads
/// Acme's logo and sets its colours and some CSS of her own, part of which
/// reaches out to another site. Soon the page wears the logo, from where it
/// is served, and both colours; her CSS is on it, without the part that
/// would load something from elsewhere.
#[tokio::test]
async fn the_sign_in_page_wears_tess_s_logo_colours_and_cleaned_css() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let portal = Portal::opened(&world).await;
    let visitor = world.anonymous().client();
    let before = portal.page(visitor, None).await;
    assert!(
        before.contains(PLATFORM_PRIMARY),
        "the platform's look at first"
    );
    assert!(!before.contains("class=\"logo\""), "no logo at first");
    let tess = world.admin().client();
    let logo = branding::upload_logo(world.tenant(), &claimed_png(png(LOGO_SIDE, LOGO_SIDE)))
        .send(tess)
        .await
        .ok();
    let look = PageLook {
        primary_color: Some(ACME_BLUE.to_owned()),
        background_color: Some(ACME_NIGHT.to_owned()),
        custom_css: Some(CSS_WITH_A_REACH_OUT.to_owned()),
    };
    branding::change_look(world.tenant(), &look)
        .send(tess)
        .await
        .ok();

    let primary = format!("--primary: {ACME_BLUE};");
    let page = eventually("the sign-in page to wear Acme's look", || async {
        let page = portal.page(visitor, None).await;
        page.contains(&primary).then_some(page)
    })
    .await;
    assert!(page.contains(&format!("--background: {ACME_NIGHT};")));
    assert!(
        page.replace(ESCAPED_SLASH, "/")
            .contains(&format!("src=\"{}\"", logo.logo_url)),
        "the page shows Acme's logo from where it is served"
    );
    assert!(page.contains(CSS_AS_DRAWN), "her own rule is drawn");
    assert!(!page.contains("evil.example"), "nothing reaches elsewhere");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess gives Acme its colour. A German browser's visitor reads the page in
/// German, a French browser's in French; asking first for a language the
/// platform lacks falls to the next it has, and only to English when none
/// is left. Whatever it reads in, the page wears Acme's colour.
#[tokio::test]
async fn the_sign_in_page_is_drawn_in_the_language_the_browser_asks_for() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let portal = Portal::opened(&world).await;
    let visitor = world.anonymous().client();
    let primary = format!("--primary: {ACME_BLUE};");
    let look = PageLook {
        primary_color: Some(ACME_BLUE.to_owned()),
        ..PageLook::default()
    };
    branding::change_look(world.tenant(), &look)
        .send(world.admin().client())
        .await
        .ok();
    eventually("the sign-in page to wear Acme's colour", || async {
        portal
            .page(visitor, None)
            .await
            .contains(&primary)
            .then_some(())
    })
    .await;

    for (asked, language, heading) in LANGUAGES {
        let page = portal.page(visitor, asked).await;
        assert!(
            page.contains(&format!("<html lang=\"{language}\">")),
            "a browser asking for {asked:?} reads the page in {language}"
        );
        assert!(page.contains(heading), "the page reads {heading:?}");
        assert!(
            page.contains(&primary),
            "it wears Acme's colour in {language}"
        );
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess's CSS holding nothing a page may render is refused and the page
/// keeps the platform's look. Max, a plain member, may not change the look.
#[tokio::test]
async fn css_with_nothing_safe_in_it_is_refused() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let portal = Portal::opened(&world).await;
    let seen = world.trail().ids().await;
    let nothing_safe = PageLook {
        custom_css: Some("@import url(https://evil.example/x.css);".to_owned()),
        ..PageLook::default()
    };

    branding::change_look(world.tenant(), &nothing_safe)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    branding::change_look(world.tenant(), &nothing_safe)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let page = portal.page(world.anonymous().client(), None).await;
    assert!(page.contains(PLATFORM_PRIMARY), "the look is unchanged");
    assert!(
        !page.contains("evil.example"),
        "nothing of the CSS is drawn"
    );
    world.trail().nothing_after(&seen, "branding.updated").await;

    stack.stop().await.expect("the stack stops cleanly");
}
