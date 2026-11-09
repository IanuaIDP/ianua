//! Tess's logo, kept and served by the platform. What the file really is
//! is read from its own bytes, never from the name or type the upload
//! claims, and only someone who may change the look changes it.

use ianua_scenarios::api::branding;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::net::Call;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use crate::support::{claimed_png, person, png};

/// The record a saved branding leaves.
const BRANDING_UPDATED: &str = "branding.updated";

/// The sides of the logo Tess uploads, in pixels.
const LOGO_SIDE: u32 = 64;

/// Past what a logo may hold: half a mebibyte and some.
const PAST_A_LOGO: usize = 600 * 1024;

/// Past what the API reads of any request: two mebibytes.
const PAST_ANY_REQUEST: usize = 2 * 1024 * 1024;

/// An image too small to be a logo, in pixels a side.
const TOO_SMALL_SIDE: u32 = 8;

/// Tess uploads Acme's logo. The answer says where it is served and the
/// branding says the same. Nobody signed in fetches it from there: an
/// image of the bytes she sent, under a type a browser cannot be talked
/// out of, and on record as a PNG. A second, different image moves the
/// address on.
#[tokio::test]
async fn tess_uploads_the_logo_and_anyone_fetches_it_from_its_own_address() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let seen = world.trail().ids().await;
    let image = png(LOGO_SIDE, LOGO_SIDE);

    let uploaded = branding::upload_logo(world.tenant(), &claimed_png(image.clone()))
        .send(tess)
        .await
        .ok();

    let look = branding::get(world.tenant()).send(tess).await.ok();
    assert_eq!(look.logo_url.as_deref(), Some(uploaded.logo_url.as_str()));
    let served = world
        .anonymous()
        .client()
        .send::<IgnoredAny>(Call::get(&uploaded.logo_url))
        .await;
    assert_eq!(served.status(), Status::OK, "{}", served.summary());
    assert_eq!(served.header("content-type"), Some("image/png"));
    assert_eq!(
        served.header("x-content-type-options"),
        Some("nosniff"),
        "a browser may not guess it is anything else"
    );
    assert_eq!(
        served.header("content-length"),
        Some(image.len().to_string().as_str()),
        "it is served whole"
    );
    let recorded = world.trail().recorded_after(&seen, BRANDING_UPDATED).await;
    assert_eq!(recorded.details["part"], "logo");
    assert_eq!(recorded.details["format"], "png");

    let moved = branding::upload_logo(world.tenant(), &claimed_png(png(LOGO_SIDE, LOGO_SIDE * 2)))
        .send(tess)
        .await
        .ok();
    assert_ne!(
        moved.logo_url, uploaded.logo_url,
        "a new logo has a new address"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess uploads an SVG with a script in it, a web page, a sliver of an
/// image and an image far too heavy, each claiming to be a PNG, and each is
/// refused for what it really holds. A form with no file is refused, and
/// a body past what the API reads is turned away by size. The tenant has
/// no logo after all of it, and nothing is recorded.
#[tokio::test]
async fn an_upload_that_is_no_logo_is_refused_whatever_it_claims_to_be() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let seen = world.trail().ids().await;
    let mut heavy = png(LOGO_SIDE, LOGO_SIDE);
    heavy.resize(PAST_A_LOGO, 0);

    for bytes in [
        b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>".to_vec(),
        b"<!doctype html><title>not an image</title>".to_vec(),
        png(TOO_SMALL_SIDE, TOO_SMALL_SIDE),
        heavy,
    ] {
        branding::upload_logo(world.tenant(), &claimed_png(bytes))
            .send(tess)
            .await
            .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    }
    let no_logo_field = Call::post(world.tenant().at("/branding/logo")).bytes(
        "multipart/form-data; boundary=other",
        b"--other\r\nContent-Disposition: form-data; name=\"picture\"\r\n\r\nhello\r\n--other--\r\n"
            .to_vec(),
    );
    tess.send::<IgnoredAny>(no_logo_field)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    branding::upload_logo(world.tenant(), &claimed_png(vec![0; PAST_ANY_REQUEST]))
        .send(tess)
        .await
        .refused(Status::PAYLOAD_TOO_LARGE, "body_too_large");

    let look = branding::get(world.tenant()).send(tess).await.ok();
    assert_eq!(look.logo_url, None, "the tenant has no logo");
    world.trail().nothing_after(&seen, BRANDING_UPDATED).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma, an ordinary user, Max, a member with no administrator's rights,
/// Sam from the other company and nobody signed in may not put up a logo.
/// The tenant has none, and nothing is recorded.
#[tokio::test]
async fn nobody_without_the_right_changes_the_logo() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = person(&world, "uma").await;
    let seen = world.trail().ids().await;
    let upload =
        branding::upload_logo(world.tenant(), &claimed_png(png(LOGO_SIDE, LOGO_SIDE))).call();

    Matrix::new("putting up a logo", upload)
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

    let look = branding::get(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(look.logo_url, None, "the tenant has no logo");
    world.trail().nothing_after(&seen, BRANDING_UPDATED).await;

    stack.stop().await.expect("the stack stops cleanly");
}
