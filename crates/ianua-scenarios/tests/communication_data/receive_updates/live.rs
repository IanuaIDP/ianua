//! Notices arriving as they happen, over the WebSocket the dashboard's
//! bell listens on. Pat and Ann each hear their own the moment Tess acts,
//! and nobody hears another's. A stream is refused to anyone who may not
//! read that inbox, and one that was open closes once Pat signs out.

use std::time::Duration;

use ianua_scenarios::api::{notifications, sessions};
use ianua_scenarios::net::{Frame, Socket};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::notifications::{LiveFrame, LiveNotification};
use ianua_scenarios::world::World;

use crate::support::{
    AUTHORIZATION, fresh_tenant_notice, give_role, person, reader_role, tenant_ids,
};

/// How long a live notice is waited for: the worker writes it first.
const PATIENCE: Duration = Duration::from_secs(45);

/// How long a stream is watched for a notice that must not come, once the
/// one that should has arrived elsewhere.
const QUIET: Duration = Duration::from_secs(3);

/// The close code of a stream whose reader may no longer read it.
const NO_LONGER_ADMITTED: u16 = 1008;

/// The category a live frame names a role given or taken back under.
const LIVE_AUTHORIZATION: &str = "authorization";

/// Pat and Uma open the tenant's live stream and Ann her company's. Tess
/// gives Pat a role. Pat's stream carries the notice at once, unread, under
/// the same id her inbox lists it by; Ann's carries the one her company
/// inbox holds. Uma, in the same tenant, gets nothing about Pat. Each
/// closes the stream by leaving.
#[tokio::test]
async fn pat_and_ann_each_hear_their_own_notice_live_and_uma_hears_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let role = reader_role(&world).await;
    let ann = world.owner().client();
    let pat_seen = tenant_ids(world.tenant(), pat.client()).await;
    let tenant_stream = notifications::stream(world.tenant());
    let mut pat_stream = pat.client().open_socket(&tenant_stream).await.open();
    let mut uma_stream = uma.client().open_socket(&tenant_stream).await.open();
    let mut ann_stream = ann
        .open_socket(&notifications::member_stream(world.org()))
        .await
        .open();

    give_role(&world, &pat, &role).await;

    let heard = live_notice(&mut pat_stream).await;
    let listed = fresh_tenant_notice(world.tenant(), pat.client(), &pat_seen, AUTHORIZATION).await;
    assert_eq!(
        heard.id, listed.id,
        "the stream and the inbox show one notice"
    );
    assert!(!heard.read, "a notice arrives unread");
    assert_eq!(
        heard.title, listed.title,
        "the stream says what the inbox says"
    );

    let told = live_notice(&mut ann_stream).await;
    let inbox = notifications::member_inbox(world.org())
        .send(ann)
        .await
        .ok();
    assert!(
        inbox.items.iter().any(|notice| notice.id == told.id),
        "Ann's stream shows a notice of her own inbox"
    );

    let overheard = uma_stream.texts_until_quiet(QUIET).await;
    assert!(
        overheard
            .iter()
            .all(|frame| !frame.contains(&heard.id) && !frame.contains(&told.id)),
        "Uma hears nothing of Pat's role"
    );

    pat_stream.close().await;
    uma_stream.close().await;
    ann_stream.close().await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Nobody signed in is asked to sign in before any stream opens. Sam, from
/// the other company, reaches neither the tenant's stream nor the company's,
/// and Max, whose notices live in his organization, has none in the tenant.
/// Pat's own stream still opens.
#[tokio::test]
async fn a_stream_is_refused_to_anyone_who_may_not_read_that_inbox() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let tenant_stream = notifications::stream(world.tenant());
    let member_stream = notifications::member_stream(world.org());

    for (client, path, status, code) in [
        (
            world.anonymous().client(),
            &tenant_stream,
            Status::UNAUTHORIZED,
            "unauthenticated",
        ),
        (
            world.anonymous().client(),
            &member_stream,
            Status::UNAUTHORIZED,
            "unauthenticated",
        ),
        (
            world.stranger().client(),
            &tenant_stream,
            Status::FORBIDDEN,
            "forbidden",
        ),
        (
            world.stranger().client(),
            &member_stream,
            Status::FORBIDDEN,
            "forbidden",
        ),
        (
            world.member().client(),
            &tenant_stream,
            Status::FORBIDDEN,
            "forbidden",
        ),
    ] {
        client
            .open_socket(path)
            .await
            .refusal()
            .refused(status, code);
    }

    pat.client()
        .open_socket(&tenant_stream)
        .await
        .open()
        .close()
        .await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat's stream is open, and her session is asked after every second. She
/// signs out on the same session. The stream closes as no longer admitted
/// within moments, and opening it again with the ended session is refused.
#[tokio::test]
async fn signing_out_closes_pat_s_open_stream() {
    let stack = Stack::start(Profile::standard().with("STREAM_RECHECK_SECONDS", "1"))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let tenant_stream = notifications::stream(world.tenant());
    let mut stream = pat.client().open_socket(&tenant_stream).await.open();

    sessions::sign_out(world.tenant())
        .send(pat.client())
        .await
        .ok();

    assert_eq!(
        closing_frame(&mut stream).await,
        Frame::Closed(Some(NO_LONGER_ADMITTED)),
        "the stream closes as no longer admitted"
    );
    pat.client()
        .open_socket(&tenant_stream)
        .await
        .refusal()
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    stack.stop().await.expect("the stack stops cleanly");
}

/// The next notice about a role the stream gives, passing over any other
/// update.
async fn live_notice(stream: &mut Socket) -> LiveNotification {
    loop {
        let Some(Frame::Text(text)) = stream.next_within(PATIENCE).await else {
            panic!("no live notice came within {PATIENCE:?}");
        };
        let Ok(frame) = serde_json::from_str::<LiveFrame>(&text) else {
            continue;
        };
        if frame.msg_type == "notification" && frame.notification.category == LIVE_AUTHORIZATION {
            return frame.notification;
        }
    }
}

/// How the stream ends, passing over anything it still delivers first.
async fn closing_frame(stream: &mut Socket) -> Frame {
    loop {
        match stream.next_within(PATIENCE).await {
            Some(Frame::Text(_)) => continue,
            Some(closed) => return closed,
            None => panic!("the stream was still open after {PATIENCE:?}"),
        }
    }
}
