//! Bodies through the gateway: they move a piece at a time, so the app
//! has the first of an upload before the rest is sent and a client the
//! first of a download before the rest is written; a body past the limit
//! is refused, and the app never gets one whole.

use std::time::Duration;

use bytes::Bytes;
use ianua_scenarios::expect::{Records, eventually};
use ianua_scenarios::net::Call;
use ianua_scenarios::net::streams::{Download, Target, Upload};
use ianua_scenarios::routes::{Placement, RouteSpec};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::{DownloadSizes, Pipe, Uploaded, digest_of, pattern};
use ianua_scenarios::wire::Status;
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;
use tokio::time::timeout;

use crate::support::{app_host, probe, profile};

/// The size of each piece an upload is sent in.
const PIECE_BYTES: usize = 64 * 1024;

/// How much of a whole upload or download moves in these scenarios.
const WHOLE_BYTES: usize = 4 * 1024 * 1024;

/// The most the gateway takes in the deployment that refuses a body.
const LIMIT_BYTES: usize = 1024 * 1024;

/// How many pieces past the limit an oversized upload goes: few enough
/// that all of it is already on its way when the refusal comes.
const PIECES_PAST_THE_LIMIT: usize = 2;

/// How long a piece may take to come through.
const PIECE_WITHIN: Duration = Duration::from_secs(20);

/// A file store Tess puts behind a route open to anyone.
async fn file_store(world: &World<'_>, sizes: DownloadSizes) -> (String, Pipe) {
    let host = app_host(world).await;
    let pipe = Pipe::start(sizes).await.expect("the file store starts");
    RouteSpec::public("files", "/files/*")
        .applied(
            world.admin().client(),
            &probe(world.stack()),
            Placement {
                tenant: world.tenant(),
                upstream: &pipe.url(),
                host: &host,
            },
        )
        .await;
    (host, pipe)
}

/// A visitor uploads a report a piece at a time: the store has the first
/// piece before the second is sent, and the whole of it, byte for byte,
/// at the end. The visitor then downloads a large file: the first piece
/// arrives while the store is still holding the rest back, and the whole
/// file arrives once it lets go. The gateway records the upload as allowed.
#[tokio::test]
async fn bodies_move_through_the_gateway_a_piece_at_a_time() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let sizes = DownloadSizes {
        first: PIECE_BYTES,
        held: WHOLE_BYTES - PIECE_BYTES,
    };
    let (host, pipe) = file_store(&world, sizes).await;

    let whole = pattern(WHOLE_BYTES);
    let upload = Upload::begin(&stack, &Target::new(&host, "/files/report"))
        .await
        .expect("the upload starts");
    let (first, rest) = whole.split_at(PIECE_BYTES);
    upload
        .send(Bytes::copy_from_slice(first))
        .await
        .expect("the first piece is taken");
    eventually("the store to have the first piece", || async {
        (pipe.received() >= PIECE_BYTES).then_some(())
    })
    .await;
    assert!(
        pipe.uploads().is_empty(),
        "the store has not got the whole upload yet"
    );
    for piece in rest.chunks(PIECE_BYTES) {
        upload
            .send(Bytes::copy_from_slice(piece))
            .await
            .expect("the gateway takes every piece");
    }
    let answer = upload.finish().await.expect("the upload is answered");
    assert_eq!(answer.status, Status::OK, "the upload is taken");
    assert_eq!(
        pipe.uploads(),
        vec![Uploaded {
            bytes: WHOLE_BYTES,
            digest: digest_of(&whole),
        }],
        "the store got every byte, unchanged"
    );

    let mut download = Download::begin(&stack, &Target::new(&host, "/files/archive"))
        .await
        .expect("the download starts");
    assert_eq!(download.status(), Status::OK, "the file is there");
    let mut got = timeout(PIECE_WITHIN, download.next_piece())
        .await
        .expect("the first piece arrives while the rest is held back")
        .expect("the download reads")
        .expect("the file has a first piece")
        .to_vec();
    pipe.release();
    let rest = timeout(PIECE_WITHIN, download.rest())
        .await
        .expect("the rest arrives once it is let go")
        .expect("the rest reads");
    got.extend_from_slice(&rest);
    assert_eq!(digest_of(&got), digest_of(&whole), "the file is whole");

    let record = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded("/files/report")
        .await;
    assert_eq!(record.decision, "allowed", "the upload was allowed");
    assert_eq!(
        record.status,
        Status::OK,
        "the store's answer was passed on"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// On a deployment taking at most one mebibyte, a visitor's upload a
/// little past it, sent a piece at a time without saying how long it is,
/// and another declaring its length, are each refused as too large. The
/// store gets at most the limit of each and neither whole, and the
/// gateway records the status it answered.
#[tokio::test]
async fn a_body_past_the_limit_is_refused_and_never_arrives_whole() {
    let profile = profile().with("GATEWAY_DEFAULT_MAX_BODY_BYTES", &LIMIT_BYTES.to_string());
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let sizes = DownloadSizes { first: 1, held: 0 };
    let (host, pipe) = file_store(&world, sizes).await;

    let upload = Upload::begin(&stack, &Target::new(&host, "/files/huge"))
        .await
        .expect("the upload starts");
    let piece = pattern(PIECE_BYTES);
    for _ in 0..(LIMIT_BYTES / PIECE_BYTES + PIECES_PAST_THE_LIMIT) {
        if upload.send(Bytes::copy_from_slice(&piece)).await.is_err() {
            break;
        }
    }
    let answer = upload.finish().await.expect("the upload is answered");
    assert_eq!(
        answer.status,
        Status::PAYLOAD_TOO_LARGE,
        "the upload is too large"
    );
    assert!(
        pipe.received() <= LIMIT_BYTES,
        "the store got {} bytes, past the limit",
        pipe.received()
    );

    let declared = world
        .anonymous()
        .client()
        .send::<IgnoredAny>(Call::post(format!("https://{host}/files/declared")).raw(
            "application/octet-stream",
            "x".repeat(LIMIT_BYTES + PIECE_BYTES),
        ))
        .await;
    assert_eq!(
        declared.status(),
        Status::PAYLOAD_TOO_LARGE,
        "a body declaring too much is too large: {}",
        declared.summary()
    );
    assert!(pipe.uploads().is_empty(), "no body arrived whole");

    let record = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded("/files/huge")
        .await;
    assert_eq!(
        record.status,
        Status::PAYLOAD_TOO_LARGE,
        "the record carries the status answered"
    );
    stack.stop().await.expect("the stack stops cleanly");
}
