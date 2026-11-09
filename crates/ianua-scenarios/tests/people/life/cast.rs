//! The whole cast trying a step's protected reads: Pat's record and Pat's
//! own sessions, read by Ann, Tess, Max, Sam, nobody signed in, Pat's own
//! client and every client whose session ended.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{people, sessions};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::net::Client;
use ianua_scenarios::wire::{Exchange, Status};
use ianua_scenarios::world::World;

/// What Pat's own client answers reading Pat's record: before Pat signed
/// in nobody is signed in on it, after it Pat's tenant role lets Pat read
/// no user's record.
#[derive(Clone, Copy)]
pub(super) enum PatsClient {
    /// No session yet.
    SignedOut,
    /// A live session.
    SignedIn,
}

/// Pat's record, read by the whole cast: Ann and Tess may; Max holds no
/// administrator's rights, Sam acts in another organization; nobody signed
/// in, and every one of Pat's ended sessions in `spoiled`, is not known.
pub(super) async fn record_read_by_the_cast(
    world: &World<'_>,
    pat: &Person,
    pats_client: PatsClient,
    spoiled: &[&Client],
) -> Vec<Exchange> {
    let call = people::get(world.tenant(), pat.id()).call();
    let matrix = Matrix::new("reading Pat's record", call)
        .allowed(world.owner().client())
        .allowed(world.admin().client())
        .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
        .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
        .refused(
            world.anonymous().client(),
            Status::UNAUTHORIZED,
            "unauthenticated",
        );
    let matrix = match pats_client {
        PatsClient::SignedOut => {
            matrix.refused(pat.client(), Status::UNAUTHORIZED, "unauthenticated")
        }
        PatsClient::SignedIn => matrix.refused(pat.client(), Status::FORBIDDEN, "forbidden"),
    };
    spoiled
        .iter()
        .fold(matrix, |matrix, client| {
            matrix.refused(client, Status::UNAUTHORIZED, "unauthenticated")
        })
        .run()
        .await
}

/// Pat's own sessions, listed by the whole cast: only a tenant user's live
/// session lists its own; the organization's members hold no tenant user's
/// session; Sam acts in another organization; nobody signed in, and every
/// session of Pat's in `ended`, is not known.
pub(super) async fn own_sessions_by_the_cast(
    world: &World<'_>,
    pat: &Client,
    ended: &[&Client],
) -> Vec<Exchange> {
    let call = sessions::my_sessions(world.tenant()).call();
    let mut matrix = Matrix::new("listing Pat's own sessions", call).allowed(pat);
    for client in [
        world.owner().client(),
        world.admin().client(),
        world.member().client(),
    ] {
        matrix = matrix.refused(client, Status::UNAUTHORIZED, "unauthenticated");
    }
    let matrix = matrix
        .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
        .refused(
            world.anonymous().client(),
            Status::UNAUTHORIZED,
            "unauthenticated",
        );
    ended
        .iter()
        .fold(matrix, |matrix, client| {
            matrix.refused(client, Status::UNAUTHORIZED, "unauthenticated")
        })
        .run()
        .await
}
