//! Tess brings people over from another system's export: a worker opens
//! them, each waiting for its holder to follow the link mailed to it;
//! the one whose address is taken is set aside and named by its line.
//! Someone with a password in the export signs in with it, and the import
//! keeps no hash or address in what it reports.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac as _};
use ianua_scenarios::actors::{Person, SignedInWith};
use ianua_scenarios::api::{people, registration, sessions};
use ianua_scenarios::expect::{eventually, no_secret_leaked};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::people::{ImportProgress, ImportUsers, ImportedAccount, LinkToken};
use ianua_scenarios::wire::tenant_sign_in::TenantPasswordSignIn;
use ianua_scenarios::world::World;
use sha2::Sha256;

use crate::support::person;

/// The salt the export's hashes were made with.
const SALT: &str = "ScenarioSalt42";

/// The rounds the export's hashes were made with: the fewest the platform
/// reads, so the scenario's own hashing stays quick.
const ROUNDS: u32 = 1_000;

/// The record starting an import leaves.
const STARTED: &str = "identity.user_import_started";

/// The record each imported account leaves.
const OPENED: &str = "identity.user_imported";

/// The record the import's end leaves.
const ENDED: &str = "identity.users_imported";

/// The most mails passed over before the verification link, so a missing
/// link fails rather than reading forever.
const PASSED_OVER: usize = 10;

/// `password` hashed as another system's PBKDF2-SHA256 export writes it.
///
/// # Panics
///
/// Never: HMAC takes a key of any length.
fn export_hash(password: &str) -> String {
    let first = pbkdf2_block(password, &[SALT.as_bytes(), &1_u32.to_be_bytes()].concat());
    let mut block = first;
    let mut digest = first;
    for _ in 1..ROUNDS {
        block = pbkdf2_block(password, &block);
        for (out, byte) in digest.iter_mut().zip(block.iter()) {
            *out ^= byte;
        }
    }
    format!("pbkdf2_sha256${ROUNDS}${SALT}${}", STANDARD.encode(digest))
}

/// One HMAC-SHA256 round of the PBKDF2 calculation.
fn pbkdf2_block(password: &str, data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(password.as_bytes()).expect("any key is taken");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// One account of an export, with its password `hash` when it had one.
fn account(email: &str, name: &str, hash: Option<String>) -> ImportedAccount {
    ImportedAccount {
        email: email.to_owned(),
        display_name: name.to_owned(),
        password_hash: hash,
    }
}

/// The import `id`, once a worker finished it.
async fn finished(world: &World<'_>, id: &str) -> ImportProgress {
    eventually("the import to finish", || async {
        let progress = people::import_progress(world.tenant(), id)
            .send(world.admin().client())
            .await
            .ok();
        (progress.status == "finished").then_some(progress)
    })
    .await
}

/// Tess imports Ivy with the password hash her old system kept, Ned with
/// none, and a record for Pat's address, which is taken: the import is
/// answered at once and finishes after: two opened, one set aside at line
/// three as taken, and its report names no address or hash. Ivy's password
/// is refused until she follows the mailed link; then it signs her in as
/// herself, and the import, each account and its end are all on record.
#[tokio::test]
async fn tess_imports_people_who_join_by_their_mailed_link() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let mut ivy = world.newcomer("ivy", "Ivy Imported");
    let ned = world.newcomer("ned", "Ned Imported");
    let hash = export_hash(ivy.password());
    let batch = ImportUsers {
        users: vec![
            account(ivy.email(), "Ivy Imported", Some(hash.clone())),
            account(ned.email(), "Ned Imported", None),
            account(pat.email(), "Pat Again", None),
        ],
    };

    let started = people::import(world.tenant(), &batch)
        .send(world.admin().client())
        .await
        .ok();
    let progress = finished(&world, &started.import_id).await;
    assert_eq!(progress.total, 3);
    assert_eq!(progress.imported, 2, "Ivy and Ned were opened");
    assert_eq!(progress.failed, 1, "Pat's address was set aside");
    assert_eq!(progress.remaining, 0, "nothing is left to do");
    assert_eq!(progress.errors.len(), 1);
    assert_eq!(progress.errors[0].line, 3, "the third record was set aside");
    assert_eq!(progress.errors[0].reason, "address_taken");

    ivy_is_kept_out_then_joins(&world, &mut ivy, &stack).await;
    trail_tells_the_import_without_its_hash(&world, &hash).await;
    ned_waits_for_his_link(&world, &ned).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Before the mailed link Ivy's right password is refused as unconfirmed;
/// after it she signs in with it and reads as herself.
async fn ivy_is_kept_out_then_joins(world: &World<'_>, ivy: &mut Person, stack: &Stack) {
    let before = TenantPasswordSignIn {
        email: ivy.email().to_owned(),
        password: ivy.password().to_owned(),
        fingerprint_hash: None,
    };
    sessions::sign_in(world.tenant(), &before)
        .send(world.anonymous().client())
        .await
        .refused(Status::FORBIDDEN, "email_not_verified");

    let proof = verification_link(world, ivy.email()).await;
    registration::verify(world.tenant(), &proof)
        .send(world.anonymous().client())
        .await
        .ok();
    let listed = people::list(world.tenant(), Some(ivy.email()))
        .send(world.admin().client())
        .await
        .ok();
    let record = &listed.items[0];
    assert_eq!(record.status, "Active", "the link activated her");
    assert!(record.email_verified, "the link proved her address");
    ivy.record_invitation(&record.id);
    assert_eq!(ivy.sign_in(stack).await, SignedInWith::Password);
    let own = people::me(world.tenant()).send(ivy.client()).await.ok();
    assert_eq!(own.id, ivy.id(), "the export's password opens her account");
}

/// Ned, with no password carried over, is listed as waiting for his link.
async fn ned_waits_for_his_link(world: &World<'_>, ned: &Person) {
    let listed = people::list(world.tenant(), Some(ned.email()))
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(listed.items[0].status, "PendingVerification");
}

/// The import's records exist, none holding the hash that came with it.
async fn trail_tells_the_import_without_its_hash(world: &World<'_>, hash: &str) {
    let trail = world.trail();
    trail.recorded(STARTED).await;
    trail.recorded(ENDED).await;
    assert_eq!(
        trail.count(OPENED).await,
        2,
        "each opened account is recorded once"
    );
    for event_type in [STARTED, OPENED, ENDED] {
        let entries = trail.entries(event_type).await;
        no_secret_leaked(&format!("{entries:?}"), &[hash]);
    }
}

/// The token of the verification link mailed to `email`.
///
/// # Panics
///
/// When no such link comes, or more than ten other mails came before it.
async fn verification_link(world: &World<'_>, email: &str) -> LinkToken {
    for _ in 0..=PASSED_OVER {
        let mail = world.stack().mailbox().next_for(email).await;
        if mail
            .links()
            .iter()
            .any(|link| link.path().ends_with("/verify-email"))
        {
            return LinkToken {
                token: mail.token_in("/verify-email"),
            };
        }
    }
    panic!("{email} got {PASSED_OVER} mails before one linking to /verify-email");
}

/// Uma, an ordinary user, Sam from the other company and nobody signed in
/// cannot import accounts or read an import. Two records for one address
/// and a hash in no format the platform reads are each refused whole, and
/// no import starts. An import nobody ran reads as not found.
#[tokio::test]
async fn nobody_without_the_right_imports_and_a_bad_batch_is_refused_whole() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = person(&world, "uma").await;
    let kept_out = world.address("kept-out");
    let batch = ImportUsers {
        users: vec![account(&kept_out, "Kept Out", None)],
    };
    let started = people::import(world.tenant(), &batch)
        .send(world.admin().client())
        .await
        .ok();

    refuse_those_without_the_right(&world, &uma, &batch, &started.import_id).await;

    let seen = world.trail().ids().await;
    let twice = ImportUsers {
        users: vec![
            account(&world.address("twice"), "Twice", None),
            account(&world.address("twice"), "Twice Again", None),
        ],
    };
    people::import(world.tenant(), &twice)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let unreadable_hash = ImportUsers {
        users: vec![account(
            &world.address("badhash"),
            "Bad Hash",
            Some("nothing the platform reads".to_owned()),
        )],
    };
    people::import(world.tenant(), &unreadable_hash)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    world.trail().nothing_after(&seen, STARTED).await;

    people::import_progress(world.tenant(), "00000000-0000-7000-8000-00000000abcd")
        .send(world.admin().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma, Sam and nobody signed in are each refused the import and its
/// progress.
async fn refuse_those_without_the_right(
    world: &World<'_>,
    uma: &Person,
    batch: &ImportUsers,
    import_id: &str,
) {
    people::import(world.tenant(), batch)
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    people::import(world.tenant(), batch)
        .send(world.stranger().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    people::import(world.tenant(), batch)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    people::import_progress(world.tenant(), import_id)
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}
