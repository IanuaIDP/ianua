//! Ann posts her company's notifications outside the app: to a Slack
//! channel or a webhook of its own. The address is sealed at once and
//! never shown again, a webhook's signing secret shows once, and each
//! change is recorded naming the kind only. Tess, Max, Sam and nobody
//! signed in change nothing.
//!
//! The filters chosen here match no event these scenarios raise, so no
//! post ever leaves the stack, except the scenario that points Ann's
//! webhook at a stand-in for the company's own server and reads what
//! arrives there.

use ianua_scenarios::api::{destinations, people, roles};
use ianua_scenarios::expect::{Matrix, eventually, no_secret_leaked, standard_webhook_signed_by};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, OutsideReceiver};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::destinations::{Destination, DestinationForm, DestinationTarget};
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::roles::{AssignRole, NewRole, SystemPermission};
use ianua_scenarios::world::{MEMBER_ROLE, World};

/// The kind of event no scenario here raises.
const QUIET_CATEGORY: &str = "Pipeline";

/// The severity no event below `Critical` reaches.
const CRITICAL: &str = "Critical";

/// A Slack channel's address on the host Slack posts from.
const SLACK_ADDRESS: &str = "https://hooks.slack.com/services/T0/B0/scenario";

/// A webhook's address no scenario ever posts to.
const WEBHOOK_ADDRESS: &str = "https://hooks.orchard.example/notify";

/// The record of a destination added.
const ADDED: &str = "notifications.destination_added";

/// The record of a destination changed.
const CHANGED: &str = "notifications.destination_changed";

/// The record of a destination paused.
const PAUSED: &str = "notifications.destination_paused";

/// The record of a destination resumed.
const RESUMED: &str = "notifications.destination_resumed";

/// The record of a destination removed.
const REMOVED: &str = "notifications.destination_removed";

/// The form for a webhook called `name`.
fn webhook(name: &str) -> DestinationForm {
    DestinationForm {
        name: name.to_owned(),
        target: DestinationTarget::Webhook {
            url: WEBHOOK_ADDRESS.to_owned(),
        },
        categories: vec![QUIET_CATEGORY.to_owned()],
        minimum_severity: CRITICAL.to_owned(),
    }
}

/// The form for a Slack channel called `name`.
fn slack(name: &str) -> DestinationForm {
    DestinationForm {
        name: name.to_owned(),
        target: DestinationTarget::Slack {
            url: SLACK_ADDRESS.to_owned(),
        },
        categories: vec![QUIET_CATEGORY.to_owned()],
        minimum_severity: CRITICAL.to_owned(),
    }
}

/// The one destination Ann's company lists.
///
/// # Panics
///
/// When there is not exactly one, or it cannot be read.
async fn the_one_destination(world: &World<'_>) -> Destination {
    let listed = destinations::list(world.org())
        .send(world.owner().client())
        .await
        .ok();
    let [destination] = listed.as_slice() else {
        panic!("one destination is listed, not {}", listed.len());
    };
    destination.clone()
}

/// Ann adds a webhook: its signing secret is in the answer and never
/// again. It lists active, named and filtered, and neither its address
/// nor its secret shows anywhere afterwards, not in the list and not in
/// the record, which names the kind only. A Slack channel shows no secret
/// since Slack's address carries its own key.
#[tokio::test]
async fn ann_adds_a_webhook_and_its_secret_shows_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    let added = destinations::add(world.org(), &webhook("Orchard alerts"))
        .send(world.owner().client())
        .await
        .ok();
    let secret = added.signing_secret.as_deref().expect("a signing secret");

    let listed = the_one_destination(&world).await;
    assert_eq!(listed.id, added.id, "the id is the one made");
    assert_eq!(listed.name, "Orchard alerts", "named as Ann named it");
    assert_eq!(listed.kind, "webhook", "it is a webhook");
    assert_eq!(listed.categories, [QUIET_CATEGORY], "filtered as asked");
    assert_eq!(listed.minimum_severity, CRITICAL, "at the severity asked");
    assert_eq!(listed.state, "active", "active at once");
    no_secret_leaked(&format!("{listed:?}"), &[secret, WEBHOOK_ADDRESS]);

    let records = world.trail().entries(ADDED).await;
    let [record] = records.as_slice() else {
        panic!("one {ADDED} is recorded, not {}", records.len());
    };
    assert!(
        record.actor.contains(world.owner().email()),
        "the addition is recorded under Ann"
    );
    no_secret_leaked(&record.details.to_string(), &[secret, WEBHOOK_ADDRESS]);

    let channel = destinations::add(world.org(), &slack("Orchard channel"))
        .send(world.owner().client())
        .await
        .ok();
    assert!(
        channel.signing_secret.is_none(),
        "a Slack address signs nothing"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann replaces the webhook whole: a new name, a new signing secret, the
/// address retyped. Pausing stops it, pausing again is refused, resuming
/// starts it, and resuming a running one is refused. Each step is
/// recorded once and each secret is shown once.
#[tokio::test]
async fn ann_changes_pauses_and_resumes_a_destination() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let added = destinations::add(world.org(), &webhook("Old name"))
        .send(world.owner().client())
        .await
        .ok();
    let old_secret = added.signing_secret.expect("the first secret");

    let replaced = destinations::change(world.org(), &added.id, &webhook("New name"))
        .send(world.owner().client())
        .await
        .ok();
    let new_secret = replaced.signing_secret.expect("a new secret");
    assert_ne!(new_secret, old_secret, "the secret is a new one");
    assert_eq!(
        the_one_destination(&world).await.name,
        "New name",
        "the name is the new one"
    );

    pause_then_resume(&world, &added.id).await;

    assert_eq!(
        world.trail().count(CHANGED).await,
        1,
        "the change is recorded once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pausing and resuming twice each, the second of each refused, leaves
/// the destination active with one record of each.
async fn pause_then_resume(world: &World<'_>, id: &str) {
    destinations::pause(world.org(), id)
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        the_one_destination(world).await.state,
        "paused",
        "pausing stops it"
    );
    destinations::pause(world.org(), id)
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    destinations::resume(world.org(), id)
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        the_one_destination(world).await.state,
        "active",
        "resuming starts it again"
    );
    destinations::resume(world.org(), id)
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    assert_eq!(world.trail().count(PAUSED).await, 1, "paused once");
    assert_eq!(world.trail().count(RESUMED).await, 1, "resumed once");
}

/// Ann removes a destination: the list is empty, changing it or pausing
/// it is not found, and the removal is recorded once.
#[tokio::test]
async fn ann_removes_a_destination_and_it_is_gone() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let added = destinations::add(world.org(), &webhook("Short lived"))
        .send(world.owner().client())
        .await
        .ok();

    destinations::remove(world.org(), &added.id)
        .send(world.owner().client())
        .await
        .ok();

    let listed = destinations::list(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert!(listed.is_empty(), "it is gone");
    destinations::pause(world.org(), &added.id)
        .send(world.owner().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    destinations::remove(world.org(), &added.id)
        .send(world.owner().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert_eq!(
        world.trail().count(REMOVED).await,
        1,
        "the removal is recorded once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// A Slack address on another host, a form with no category, and a form
/// naming the same category twice add nothing and record nothing.
#[tokio::test]
async fn a_form_that_does_not_fit_adds_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    let off_host = DestinationForm {
        target: DestinationTarget::Slack {
            url: "https://hooks.orchard.example/channel".to_owned(),
        },
        ..slack("Not Slack")
    };
    let nothing_chosen = DestinationForm {
        categories: Vec::new(),
        ..webhook("No category")
    };
    let chosen_twice = DestinationForm {
        categories: vec![QUIET_CATEGORY.to_owned(), QUIET_CATEGORY.to_owned()],
        ..webhook("Doubled")
    };
    for form in [off_host, nothing_chosen, chosen_twice] {
        destinations::add(world.org(), &form)
            .send(world.owner().client())
            .await
            .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    }

    let listed = destinations::list(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert!(listed.is_empty(), "nothing was added");
    assert_eq!(
        world.trail().count(ADDED).await,
        0,
        "nothing refused is recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The Free plan allows two destinations. Ann adds them; a third is
/// refused, adding nothing. Once one is removed, she may add another.
#[tokio::test]
async fn the_plans_destination_limit_is_enforced() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    let first = destinations::add(world.org(), &webhook("First"))
        .send(world.owner().client())
        .await
        .ok();
    destinations::add(world.org(), &webhook("Second"))
        .send(world.owner().client())
        .await
        .ok();

    let refused = destinations::add(world.org(), &webhook("Third"))
        .send(world.owner().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    assert!(
        refused.message().contains("limit"),
        "the refusal names the limit: {}",
        refused.message()
    );
    assert_eq!(world.trail().count(ADDED).await, 2, "only two were added");

    destinations::remove(world.org(), &first.id)
        .send(world.owner().client())
        .await
        .ok();
    destinations::add(world.org(), &webhook("Room again"))
        .send(world.owner().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess, Max, Sam and nobody signed in neither read Ann's destinations
/// nor change one. A destination of Ann's is nobody's in Sam's company.
#[tokio::test]
async fn only_someone_who_manages_the_notifications_touches_a_destination() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let added = destinations::add(world.org(), &webhook("Orchard alerts"))
        .send(world.owner().client())
        .await
        .ok();

    for call in [
        destinations::list(world.org()).call(),
        destinations::add(world.org(), &webhook("Theirs")).call(),
        destinations::change(world.org(), &added.id, &webhook("Theirs")).call(),
        destinations::pause(world.org(), &added.id).call(),
        destinations::remove(world.org(), &added.id).call(),
    ] {
        Matrix::new("touching Ann's destinations", call)
            .refused(world.admin().client(), Status::FORBIDDEN, "forbidden")
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
    destinations::pause(world.stranger().org(), &added.id)
        .send(world.stranger().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert_eq!(
        the_one_destination(&world).await.state,
        "active",
        "Ann's destination is untouched"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The path Ann's company's server takes posts at.
const NOTIFIED: &str = "/notify";

/// Ann points a webhook at her company's real server, for every event
/// about who may do what. Tess gives Pat, a person of the tenant, a role,
/// and the post that arrives names the event and its category, carries a
/// signature the server verifies with the secret Ann was shown once, and
/// shows nothing of the secret anywhere in its body.
#[tokio::test]
async fn a_notification_reaches_the_companys_server_signed() {
    let server = OutsideReceiver::start(
        "alerts.orchard.example",
        [(NOTIFIED, Canned::json(&serde_json::json!({ "ok": true })))],
    )
    .await;
    let stack = Stack::start(
        Profile::standard().with("OUTBOUND_DELIVERY_CA_FILE", server.authority_file()),
    )
    .await
    .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let mut pat = world.newcomer("pat", "Pat Person");
    let invitation = InviteUser {
        email: pat.email().to_owned(),
        display_name: pat.account().display_name.clone(),
        role_id: world.role_id(MEMBER_ROLE).await,
    };
    let invited = people::invite(world.tenant(), &invitation)
        .send(tess)
        .await
        .ok();
    pat.record_invitation(&invited.id);
    pat.accept_invitation(world.stack()).await;
    let form = DestinationForm {
        name: "Orchard server".to_owned(),
        target: DestinationTarget::Webhook {
            url: server.url_on(&stack, NOTIFIED),
        },
        categories: vec!["Authorization".to_owned()],
        minimum_severity: "Info".to_owned(),
    };
    let added = destinations::add(world.org(), &form)
        .send(world.owner().client())
        .await
        .ok();
    let secret = added.signing_secret.as_deref().expect("a signing secret");
    let role = roles::create(
        world.tenant(),
        &NewRole {
            name: "Destination Readers".to_owned(),
            system_permissions: vec![SystemPermission::new("Users", "View")],
        },
    )
    .send(tess)
    .await
    .ok();

    roles::assign(
        world.tenant(),
        &role.id,
        &AssignRole {
            user_id: pat.id().to_owned(),
        },
    )
    .send(tess)
    .await
    .ok();

    let acme = &server;
    let post = eventually("the company's server got the post", || async move {
        acme.received_at("POST", NOTIFIED).into_iter().next()
    })
    .await;
    assert_eq!(post.header("content-type"), Some("application/json"));
    assert!(
        standard_webhook_signed_by(&post, secret),
        "the post verifies with the secret Ann was shown: {:?}",
        post.header("webhook-signature")
    );
    let body = post.json();
    assert_eq!(body["category"], "authorization", "the category asked for");
    assert_eq!(body["severity"], "info");
    assert!(
        body["type"]
            .as_str()
            .is_some_and(|name| name.starts_with("authorization.")),
        "it names the event: {body}"
    );
    no_secret_leaked(&post.body, &[secret]);

    stack.stop().await.expect("the stack stops cleanly");
}
