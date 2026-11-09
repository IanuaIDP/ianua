//! The demo seeder.

use ianua_server::command::Command;
use ianua_server::demo::{self, DemoError};
use ianua_server::install;

use crate::support::Server;

/// What the demo makes, each kind beside the record that says it was made:
/// its table, the event, and how many of them the demo holds.
const MADE: [(&str, &str, i64); 12] = [
    ("tenants", "tenant.provisioned", 3),
    ("org_users", "organization.org_user_created", 1),
    ("org_mfa_enrollments", "organization.org_mfa_enrolled", 1),
    ("users", "identity.user_registered", 22),
    ("roles", "authorization.role_created", 12),
    ("groups", "authorization.group_created", 12),
    ("group_memberships", "authorization.group_member_added", 22),
    ("services", "routing.service_created", 9),
    ("routes", "routing.route_created", 9),
    ("webhook_subscriptions", "webhooks.subscription_created", 3),
    ("agents", "agents.agent_created", 6),
    (
        "agent_model_providers",
        "agents.model_provider_connected",
        3,
    ),
];

/// The owner's sessions: the one their sign-in opened in the first tenant,
/// and the one each move into the two tenants provisioned after it opened.
/// A move ends the session it leaves, which stays as a row.
const OWNER_SESSIONS: i64 = 3;

async fn development() -> Server {
    Server::start(&Command::Demo, &[]).await
}

/// A developer seeds the demo. The organization, its tenants and
/// everything in them are made; only the first tenant is found, made with
/// the organization. The owner's sign-in set up their authenticator app,
/// whose link the run hands back to show.
#[tokio::test]
async fn the_demo_seeds_its_organization() {
    let server = development().await;

    let seeded = demo::seed(&server.deps).await.unwrap();

    let tally = seeded.tally;
    assert!(seeded.authenticator.is_some());
    assert!(tally.made > 0);
    assert_eq!(tally.found, 1);
    assert_eq!(server.rows("organizations").await, 1);
    for (table, _, holds) in MADE {
        assert_eq!(server.rows(table).await, holds, "{table}");
    }
    assert_eq!(server.rows("org_notification_destinations").await, 1);
    assert_eq!(server.rows("org_sessions").await, OWNER_SESSIONS);
}

/// The developer seeds the demo again. Everything is found, nobody signs
/// in, so no code is asked for and no authenticator is set up, and nothing
/// is added: no row and no record.
#[tokio::test]
async fn seeding_again_adds_nothing() {
    let server = development().await;
    let first = demo::seed(&server.deps).await.unwrap().tally;
    let trail = server.trail().await;

    let seeded = demo::seed(&server.deps).await.unwrap();

    let again = seeded.tally;
    assert!(seeded.authenticator.is_none());
    assert_eq!(again.made, 0);
    assert_eq!(again.found, first.made + first.found);
    assert_eq!(server.trail().await, trail);
    assert_eq!(server.rows("org_sessions").await, OWNER_SESSIONS);
    for (table, _, holds) in MADE {
        assert_eq!(server.rows(table).await, holds, "{table}");
    }
}

/// Demo resource counts match their creation-event counts, and the trail
/// also records its organization, notification destination, session moves
/// and group-role assignments.
#[tokio::test]
async fn every_row_the_demo_made_is_on_the_trail() {
    let server = development().await;

    demo::seed(&server.deps).await.unwrap();

    for (table, event, _) in MADE {
        assert_eq!(
            server.rows(table).await,
            server.recorded(event).await,
            "{table} against {event}"
        );
    }
    assert_eq!(server.recorded("organization.created").await, 1);
    assert_eq!(server.recorded("notifications.destination_added").await, 1);
    assert_eq!(
        server.recorded("organization.org_session_moved").await,
        OWNER_SESSIONS - 1
    );
    assert_eq!(
        server.recorded("authorization.group_role_assigned").await,
        12
    );
}

/// Seeding beside an installed organization is refused as occupied,
/// preserving the organization count and audit trail.
#[tokio::test]
async fn the_demo_beside_another_organization_makes_nothing() {
    let settings = [
        ("DEPLOYMENT", "self_hosted"),
        ("INSTALL_ORGANIZATION_NAME", "Acme Corp"),
        ("INSTALL_OWNER_EMAIL", "owner@acme.example.com"),
        ("INSTALL_OWNER_PASSWORD", "A quiet meadow after 7 rains"),
    ];
    let server = Server::start(&Command::Install, &settings).await;
    let installation = server
        .config
        .installation
        .as_ref()
        .expect("the test platform was read for the install command");
    install::install(&server.deps, installation).await.unwrap();
    let trail = server.trail().await;

    let refused = demo::seed(&server.deps).await;

    assert!(matches!(refused, Err(DemoError::Occupied)));
    assert_eq!(server.rows("organizations").await, 1);
    assert_eq!(server.trail().await, trail);
}
