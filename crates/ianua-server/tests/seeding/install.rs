//! The self-hosted installer.

use ianua_server::command::Command;
use ianua_server::config::installation::Installation;
use ianua_server::install::{self, Outcome};

use crate::support::Server;

/// An installation's settings.
const INSTALLATION: [(&str, &str); 5] = [
    ("DEPLOYMENT", "self_hosted"),
    ("INSTALL_ORGANIZATION_NAME", "Acme Corp"),
    ("INSTALL_TENANT_NAME", "Main"),
    ("INSTALL_OWNER_EMAIL", "owner@acme.example.com"),
    ("INSTALL_OWNER_PASSWORD", "A quiet meadow after 7 rains"),
];

async fn installer() -> Server {
    Server::start(&Command::Install, &INSTALLATION).await
}

fn installation(server: &Server) -> &Installation {
    server
        .config
        .installation
        .as_ref()
        .expect("the test platform was read for the install command")
}

/// Olivia installs ianua on her own hardware. Its one organization, first
/// tenant and her account as owner are made, and the trail says so.
#[tokio::test]
async fn the_installer_makes_the_organization_tenant_and_owner() {
    let server = installer().await;

    let outcome = install::install(&server.deps, installation(&server))
        .await
        .unwrap();

    let Outcome::Made(founded) = outcome else {
        panic!("the organization was not made");
    };
    assert_eq!(founded.org_slug, "acme-corp");
    assert_eq!(founded.tenant_slug, "main");
    assert_eq!(server.rows("organizations").await, 1);
    assert_eq!(server.rows("tenants").await, 1);
    assert_eq!(server.rows("org_users").await, 1);
    assert_eq!(server.recorded("organization.created").await, 1);
    assert_eq!(server.recorded("tenant.provisioned").await, 1);
}

/// Olivia runs the installer again. Nothing is made twice and nothing
/// more is recorded.
#[tokio::test]
async fn installing_again_changes_nothing() {
    let server = installer().await;
    install::install(&server.deps, installation(&server))
        .await
        .unwrap();
    let trail = server.trail().await;

    let again = install::install(&server.deps, installation(&server))
        .await
        .unwrap();

    assert!(matches!(again, Outcome::AlreadyInstalled));
    assert_eq!(server.rows("organizations").await, 1);
    assert_eq!(server.rows("org_users").await, 1);
    assert_eq!(server.trail().await, trail);
}

/// A weak owner password refuses installation, leaving no organization
/// or audit records.
#[tokio::test]
async fn a_weak_owner_password_makes_nothing() {
    let mut settings = INSTALLATION;
    settings[4] = ("INSTALL_OWNER_PASSWORD", "short");
    let server = Server::start(&Command::Install, &settings).await;

    let refused = install::install(&server.deps, installation(&server)).await;

    assert!(refused.is_err());
    assert_eq!(server.rows("organizations").await, 0);
    assert_eq!(server.trail().await, 0);
}
