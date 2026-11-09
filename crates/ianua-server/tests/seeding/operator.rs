//! The platform's first operator.

use ianua_app::use_cases::operator::accounts::FirstOperator;
use ianua_domain::types::Email;
use ianua_server::command::Command;
use ianua_server::config::operator::FirstOperatorConfig;
use ianua_server::install::operator;

use crate::support::Server;

/// The operator command for `address`.
fn create(address: &str) -> Command {
    Command::CreateOperator {
        email: Email::new(address).unwrap(),
    }
}

async fn platform_for(address: &str) -> Server {
    Server::start(
        &create(address),
        &[("OPERATOR_PASSWORD", "Copper kettle on 9 cold mornings")],
    )
    .await
}

fn first_operator(server: &Server) -> &FirstOperatorConfig {
    server
        .config
        .first_operator
        .as_ref()
        .expect("the operator command names an operator")
}

/// Bob sets up a fresh platform. He is made its first operator, and the
/// trail says so.
#[tokio::test]
async fn the_first_operator_is_made_on_a_fresh_platform() {
    let server = platform_for("bob@ianua.example.com").await;

    let made = operator::create(&server.deps, first_operator(&server))
        .await
        .unwrap();

    assert!(matches!(made, FirstOperator::Installed(_)));
    assert_eq!(server.rows("operators").await, 1);
    assert_eq!(server.recorded("operator.operator_created").await, 1);
}

/// After Bob is installed, requesting Mallory as the first operator
/// reports already installed and adds neither an operator nor its event.
#[tokio::test]
async fn a_second_first_operator_is_refused() {
    let server = platform_for("bob@ianua.example.com").await;
    operator::create(&server.deps, first_operator(&server))
        .await
        .unwrap();
    let mallory = FirstOperatorConfig {
        email: Email::new("mallory@ianua.example.com").unwrap(),
        password: first_operator(&server).password.clone(),
    };

    let again = operator::create(&server.deps, &mallory).await.unwrap();

    assert_eq!(again, FirstOperator::AlreadyInstalled);
    assert_eq!(server.rows("operators").await, 1);
    assert_eq!(server.recorded("operator.operator_created").await, 1);
}
