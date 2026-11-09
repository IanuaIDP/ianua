//! Reporter's authority: Ann hands it a narrowed part of what she holds,
//! it takes a bearer token and a key-bound one under that grant, and it
//! passes the permission alone on to Helper.

use ianua_scenarios::agent::external::{ExternalAgent, IssuedToken};
use ianua_scenarios::api::agents::delegation;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::wire::agents::authority::{
    Attenuation, Budget, Capabilities, Grant, Granted, Limits,
};
use ianua_scenarios::world::World;

use super::{Agents, BUDGET, TOKEN_SECONDS, WINDOW, reporting};
use crate::support::{Witness, granted_by_owner, hidden_from_the_rest};

/// Reporter's parent grant used when it delegates authority to Helper.
pub(super) struct HandOn<'a> {
    /// The agent passing part of its authority onward.
    pub(super) reporter: &'a ExternalAgent,
    /// Ann's parent delegation limiting that hand-on.
    pub(super) grant: &'a Granted,
}

/// Ann hands Reporter a narrowed part of what she holds: one permission,
/// publishing to its own topic, fifty requests an hour, passed on at most
/// once. Nobody else may grant it. The grant names Ann as who Reporter
/// acts for, is on record, and is read back by Ann and Tess alone.
pub(super) async fn delegated(
    world: &World<'_>,
    witness: &mut Witness<'_>,
    agents: &Agents<'_>,
    topic: &str,
) -> Granted {
    let Agents { reporter, helper } = *agents;
    let grant = reporting_grant(topic);
    let call = delegation::grant(world.tenant(), reporter.id(), &grant).call();
    hidden_from_the_rest(
        Matrix::new("granting Reporter a delegation", call),
        world,
        &[reporter, helper],
    )
    .run()
    .await;
    witness.nothing_new("agents.delegation_granted").await;
    let granted = granted_by_owner(world, reporter, &grant).await;
    assert_owner_grant(world, &grant, &granted);
    witness.recorded("agents.delegation_granted").await;
    witness.recorded("agents.token_issued").await;
    let call = delegation::list(world.tenant(), reporter.id()).call();
    let matrix = Matrix::new("reading Reporter's delegations", call)
        .allowed(world.owner().client())
        .allowed(world.admin().client());
    hidden_from_the_rest(matrix, world, &[reporter, helper])
        .run()
        .await;
    granted
}

/// Ann's reporting grant permits one further delegation within its hourly budget.
fn reporting_grant(topic: &str) -> Grant {
    Grant {
        granted: Capabilities::http(&["users:view"]).publishing_to(topic),
        limits: Limits {
            ttl_seconds: WINDOW,
            max_depth: 1,
            budget: Some(Budget::of(BUDGET, WINDOW)),
            ..Limits::default()
        },
        name: Some("Weekly reports".to_owned()),
    }
}

/// The returned delegation carries exactly Ann's grant and names her as principal.
fn assert_owner_grant(world: &World<'_>, grant: &Grant, granted: &Granted) {
    assert_eq!(
        granted.granted, grant.granted,
        "the delegation grants what Ann handed over"
    );
    let acting_for = granted
        .on_behalf_of
        .first()
        .map(|principal| principal.id.as_str());
    assert_eq!(
        acting_for,
        Some(world.owner().id()),
        "the delegation names Ann as who Reporter acts for"
    );
}

/// Reporter asks for two tokens of its own: a bearer token for the relay,
/// and one bound to its key. Each carries only what it asked of Ann's
/// grant, under her budget, which Reporter reads from its token; the bound
/// one names Reporter's own key. Both are on record.
pub(super) async fn tokens_taken(
    witness: &mut Witness<'_>,
    reporter: &mut ExternalAgent,
    topic: &str,
) -> IssuedToken {
    let bearer = reporter.take_token(&reporting(topic)).await;
    witness.recorded("agents.token_issued").await;
    assert_eq!(
        bearer.acting_agent(),
        Some(reporter.id()),
        "the token names Reporter as the one acting"
    );
    assert_eq!(
        bearer.granted(),
        &Capabilities::default().publishing_to(topic),
        "the token carries only what Reporter asked for"
    );
    assert!(bearer.bound_key().is_none(), "a bearer token names no key");
    assert_eq!(
        bearer.budget(),
        Some(Budget::of(BUDGET, WINDOW)),
        "the token carries Ann's budget"
    );

    let bound = IssuedToken::of(reporter.ask_token(&reporting(topic).key_bound()).await.ok());
    witness.recorded("agents.token_issued").await;
    assert_eq!(
        bound.bound_key(),
        Some(reporter.key().jwk()),
        "the bound token names Reporter's own key"
    );
    bound
}

/// Reporter passes part of Ann's grant on to Helper: the permission alone,
/// for ten minutes, passed on no further. Helper holds the child's token,
/// which names Reporter, then Ann, as who it acts for.
pub(super) async fn passed_on(
    world: &World<'_>,
    witness: &mut Witness<'_>,
    helper: &mut ExternalAgent,
    hand_on: HandOn<'_>,
) {
    let HandOn { reporter, grant } = hand_on;
    let attenuation = Attenuation {
        delegate: helper.id().to_owned(),
        granted: Capabilities::http(&["users:view"]),
        limits: Limits {
            ttl_seconds: TOKEN_SECONDS,
            ..Limits::default()
        },
    };
    let child = reporter
        .pass_on(&grant.delegation_id, &attenuation)
        .await
        .ok();
    witness.recorded("agents.delegation_granted").await;
    let acting_for: Vec<&str> = child
        .on_behalf_of
        .iter()
        .map(|principal| principal.id.as_str())
        .collect();
    assert_eq!(
        acting_for,
        [reporter.id(), world.owner().id()],
        "the child names Reporter, then Ann, as who Helper acts for"
    );
    helper.hold(IssuedToken::of(child));
}
