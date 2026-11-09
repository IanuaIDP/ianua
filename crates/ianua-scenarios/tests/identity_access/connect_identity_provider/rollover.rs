//! Acme's provider rolling its signing key over without locking anybody
//! out, and the old key losing its say once the connection rolls over.

use ianua_scenarios::actors::Person;
use ianua_scenarios::net::Call;
use ianua_scenarios::providers::saml::{Claim, Provider};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::world::World;

use crate::support::{
    Outcome, SamlAnswer, Settings, begun, connected, owned_domain, pat, reconfigured, signed_in,
};

/// Tess links the tenant to Acme's provider. The provider makes a new key
/// and Tess adds its certificate beside the current one: while both
/// stand, an answer signed by either signs Pat in. Tess rolls the
/// connection over: an answer signed by the old key signs nobody in any
/// more, and one signed by the new key still does.
#[tokio::test]
async fn a_provider_rolls_its_key_over_without_locking_pat_out() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let domain = owned_domain(&world).await;
    let old = Provider::new();
    let new = Provider::new();
    let mut settings = Settings {
        provider: &old,
        next: None,
        sign_requests: false,
    };
    let connection = connected(&world, &domain, &settings).await;
    let mut pat = pat(&world, &domain).await;

    settings.next = Some(&new);
    reconfigured(&world, &connection, &settings).await;
    let keys = [(&old, "the current key"), (&new, "the next key")];
    assert_overlap(&world, &mut pat, &connection, &keys).await;
    let roll_over = Call::post(world.tenant().at(&format!(
        "/federation/connections/{connection}/certificate/roll-over"
    )));
    world.admin().client().send::<()>(roll_over).await.ok();
    assert_old_key_refused(&world, &mut pat, &old, &connection).await;
    assert_new_key_accepted(&world, &mut pat, &new, &connection).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Both advertised signing keys authenticate Pat before the rollover.
async fn assert_overlap(
    world: &World<'_>,
    pat: &mut Person,
    connection: &str,
    keys: &[(&Provider, &str)],
) {
    for (key, which) in keys {
        let redirect = begun(world, pat, connection).await;
        let answer = SamlAnswer {
            provider: key,
            redirect,
            claim: Claim::Correct,
        };
        let outcome = signed_in(world, pat, answer).await;
        assert!(
            matches!(outcome, Outcome::SignedIn),
            "an answer signed by {which} signs Pat in while both stand: {outcome:?}"
        );
    }
}

/// The removed signing key no longer opens a session after rollover.
async fn assert_old_key_refused(
    world: &World<'_>,
    pat: &mut Person,
    old: &Provider,
    connection: &str,
) {
    let redirect = begun(world, pat, connection).await;
    let answer = SamlAnswer {
        provider: old,
        redirect,
        claim: Claim::Correct,
    };
    let outcome = signed_in(world, pat, answer).await;
    assert!(
        matches!(outcome, Outcome::Failed),
        "the old key signs nobody in once the connection rolled over: {outcome:?}"
    );
}

/// The replacement signing key still opens Pat's session after rollover.
async fn assert_new_key_accepted(
    world: &World<'_>,
    pat: &mut Person,
    new: &Provider,
    connection: &str,
) {
    let redirect = begun(world, pat, connection).await;
    let answer = SamlAnswer {
        provider: new,
        redirect,
        claim: Claim::Correct,
    };
    let outcome = signed_in(world, pat, answer).await;
    assert!(
        matches!(outcome, Outcome::SignedIn),
        "the new key still signs Pat in: {outcome:?}"
    );
}
