//! Pat's link to a real identity provider: her first sign-in through it
//! links her account, a second reuses the link, she confirms the link
//! again with her password and removes it, her password signing her in
//! throughout. A provider that did not prove her address links nothing,
//! and one claiming Tess's administrator account links nothing either.

use ianua_scenarios::actors::{Person, PersonAccount};
use ianua_scenarios::api::{account, people, roles, tenants};
use ianua_scenarios::net::Client;
use ianua_scenarios::providers::oidc::{Claim, Provider};
use ianua_scenarios::providers::parameter;
use ianua_scenarios::routes::domain;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::account::{LinkProof, ReconfirmLink, Requested};
use ianua_scenarios::wire::federation::{Begun, ProviderAnswer};
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::roles::NewRole;
use ianua_scenarios::wire::sign_in::Owed;
use ianua_scenarios::wire::tenant_sign_in::TenantSession;
use ianua_scenarios::wire::tenants::{PasswordAgain, ReplaceSignInSettings};
use ianua_scenarios::world::{ADMIN_ROLE, World};
use serde_json::json;

use crate::support::{device, still_signed_in, tenant_records};

/// The state the dashboard keeps across the provider round trip, which
/// only the browser that started the sign-in knows.
const DASHBOARD_STATE: &str = "holder-keeps-this-independent-random-dashboard-value";

/// The password of Pat's local account: a sentence, so no scanner takes
/// it for a key.
const LOCAL_PASSWORD: &str = "Local Orchard Lantern Meadow 7438!";

/// A wrong guess at that password.
const WRONG_PASSWORD: &str = "Wrong Orchard Meadow 7543!";

/// The connection the tenant made to the provider, and Pat, invited with
/// a local account at an address under the provider's domain.
struct Connected {
    /// Pat, signed in with her local password.
    holder: Person,
    /// The connection's id.
    id: String,
}

/// The provider claim and the browser carrying its answer through the round trip.
struct ProviderVisit<'a> {
    /// The real provider issuing the answer.
    provider: &'a Provider,
    /// The browser that starts and completes this sign-in.
    browser: &'a Client,
    /// Whether the provider proves the holder's mailbox.
    claim: Claim,
}

/// What rights Pat's account carries, which decides whether a provider
/// may link it on her first sign-in.
#[derive(Clone, Copy)]
enum Rights {
    /// None at all: an application account.
    None,
    /// The tenant's `Admin` role.
    Administrator,
}

/// Pat's first sign-in through the provider links her account; her second
/// reuses the link, so one linking is recorded. Reconfirmation with a
/// wrong password is refused. With the right one it is confirmed, and
/// she removes it: her list of links is empty, her password still signs
/// her in, and the confirmation and the removal are each recorded once
/// with no password in them.
#[tokio::test]
async fn pat_links_her_provider_account_reconfirms_it_and_unlinks_it() {
    let provider = Provider::start().await;
    let stack = Stack::start(trusting(&provider))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut connected = connected(&world, &provider, Rights::None).await;

    let _signed_in = signed_in_through(&world, &connected, &provider).await;
    check_first_link(&world, &connected).await;
    let _returning = signed_in_through(&world, &connected, &provider).await;
    assert_eq!(
        tenant_records(&world, "federation.account_linked", &[]).await,
        1,
        "the second sign-in reuses the link"
    );
    reconfirm_link(&world, &connected).await;
    remove_link(&world, &connected).await;
    connected.holder.sign_in(&stack).await;
    still_signed_in(&world, &connected.holder).await;
    check_link_change_records(&world, connected.holder.password()).await;
    stack.stop().await.expect("the stack stops cleanly");
    provider.stop().await;
}

/// The first provider sign-in records exactly the expected connection and subject.
async fn check_first_link(world: &World<'_>, connected: &Connected) {
    let links = account::provider_links(world.tenant())
        .send(connected.holder.client())
        .await
        .ok();
    assert_eq!(links.links.len(), 1, "the first sign-in made one link");
    assert_eq!(
        links.links[0].connection_id, connected.id,
        "the link goes through the tenant's connection"
    );
    assert_eq!(
        links.links[0].subject, "ann-at-provider",
        "the link names the provider's subject"
    );
}

/// Reconfirming the link requires the holder's correct local password.
async fn reconfirm_link(world: &World<'_>, connected: &Connected) {
    let wrong = ReconfirmLink {
        proof: LinkProof::Password {
            password: WRONG_PASSWORD.to_owned(),
            code: None,
        },
    };
    account::reconfirm_provider_link(world.tenant(), &connected.id, &wrong)
        .send(connected.holder.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let right = ReconfirmLink {
        proof: LinkProof::Password {
            password: connected.holder.password().to_owned(),
            code: None,
        },
    };
    account::reconfirm_provider_link(world.tenant(), &connected.id, &right)
        .send(connected.holder.client())
        .await
        .ok();
}

/// Unlinking removes the connection from the holder's account list.
async fn remove_link(world: &World<'_>, connected: &Connected) {
    account::unlink_provider(world.tenant(), &connected.id)
        .send(connected.holder.client())
        .await
        .ok();
    let links = account::provider_links(world.tenant())
        .send(connected.holder.client())
        .await
        .ok();
    assert!(links.links.is_empty(), "the removed link is gone");
}

/// Reconfirmation and removal each produce one audit record without the password.
async fn check_link_change_records(world: &World<'_>, password: &str) {
    assert_eq!(
        tenant_records(world, "federation.account_unlinked", &[password]).await,
        1,
        "the removal is recorded once"
    );
    assert_eq!(
        tenant_records(world, "federation.link_reconfirmed", &[password]).await,
        1,
        "the confirmation is recorded once"
    );
}

/// A provider answer without email proof fails to sign Pat in or link her
/// account. Her existing session remains usable, and a later sign-in through the
/// provider, with the address proved, links her account.
#[tokio::test]
async fn a_provider_that_did_not_prove_the_address_links_nothing() {
    let provider = Provider::start().await;
    let stack = Stack::start(trusting(&provider))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let connected = connected(&world, &provider, Rights::None).await;
    refuse_unproved_address(&world, &connected, &provider).await;
    still_signed_in(&world, &connected.holder).await;
    let _verified = signed_in_through(&world, &connected, &provider).await;
    assert_eq!(
        tenant_records(&world, "federation.account_linked", &[]).await,
        1,
        "the proved sign-in links the account"
    );
    stack.stop().await.expect("the stack stops cleanly");
    provider.stop().await;
}

/// An unproved mailbox redirects to failure and creates neither a session nor a link.
async fn refuse_unproved_address(world: &World<'_>, connected: &Connected, provider: &Provider) {
    let browser = device(world.stack(), "a provider that did not prove Pat's address");
    let visit = ProviderVisit {
        provider,
        browser: &browser,
        claim: Claim::UnverifiedEmail,
    };
    let redirect = returned(world, connected, visit).await;
    assert_eq!(
        parameter(&redirect, "sso"),
        "failed",
        "the dashboard is told the sign-in failed"
    );
    people::me(world.tenant())
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let links = account::provider_links(world.tenant())
        .send(connected.holder.client())
        .await
        .ok();
    assert!(links.links.is_empty(), "an unproved address links nothing");
}

/// Even with email proof, the provider cannot claim Pat's account holding
/// the tenant's `Admin` role. An account with rights is not
/// linked on a first sign-in: the sign-in fails, the browser is not
/// signed in, Pat has no link and no linking is recorded, while her own
/// session still reads her record.
#[tokio::test]
async fn a_provider_cannot_claim_an_administrators_account() {
    let provider = Provider::start().await;
    let stack = Stack::start(trusting(&provider))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let connected = connected(&world, &provider, Rights::Administrator).await;
    refuse_administrator_claim(&world, &connected, &provider).await;
    let own = people::me(world.tenant())
        .send(connected.holder.client())
        .await
        .ok();
    assert_eq!(
        own.id,
        connected.holder.id(),
        "Pat's own session still reads her record"
    );
    assert_eq!(
        tenant_records(&world, "federation.account_linked", &[]).await,
        0,
        "the refused sign-in records no link"
    );
    stack.stop().await.expect("the stack stops cleanly");
    provider.stop().await;
}

/// Even a proved provider address cannot automatically link an administrator's account.
async fn refuse_administrator_claim(world: &World<'_>, connected: &Connected, provider: &Provider) {
    let browser = device(
        world.stack(),
        "Pat, from a provider claiming an administrator",
    );
    let visit = ProviderVisit {
        provider,
        browser: &browser,
        claim: Claim::Correct,
    };
    let redirect = returned(world, connected, visit).await;
    assert_eq!(
        parameter(&redirect, "sso"),
        "failed",
        "the dashboard is told the sign-in failed"
    );
    people::me(world.tenant())
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let links = account::provider_links(world.tenant())
        .send(connected.holder.client())
        .await
        .ok();
    assert!(
        links.links.is_empty(),
        "an account with rights is not linked by a first sign-in"
    );
}

/// The standard profile trusting `provider`'s certificate authority.
fn trusting(provider: &Provider) -> Profile {
    Profile::standard().with("OIDC_PROVIDER_CA_FILE", provider.authority_file())
}

/// The tenant connected to `provider`: a domain of the customer's brought
/// in and proved, the connection made for it, the method switched on, and
/// Pat invited at an address under that domain with an account carrying
/// `rights`, accepted from her mailbox and signed in with her password.
///
/// # Panics
///
/// When any step is refused.
async fn connected(world: &World<'_>, provider: &Provider, rights: Rights) -> Connected {
    let host = format!("accounts.{}", world.stack().customer_domain());
    domain::brought(world.stack(), world.admin().client(), world.tenant(), &host).await;
    let connection = json!({
        "provider_name": "Independent OIDC",
        "config": provider.config(),
        "allowed_domains": [host],
    });
    let made = world
        .admin()
        .client()
        .post::<Requested>(&world.tenant().at("/federation/connections"), &connection)
        .await
        .ok();
    oidc_switched_on(world).await;
    let role_id = role_carrying(world, rights).await;
    let holder = invited_at(world, &format!("pat@{host}"), role_id).await;
    Connected {
        holder,
        id: made.id,
    }
}

/// Switches the OIDC method on in the tenant's sign-in settings, as Ann.
async fn oidc_switched_on(world: &World<'_>) {
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    settings.enabled_methods.push("Oidc".to_owned());
    let replace = ReplaceSignInSettings {
        settings,
        proof: PasswordAgain {
            password: world.owner().password().to_owned(),
            code: None,
        },
    };
    tenants::replace_sign_in_settings(world.tenant(), &replace)
        .send(world.owner().client())
        .await
        .ok();
}

/// The id of a role carrying `rights`: a new role with no permission at
/// all, or the tenant's `Admin` role.
async fn role_carrying(world: &World<'_>, rights: Rights) -> String {
    match rights {
        Rights::None => {
            let empty = NewRole {
                name: "Application account".to_owned(),
                system_permissions: Vec::new(),
            };
            roles::create(world.tenant(), &empty)
                .send(world.admin().client())
                .await
                .ok()
                .id
        }
        Rights::Administrator => world.role_id(ADMIN_ROLE).await,
    }
}

/// Pat, invited by Tess at `email` with the role `role_id`, accepted from
/// her mailbox and signed in with her local password.
async fn invited_at(world: &World<'_>, email: &str, role_id: String) -> Person {
    let invitation = InviteUser {
        email: email.to_owned(),
        display_name: "Pat Provider Holder".to_owned(),
        role_id,
    };
    let invited = people::invite(world.tenant(), &invitation)
        .send(world.admin().client())
        .await
        .ok();
    let account = PersonAccount {
        email: email.to_owned(),
        display_name: "Pat Provider Holder".to_owned(),
        tenant: world.tenant().clone(),
    };
    let mut holder = Person::new(
        device(world.stack(), "Pat's local account"),
        account,
        LOCAL_PASSWORD,
    );
    holder.record_invitation(&invited.id);
    holder.accept_invitation(world.stack()).await;
    holder.sign_in(world.stack()).await;
    holder
}

/// Where the dashboard is sent once `browser` has started a sign-in
/// through the connection, been sent to the provider, and come back with
/// the provider's answer for Pat carrying `claim`. The redirect carries
/// a code, so it is never printed.
///
/// # Panics
///
/// When either leg is not a redirect.
async fn returned(world: &World<'_>, connected: &Connected, visit: ProviderVisit<'_>) -> String {
    let begun = begin_provider_sign_in(world, connected, visit.browser).await;
    let callback = visit
        .provider
        .callback(begun, connected.holder.email(), visit.claim);
    let ProviderAnswer::Oidc { state, code } = callback.answer else {
        panic!("an OIDC provider answers with a state and a code");
    };
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("state", &state)
        .append_pair("code", &code)
        .finish();
    finish_provider_return(world, visit.browser, &query).await
}

/// Start the bound browser's sign-in and require the redirect to the provider.
async fn begin_provider_sign_in(
    world: &World<'_>,
    connected: &Connected,
    browser: &Client,
) -> Begun {
    let login = format!(
        "/federation/connections/{}/login?state={DASHBOARD_STATE}",
        connected.id
    );
    let start = browser.get::<()>(&world.tenant().at(&login)).await;
    assert_eq!(
        start.status(),
        Status::SEE_OTHER,
        "the sign-in is sent to the provider: {}",
        start.exchange()
    );
    let Some(location) = start.header("location") else {
        panic!("a redirect to the provider names where to go");
    };
    Begun {
        redirect_url: location.to_owned(),
        binding: String::new(),
    }
}

/// Deliver the provider's answer and require the redirect back to the dashboard.
async fn finish_provider_return(world: &World<'_>, browser: &Client, query: &str) -> String {
    let answer = browser
        .get::<()>(
            &world
                .tenant()
                .at(&format!("/federation/oidc/callback?{query}")),
        )
        .await;
    assert_eq!(
        answer.status(),
        Status::SEE_OTHER,
        "the provider's answer sends the browser on to the dashboard: {}",
        answer.exchange()
    );
    let Some(dashboard) = answer.header("location") else {
        panic!("the redirect to the dashboard names where to go");
    };
    dashboard.to_owned()
}

/// Pat's browser, signed in through the provider with her address proved:
/// the dashboard's code traded for a session that owes nothing, bound to
/// this browser, reading Pat's own record.
///
/// # Panics
///
/// When the trade is refused, the session owes more, or it is not Pat's.
async fn signed_in_through(
    world: &World<'_>,
    connected: &Connected,
    provider: &Provider,
) -> Client {
    let mut browser = device(world.stack(), "Pat, back from the provider");
    let visit = ProviderVisit {
        provider,
        browser: &browser,
        claim: Claim::Correct,
    };
    let redirect = returned(world, connected, visit).await;
    let exchange = json!({
        "code": parameter(&redirect, "code"),
        "state": DASHBOARD_STATE,
    });
    let session = browser
        .post::<TenantSession>(&world.tenant().at("/auth/sso/exchange"), &exchange)
        .await
        .ok();
    assert_eq!(
        session.owed(),
        Owed::Nothing,
        "a sign-in through the provider owes nothing more"
    );
    browser.authorize(&session.refresh_token);
    let own = people::me(world.tenant()).send(&browser).await.ok();
    assert_eq!(
        own.id,
        connected.holder.id(),
        "the provider signed Pat in as herself"
    );
    browser
}
