//! Ann signing in to Acme through Acme's own identity provider. Each
//! provider here is independent of the platform and signs with its own
//! key; Ann registers it through the API as a customer would, trusts the
//! addresses it vouches for, switches it on and allows its sign-in
//! method. A sign-in begins at the platform, which hands the browser a
//! secret binding it, and finishes when the browser hands back the
//! provider's answer with that binding.
//!
//! - `oidc`: an OIDC provider over real HTTPS signs Ann in once; tokens
//!   wrong in any signed claim, signed with another key or unsigned, an
//!   unproved address, an unknown state, a failed exchange, a provider
//!   switched off mid-sign-in and an address Acme never let in are each
//!   refused, and a fresh answer still signs Ann in.
//! - `saml`: a SAML provider's signed assertion signs Ann in once;
//!   assertions for another audience, from another issuer, for another
//!   recipient or request, out of date, signed with another key or not at
//!   all, and an answer handed back in another tab are each refused.

mod oidc;
mod saml;

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{OrgPath, Request, members, organizations, sessions};
use ianua_scenarios::expect::Trail;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::federation::{Begin, Begun, Callback, ProviderAnswer};
use ianua_scenarios::wire::organization::{
    AddIdentityProvider, ChangeIdentityProvider, IdentityProviderConfig, ReplaceOrgSignInSettings,
    SwitchIdentityProvider,
};
use ianua_scenarios::wire::sign_in::{MemberProof, Owed, Session, SignedIn};
use serde_json::json;

/// The account whose organization has registered the test provider.
struct Company {
    ann: Founder,
    org: OrgPath,
}

/// Creates Ann's organization and registers an active provider through the
/// same API she administers. Her password authorizes trusting its email
/// claims; her existing session is retained to check access after refusals.
async fn configured(stack: &Stack, config: IdentityProviderConfig) -> Company {
    let mut ann = Founder::named(stack, "Ann");
    let founded = ann.founded(stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let session = ann.signed_in(stack).await;
    ann.client_mut().authorize(&session.refresh_token);
    let method = config.method();
    let add = AddIdentityProvider {
        name: "Acme's identity provider".to_owned(),
        config,
    };
    organizations::add_identity_provider(&org, &add)
        .send(ann.client())
        .await
        .ok();
    activate_trusted_provider(&ann, &org).await;
    allow_provider(&ann, &org, method).await;
    Company { ann, org }
}

/// Ann trusts the registered provider's email claims and enables it with fresh proof.
async fn activate_trusted_provider(ann: &Founder, org: &OrgPath) {
    let trusted = ChangeIdentityProvider {
        email_trust: Some("Authoritative".to_owned()),
        proof: founder_proof(),
    };
    organizations::change_identity_provider(org, &trusted)
        .send(ann.client())
        .await
        .ok();
    let active = SwitchIdentityProvider {
        status: "Active".to_owned(),
        proof: founder_proof(),
    };
    organizations::switch_identity_provider(org, &active)
        .send(ann.client())
        .await
        .ok();
}

/// Ann's password typed again, as every change to her organization asks.
fn founder_proof() -> MemberProof {
    MemberProof {
        password: FOUNDER_PASSWORD.to_owned(),
        code: None,
    }
}

/// Allows the provider's method and turns off challenges for a new device
/// or country. This lets the scenario judge the provider's proof without
/// a separate mailbox step, using Ann's password to authorize the change.
async fn allow_provider(ann: &Founder, org: &OrgPath, method: &str) {
    let mut settings = organizations::sign_in_settings(org)
        .send(ann.client())
        .await
        .ok();
    settings.enabled_methods.push(method.to_owned());
    let policy = settings
        .rest
        .get_mut("step_up")
        .expect("the sign-in policy");
    policy["require_mfa_new_device"] = json!(false);
    policy["require_mfa_new_country"] = json!(false);
    organizations::replace_sign_in_settings(
        org,
        &ReplaceOrgSignInSettings {
            settings,
            proof: founder_proof(),
        },
    )
    .send(ann.client())
    .await
    .ok();
}

/// Starts SSO for the named organization through the public login endpoint.
/// Returns both the provider redirect and the browser binding, which the
/// callback must carry together to finish this flow.
async fn begin(browser: &Client, org: &OrgPath) -> Begun {
    let begin = Begin {
        organization: org.slug().to_owned(),
    };
    sessions::start_sso(&begin).send(browser).await.ok()
}

/// Builds the callback request the dashboard submits, including the browser
/// binding. The caller sends it through the browser whose access is checked.
fn finish(callback: &Callback) -> Request<SignedIn> {
    sessions::finish_sso(callback)
}

/// The session the provider's answer opens on the returning `browser`,
/// which then carries it: it owes nothing more, lands in Acme, and reads
/// Ann's own record, nobody else's.
///
/// # Panics
///
/// When the answer is refused, offers a choice, owes more, or reads
/// someone other than Ann.
async fn accepted(browser: &mut Client, company: &Company, callback: &Callback) -> Session {
    let SignedIn::Authenticated(session) = finish(callback).send(browser).await.ok() else {
        panic!("a provider's answer names one organization, so no choice is offered");
    };
    assert_eq!(
        session.owed(),
        Owed::Nothing,
        "the provider's proof is all the sign-in owes"
    );
    assert_eq!(
        session.org_slug,
        company.org.slug(),
        "the sign-in lands in Acme"
    );
    browser.authorize(&session.refresh_token);
    let own = members::me(&company.org).send(browser).await.ok();
    assert_eq!(
        own.email,
        company.ann.email(),
        "the new session reads Ann's own record"
    );
    session
}

/// How many sign-ins Acme's trail records, read by `reader`, a member who
/// may read it.
async fn successful_sign_ins(reader: &Client, company: &Company) -> usize {
    Trail::of_organization(reader, company.org.slug())
        .count("organization.org_login_succeeded")
        .await
}

/// The answer is refused as forbidden, the browser stays signed out, and
/// Ann's own session still works. A token that fails its signed checks is
/// refused differently; the OIDC scenarios check that refusal themselves.
async fn refused(browser: &Client, company: &Company, callback: &Callback) {
    finish(callback)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    unchanged_access(browser, company).await;
}

/// The returning browser is still signed out, and Ann's own session still
/// works.
async fn unchanged_access(browser: &Client, company: &Company) {
    members::me(&company.org)
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    members::me(&company.org)
        .send(company.ann.client())
        .await
        .ok();
}
