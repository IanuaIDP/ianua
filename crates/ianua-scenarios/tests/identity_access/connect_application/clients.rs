//! The OAuth clients the scenarios register and the steps they share: the
//! tenant as an app learns it from its discovery document and published
//! keys, Tess registering a client, Pat's consent and the code grant with
//! PKCE, and the client proofs a confidential client sends.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{oauth, people};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::oauth::{
    ClientProof, ClientSettings, Consent, Discovery, Keys, NewConfiguredClient, ProvenGrant,
    ProvenQuestion, ProvenTokenRequest, RegisteredClient, TokenFacts, TokenRequest, Tokens,
};
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::world::{MEMBER_ROLE, World};
use sha2::{Digest as _, Sha256};

/// The PKCE verifier an app keeps to itself: longer than the forty-three
/// characters the standard asks for at least.
pub(crate) const VERIFIER: &str =
    "an_app_owned_random_verifier_with_more_than_forty_three_characters_5182";

/// The state an app sends with its request and expects back.
pub(crate) const STATE: &str = "app-owned-state";

/// The nonce an app binds into Pat's ID token.
pub(crate) const NONCE: &str = "app-owned-nonce-of-ledger";

/// The scopes a sign-in app asks for.
pub(crate) const SIGN_IN_SCOPES: &str = "openid email profile offline_access";

/// The tenant as an app learns it before trusting anything it says: its
/// discovery document, and the keys that document points to.
pub(crate) struct Provider {
    /// The discovery document.
    pub(crate) discovery: Discovery,
    /// The signing keys published at its `jwks_uri`.
    pub(crate) keys: Keys,
}

/// The tenant `world` names, read by nobody signed in, as any app reads
/// it.
pub(crate) async fn provider(world: &World<'_>) -> Provider {
    let discovery = oauth::discovery(world.tenant())
        .send(world.anonymous().client())
        .await
        .ok();
    let keys = oauth::keys(&discovery.jwks_uri)
        .send(world.anonymous().client())
        .await
        .ok();
    Provider { discovery, keys }
}

/// Someone at the address `name`, called `display_name`, invited into the
/// tenant by Tess with its `Member` role, who accepted and signed in.
pub(crate) async fn person(world: &World<'_>, name: &str, display_name: &str) -> Person {
    let mut person = world.newcomer(name, display_name);
    let invitation = InviteUser {
        email: person.email().to_owned(),
        display_name: person.account().display_name.clone(),
        role_id: world.role_id(MEMBER_ROLE).await,
    };
    let made = people::invite(world.tenant(), &invitation)
        .send(world.admin().client())
        .await
        .ok();
    person.record_invitation(&made.id);
    person.accept_invitation(world.stack()).await;
    person.sign_in(world.stack()).await;
    person
}

/// The callback of the app at `host` under the stack's customer domain.
pub(crate) fn callback(stack: &Stack, host: &str) -> String {
    format!("https://{host}.{}/callback", stack.customer_domain())
}

/// `client`, registered by Tess.
pub(crate) async fn registered(
    world: &World<'_>,
    client: &NewConfiguredClient,
) -> RegisteredClient {
    oauth::register_configured(world.tenant(), client)
        .send(world.admin().client())
        .await
        .ok()
}

/// A public app called `name`, holding no secret, taking codes at
/// `callback` and refreshing them, for the sign-in scopes, set up with
/// `settings`.
pub(crate) fn public_app(
    name: &str,
    callback: &str,
    settings: ClientSettings,
) -> NewConfiguredClient {
    NewConfiguredClient {
        name: name.to_owned(),
        redirect_uris: vec![callback.to_owned()],
        grant_types: vec!["AuthorizationCode".to_owned(), "RefreshToken".to_owned()],
        scopes: words(SIGN_IN_SCOPES),
        token_endpoint_auth_method: "none".to_owned(),
        jwks: None,
        settings,
    }
}

/// A service called `name`, proving itself with the secret it is shown,
/// allowed `grants` for `scopes`.
pub(crate) fn service(name: &str, grants: &[&str], scopes: &[&str]) -> NewConfiguredClient {
    NewConfiguredClient {
        name: name.to_owned(),
        redirect_uris: Vec::new(),
        grant_types: grants.iter().map(|grant| (*grant).to_owned()).collect(),
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        token_endpoint_auth_method: "client_secret_post".to_owned(),
        jwks: None,
        settings: ClientSettings::default(),
    }
}

/// The proof `client` sends with the secret it was shown.
pub(crate) fn secret_of(client: &RegisteredClient) -> ClientProof {
    ClientProof::Secret {
        client_id: client.client_id.clone(),
        client_secret: client
            .client_secret
            .clone()
            .expect("a confidential client is shown its secret"),
    }
}

/// The client-credentials request of the client proving itself by
/// `proof`, for `scope` or every scope it was given.
pub(crate) fn own_tokens(proof: &ClientProof, scope: Option<&str>) -> ProvenTokenRequest {
    ProvenTokenRequest {
        proof: proof.clone(),
        grant: ProvenGrant::ClientCredentials {
            scope: scope.map(str::to_owned),
        },
    }
}

/// The tokens the client proving itself by `proof` gets for itself.
pub(crate) async fn service_tokens(world: &World<'_>, proof: &ClientProof) -> Tokens {
    oauth::proven_token(world.tenant(), &own_tokens(proof, None))
        .send(world.anonymous().client())
        .await
        .ok()
}

/// What the platform tells the client proving itself by `asking` about
/// `token`.
pub(crate) async fn facts_about(
    world: &World<'_>,
    asking: &ClientProof,
    token: &str,
) -> TokenFacts {
    let question = ProvenQuestion {
        proof: asking.clone(),
        token: token.to_owned(),
    };
    oauth::proven_introspect(world.tenant(), &question)
        .send(world.anonymous().client())
        .await
        .ok()
}

/// Pat's consent to `client_id`'s request for a code for `scope` sent to
/// `callback`, bound to the S256 challenge of [`VERIFIER`].
pub(crate) fn consent(client_id: &str, callback: &str, scope: &str) -> Consent {
    Consent {
        client_id: client_id.to_owned(),
        redirect_uri: callback.to_owned(),
        response_type: "code".to_owned(),
        scope: scope.to_owned(),
        state: STATE.to_owned(),
        nonce: NONCE.to_owned(),
        code_challenge: challenge(VERIFIER),
        code_challenge_method: "S256".to_owned(),
        consent: "given".to_owned(),
    }
}

/// The S256 challenge of `verifier`.
pub(crate) fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The code issued once `pat` consents to `client_id`'s request for the
/// sign-in scopes sent to `callback`.
pub(crate) async fn code_for(
    world: &World<'_>,
    pat: &Person,
    client_id: &str,
    callback: &str,
) -> String {
    let authorized = oauth::authorize(
        world.tenant(),
        &consent(client_id, callback, SIGN_IN_SCOPES),
    )
    .send(pat.client())
    .await
    .ok();
    assert_eq!(authorized.outcome, "issued", "consent given issues a code");
    authorized.code.expect("an issued outcome carries the code")
}

/// The code grant redeeming `code` for `client_id` at `callback` with
/// [`VERIFIER`].
pub(crate) fn code_grant(client_id: &str, code: &str, callback: &str) -> TokenRequest {
    TokenRequest::AuthorizationCode {
        client_id: client_id.to_owned(),
        code: code.to_owned(),
        redirect_uri: callback.to_owned(),
        code_verifier: VERIFIER.to_owned(),
    }
}

/// The refresh grant trading `refresh_token` for `client_id`.
pub(crate) fn refresh_grant(client_id: &str, refresh_token: &str) -> TokenRequest {
    TokenRequest::RefreshToken {
        client_id: client_id.to_owned(),
        refresh_token: refresh_token.to_owned(),
    }
}

/// The words of `spaced`, each owned.
pub(crate) fn words(spaced: &str) -> Vec<String> {
    spaced.split(' ').map(str::to_owned).collect()
}

/// The seconds since the epoch on the wall clock, as an app outside the
/// platform stamps what it signs.
pub(crate) fn wall_seconds() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
