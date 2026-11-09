//! What the signal stream scenarios share: a receiver of Acme's holding
//! its key, the published configuration and keys it checks tokens with,
//! its endpoint proved, and people Tess hands roles to.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{TenantPath, oauth, people, roles, signals};
use ianua_scenarios::expect::{eventually, verified_rs256};
use ianua_scenarios::net::Client;
use ianua_scenarios::wire::oauth::Keys;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::roles::{AssignRole, NewRole, SystemPermission};
use ianua_scenarios::wire::signals::{
    ConfirmEndpoint, NewStream, PollAsk, StreamRegistered, TransmitterConfiguration,
};
use ianua_scenarios::world::{MEMBER_ROLE, World};
use serde_json::Value;

/// The receiver's endpoint: public-looking and answered by nothing, so a
/// poll stream's token names it as its audience and no push goes
/// anywhere.
pub(crate) const ENDPOINT: &str = "https://signals.acme.invalid/events";

/// The URN a verification event is keyed by.
pub(crate) const VERIFICATION: &str =
    "https://schemas.openid.net/secevent/ssf/event-type/verification";

/// The URN a token-claims change, as a role given or taken, is keyed by.
pub(crate) const TOKEN_CLAIMS_CHANGE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/token-claims-change";

/// The type a security event token carries.
const SET_TYPE: &str = "secevent+jwt";

/// A receiver of Acme's: its stream and the client holding its key.
pub(crate) struct Receiver {
    /// Its stream.
    pub(crate) id: String,
    /// Its key, as a bearer.
    pub(crate) key: String,
    /// The client making its calls.
    pub(crate) client: Client,
}

/// A client calling as the receiver holding `key`.
pub(crate) fn holding_key(world: &World<'_>, actor: &str, key: &str) -> Client {
    let mut client = Client::new(world.stack(), actor).expect("a client");
    client.authorize(key);
    client
}

/// The stream Tess registers for permission changes, delivered by
/// `method`, hearing about `subjects` to start with.
pub(crate) fn stream(method: &str, subjects: &str) -> NewStream {
    NewStream {
        endpoint: ENDPOINT.to_owned(),
        delivery_method: method.to_owned(),
        signal_types: vec!["PermissionsChanged".to_owned()],
        authorization_header: None,
        default_subjects: subjects.to_owned(),
    }
}

/// Tess registers `new`, and `actor` becomes its receiver.
pub(crate) async fn register(world: &World<'_>, new: &NewStream, actor: &str) -> Receiver {
    let registered: StreamRegistered = signals::register(world.tenant(), new)
        .send(world.admin().client())
        .await
        .ok();
    Receiver {
        client: holding_key(world, actor, &registered.receiver_key),
        id: registered.id,
        key: registered.receiver_key,
    }
}

/// The transmitter's published configuration and signing keys, as a
/// receiver fetches them.
pub(crate) async fn published(world: &World<'_>) -> (TransmitterConfiguration, Keys) {
    let client = world.anonymous().client();
    let configuration = signals::configuration(world.tenant())
        .send(client)
        .await
        .ok();
    let keys = oauth::keys(&configuration.jwks_uri).send(client).await.ok();
    (configuration, keys)
}

/// `token`'s claims, once the tenant's published `keys` verify it as a
/// security event token.
pub(crate) fn checked(keys: &Keys, token: &str) -> Value {
    verified_rs256(keys, token, SET_TYPE).expect("a published key verifies the token")
}

/// `token` with its claims changed by one character, as Mallory would
/// send it on.
pub(crate) fn tampered(token: &str) -> String {
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    let body = &mut parts[1];
    let last = body.pop().expect("a token has claims");
    body.push(if last == 'A' { 'B' } else { 'A' });
    parts.join(".")
}

/// Where events are read from: a receiver of a tenant, and the keys its
/// tokens are checked with.
pub(crate) struct EventSource<'a> {
    /// The tenant the stream belongs to.
    pub(crate) tenant: &'a TenantPath,
    /// The receiver that polls.
    pub(crate) receiver: &'a Receiver,
    /// The published keys each token must verify against.
    pub(crate) keys: &'a Keys,
}

/// Polls `source` once, verifying each token, and answers the `jti` and
/// claims of the first token about `urn` for which `matches` holds, without
/// acknowledging it.
async fn taken(
    source: &EventSource<'_>,
    urn: &str,
    matches: impl Fn(&Value) -> bool,
) -> Option<(String, Value, String)> {
    let polled = signals::poll(source.tenant, &source.receiver.id, &PollAsk::default())
        .send(&source.receiver.client)
        .await
        .ok();
    polled.sets.iter().find_map(|(jti, token)| {
        let claims = checked(source.keys, token);
        let event = claims["events"].get(urn)?;
        matches(event).then(|| (jti.clone(), claims.clone(), token.clone()))
    })
}

/// The jti, claims and token of the next event about `urn` from `source`
/// matching `matches`, once it has arrived.
///
/// # Panics
///
/// When none comes within the patience of `eventually`.
pub(crate) async fn awaited(
    source: &EventSource<'_>,
    urn: &str,
    matches: impl Fn(&Value) -> bool,
) -> (String, Value, String) {
    let matches = &matches;
    let what = format!("an event {urn} for the receiver");
    eventually(&what, || async move { taken(source, urn, matches).await }).await
}

/// `receiver` answers the verification event waiting for it with the
/// challenge it carries, and acknowledges the event, so its stream's
/// endpoint is proved.
pub(crate) async fn prove_endpoint(world: &World<'_>, receiver: &Receiver, keys: &Keys) {
    let tenant = world.tenant();
    let source = EventSource {
        tenant,
        receiver,
        keys,
    };
    let (jti, claims, _) = awaited(&source, VERIFICATION, |_| true).await;
    let challenge = claims["events"][VERIFICATION]["state"]
        .as_str()
        .expect("the verification event carries a challenge")
        .to_owned();
    signals::confirm(tenant, &receiver.id, &ConfirmEndpoint { challenge })
        .send(world.anonymous().client())
        .await
        .ok();
    let acknowledged = PollAsk {
        ack: vec![jti],
        max_events: None,
    };
    signals::poll(tenant, &receiver.id, &acknowledged)
        .send(&receiver.client)
        .await
        .ok();
}

/// Someone Tess invited with the tenant's `Member` role, who accepted and
/// signed in.
///
/// # Panics
///
/// When the invitation or the acceptance is refused.
pub(crate) async fn person(world: &World<'_>, name: &str) -> Person {
    let mut person = world.newcomer(name, &format!("{name} Signalled"));
    let invitation = people::invite(
        world.tenant(),
        &InviteUser {
            email: person.email().to_owned(),
            display_name: person.account().display_name.clone(),
            role_id: world.role_id(MEMBER_ROLE).await,
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    person.record_invitation(&invitation.id);
    person.accept_invitation(world.stack()).await;
    person.sign_in(world.stack()).await;
    person
}

/// The id of a role Tess makes named `name`, letting its holder read the
/// tenant's users, for her to hand out.
pub(crate) async fn reading_role(world: &World<'_>, name: &str) -> String {
    roles::create(
        world.tenant(),
        &NewRole {
            name: name.to_owned(),
            system_permissions: vec![SystemPermission::new("Users", "View")],
        },
    )
    .send(world.admin().client())
    .await
    .ok()
    .id
}

/// Tess gives `person` the role `role_id`.
pub(crate) async fn give_role(world: &World<'_>, person: &Person, role_id: &str) {
    let assignment = AssignRole {
        user_id: person.id().to_owned(),
    };
    roles::assign(world.tenant(), role_id, &assignment)
        .send(world.admin().client())
        .await
        .ok();
}
