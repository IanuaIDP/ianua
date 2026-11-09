//! Sam, who administers the twin tenant of another organization, tries
//! every read and write of the first tenant's people, roles, API keys and
//! audit trail, through that tenant's paths and through his own naming its
//! ids, and is refused each without changing or recording anything.

use ianua_scenarios::actors::{KeyHolder, KeyRequest, Person, SignedInWith};
use ianua_scenarios::api::{TenantPath, api_keys, audit, people, roles, sessions, tenants};
use ianua_scenarios::expect::{Matrix, no_secret_leaked};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::api_keys::{ApiKeyChange, NewApiKey};
use ianua_scenarios::wire::people::{ChangeUserStatus, InviteUser, UserChange};
use ianua_scenarios::wire::roles::{AssignRole, NewRole, RoleChange, SystemPermission};
use ianua_scenarios::wire::{Exchange, Status};
use ianua_scenarios::world::{MEMBER_ROLE, World};

/// The first tenant's things Sam goes after.
struct Targets {
    pat: Person,
    session_id: String,
    role_id: String,
    key: KeyHolder,
}

/// The records a probe across could leave, none of which may appear.
const NEVER_RECORDED: [&str; 9] = [
    "identity.user_deleted",
    "identity.user_status_changed",
    "identity.user_renamed",
    "authorization.role_created",
    "authorization.role_deleted",
    "authorization.role_renamed",
    "authorization.role_revoked",
    "oauth.api_key_created",
    "oauth.api_key_revoked",
];

/// Sam tries every read and write of the first tenant's people, roles, API
/// keys and audit trail that the API offers, through that tenant's paths
/// and through his own naming its ids. Every one is refused, nothing
/// changes, nothing is recorded, and no secret shows in any answer.
#[tokio::test]
async fn a_stranger_reaches_nothing_of_another_tenant() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let targets = targets(&world).await;
    let trail = world.trail();
    let before = trail.ids().await;

    let mut exchanges = reads_through_its_paths(&world, &targets).await;
    exchanges.extend(writes_through_its_paths(&world, &targets).await);
    exchanges.extend(its_ids_through_his_tenant(&world, &targets).await);

    nothing_changed(&world, &targets).await;
    for event_type in NEVER_RECORDED {
        trail.nothing_after(&before, event_type).await;
    }
    let mut secrets = targets.pat.secrets();
    secrets.extend(world.cast_secrets());
    secrets.push(targets.key.secret().to_owned());
    let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
    for exchange in &exchanges {
        no_secret_leaked(&exchange.to_string(), &secrets);
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// What Sam goes after: Pat, a user signed in to the first tenant with the
/// `Member` role; an `Auditors` role Tess made; and a key Tess made.
async fn targets(world: &World<'_>) -> Targets {
    let tenant = world.tenant();
    let pat = invite_pat(world).await;
    let session_id = pat.session_id().to_owned();
    let auditors = NewRole {
        name: "Auditors".to_owned(),
        system_permissions: vec![SystemPermission::new("AuditLog", "View")],
    };
    let role = roles::create(tenant, &auditors)
        .send(world.admin().client())
        .await
        .ok();
    let key = KeyHolder::issued_by(
        world.stack(),
        world.admin(),
        tenant,
        KeyRequest {
            name: "Directory sync",
            scopes: &["idp:users:view"],
        },
    )
    .await;
    Targets {
        pat,
        session_id,
        role_id: role.id,
        key,
    }
}

/// Pat joins the first tenant and signs in with the password alone.
async fn invite_pat(world: &World<'_>) -> Person {
    let mut pat = world.newcomer("pat", "Pat Person");
    let invitation = InviteUser {
        email: pat.email().to_owned(),
        display_name: "Pat Person".to_owned(),
        role_id: world.role_id(MEMBER_ROLE).await,
    };
    let made = people::invite(world.tenant(), &invitation)
        .send(world.admin().client())
        .await
        .ok();
    pat.record_invitation(&made.id);
    pat.accept_invitation(world.stack()).await;
    assert_eq!(
        pat.sign_in(world.stack()).await,
        SignedInWith::Password,
        "Pat, with no factor, signs in with the password alone"
    );
    pat
}

/// Every read of the first tenant, through its own paths: Tess may make
/// each, Sam is refused each.
async fn reads_through_its_paths(world: &World<'_>, targets: &Targets) -> Vec<Exchange> {
    let tenant = world.tenant();
    let mut reads = user_reads(tenant, targets.pat.id());
    reads.extend(role_reads(tenant, &targets.role_id));
    reads.extend(tenant_reads(world, targets));
    let mut exchanges = Vec::new();
    for (what, call) in reads {
        let matrix = Matrix::new(what, call)
            .allowed(world.admin().client())
            .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden");
        exchanges.extend(matrix.run().await);
    }
    exchanges
}

/// User and session reads target Pat through the first tenant's paths.
fn user_reads(tenant: &TenantPath, pat: &str) -> Vec<(&'static str, Call)> {
    vec![
        ("listing its users", people::list(tenant, None).call()),
        ("reading Pat", people::get(tenant, pat).call()),
        (
            "listing Pat's sessions",
            sessions::user_sessions(tenant, pat).call(),
        ),
    ]
}

/// Role reads include the definition, holders and the tenant's permission list.
fn role_reads(tenant: &TenantPath, role: &str) -> Vec<(&'static str, Call)> {
    vec![
        ("listing its roles", roles::list(tenant).call()),
        ("reading a role", roles::get(tenant, role).call()),
        (
            "listing who holds a role",
            roles::holders(tenant, role).call(),
        ),
        ("reading its permissions", roles::permissions(tenant).call()),
    ]
}

/// Key, audit and tenant settings reads complete the cross-tenant read probes.
fn tenant_reads(world: &World<'_>, targets: &Targets) -> Vec<(&'static str, Call)> {
    let tenant = world.tenant();
    vec![
        ("listing its keys", api_keys::list(tenant).call()),
        (
            "reading a key",
            api_keys::get(tenant, targets.key.key_id()).call(),
        ),
        (
            "reading its audit log",
            audit::tenant_log(tenant, "").call(),
        ),
        (
            "checking its audit chain",
            audit::verify_chain(tenant).call(),
        ),
        ("reading the tenant", tenants::get(tenant).call()),
        (
            "reading its sign-in settings",
            tenants::sign_in_settings(tenant).call(),
        ),
        (
            "reading the organization's audit log",
            audit::organization_log(world.org(), "").call(),
        ),
    ]
}

/// Every write of the first tenant, through its own paths: Sam is refused
/// each.
async fn writes_through_its_paths(world: &World<'_>, targets: &Targets) -> Vec<Exchange> {
    let tenant = world.tenant();
    let mut exchanges = Vec::new();
    for (what, call) in writes(world, tenant, targets) {
        let matrix = Matrix::new(what, call).refused(
            world.stranger().client(),
            Status::FORBIDDEN,
            "forbidden",
        );
        exchanges.extend(matrix.run().await);
    }
    exchanges
}

/// The first tenant's ids, named through Sam's own tenant, where he holds
/// every permission: none is found, read or written.
async fn its_ids_through_his_tenant(world: &World<'_>, targets: &Targets) -> Vec<Exchange> {
    let twin = world.twin();
    let probes = foreign_id_reads(twin, targets);
    let mut exchanges = Vec::new();
    for (what, call) in probes.into_iter().chain(id_writes(twin, targets)) {
        let matrix = Matrix::new(what, call).refused(
            world.stranger().client(),
            Status::NOT_FOUND,
            "not_found",
        );
        exchanges.extend(matrix.run().await);
    }
    exchanges
}

/// The victim's identifiers are read through the stranger's own tenant paths.
fn foreign_id_reads(twin: &TenantPath, targets: &Targets) -> [(&'static str, Call); 5] {
    let pat = targets.pat.id();
    let role = &targets.role_id;
    let key = targets.key.key_id();
    [
        ("reading Pat from the twin", people::get(twin, pat).call()),
        (
            "listing Pat's sessions from the twin",
            sessions::user_sessions(twin, pat).call(),
        ),
        (
            "reading the role from the twin",
            roles::get(twin, role).call(),
        ),
        (
            "listing the role's holders from the twin",
            roles::holders(twin, role).call(),
        ),
        (
            "reading the key from the twin",
            api_keys::get(twin, key).call(),
        ),
    ]
}

/// Every write a stranger might try on the first tenant through `tenant`'s
/// paths, those making something new as well as those naming its ids.
fn writes(world: &World<'_>, tenant: &TenantPath, targets: &Targets) -> Vec<(&'static str, Call)> {
    let invitation = InviteUser {
        email: world.address("mallory"),
        display_name: "Mallory".to_owned(),
        role_id: targets.role_id.clone(),
    };
    let role = NewRole {
        name: "Backdoor".to_owned(),
        system_permissions: vec![SystemPermission::new("Users", "Manage")],
    };
    let key = NewApiKey {
        name: "Backdoor".to_owned(),
        scopes: vec!["idp:users:view".to_owned()],
    };
    let mut writes = vec![
        (
            "inviting into it",
            people::invite(tenant, &invitation).call(),
        ),
        ("making a role in it", roles::create(tenant, &role).call()),
        ("making a key in it", api_keys::create(tenant, &key).call()),
    ];
    writes.extend(id_writes(tenant, targets));
    writes
}

/// Every write naming one of the first tenant's ids, through `tenant`'s
/// paths.
fn id_writes(tenant: &TenantPath, targets: &Targets) -> Vec<(&'static str, Call)> {
    let mut writes = user_writes(tenant, targets);
    writes.extend(role_writes(tenant, targets));
    writes.extend(key_writes(tenant, targets));
    writes
}

/// Mutations target Pat's profile, status, session and account.
fn user_writes(tenant: &TenantPath, targets: &Targets) -> Vec<(&'static str, Call)> {
    let pat = targets.pat.id();
    let renamed = UserChange {
        display_name: Some("Taken over".to_owned()),
    };
    let locked = ChangeUserStatus {
        status: "Locked".to_owned(),
    };
    vec![
        ("renaming Pat", people::change(tenant, pat, &renamed).call()),
        (
            "locking Pat out",
            people::change_status(tenant, pat, &locked).call(),
        ),
        (
            "ending Pat's session",
            sessions::end_user_session(tenant, pat, &targets.session_id).call(),
        ),
        ("removing Pat", people::remove(tenant, pat).call()),
    ]
}

/// Role probes rename, assign, withdraw and remove the victim's role.
fn role_writes(tenant: &TenantPath, targets: &Targets) -> Vec<(&'static str, Call)> {
    let role = &targets.role_id;
    let pat = targets.pat.id();
    let widened = RoleChange {
        name: Some("Everything".to_owned()),
        system_permissions: None,
    };
    let assigned = AssignRole {
        user_id: pat.to_owned(),
    };
    vec![
        (
            "renaming a role",
            roles::change(tenant, role, &widened).call(),
        ),
        (
            "assigning a role",
            roles::assign(tenant, role, &assigned).call(),
        ),
        (
            "taking a role back",
            roles::unassign(tenant, role, pat).call(),
        ),
        ("removing a role", roles::remove(tenant, role).call()),
    ]
}

/// Key probes try to widen its authority and then revoke it.
fn key_writes(tenant: &TenantPath, targets: &Targets) -> Vec<(&'static str, Call)> {
    let key = targets.key.key_id();
    let rescoped = ApiKeyChange {
        name: None,
        scopes: Some(vec!["idp:users:manage".to_owned()]),
    };
    vec![
        (
            "widening a key",
            api_keys::change(tenant, key, &rescoped).call(),
        ),
        ("revoking a key", api_keys::revoke(tenant, key).call()),
    ]
}

/// Pat is still active and signed in, the role still there under its name,
/// and the key still works.
async fn nothing_changed(world: &World<'_>, targets: &Targets) {
    let tenant = world.tenant();
    let admin: &Client = world.admin().client();
    let pat = people::get(tenant, targets.pat.id()).send(admin).await.ok();
    assert_eq!(pat.status, "Active", "Pat was not locked out");
    assert_eq!(pat.display_name, "Pat Person", "Pat was not renamed");
    sessions::my_sessions(tenant)
        .send(targets.pat.client())
        .await
        .ok();
    let role = roles::get(tenant, &targets.role_id).send(admin).await.ok();
    assert_eq!(role.name, "Auditors", "the role was not renamed");
    people::get(tenant, targets.pat.id())
        .send(targets.key.client())
        .await
        .ok();
}
