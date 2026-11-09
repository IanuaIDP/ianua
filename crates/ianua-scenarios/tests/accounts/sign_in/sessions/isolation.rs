//! What stays its member's own: the device Max remembered, which Ann and
//! Tess neither see nor forget and Sam cannot reach; and the tenant a
//! session moves into, which Uma reaches only once granted, while a
//! refused move leaves the session she had.

use ianua_scenarios::actors::Member;
use ianua_scenarios::api::{members, people, sessions, tenants};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Matrix, no_secret_leaked};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::{OrgRole, TenantRoles};
use ianua_scenarios::wire::sign_in::{
    ForgetDevice, Owed, PasswordSignIn, RememberDevice, Session, SignedIn, SwitchTenant,
};
use ianua_scenarios::world::{ADMIN_ROLE, World};

use crate::factors::member::{answered, enrolled, others_keep_access, waiting};
use crate::support::settled_sign_in;

/// Max proves his authenticator and remembers his laptop. Ann and Tess
/// see no such device in their own lists and cannot forget it, Sam from
/// the other company and nobody signed in are refused, and no forgetting
/// is recorded. Max still lists it as trusted, and his password alone
/// signs him in from it. He forgets it himself: one forgetting is
/// recorded in his name, with no secret in it, and his next sign-in from
/// the laptop is asked for the code again, which he gives. The clock is
/// controlled so the authenticator shows fresh codes.
#[tokio::test]
async fn a_remembered_device_can_only_be_listed_and_revoked_by_its_member() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut factor = enrolled(&world).await;
    let mut browser = Client::new(&stack, "Max, remembering his laptop").expect("a client");
    waiting(&world, &mut browser, world.member().password()).await;
    answered(&world, &browser, &mut factor.phone).await;
    let secret = "ef".repeat(32);
    let device_id = remember_private_laptop(&world, &browser, &secret).await;
    let forget = assert_private_device(&world, &device_id).await;
    assert_own_trusted_device(&world, &browser, &device_id).await;
    others_keep_access(&world).await;
    let from_laptop =
        PasswordSignIn::of(world.member().email(), world.member().password()).from_device(&secret);
    let trusted = sign_in_trusted_laptop(&mut browser, &from_laptop).await;

    sessions::forget_device(world.org(), &forget)
        .send(&browser)
        .await
        .ok();
    members::me(world.org()).send(&browser).await.ok();
    let secrets: [&str; 3] = [&secret, &trusted.refresh_token, factor.phone.secret()];
    assert_revocation_record(&world, &secrets).await;
    sign_in_forgotten_laptop(&world, &mut browser, &from_laptop).await;
    answered(&world, &browser, &mut factor.phone).await;
    others_keep_access(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max records a private device secret after proving his authenticator.
async fn remember_private_laptop(world: &World<'_>, browser: &Client, secret: &str) -> String {
    let device = sessions::remember_device(
        world.org(),
        &RememberDevice {
            fingerprint_hash: secret.to_owned(),
            device_name: "Max's private laptop".to_owned(),
        },
    )
    .send(browser)
    .await
    .ok();
    device.device_id
}

/// Other members cannot see or forget Max's device, and the attempts record no revocation.
async fn assert_private_device(world: &World<'_>, device_id: &str) -> ForgetDevice {
    not_listed_for(world, world.owner().client(), device_id, "Ann").await;
    not_listed_for(world, world.admin().client(), device_id, "Tess").await;
    let forget = ForgetDevice {
        device_id: device_id.to_owned(),
    };
    Matrix::new(
        "forgetting another member's remembered device",
        sessions::forget_device(world.org(), &forget).call(),
    )
    .refused(world.owner().client(), Status::NOT_FOUND, "not_found")
    .refused(world.admin().client(), Status::NOT_FOUND, "not_found")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
    let trail = world.trail();
    assert_eq!(
        trail.count("organization.org_device_revoked").await,
        0,
        "a refused forgetting records nothing"
    );
    forget
}

/// Max still lists exactly his trusted laptop and retains his account access after others' refusals.
async fn assert_own_trusted_device(world: &World<'_>, browser: &Client, device_id: &str) {
    let listed = sessions::member_devices(world.org())
        .send(browser)
        .await
        .ok();
    let [own] = listed.devices.as_slice() else {
        panic!(
            "Max remembered one device, {} are listed",
            listed.devices.len()
        );
    };
    assert_eq!(own.id, device_id, "the device listed is the laptop");
    assert_eq!(own.status, "trusted", "the laptop is still trusted");
    members::me(world.org()).send(browser).await.ok();
}

/// The trusted laptop opens Max's session without another factor challenge.
async fn sign_in_trusted_laptop(browser: &mut Client, from_laptop: &PasswordSignIn) -> Session {
    let answer = sessions::member_sign_in(from_laptop)
        .send(browser)
        .await
        .ok();
    let SignedIn::Authenticated(trusted) = answer else {
        panic!("Max is in one organization, so no choice is offered");
    };
    assert_eq!(
        trusted.owed(),
        Owed::Nothing,
        "the remembered laptop is asked for nothing more"
    );
    browser.authorize(&trusted.refresh_token);
    trusted
}

/// Max's single device revocation names him and contains none of the authentication secrets.
async fn assert_revocation_record(world: &World<'_>, secrets: &[&str]) {
    let trail = world.trail();
    let revoked = trail.entries("organization.org_device_revoked").await;
    let [record] = revoked.as_slice() else {
        panic!("one forgetting is recorded, not {} times", revoked.len());
    };
    assert!(
        record.actor.contains(world.member().email()),
        "the forgetting is recorded in Max's name"
    );
    no_secret_leaked(&format!("{record:?}"), secrets);
}

/// The revoked laptop again owes a factor and cannot read Max's account yet.
async fn sign_in_forgotten_laptop(
    world: &World<'_>,
    browser: &mut Client,
    from_laptop: &PasswordSignIn,
) {
    let answer = sessions::member_sign_in(from_laptop)
        .send(browser)
        .await
        .ok();
    let SignedIn::Authenticated(untrusted) = answer else {
        panic!("Max is in one organization, so no choice is offered");
    };
    assert_eq!(
        untrusted.owed(),
        Owed::FactorCode,
        "the forgotten laptop is asked for the code again"
    );
    browser.authorize(&untrusted.refresh_token);
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Uma, a new colleague granted no tenant, signs in to Acme alone. She
/// cannot move her session into Globex's tenant, though she knows its
/// id: the session she has still reads her record, Globex's people stay
/// closed to her, and no move is recorded. Ann grants her Acme's tenant:
/// her session moves in, the one before it is dead at once, and the new
/// one reads Acme's people. Globex's tenant is still refused from there,
/// the move is recorded once in Uma's name with no token in it, and her
/// colleagues keep their access.
#[tokio::test]
async fn a_cross_organization_switch_preserves_the_session_until_a_valid_move() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = world.colleague("uma", "Uma Member", OrgRole::Member).await;
    let mut browser = Client::new(&stack, "Uma, choosing a tenant").expect("a client");
    let session = sign_in_without_tenant(&stack, &mut browser, &uma).await;

    let into_globex = foreign_tenant(&world).await;
    assert_refused_move(&world, &uma, &browser, &into_globex).await;
    let moved_token = grant_and_move(&world, &uma, &mut browser).await;
    assert_foreign_tenant_closed(&world, &browser, &into_globex).await;
    assert_move_record(
        &world,
        &uma,
        &[&session.refresh_token, &moved_token, uma.password()],
    )
    .await;
    others_keep_access(&world).await;
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma signs in with an organization-only session before receiving any tenant grant.
async fn sign_in_without_tenant(stack: &Stack, browser: &mut Client, uma: &Member) -> Session {
    let session = settled_sign_in(
        stack,
        browser,
        &PasswordSignIn::of(uma.email(), uma.password()),
    )
    .await;
    assert!(
        session.tenant_slug.is_none(),
        "Uma reaches no tenant yet, so her session works on the organization alone"
    );
    browser.authorize(&session.refresh_token);
    session
}

/// Sam reveals his tenant id so the scenario attempts a known cross-organization target.
async fn foreign_tenant(world: &World<'_>) -> SwitchTenant {
    let globex_tenant = tenants::get(world.twin())
        .send(world.stranger().client())
        .await
        .ok();
    SwitchTenant {
        tenant_id: globex_tenant.id,
    }
}

/// A forbidden tenant move preserves Uma's organization session and everybody else's access.
async fn assert_refused_move(
    world: &World<'_>,
    uma: &Member,
    browser: &Client,
    into_globex: &SwitchTenant,
) {
    sessions::switch_tenant(world.org(), into_globex)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    assert_eq!(
        members::me(world.org()).send(browser).await.ok().email,
        uma.email(),
        "the refused move leaves Uma the session she had"
    );
    people::list(world.twin(), None)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let trail = world.trail();
    assert_eq!(
        trail.count("organization.org_session_moved").await,
        0,
        "a refused move records nothing"
    );
    others_keep_access(world).await;
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
}

/// Ann's grant permits the move, which immediately replaces Uma's old session credential.
async fn grant_and_move(world: &World<'_>, uma: &Member, browser: &mut Client) -> String {
    grant_acme_tenant(world, uma).await;
    let acme_tenant = tenants::get(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    let moved = sessions::switch_tenant(
        world.org(),
        &SwitchTenant {
            tenant_id: acme_tenant.id.clone(),
        },
    )
    .send(browser)
    .await
    .ok();
    assert_eq!(
        moved.tenant_id, acme_tenant.id,
        "the session moved into Acme's tenant"
    );
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    browser.authorize(&moved.refresh_token);
    people::list(world.tenant(), None).send(browser).await.ok();
    moved.refresh_token
}

/// Ann grants Uma the tenant's Admin role before the same session attempts its move.
async fn grant_acme_tenant(world: &World<'_>, uma: &Member) {
    members::set_tenant_roles(
        world.org(),
        uma.id(),
        world.tenant().slug(),
        &TenantRoles {
            roles: vec![ADMIN_ROLE.to_owned()],
        },
    )
    .send(world.owner().client())
    .await
    .ok();
}

/// Even from Acme's tenant, the foreign move and foreign user listing remain forbidden.
async fn assert_foreign_tenant_closed(
    world: &World<'_>,
    browser: &Client,
    into_globex: &SwitchTenant,
) {
    sessions::switch_tenant(world.org(), into_globex)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    people::list(world.tenant(), None).send(browser).await.ok();
    people::list(world.twin(), None)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// The sole successful move names Uma and exposes neither credential nor her password.
async fn assert_move_record(world: &World<'_>, uma: &Member, secrets: &[&str]) {
    let trail = world.trail();
    let moves = trail.entries("organization.org_session_moved").await;
    let [record] = moves.as_slice() else {
        panic!("one move is recorded, not {} times", moves.len());
    };
    assert!(
        record.actor.contains(uma.email()),
        "the move is recorded in Uma's name"
    );
    no_secret_leaked(&format!("{record:?}"), secrets);
}

/// Fails when `reader`, named `who`, lists `device_id` among their own
/// remembered devices: another member's device is not theirs to see.
async fn not_listed_for(world: &World<'_>, reader: &Client, device_id: &str, who: &str) {
    let listed = sessions::member_devices(world.org())
        .send(reader)
        .await
        .ok();
    assert!(
        listed.devices.iter().all(|entry| entry.id != device_id),
        "{who} does not see Max's device among their own"
    );
}
