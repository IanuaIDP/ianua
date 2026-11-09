//! A member's sessions as the company runs them: Ann sees who is signed
//! in and ends Uma's session when nobody else may; a member Ann locks or
//! deactivates is signed out at once and answers like a wrong guess; Uma,
//! granted no tenant, signs in to the organization alone and moves into
//! a tenant once granted one, naming it at sign-in only once granted; and
//! a lock midway through her sign-in spoils the link mailed for it.

use ianua_scenarios::actors::Member;
use ianua_scenarios::api::{members, organizations, people, sessions, tenants};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::{
    ChangeMemberStatus, OrgRole, ReplaceOrgSignInSettings, TenantRoles,
};
use ianua_scenarios::wire::sign_in::{
    ConfirmSignIn, MemberProof, Owed, PasswordSignIn, SignOut, SignedIn, SwitchTenant,
};
use ianua_scenarios::world::{ADMIN_ROLE, World};
use serde_json::json;

use crate::support::{WRONG_GUESS, mail_linking_to, settled_sign_in};

/// Uma, a new colleague, signs in. Ann sees her among the live sessions,
/// and so may Max, a member of the company; Sam from another company and
/// nobody signed in may not look. Max signing out with Uma's session id
/// is told there is no such session,
/// and Uma stays in. Ending her session is refused to Max, to Sam and to
/// nobody; Ann ends it, Uma is out at once, and the session cannot be
/// ended twice.
#[tokio::test]
async fn only_someone_with_the_right_ends_another_members_session() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut uma = world.colleague("uma", "Uma Member", OrgRole::Member).await;
    uma.sign_in(&stack).await;
    let uma_session = uma.session_id().to_owned();

    assert_session_readers(&world, &uma_session).await;
    assert_foreign_sign_out(&world, &uma, &uma_session).await;
    end_umas_session(&world, &uma, &uma_session).await;

    world
        .trail()
        .recorded("organization.org_session_revoked")
        .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann sees Uma's session, and the actor matrix limits the session listing to
/// members of the same company.
async fn assert_session_readers(world: &World<'_>, uma_session: &str) {
    let active = sessions::member_sessions(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert!(
        active
            .items
            .iter()
            .any(|session| session.session_id == uma_session),
        "Ann sees Uma among the live sessions"
    );
    Matrix::new(
        "reading who is signed in",
        sessions::member_sessions(world.org()).call(),
    )
    .allowed(world.owner().client())
    .allowed(world.member().client())
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
}

/// Max cannot sign out Uma by presenting her session id, and Uma retains access.
async fn assert_foreign_sign_out(world: &World<'_>, uma: &Member, uma_session: &str) {
    let sign_out = SignOut {
        session_id: uma_session.to_owned(),
    };
    sessions::member_sign_out(world.org(), &sign_out)
        .send(world.member().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    members::me(world.org()).send(uma.client()).await.ok();
}

/// Only Ann ends Uma's session; the ended session loses access and cannot be
/// ended a second time.
async fn end_umas_session(world: &World<'_>, uma: &Member, uma_session: &str) {
    Matrix::new(
        "ending Uma's session",
        sessions::end_member_session(world.org(), uma_session).call(),
    )
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .allowed(world.owner().client())
    .run()
    .await;
    members::me(world.org())
        .send(uma.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    sessions::end_member_session(world.org(), uma_session)
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
}

/// Ann locks Uma: the session Uma held reads nothing at once, and her
/// own password is answered exactly as Mallory's wrong guess at her is,
/// so a lock tells nobody anything. Ann lets her back in, and she signs
/// in again.
#[tokio::test]
async fn a_locked_member_is_signed_out_at_once_and_answers_like_a_wrong_guess() {
    an_inactive_member_is_refused("Locked").await;
}

/// Ann deactivates Uma: the session Uma held reads nothing at once, and
/// her own password is answered exactly as Mallory's wrong guess at her
/// is. Ann reactivates her: the old session stays dead, and she signs in
/// again.
#[tokio::test]
async fn a_deactivated_member_is_signed_out_and_can_return_only_after_reactivation() {
    an_inactive_member_is_refused("Deactivated").await;
}

/// Uma joined as a member and nobody granted her a tenant: she signs in
/// to the organization alone, and moving into Ann's tenant is refused.
/// Ann grants her the tenant's `Admin` role: Uma moves her session in
/// without signing in again, the old session is dead the moment the new
/// one exists, and the new one reads the tenant's people.
#[tokio::test]
async fn a_member_without_a_tenant_signs_in_alone_and_moves_in_once_granted() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = world.colleague("uma", "Uma Member", OrgRole::Member).await;
    let mut browser = Client::new(&stack, "Uma, at the dashboard").expect("a client");
    let sign_in = PasswordSignIn {
        organization: Some(world.org().slug().to_owned()),
        ..PasswordSignIn::of(uma.email(), uma.password())
    };
    let alone = settled_sign_in(&stack, &browser, &sign_in).await;
    assert!(
        alone.tenant_slug.is_none(),
        "Uma reaches no tenant yet, so her session works on the organization alone"
    );
    browser.authorize(&alone.refresh_token);

    move_after_grant(&world, &uma, &mut browser).await;

    world
        .trail()
        .recorded("organization.org_session_moved")
        .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma cannot enter Ann's tenant until granted its Admin role, after which the
/// move replaces her old session and the new session reads the tenant's people.
async fn move_after_grant(world: &World<'_>, uma: &Member, browser: &mut Client) {
    let tenant = tenants::get(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    let switch = SwitchTenant {
        tenant_id: tenant.id.clone(),
    };
    sessions::switch_tenant(world.org(), &switch)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    grant_tenant(world, uma).await;
    let moved = sessions::switch_tenant(world.org(), &switch)
        .send(browser)
        .await
        .ok();
    assert_eq!(
        moved.tenant_id, tenant.id,
        "the session moved into the tenant Ann granted"
    );
    people::list(world.tenant(), None)
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    browser.authorize(&moved.refresh_token);
    people::list(world.tenant(), None).send(browser).await.ok();
}

/// Uma, granted no tenant, names Ann's tenant as she signs in with her
/// right password: the sign-in is refused and her browser reads nothing.
/// Once Ann grants her the tenant, the same sign-in lands her there, and
/// she reads its people but not Globex's.
#[tokio::test]
async fn a_requested_tenant_requires_a_grant_even_with_the_right_password() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = world.colleague("uma", "Uma Member", OrgRole::Member).await;
    let mut browser = Client::new(&stack, "Uma, choosing a tenant").expect("a client");
    let sign_in = PasswordSignIn {
        organization: Some(world.org().slug().to_owned()),
        tenant_slug: Some(world.tenant().slug().to_owned()),
        ..PasswordSignIn::of(uma.email(), uma.password())
    };

    sessions::member_sign_in(&sign_in)
        .send(&browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    members::me(world.org())
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    grant_tenant(&world, &uma).await;
    enter_requested_tenant(&stack, &world, &mut browser, &sign_in).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann grants Uma the tenant's Admin role without changing her organization role.
async fn grant_tenant(world: &World<'_>, uma: &Member) {
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

/// Uma's newly granted tenant is selected at sign-in and grants access only to
/// that tenant's people, leaving Globex forbidden.
async fn enter_requested_tenant(
    stack: &Stack,
    world: &World<'_>,
    browser: &mut Client,
    sign_in: &PasswordSignIn,
) {
    let session = settled_sign_in(stack, browser, sign_in).await;
    assert_eq!(
        session.tenant_slug.as_deref(),
        Some(world.tenant().slug()),
        "once granted, the sign-in lands Uma in the tenant she named"
    );
    browser.authorize(&session.refresh_token);
    people::list(world.tenant(), None).send(browser).await.ok();
    people::list(world.twin(), None)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Ann has her company ask every new device for a second step, and Uma,
/// a colleague, signs in from a new browser: her password is accepted and
/// the sign-in waits for her mailbox. Ann locks Uma before she follows
/// the link: the link finishes nothing and the browser reads nothing,
/// and when Ann lets her back in the old link still finishes nothing. A
/// fresh sign-in, settled from her mailbox, opens Uma's account.
#[tokio::test]
async fn a_member_locked_during_sign_in_cannot_finish_with_an_issued_link() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    require_new_device_proof(&world).await;
    let mut uma = world.colleague("uma", "Uma Member", OrgRole::Member).await;
    uma.sign_in(&stack).await;

    let mut browser = Client::new(&stack, "Uma, midway through a sign-in").expect("a client");
    let sign_in = PasswordSignIn::of(uma.email(), uma.password());
    let confirm = lock_pending_sign_in(&stack, &world, &uma, &mut browser).await;
    assert_stale_confirmation(&world, &browser, &confirm).await;

    change_status(&world, &uma, "Active").await;
    assert_stale_confirmation(&world, &browser, &confirm).await;

    let fresh = settled_sign_in(&stack, &browser, &sign_in).await;
    browser.authorize(&fresh.refresh_token);
    members::me(world.org()).send(&browser).await.ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann requires mailbox proof from new devices while leaving factor enrollment
/// optional, so Uma's next password sign-in pauses for its mailed link.
async fn require_new_device_proof(world: &World<'_>) {
    let mut settings = organizations::sign_in_settings(world.org())
        .send(world.owner().client())
        .await
        .ok();
    settings.rest.get_mut("step_up").expect("step-up policy")["require_mfa_new_device"] =
        json!(true);
    settings
        .rest
        .insert("mfa_policy".to_owned(), json!("Optional"));
    organizations::replace_sign_in_settings(
        world.org(),
        &ReplaceOrgSignInSettings {
            settings,
            proof: MemberProof {
                password: world.owner().password().to_owned(),
                code: None,
            },
        },
    )
    .send(world.owner().client())
    .await
    .ok();
}

/// Uma receives a mailbox proof for her pending session, then Ann locks her
/// before that proof is submitted.
async fn lock_pending_sign_in(
    stack: &Stack,
    world: &World<'_>,
    uma: &Member,
    browser: &mut Client,
) -> ConfirmSignIn {
    let sign_in = PasswordSignIn::of(uma.email(), uma.password());
    let answer = sessions::member_sign_in(&sign_in).send(browser).await.ok();
    let SignedIn::Authenticated(waiting) = answer else {
        panic!("Uma is in one organization, so no choice is offered");
    };
    assert_eq!(
        waiting.owed(),
        Owed::MailedConfirmation,
        "a new browser waits for Uma's mailbox"
    );
    let mail = mail_linking_to(stack, uma.email(), "/confirm-sign-in").await;
    browser.authorize(&waiting.refresh_token);

    change_status(world, uma, "Locked").await;
    ConfirmSignIn {
        token: mail.token_in("/confirm-sign-in"),
        refresh_token: waiting.refresh_token,
    }
}

/// The issued proof cannot complete the revoked session, which still cannot
/// read Uma's member record.
async fn assert_stale_confirmation(world: &World<'_>, browser: &Client, confirm: &ConfirmSignIn) {
    sessions::confirm_member_sign_in(confirm)
        .send(browser)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Ann puts Uma's account in `status`, which is not active: the session
/// Uma held reads nothing at once, and her own password is answered
/// exactly as Mallory's wrong guess at her is. Ann makes her active
/// again: the old session stays dead, Uma signs in again, and the change
/// of standing is recorded.
async fn an_inactive_member_is_refused(status: &str) {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut uma = world.colleague("uma", "Uma Member", OrgRole::Member).await;
    uma.sign_in(&stack).await;

    change_status(&world, &uma, status).await;
    members::me(world.org())
        .send(uma.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_inactive_password(&stack, &world, &uma, status).await;
    reactivate_member(&stack, &world, &mut uma).await;

    world
        .trail()
        .recorded("organization.org_user_status_changed")
        .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann changes Uma's standing through the member administration endpoint.
async fn change_status(world: &World<'_>, uma: &Member, status: &str) {
    members::change_status(
        world.org(),
        uma.id(),
        &ChangeMemberStatus {
            status: status.to_owned(),
        },
    )
    .send(world.owner().client())
    .await
    .ok();
}

/// Uma's correct password and Mallory's wrong guess reveal the same refusal
/// while Uma's account is inactive.
async fn assert_inactive_password(stack: &Stack, world: &World<'_>, uma: &Member, status: &str) {
    let at_the_door = Client::new(stack, "Uma, with an inactive account").expect("a client");
    let own_password = PasswordSignIn {
        organization: Some(world.org().slug().to_owned()),
        ..PasswordSignIn::of(uma.email(), uma.password())
    };
    let refused = sessions::member_sign_in(&own_password)
        .send(&at_the_door)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let mallory = Client::new(stack, "Mallory, guessing at Uma").expect("a client");
    let wrong_guess = PasswordSignIn {
        organization: Some(world.org().slug().to_owned()),
        ..PasswordSignIn::of(uma.email(), WRONG_GUESS)
    };
    let guessed = sessions::member_sign_in(&wrong_guess)
        .send(&mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert_eq!(
        refused.message(),
        guessed.message(),
        "a {status} member and a wrong guess are told the same"
    );
}

/// Reactivation leaves Uma's old session dead, and a new sign-in restores her
/// ability to read her member record.
async fn reactivate_member(stack: &Stack, world: &World<'_>, uma: &mut Member) {
    change_status(world, uma, "Active").await;
    members::me(world.org())
        .send(uma.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    uma.sign_in(stack).await;
    members::me(world.org()).send(uma.client()).await.ok();
}
