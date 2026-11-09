//! A verified member founding another company from their own session: Max
//! founds New Venture and stays a plain member of Acme; nobody signed in
//! and no program with a key founds one; a refused form changes nothing;
//! an audit failure rolls the founding back; and a self-hosted owner
//! founds none.

use ianua_scenarios::actors::{Founder, Member, MemberAccount};
use ianua_scenarios::api::{
    OrgPath, api_keys, members, onboarding, registration, sessions, tenants,
};
use ianua_scenarios::expect::{Matrix, Trail, eventually, no_secret_leaked};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{AuditWrites, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::onboarding::{ConfirmInstaller, Founded};
use ianua_scenarios::wire::organization::{NewOrgApiKey, OrgRole};
use ianua_scenarios::wire::registration::AnotherCompany;
use ianua_scenarios::wire::sign_in::PasswordSignIn;
use ianua_scenarios::wire::tenants::TenantStatus;
use ianua_scenarios::world::World;

use crate::support::{QUIET, installation_of, installed, owner_signed_in};

/// The new company's own password, which must never replace the password
/// of the account that founded it: a sentence, so no scanner takes it for
/// a key.
const NEW_PASSWORD: &str = "Another quiet orchard lantern 9573";

/// The events a founding records once in the new company's trail.
const FOUNDING_EVENTS: [&str; 5] = [
    "organization.created",
    "organization.org_user_created",
    "organization.org_user_email_verified",
    "organization.subscription_started",
    "organization.tenant_created",
];

/// Max, a plain member of Acme, founds New Venture: it is his, under his
/// verified address, with a password and session of its own, and its
/// first tenant is set up. In Acme he stays a plain member. Neither his
/// Acme session, nor Sam's, nor nobody signed in reads the new company;
/// its own session does not read Acme; and each password opens only the
/// company it belongs to. The founding is recorded once, with no secret.
#[tokio::test]
async fn a_verified_member_founds_an_independent_company_without_changing_the_original() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let max = world.member();
    let before = members::me(world.org()).send(max.client()).await.ok();

    let founded = registration::another_company(&company("New Venture"))
        .send(max.client())
        .await
        .ok();
    assert_verified_member_mail(&stack, max).await;
    let owner = signed_in_as_new_owner(&world, max, &founded).await;

    let after = members::me(world.org()).send(max.client()).await.ok();
    assert_eq!(before.id, after.id, "Max is still Max in Acme");
    assert_eq!(
        after.role,
        Some(OrgRole::Member),
        "and still a plain member there"
    );
    assert_company_isolation(&world, &owner).await;
    assert_ready_and_passwords(&world, &owner, &founded).await;
    assert_founding_events(&owner).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A member whose mailbox is already verified receives no signup proof.
async fn assert_verified_member_mail(stack: &Stack, max: &Member) {
    if let Some(mail) = stack.mailbox().within(max.email(), QUIET).await {
        assert!(
            mail.links()
                .iter()
                .all(|link| !link.path().starts_with("/signup/confirm")),
            "a verified member is mailed no link to confirm"
        );
    }
}

/// Each company accepts only its own session, including for the same founder.
async fn assert_company_isolation(world: &World<'_>, owner: &Member) {
    Matrix::new(
        "reading the new company's owner record",
        members::me(owner.org()).call(),
    )
    .allowed(owner.client())
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
    members::me(world.org())
        .send(owner.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// The new tenant becomes ready and neither password opens the other company.
async fn assert_ready_and_passwords(world: &World<'_>, owner: &Member, founded: &Founded) {
    let max = world.member();
    let first_tenant = owner.org().tenant(&founded.tenant_slug);
    eventually("the new company's first tenant to be ready", || async {
        let tenant = tenants::get(&first_tenant).send(owner.client()).await.ok();
        (tenant.status == TenantStatus::Active && tenant.setup.state == "over").then_some(())
    })
    .await;
    for (password, wrong_company) in [
        (NEW_PASSWORD, world.org().slug()),
        (max.password(), owner.org().slug()),
    ] {
        let sign_in = PasswordSignIn {
            organization: Some(wrong_company.to_owned()),
            ..PasswordSignIn::of(max.email(), password)
        };
        sessions::member_sign_in(&sign_in)
            .send(world.anonymous().client())
            .await
            .refused(Status::NOT_FOUND, "not_found");
    }
}

/// Each founding event appears once without any of the owner's secrets.
async fn assert_founding_events(owner: &Member) {
    let trail = Trail::of_organization(owner.client(), owner.org().slug());
    let secrets = owner.secrets();
    let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
    for event in FOUNDING_EVENTS {
        let record = trail.recorded(event).await;
        assert_eq!(trail.count(event).await, 1, "one {event}");
        no_secret_leaked(&record.details.to_string(), &secrets);
    }
}

/// An anonymous caller and a program using Ann's organization key cannot
/// found a company. The same form from
/// Ann's own session founds it, so what was refused was the caller.
#[tokio::test]
async fn only_a_members_own_session_founds_another_company() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let key = create_program_key(&world).await;
    let mut program = Client::new(&stack, "a program holding Ann's key").expect("a client");
    program.authorize(&key);
    let form = company("New Venture");

    registration::another_company(&form)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    registration::another_company(&form)
        .send(&program)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    let founded = registration::another_company(&form)
        .send(world.owner().client())
        .await
        .ok();
    signed_in_as_new_owner(&world, world.owner(), &founded).await;
    members::me(world.org())
        .send(world.owner().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann issues an organization key to distinguish program access from her session.
async fn create_program_key(world: &World<'_>) -> String {
    let key = api_keys::create_for_organization(
        world.org(),
        &NewOrgApiKey {
            name: "An automated caller".to_owned(),
            scopes: vec!["org:members:view".to_owned()],
        },
    )
    .send(world.owner().client())
    .await
    .ok();
    key.raw_key
}

/// Max tries Acme's own name, then a password of three letters: each is
/// refused and leaves no half-made company, and Max still reads his Acme
/// record. The corrected form founds New Venture from the same session,
/// and its new password signs him in there.
#[tokio::test]
async fn a_refused_additional_company_can_be_corrected_without_changing_existing_access() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let max = world.member();

    registration::another_company(&company(world.org().slug()))
        .send(max.client())
        .await
        .refused(Status::CONFLICT, "conflict");
    let mut weak = company("New Venture");
    weak.password = "abc".to_owned();
    registration::another_company(&weak)
        .send(max.client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    members::me(world.org()).send(max.client()).await.ok();

    let founded = registration::another_company(&company("New Venture"))
        .send(max.client())
        .await
        .ok();
    signed_in_as_new_owner(&world, max, &founded).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Audit storage refusing writes makes Max's founding attempt fail, while
/// Max still reads his
/// Acme record; once audit writes are allowed again the same form founds
/// the company, recorded once.
#[tokio::test]
async fn an_additional_company_rolls_back_on_audit_failure_and_can_be_retried() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let max = world.member();

    stack.audit_writes(AuditWrites::Refuse).await;
    let failed = registration::another_company(&company("New Venture"))
        .send(max.client())
        .await;
    assert_eq!(
        failed.status(),
        Status::INTERNAL_SERVER_ERROR,
        "a founding nobody can record fails: {}",
        failed.summary()
    );
    stack.audit_writes(AuditWrites::Allow).await;
    members::me(world.org()).send(max.client()).await.ok();

    let founded = registration::another_company(&company("New Venture"))
        .send(max.client())
        .await
        .ok();
    let owner = signed_in_as_new_owner(&world, max, &founded).await;
    let trail = Trail::of_organization(owner.client(), owner.org().slug());
    assert_eq!(
        trail.count("organization.created").await,
        1,
        "the company was founded once, after the retry"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann owns a self-hosted installation, confirmed by its installer's
/// proof. Her attempt to found a second organization is refused, and she
/// still reads her own record.
#[tokio::test]
async fn a_self_hosted_owner_cannot_found_a_second_company() {
    let stack = Stack::start(Profile::standard().with("DEPLOYMENT", "self_hosted"))
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let installation = installed(&stack, &installation_of(&ann)).await;
    onboarding::confirm_installer(&ConfirmInstaller {
        token: installation.setup_token,
    })
    .send(ann.client())
    .await
    .ok();
    owner_signed_in(&stack, &mut ann, &installation.founded).await;

    registration::another_company(&company("New Venture"))
        .send(ann.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    members::me(&OrgPath::new(&installation.founded.org_slug))
        .send(ann.client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// The form for another company named `name`, with a password of its own.
fn company(name: &str) -> AnotherCompany {
    AnotherCompany {
        company_name: name.to_owned(),
        tenant_name: "Production".to_owned(),
        password: NEW_PASSWORD.to_owned(),
    }
}

/// `original`, signed in to the company they founded as its owner with
/// the new password, on a client of their own: the owner's record is
/// theirs, at their address, verified, with the owner's role.
///
/// # Panics
///
/// When the sign-in or the read is refused.
async fn signed_in_as_new_owner(world: &World<'_>, original: &Member, founded: &Founded) -> Member {
    let client = Client::new(world.stack(), "the founder in their new company").expect("a client");
    let mut owner = Member::new(
        client,
        MemberAccount {
            id: founded.admin_user_id.clone(),
            email: original.email().to_owned(),
            display_name: "New owner".to_owned(),
            org: OrgPath::new(&founded.org_slug),
            role: OrgRole::Owner,
            landing: None,
        },
        NEW_PASSWORD,
    );
    owner.sign_in(world.stack()).await;
    let record = members::me(owner.org()).send(owner.client()).await.ok();
    assert_eq!(record.id, founded.admin_user_id, "the founder is the owner");
    assert_eq!(record.email, original.email(), "at their own address");
    assert!(record.email_verified, "verified as it already was");
    assert_eq!(record.role, Some(OrgRole::Owner), "with the owner's role");
    owner
}
