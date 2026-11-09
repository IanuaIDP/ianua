//! Pat holding two accounts at one address, in Ann's first tenant and in
//! a staging tenant Ann adds, each with a password of its own. Signed in
//! to both, she links them, and a session in one then switches into the
//! other. A link takes a live session at each end: a shared mailbox, a
//! made-up or ended session, or a different proved address links nothing.
//!
//! - `switching`: Pat links her two accounts and switches into the staging
//!   one; unlinking stops the switch and both passwords still work; a
//!   deactivated staging account cannot be switched into until restored.
//! - `proofs`: a shared mailbox or a made-up token links nothing, nor does
//!   a token from an ended session, nor accounts at different addresses.

mod proofs;
mod switching;

use std::time::Duration;

use ianua_scenarios::actors::{Member, Person, PersonAccount};
use ianua_scenarios::api::{TenantPath, account, organizations, people, roles, tenants};
use ianua_scenarios::expect::eventually;
use ianua_scenarios::stack::Profile;
use ianua_scenarios::wire::organization::PlanChoice;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::tenants::{
    MfaPolicy, NewTenant, PasswordAgain, ReplaceSignInSettings, TenantStatus,
};
use ianua_scenarios::world::{MEMBER_ROLE, World};

use crate::support::{
    SignedDevice, device, invited_and_signed_in, past_lifetime, signed_in_elsewhere,
};

/// How long the platform holds back a second mail to one address, set
/// short so Pat's second invitation to the same mailbox goes out while
/// the scenario waits.
const MAIL_COOLDOWN: Duration = Duration::from_secs(1);

/// The password of Pat's staging account, not the one of her first: a
/// sentence, so no scanner takes it for a key.
const STAGING_PASSWORD: &str = "Separate Golden Orchard Meadow 7814!";

/// Pat's two accounts at one address, and Ann administering the staging
/// tenant they span.
pub(super) struct Accounts {
    /// Ann, signed in to the staging tenant.
    pub(super) administrator: Member,
    /// Pat's account in the first tenant, signed in.
    pub(super) source: Person,
    /// Pat's account in the staging tenant, signed in.
    pub(super) target: Person,
    /// The staging tenant.
    pub(super) target_tenant: TenantPath,
    /// The staging tenant's id, which a switch names.
    pub(super) target_id: String,
}

/// The standard profile with the mail cooldown shortened to
/// [`MAIL_COOLDOWN`].
pub(super) fn linking_profile() -> Profile {
    Profile::standard().with(
        "MAIL_COOLDOWN_SECONDS",
        &MAIL_COOLDOWN.as_secs().to_string(),
    )
}

/// Pat's two accounts: Ann moves her company to a plan that admits a
/// second tenant, adds the staging tenant, signs in to it and turns its
/// second factors to optional; Pat joins the first tenant, then, once the
/// mail cooldown has passed, is invited into the staging tenant at the
/// same address, accepts with a password of its own and signs in.
///
/// # Panics
///
/// When any step is refused, or the staging tenant's setup does not
/// finish.
pub(super) async fn accounts(world: &World<'_>) -> Accounts {
    let (target_tenant, target_id) = staging_tenant(world).await;
    let administrator = administering(world, &target_tenant).await;
    factors_optional(world, &administrator, &target_tenant).await;
    let source = invited_and_signed_in(world, "pat").await;
    past_lifetime(MAIL_COOLDOWN).await;
    let target = invited_into(world, &administrator, &target_tenant, source.email()).await;
    Accounts {
        administrator,
        source,
        target,
        target_tenant,
        target_id,
    }
}

/// The staging tenant Ann adds to her company, once its setup is over,
/// and its id. The company first moves to a plan that admits a second
/// tenant, through the billing endpoint as a customer would.
async fn staging_tenant(world: &World<'_>) -> (TenantPath, String) {
    let business = PlanChoice {
        plan: "Business".to_owned(),
    };
    organizations::choose_plan(world.org(), &business)
        .send(world.owner().client())
        .await
        .ok();
    let staging = NewTenant {
        slug: "staging".to_owned(),
        display_name: "Staging".to_owned(),
        contact_email: world.address("contact"),
        timezone: "Europe/Berlin".to_owned(),
        locale: "en-US".to_owned(),
    };
    let made = tenants::create(world.org(), &staging)
        .send(world.owner().client())
        .await
        .ok();
    let target_tenant = world.org().tenant("staging");
    eventually("the staging tenant's setup to be over", || async {
        let tenant = tenants::get(&target_tenant)
            .send(world.owner().client())
            .await
            .ok();
        (tenant.status == TenantStatus::Active).then_some(())
    })
    .await;
    (target_tenant, made.id)
}

/// Ann on another device, signed in to `tenant` to administer it.
async fn administering(world: &World<'_>, tenant: &TenantPath) -> Member {
    let mut administrator = Member::new(
        device(world.stack(), "Ann administering staging"),
        world.owner().account().clone(),
        world.owner().password(),
    );
    administrator.land_in(tenant.slug());
    administrator.sign_in(world.stack()).await;
    administrator
}

/// Turns `tenant`'s second factors to optional, as `administrator`.
async fn factors_optional(world: &World<'_>, administrator: &Member, tenant: &TenantPath) {
    let mut settings = tenants::sign_in_settings(tenant)
        .send(administrator.client())
        .await
        .ok();
    settings.mfa_policy = MfaPolicy::Optional;
    let replace = ReplaceSignInSettings {
        settings,
        proof: PasswordAgain {
            password: world.owner().password().to_owned(),
            code: None,
        },
    };
    tenants::replace_sign_in_settings(tenant, &replace)
        .send(administrator.client())
        .await
        .ok();
}

/// Pat, invited by `administrator` into `tenant` at `email` with its
/// `Member` role, accepted from her mailbox with the staging password and
/// signed in on a device of her own.
async fn invited_into(
    world: &World<'_>,
    administrator: &Member,
    tenant: &TenantPath,
    email: &str,
) -> Person {
    let role_id = staging_member_role(administrator, tenant).await;
    let invitation = InviteUser {
        email: email.to_owned(),
        display_name: "Pat Staging".to_owned(),
        role_id,
    };
    let invited = people::invite(tenant, &invitation)
        .send(administrator.client())
        .await
        .ok();
    let account = PersonAccount {
        email: email.to_owned(),
        display_name: "Pat Staging".to_owned(),
        tenant: tenant.clone(),
    };
    let mut target = Person::new(
        device(world.stack(), "Pat's staging account"),
        account,
        STAGING_PASSWORD,
    );
    target.record_invitation(&invited.id);
    target.accept_invitation(world.stack()).await;
    target.sign_in(world.stack()).await;
    target
}

/// Resolve staging's default member role before inviting Pat into that tenant.
async fn staging_member_role(administrator: &Member, tenant: &TenantPath) -> String {
    let listed = roles::list(tenant).send(administrator.client()).await.ok();
    let Some(role) = listed.items.iter().find(|role| role.name == MEMBER_ROLE) else {
        panic!("the staging tenant has the default member role");
    };
    role.id.clone()
}

/// Pat's two accounts linked: a fresh session in the first opens the
/// group, and the staging account joins it with that session's token as
/// the proof of the other end. The fresh session, for the switch.
///
/// # Panics
///
/// When either end is refused.
pub(super) async fn linked(world: &World<'_>, accounts: &Accounts) -> SignedDevice {
    let source = signed_in_elsewhere(world, &accounts.source).await;
    account::link_accounts(world.tenant())
        .send(&source.client)
        .await
        .ok();
    account::join_linked_accounts(&accounts.target_tenant, &source.session.refresh_token)
        .send(accounts.target.client())
        .await
        .ok();
    source
}
