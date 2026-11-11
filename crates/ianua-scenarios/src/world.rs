//! A world for one scenario: a fresh organization founded through the
//! real sign-up, its first tenant once its setup finished, a twin tenant
//! in a second organization for probes across, and the cast acting in
//! them.
//!
//! Every name in a world carries a suffix of its own, so scenarios running
//! side by side on one stack never meet.

mod founding;

use std::time::Duration;

use founding::{Founder, Founding, Invitee, founded, joined};

use crate::actors::{Anonymous, Member, Person, PersonAccount};
use crate::api::{OrgPath, TenantPath, members, roles, tenants};
use crate::expect::Trail;
use crate::net::Client;
use crate::stack::{Stack, secrets};
use crate::wire::organization::{OrgRole, TenantRoles};
use crate::wire::tenants::{MfaPolicy, PasswordAgain, ReplaceSignInSettings};

/// The longest a tenant's setup is waited for.
const SETUP_WAIT: Duration = Duration::from_secs(90);

/// How often the setup is asked after: often enough that a scenario starts
/// soon after the setup ends, and still a few dozen asks at most, well
/// under the API's own rate limit.
const SETUP_ASK_EVERY: Duration = Duration::from_millis(250);

/// The tenant role holding every built-in permission, seeded into every
/// tenant by its setup.
pub const ADMIN_ROLE: &str = "Admin";

/// The tenant role new users get by default, seeded into every tenant by
/// its setup.
pub const MEMBER_ROLE: &str = "Member";

/// The organizations, tenants and cast of one scenario.
#[derive(Debug)]
pub struct World<'s> {
    stack: &'s Stack,
    suffix: String,
    tenant: TenantPath,
    twin: TenantPath,
    owner: Member,
    admin: Member,
    member: Member,
    stranger: Member,
    anonymous: Anonymous,
}

impl<'s> World<'s> {
    /// A new world on `stack`. Ann founds an organization; once its first
    /// tenant is set up she turns its second factors to optional, and
    /// invites Tess, who gets the tenant's `Admin` role, and Max, who gets
    /// its `Member` role and so no administrator's rights (a member with no
    /// tenant at all has nowhere to sign in to, so the platform refuses his
    /// sign-in). Sam founds a second organization, whose tenant is the
    /// twin. Everyone signs in, the administrators landing in their
    /// tenants, and nobody at all is the anonymous visitor. The two
    /// founders progress together, then Tess and Max join together; each
    /// actor still completes their own steps in order through the API.
    ///
    /// # Panics
    ///
    /// When any step is refused, or a setup does not finish within ninety
    /// seconds.
    pub async fn new(stack: &'s Stack) -> Self {
        let suffix = secrets::hex(4);
        let (ann, sam) = tokio::join!(
            ready_founder(stack, Founding::new(stack, "Acme", "Ann", &suffix)),
            ready_founder(stack, Founding::new(stack, "Globex", "Sam", &suffix)),
        );
        let (tess, max) = ready_colleagues(stack, &ann, &suffix).await;
        Self {
            stack,
            suffix,
            tenant: ann.tenant,
            twin: sam.tenant,
            owner: ann.member,
            admin: tess,
            member: max,
            stranger: sam.member,
            anonymous: Anonymous::new(stack),
        }
    }

    /// The stack it lives on.
    #[must_use]
    pub fn stack(&self) -> &'s Stack {
        self.stack
    }

    /// The first organization.
    #[must_use]
    pub fn org(&self) -> &OrgPath {
        self.tenant.organization()
    }

    /// The first organization's tenant, where the scenario acts.
    #[must_use]
    pub fn tenant(&self) -> &TenantPath {
        &self.tenant
    }

    /// The tenant of the second organization, for probes across.
    #[must_use]
    pub fn twin(&self) -> &TenantPath {
        &self.twin
    }

    /// Ann, who founded the first organization and owns it; her sessions
    /// land in its tenant.
    #[must_use]
    pub fn owner(&self) -> &Member {
        &self.owner
    }

    /// Ann, to sign in again: after a change to her own role ends the
    /// sessions she held.
    pub fn owner_mut(&mut self) -> &mut Member {
        &mut self.owner
    }

    /// Tess, a member of the first organization holding the tenant's
    /// `Admin` role; her sessions land in the tenant.
    #[must_use]
    pub fn admin(&self) -> &Member {
        &self.admin
    }

    /// Max, a member of the first organization holding only the tenant's
    /// `Member` role, so no administrator's rights; his session lands in
    /// the tenant.
    #[must_use]
    pub fn member(&self) -> &Member {
        &self.member
    }

    /// Sam, who owns the second organization and so administers the twin
    /// tenant, where his sessions land, and nothing of the first.
    #[must_use]
    pub fn stranger(&self) -> &Member {
        &self.stranger
    }

    /// Nobody signed in.
    #[must_use]
    pub fn anonymous(&self) -> &Anonymous {
        &self.anonymous
    }

    /// The organization's audit trail, read by Ann, its owner.
    #[must_use]
    pub fn trail(&self) -> Trail<'_> {
        Trail::of_organization(self.owner.client(), self.org().slug())
    }

    /// An address under the stack's domain for `name`, unique to this
    /// world.
    #[must_use]
    pub fn address(&self, name: &str) -> String {
        address(self.stack, name, &self.suffix)
    }

    /// Someone at an address unique to this world for `name`, invited by
    /// Ann into her organization as `role`, who accepts from the mailed
    /// link with a password of their own: a colleague the way a customer
    /// adds one. Not yet signed in.
    ///
    /// # Panics
    ///
    /// When the invitation or the acceptance is refused, or no link comes.
    pub async fn colleague(&self, name: &str, display_name: &str, role: OrgRole) -> Member {
        let email = self.address(name);
        let invitee = Invitee {
            email: &email,
            display_name,
            role,
        };
        joined(self.stack, &self.owner, invitee).await
    }

    /// Someone not yet in the tenant, named `display_name`, with an
    /// address unique to this world, a password of their own and a client
    /// of their own, for an administrator to invite.
    ///
    /// # Panics
    ///
    /// When the client cannot be built.
    /// The newcomer must have an independent client before invitation scenarios proceed.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn newcomer(&self, name: &str, display_name: &str) -> Person {
        let account = PersonAccount {
            email: self.address(name),
            display_name: display_name.to_owned(),
            tenant: self.tenant.clone(),
        };
        let client = Client::new(self.stack, display_name).expect("a client for the newcomer");
        Person::new(client, account, &secrets::password())
    }

    /// The id of the role `name` in the tenant, as Tess reads it.
    ///
    /// # Panics
    ///
    /// When the roles cannot be read or there is no such role.
    pub async fn role_id(&self, name: &str) -> String {
        let listed = roles::list(&self.tenant)
            .send(self.admin.client())
            .await
            .ok();
        let found = listed.items.into_iter().find(|role| role.name == name);
        let Some(role) = found else {
            panic!("the tenant has no role named {name}");
        };
        role.id
    }

    /// The secrets the cast holds, to make sure none appears where it
    /// should not.
    #[must_use]
    pub fn cast_secrets(&self) -> Vec<String> {
        [&self.owner, &self.admin, &self.member, &self.stranger]
            .into_iter()
            .flat_map(Member::secrets)
            .collect()
    }
}

/// Invites the administrator and ordinary member concurrently into the founder's tenant.
async fn ready_colleagues(stack: &Stack, founder: &Founder, suffix: &str) -> (Member, Member) {
    let tess_address = address(stack, "tess", suffix);
    let max_address = address(stack, "max", suffix);
    tokio::join!(
        ready_member(
            stack,
            founder,
            plain_member(&tess_address, "Tess Admin"),
            ADMIN_ROLE
        ),
        ready_member(
            stack,
            founder,
            plain_member(&max_address, "Max Member"),
            MEMBER_ROLE
        ),
    )
}

/// `name` at the stack's domain, with `suffix`.
fn address(stack: &Stack, name: &str, suffix: &str) -> String {
    format!("{name}.{suffix}@{}", stack.base_domain())
}

/// Someone at `email` named `display_name`, invited as a plain member.
fn plain_member<'a>(email: &'a str, display_name: &'a str) -> Invitee<'a> {
    Invitee {
        email,
        display_name,
        role: OrgRole::Member,
    }
}

/// Founds one organization through its mailed link, waits for its tenant
/// to become active and signs the owner into it with optional second
/// factors. It shares no account state with the other founder, so their
/// mail and setup waits can overlap.
///
/// # Panics
///
/// When founding, setup, sign-in or the settings change fails.
async fn ready_founder(stack: &Stack, founding: Founding) -> Founder {
    let mut founder = founded(stack, &founding).await;
    founder.wait_for_setup(stack).await;
    allow_second_factors(&founder).await;
    founder
}

/// Invites one colleague, accepts their mailed link, grants their tenant
/// role and signs them in there. Each colleague owns their mailbox and
/// client, so they can join together without sharing credentials or
/// skipping the grant required before sign-in.
///
/// # Panics
///
/// When the invitation, acceptance, grant or sign-in fails.
async fn ready_member(
    stack: &Stack,
    founder: &Founder,
    invitee: Invitee<'_>,
    role: &str,
) -> Member {
    let mut member = joined(stack, &founder.member, invitee).await;
    grant_tenant(&founder.member, &member, &founder.tenant, role).await;
    member.land_in(founder.tenant.slug());
    member.sign_in(stack).await;
    member
}

/// Turns the founder's tenant's second factors to optional, so its users
/// may set one up; the founder proves themselves with their password.
///
/// # Panics
///
/// When the settings cannot be read or are refused.
async fn allow_second_factors(founder: &Founder) {
    let owner = &founder.member;
    let tenant = &founder.tenant;
    let mut settings = tenants::sign_in_settings(tenant)
        .send(owner.client())
        .await
        .ok();
    settings.mfa_policy = MfaPolicy::Optional;
    let replace = ReplaceSignInSettings {
        settings,
        proof: PasswordAgain {
            password: owner.password().to_owned(),
            code: None,
        },
    };
    tenants::replace_sign_in_settings(tenant, &replace)
        .send(owner.client())
        .await
        .ok();
}

/// Gives `member` the tenant role `role` in `tenant`, as `steward`.
///
/// # Panics
///
/// When it is refused.
async fn grant_tenant(steward: &Member, member: &Member, tenant: &TenantPath, role: &str) {
    let roles = TenantRoles {
        roles: vec![role.to_owned()],
    };
    members::set_tenant_roles(tenant.organization(), member.id(), tenant.slug(), &roles)
        .send(steward.client())
        .await
        .ok();
}
