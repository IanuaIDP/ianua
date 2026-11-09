//! How a world's organizations come to be: a company signs up, its owner
//! founds the organization from the mailed link and waits for the first
//! tenant's setup; and how members join from a mailed invitation.

use super::{SETUP_ASK_EVERY, SETUP_WAIT};
use crate::actors::mailed::mail_linking;
use crate::actors::{Member, MemberAccount};
use crate::api::{OrgPath, TenantPath, members, onboarding, tenants};
use crate::expect::{Waiting, eventually_paced};
use crate::net::Client;
use crate::stack::{Stack, secrets};
use crate::wire::onboarding::{ConfirmSignup, Signup};
use crate::wire::organization::{AcceptMemberInvitation, InviteMember, OrgRole};
use crate::wire::tenants::TenantStatus;

/// A company about to sign up: its name and its owner's.
pub(super) struct Founding {
    company: String,
    owner_first_name: String,
    owner_email: String,
}

impl Founding {
    /// `company`, owned by `owner_first_name`, both made unique with
    /// `suffix`, under `stack`'s domain.
    pub(super) fn new(stack: &Stack, company: &str, owner_first_name: &str, suffix: &str) -> Self {
        Self {
            company: format!("{company} {suffix}"),
            owner_first_name: owner_first_name.to_owned(),
            owner_email: super::address(stack, &owner_first_name.to_ascii_lowercase(), suffix),
        }
    }

    /// Builds the company signup using the owner's chosen password.
    fn signup(&self, password: &str) -> Signup {
        Signup {
            company_name: self.company.clone(),
            tenant_name: "Production".to_owned(),
            admin_email: self.owner_email.clone(),
            admin_display_name: format!("{} Owner", self.owner_first_name),
            admin_password: password.to_owned(),
        }
    }
}

/// An owner who just founded their organization, and its first tenant.
pub(super) struct Founder {
    /// The owner.
    pub(super) member: Member,
    /// The first tenant.
    pub(super) tenant: TenantPath,
}

impl Founder {
    /// Waits until the first tenant's setup finished, then has the
    /// owner's sessions land there and signs them in again.
    ///
    /// # Panics
    ///
    /// When the setup fails, naming the step, or does not finish within
    /// ninety seconds.
    pub(super) async fn wait_for_setup(&mut self, stack: &Stack) {
        let what = format!("the setup of {}", self.tenant.slug());
        let named = what.as_str();
        let owner = self.member.client();
        let tenant = &self.tenant;
        let waiting = Waiting {
            patience: SETUP_WAIT,
            every: SETUP_ASK_EVERY,
        };
        eventually_paced(named, waiting, || async move {
            let read = tenants::get(tenant).send(owner).await.ok();
            tracing::info!(
                tenant = named,
                status = ?read.status,
                setup = %read.setup.state,
                "the setup read"
            );
            if let Some(step) = read.setup.failed_step {
                panic!("{named} failed at its {step} step");
            }
            (read.status == TenantStatus::Active).then_some(())
        })
        .await;
        self.member.land_in(self.tenant.slug());
        self.member.sign_in(stack).await;
    }
}

/// The organization `founding` signs up for, founded from the mailed link,
/// its owner signed in on the organization.
///
/// # Panics
///
/// When the sign-up or the founding is refused, or no link comes.
/// Founding requires a usable owner client; failure aborts scenario setup.
#[allow(clippy::expect_used)]
pub(super) async fn founded(stack: &Stack, founding: &Founding) -> Founder {
    let password = secrets::password();
    let actor = format!("{}, the owner", founding.owner_first_name);
    let client = Client::new(stack, &actor).expect("a client for the owner");
    let signup = founding.signup(&password);
    onboarding::sign_up(&signup).send(&client).await.ok();
    let mail = mail_linking(stack.mailbox(), &founding.owner_email, "/signup/confirm").await;
    let confirm = ConfirmSignup {
        token: mail.token_in("/signup/confirm"),
    };
    let founded = onboarding::confirm(&confirm).send(&client).await.ok();
    let org = OrgPath::new(&founded.org_slug);
    let account = MemberAccount {
        id: founded.admin_user_id,
        email: founding.owner_email.clone(),
        display_name: signup.admin_display_name,
        org: org.clone(),
        role: OrgRole::Owner,
        landing: None,
    };
    let mut member = Member::new(client, account, &password);
    member.sign_in(stack).await;
    Founder {
        member,
        tenant: org.tenant(&founded.tenant_slug),
    }
}

/// Who is invited into an organization: where they are written to, their
/// name and the role the invitation offers.
pub(super) struct Invitee<'a> {
    /// Their address.
    pub(super) email: &'a str,
    /// Human-readable label assigned to the invited organization member.
    pub(super) display_name: &'a str,
    /// The role they are invited to.
    pub(super) role: OrgRole,
}

/// `invitee`, invited by `steward` into their organization, who accepts
/// from the mailed link with a password of their own. Not yet signed in.
///
/// # Panics
///
/// When the invitation or the acceptance is refused, or no link comes.
/// Invitation acceptance requires a separate client for the joining member.
#[allow(clippy::expect_used)]
pub(super) async fn joined(stack: &Stack, steward: &Member, invitee: Invitee<'_>) -> Member {
    let member_id = invite(steward, &invitee).await;
    let Invitee {
        email,
        display_name,
        role,
    } = invitee;
    let org = steward.org().clone();
    let mail = mail_linking(stack.mailbox(), email, "/accept-invite").await;
    let password = secrets::password();
    let accept = AcceptMemberInvitation {
        token: mail.token_in("/accept-invite"),
        password: password.clone(),
    };
    let client = Client::new(stack, display_name).expect("a client for the member");
    members::accept_invitation(&org, &accept)
        .send(&client)
        .await
        .ok();
    let account = MemberAccount {
        id: member_id,
        email: email.to_owned(),
        display_name: display_name.to_owned(),
        org,
        role,
        landing: None,
    };
    Member::new(client, account, &password)
}

/// Sends the steward's invitation and returns the account it creates.
async fn invite(steward: &Member, invitee: &Invitee<'_>) -> String {
    let invitation = InviteMember {
        email: invitee.email.to_owned(),
        display_name: invitee.display_name.to_owned(),
        role: invitee.role,
    };
    members::invite(steward.org(), &invitation)
        .send(steward.client())
        .await
        .ok()
        .id
}
