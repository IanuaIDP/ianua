//! Joining without a mail server, on Ann's self-hosted installation: the
//! public form is refused, since no mailbox can be proved; an invitation
//! is handed to its sender as a link, which Uma or Pat joins from once,
//! with the address left unproved and an authenticator set up before
//! anything is read.

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{
    OrgPath, TenantPath, factors, member_factors, members, onboarding, people, registration, roles,
    sessions, tenants,
};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::{ConfirmFactor, FactorSetup};
use ianua_scenarios::wire::onboarding::ConfirmInstaller;
use ianua_scenarios::wire::organization::{
    AcceptMemberInvitation, InviteMember, MemberInvited, OrgRole,
};
use ianua_scenarios::wire::people::{AcceptInvitation, InviteUser, LinkToken, UserInvited};
use ianua_scenarios::wire::registration::TenantSignup;
use ianua_scenarios::wire::sign_in::{Owed, PasswordSignIn, Session, SignedIn};
use ianua_scenarios::wire::tenant_sign_in::{TenantPasswordSignIn, TenantSession, TenantSignedIn};
use ianua_scenarios::wire::tenants::{MfaPolicy, PasswordAgain, ReplaceSignInSettings};
use ianua_scenarios::world::MEMBER_ROLE;
use serde_json::json;
use url::Url;

use crate::support::{QUIET, installation_of, installed, ready_tenant};

/// The password an invitee chooses when they accept: a sentence, so no
/// scanner takes it for a key.
const INVITEES_PASSWORD: &str = "Quiet invited orchard lantern 7942";

/// The password Pat types into the public form: a sentence, so no scanner
/// takes it for a key.
const PATS_PASSWORD: &str = "Quiet orchard lantern meadow 8492";

/// Ann's installation with no mail server: Ann signed in with the
/// authenticator she set up, her first tenant ready, open to the public
/// and requiring a second factor.
pub(super) struct Offline {
    /// Ann, signed in.
    pub(super) owner: Founder,
    /// Her first tenant, set up.
    pub(super) tenant: TenantPath,
    /// Her authenticator, for the fresh proof a settings change needs.
    pub(super) phone: TotpApp,
}

/// Ann's installation, with Ann confirmed by the installer's proof,
/// signed in, her authenticator set up as the installation requires, and
/// her first tenant ready, opened to the public and requiring a second
/// factor.
///
/// # Panics
///
/// When any step is refused.
pub(super) async fn installed_without_mail(stack: &Stack) -> Offline {
    let mut owner = Founder::named(stack, "Ann");
    let installation = installed(stack, &installation_of(&owner)).await;
    onboarding::confirm_installer(&ConfirmInstaller {
        token: installation.setup_token,
    })
    .send(owner.client())
    .await
    .ok();
    let session = owner.password_sign_in().await;
    owner.client_mut().authorize(&session.refresh_token);
    let org = OrgPath::new(&installation.founded.org_slug);
    let mut phone = enroll_member(owner.client(), &org, session.session_id).await;
    let tenant = ready_tenant(&owner, &installation.founded).await;
    open_with_required_factor(&owner, &tenant, &mut phone).await;
    Offline {
        owner,
        tenant,
        phone,
    }
}

/// The waiting member session finishes enrollment with the authenticator it just registered.
async fn enroll_member(client: &Client, org: &OrgPath, session_id: String) -> TotpApp {
    let begun = member_factors::begin_required_totp(org)
        .send(client)
        .await
        .ok();
    let mut phone = TotpApp::scanning(&begun.otpauth_uri);
    member_factors::confirm_totp(
        org,
        &ConfirmFactor {
            code: phone.code().await,
            session_id: Some(session_id),
        },
    )
    .send(client)
    .await
    .ok();
    phone
}

/// Ann opens public registration while requiring every tenant user to enroll a second factor.
async fn open_with_required_factor(owner: &Founder, tenant: &TenantPath, phone: &mut TotpApp) {
    let mut settings = tenants::sign_in_settings(tenant)
        .send(owner.client())
        .await
        .ok();
    settings.mfa_policy = MfaPolicy::Required;
    settings
        .rest
        .insert("self_registration".to_owned(), json!(true));
    tenants::replace_sign_in_settings(
        tenant,
        &ReplaceSignInSettings {
            settings,
            proof: PasswordAgain {
                password: FOUNDER_PASSWORD.to_owned(),
                code: Some(phone.code().await),
            },
        },
    )
    .send(owner.client())
    .await
    .ok();
}

/// The tenant is open to the public, but with no mail server no mailbox
/// can be proved. Pat's form is refused without an account or mail;
/// Ann still lists the users.
#[tokio::test]
async fn tenant_self_signup_without_mail_refuses_without_creating_an_account() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::without_mail().with("DEPLOYMENT", "self_hosted"))
        .await
        .expect("the stack starts");
    let offline = installed_without_mail(&stack).await;
    let pat = Client::new(&stack, "Pat, at the public form").expect("a client");
    let email = format!("pat@{}", stack.base_domain());

    let form = TenantSignup {
        email: email.clone(),
        display_name: "Pat Registrant".to_owned(),
        password: PATS_PASSWORD.to_owned(),
    };
    registration::sign_up(&offline.tenant, &form)
        .send(&pat)
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let listed = people::list(&offline.tenant, Some(&email))
        .send(offline.owner.client())
        .await
        .ok();
    assert!(listed.items.is_empty(), "a refused form makes no account");
    stack.mailbox().nothing_for(&email, QUIET).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann invites Uma into the organization; with no mail server, the link
/// is handed back to Ann, who passes it to Uma. Uma joins from it once.
/// The handover proves no mailbox, and Uma cannot read her account before
/// her authenticator is set up. Set up, she reads her own record,
/// an administrator's, with the address unproved; nothing was mailed.
#[tokio::test]
async fn a_handed_over_member_invitation_joins_without_verifying_the_mailbox() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::without_mail().with("DEPLOYMENT", "self_hosted"))
        .await
        .expect("the stack starts");
    let offline = installed_without_mail(&stack).await;
    let org = offline.tenant.organization();
    let email = format!("uma@{}", stack.base_domain());

    let made = invite_member(&offline, &email).await;
    let proof = handed_proof(made.accept_link);

    let mut uma = Client::new(&stack, "Uma, with a handed-over invitation").expect("a client");
    accept_member_once(&uma, org, proof).await;
    let session = sign_in_member(&mut uma, org, &email).await;
    enroll_member(&uma, org, session.session_id).await;
    let own = members::me(org).send(&uma).await.ok();
    assert_eq!(own.id, made.id, "the record read is Uma's own");
    assert!(!own.email_verified, "a handed-over link proves no mailbox");
    assert_eq!(own.role, Some(OrgRole::Admin), "with the role offered");
    stack.mailbox().nothing_for(&email, QUIET).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann offers Uma an administrator seat and receives the link to hand over.
async fn invite_member(offline: &Offline, email: &str) -> MemberInvited {
    members::invite(
        offline.tenant.organization(),
        &InviteMember {
            email: email.to_owned(),
            display_name: "Uma Invitee".to_owned(),
            role: OrgRole::Admin,
        },
    )
    .send(offline.owner.client())
    .await
    .ok()
}

/// Uma can accept the handed proof once, using the password she chose.
async fn accept_member_once(uma: &Client, org: &OrgPath, proof: LinkToken) {
    let accept = AcceptMemberInvitation {
        token: proof.token,
        password: INVITEES_PASSWORD.to_owned(),
    };
    members::accept_invitation(org, &accept)
        .send(uma)
        .await
        .ok();
    members::accept_invitation(org, &accept)
        .send(uma)
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// Uma's password session owes enrollment and cannot yet read her account.
async fn sign_in_member(uma: &mut Client, org: &OrgPath, email: &str) -> Session {
    let answer = sessions::member_sign_in(&PasswordSignIn::of(email, INVITEES_PASSWORD))
        .send(uma)
        .await
        .ok();
    let SignedIn::Authenticated(session) = answer else {
        panic!("Uma is in one organization, so no choice is offered");
    };
    assert_eq!(
        session.owed(),
        Owed::FactorEnrolment,
        "the tenant requires a second factor, so Uma owes one"
    );
    uma.authorize(&session.refresh_token);
    members::me(org)
        .send(uma)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    session
}

/// Ann invites Pat into the tenant as a member; with no mail server, the
/// link is handed back to Ann, who passes it to Pat. Pat joins from it
/// once, which signs nobody in or verifies their mailbox. The next sign-in
/// requires authenticator enrollment. Once enrolled, Pat reads their own
/// unverified record but cannot list the users.
#[tokio::test]
async fn a_handed_over_tenant_invitation_preserves_the_unverified_address() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::without_mail().with("DEPLOYMENT", "self_hosted"))
        .await
        .expect("the stack starts");
    let offline = installed_without_mail(&stack).await;
    let email = format!("pat@{}", stack.base_domain());
    let made = invite_user(&offline, &email).await;
    let proof = handed_proof(made.accept_link);

    let mut pat = Client::new(&stack, "Pat, with a handed-over invitation").expect("a client");
    accept_user_once(&pat, &offline.tenant, proof).await;
    let session = sign_in_user(&mut pat, &offline.tenant, &email).await;
    enroll_user(&pat, &offline.tenant, session.session_id).await;
    let own = people::me(&offline.tenant).send(&pat).await.ok();
    assert_eq!(own.id, made.id, "the record read is Pat's own");
    assert!(!own.email_verified, "a handed-over link proves no mailbox");
    people::list(&offline.tenant, None)
        .send(&pat)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    stack.mailbox().nothing_for(&email, QUIET).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann offers Pat the seeded member role and receives the invitation link to hand over.
async fn invite_user(offline: &Offline, email: &str) -> UserInvited {
    let listed = roles::list(&offline.tenant)
        .send(offline.owner.client())
        .await
        .ok();
    let Some(member_role) = listed.items.iter().find(|role| role.name == MEMBER_ROLE) else {
        panic!("the ready tenant has its seeded Member role");
    };

    people::invite(
        &offline.tenant,
        &InviteUser {
            email: email.to_owned(),
            display_name: "Pat Invitee".to_owned(),
            role_id: member_role.id.clone(),
        },
    )
    .send(offline.owner.client())
    .await
    .ok()
}

/// Pat can accept once, and acceptance alone does not sign the browser in.
async fn accept_user_once(pat: &Client, tenant: &TenantPath, proof: LinkToken) {
    let accept = AcceptInvitation {
        token: proof.token,
        password: INVITEES_PASSWORD.to_owned(),
    };
    people::accept_invitation(tenant, &accept)
        .send(pat)
        .await
        .ok();
    people::accept_invitation(tenant, &accept)
        .send(pat)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    people::me(tenant)
        .send(pat)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Pat's chosen password opens a session that still requires authenticator enrollment.
async fn sign_in_user(pat: &mut Client, tenant: &TenantPath, email: &str) -> TenantSession {
    let answer = sessions::sign_in(
        tenant,
        &TenantPasswordSignIn {
            email: email.to_owned(),
            password: INVITEES_PASSWORD.to_owned(),
            fingerprint_hash: None,
        },
    )
    .send(pat)
    .await
    .ok();
    let TenantSignedIn::Session(session) = answer else {
        panic!("Pat chose the password on accepting, so none is owed");
    };
    assert_eq!(
        session.owed(),
        Owed::FactorEnrolment,
        "the tenant requires a second factor, so Pat owes one"
    );
    pat.authorize(&session.refresh_token);
    session
}

/// Pat confirms the authenticator against the waiting tenant session.
async fn enroll_user(pat: &Client, tenant: &TenantPath, session_id: String) {
    let begun = factors::enroll_totp(tenant, &FactorSetup::default())
        .send(pat)
        .await
        .ok();
    let mut phone = TotpApp::scanning(&begun.otpauth_uri);
    factors::confirm_totp(
        tenant,
        &ConfirmFactor {
            code: phone.code().await,
            session_id: Some(session_id),
        },
    )
    .send(pat)
    .await
    .ok();
}

/// The proof in the `link` handed to the inviter when no mail goes out.
///
/// # Panics
///
/// When no link was handed over, or it carries no token.
fn handed_proof(link: Option<String>) -> LinkToken {
    let link = link.expect("with no mail server, the invitation hands its link to the inviter");
    let link = Url::parse(&link).expect("the handed link is a URL");
    let token = link
        .query_pairs()
        .find(|(name, _)| name == "token")
        .map(|(_, token)| token.into_owned())
        .expect("the handed link carries its token");
    LinkToken { token }
}
