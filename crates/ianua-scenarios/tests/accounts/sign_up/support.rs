//! What the sign-up scenarios share: how long a mailbox is watched for a
//! mail that must not come, a form sent and its link read, a sign-in with
//! a password of the scenario's choosing, the owner's first protected
//! read, the first tenant waited for, the founding's audit trail, a
//! self-hosted installation, and the readiness probe after an outage.

use std::time::{Duration, Instant};

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{OrgPath, TenantPath, audit, members, onboarding, sessions, tenants};
use ianua_scenarios::expect::{Trail, Waiting, eventually, eventually_paced, no_secret_leaked};
use ianua_scenarios::mail::Mail;
use ianua_scenarios::stack::{Install, Installed, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::onboarding::Founded;
use ianua_scenarios::wire::sign_in::{ConfirmSignIn, Owed, PasswordSignIn, Session, SignedIn};
use ianua_scenarios::wire::tenants::TenantStatus;

/// How long a mailbox is watched for a mail that must not come.
pub(super) const QUIET: Duration = Duration::from_secs(3);

/// How long a first tenant's setup is given: the worker's own steps and
/// their retries, on a busy run.
const SETUP_PATIENCE: Duration = Duration::from_secs(90);

/// How often the tenant is read while its setup runs.
const SETUP_EVERY: Duration = Duration::from_secs(1);

/// The most mails passed over before the one awaited, so a missing link
/// fails rather than reading forever.
const PASSED_OVER: usize = 10;

/// The events a founding records in the organization's own trail, each
/// once; the tenant's setup is recorded in the tenant's log.
const FOUNDING_EVENTS: [&str; 5] = [
    "organization.created",
    "organization.tenant_created",
    "organization.org_user_created",
    "organization.org_user_email_verified",
    "organization.subscription_started",
];

/// What a fresh installation founded and the one-time proof it printed.
/// Holds the proof, so it has no `Debug`.
pub(super) struct Installation {
    /// The company, its first tenant and its owner.
    pub(super) founded: Founded,
    /// The proof the installer printed for the owner.
    pub(super) setup_token: String,
}

/// The link mailed to `founder` once their form for `company` is taken:
/// the form is answered "check your inbox", as every form is.
///
/// # Panics
///
/// When the form is refused, or no link comes.
pub(super) async fn requested(stack: &Stack, founder: &Founder, company: &str) -> Mail {
    let answer = onboarding::sign_up(&founder.sign_up_of(company, FOUNDER_PASSWORD))
        .send(founder.client())
        .await;
    assert_eq!(
        answer.status(),
        Status::ACCEPTED,
        "the form is taken for later: {}",
        answer.summary()
    );
    assert_eq!(
        answer.ok().status,
        "check_inbox",
        "the answer sends the founder to their inbox"
    );
    stack.mailbox().next_for(founder.email()).await
}

/// The session `password` opens for `founder`, confirmed from their
/// mailbox when a device they never remembered is asked to, so it owes
/// nothing more: a sign-in with a password the scenario chose, which
/// [`Founder::signed_in`] cannot make.
///
/// # Panics
///
/// When the sign-in is refused, offers a choice, or owes a second factor.
pub(super) async fn signed_in_with(stack: &Stack, founder: &Founder, password: &str) -> Session {
    let answer = sessions::member_sign_in(&PasswordSignIn::of(founder.email(), password))
        .send(founder.client())
        .await
        .ok();
    let SignedIn::Authenticated(session) = answer else {
        panic!(
            "{} is in one organization, so no choice is offered",
            founder.email()
        );
    };
    match session.owed() {
        Owed::Nothing => session,
        Owed::MailedConfirmation => confirmed_from_mailbox(stack, founder, session).await,
        Owed::FactorEnrolment | Owed::FactorCode => {
            panic!(
                "{} set up no second factor, yet owes {:?}",
                founder.email(),
                session.owed()
            )
        }
    }
}

/// The waiting `session` of `founder`, confirmed with the link mailed to
/// them.
///
/// # Panics
///
/// When no link comes, or the confirmation is refused.
async fn confirmed_from_mailbox(stack: &Stack, founder: &Founder, session: Session) -> Session {
    let mail = mail_linking_to(stack, founder.email(), "/confirm-sign-in").await;
    let confirm = ConfirmSignIn {
        token: mail.token_in("/confirm-sign-in"),
        refresh_token: session.refresh_token.clone(),
    };
    let confirmed = sessions::confirm_member_sign_in(&confirm)
        .send(founder.client())
        .await
        .ok();
    assert_eq!(
        confirmed.session_id, session.session_id,
        "the mailed link confirms the sign-in it was sent for"
    );
    session
}

/// The next mail to `email` with a link to `path_prefix`, passing over
/// any other mail that came first, such as a welcome or a notice.
///
/// # Panics
///
/// When no such mail comes, or more than ten others came before it.
pub(super) async fn mail_linking_to(stack: &Stack, email: &str, path_prefix: &str) -> Mail {
    for _ in 0..=PASSED_OVER {
        let mail = stack.mailbox().next_for(email).await;
        if mail
            .links()
            .iter()
            .any(|link| link.path().starts_with(path_prefix))
        {
            return mail;
        }
    }
    panic!("{email} got {PASSED_OVER} mails before one linking to {path_prefix}");
}

/// `founder` signs in and reads their own record on `founded`: they are
/// its owner, at their own address, verified. Their client keeps the
/// session.
///
/// # Panics
///
/// When the sign-in or the read is refused.
pub(super) async fn owner_signed_in(stack: &Stack, founder: &mut Founder, founded: &Founded) {
    let session = founder.signed_in(stack).await;
    founder.client_mut().authorize(&session.refresh_token);
    let owner = members::me(&OrgPath::new(&founded.org_slug))
        .send(founder.client())
        .await
        .ok();
    assert_eq!(owner.id, founded.admin_user_id, "the founder is the owner");
    assert_eq!(owner.email, founder.email(), "at their own address");
    assert!(owner.email_verified, "which the link proved");
}

/// The first tenant of `founded`, once the real worker finished its setup
/// and it is active, read by `founder`: the very tenant founded, not a
/// same-named one of another company, and not one whose setup failed.
///
/// # Panics
///
/// When the setup fails, or does not finish within ninety seconds.
pub(super) async fn ready_tenant(founder: &Founder, founded: &Founded) -> TenantPath {
    let tenant = OrgPath::new(&founded.org_slug).tenant(&founded.tenant_slug);
    let waiting = Waiting {
        patience: SETUP_PATIENCE,
        every: SETUP_EVERY,
    };
    eventually_paced("the first tenant to finish its setup", waiting, || async {
        let found = tenants::get(&tenant).send(founder.client()).await.ok();
        assert_eq!(found.id, founded.tenant_id, "the tenant founded, no other");
        assert_ne!(
            found.setup.state, "failed",
            "the setup failed at {:?}",
            found.setup.failed_step
        );
        (found.status == TenantStatus::Active && found.setup.state == "over").then_some(())
    })
    .await;
    tenant
}

/// The founding of `founded` in the audit trail, as `founder` reads it:
/// each founding event once, done by the owner, with no separate target,
/// and the tenant's setup once in the tenant's log; none of them carrying
/// the password or the link's `token`.
///
/// # Panics
///
/// When a record is missing, doubled, attributed to someone else, or
/// carries a secret.
pub(super) async fn founding_recorded_once(founder: &Founder, founded: &Founded, token: &str) {
    let org = OrgPath::new(&founded.org_slug);
    let trail = Trail::of_organization(founder.client(), &founded.org_slug);
    let owner = members::me(&org).send(founder.client()).await.ok();
    let actor = format!("{} ({})", owner.display_name, owner.email);
    for event in FOUNDING_EVENTS {
        let record = trail.recorded(event).await;
        assert_eq!(trail.count(event).await, 1, "one {event}");
        assert_eq!(record.actor, actor, "{event} was done by the owner");
        assert_eq!(
            record.target_id, None,
            "{event} is about the organization itself, with no separate target"
        );
        no_secret_leaked(&record.details.to_string(), &[FOUNDER_PASSWORD, token]);
    }
    assert_provisioning_record(founder, founded, token, &actor).await;
}

/// The tenant setup is attributed to its founder and exposes neither signup secret.
async fn assert_provisioning_record(
    founder: &Founder,
    founded: &Founded,
    token: &str,
    actor: &str,
) {
    let tenant = OrgPath::new(&founded.org_slug).tenant(&founded.tenant_slug);
    let provisioned = audit::tenant_log(&tenant, "tenant.provisioned")
        .send(founder.client())
        .await
        .ok();
    assert_eq!(provisioned.items.len(), 1, "one tenant.provisioned");
    assert_eq!(
        provisioned.items[0].actor, actor,
        "the tenant was provisioned for the owner"
    );
    assert_eq!(
        provisioned.items[0].tenant_id.as_deref(),
        Some(founded.tenant_id.as_str()),
        "in the tenant founded"
    );
    no_secret_leaked(
        &provisioned.items[0].details.to_string(),
        &[FOUNDER_PASSWORD, token],
    );
}

/// The installation of a self-hosted deployment with `ann` as its owner,
/// as `ianua install` takes it.
pub(super) fn installation_of(ann: &Founder) -> Install {
    Install {
        organization_name: "Acme".to_owned(),
        tenant_name: "Production".to_owned(),
        owner_email: ann.email().to_owned(),
        owner_name: "Ann".to_owned(),
        owner_password: FOUNDER_PASSWORD.to_owned(),
    }
}

/// `install` run on a deployment with no organization yet: what it
/// founded and the proof it printed.
///
/// # Panics
///
/// When the install fails, an organization was already there, or no
/// proof was printed.
pub(super) async fn installed(stack: &Stack, install: &Install) -> Installation {
    let made = stack
        .installed(install)
        .await
        .expect("the install succeeds");
    let Installed::Made {
        founded,
        setup_token,
    } = made
    else {
        panic!("a fresh deployment has no organization, so the install founds one");
    };
    Installation {
        founded,
        setup_token: setup_token.expect("the installer prints a proof for the owner"),
    }
}

/// Waits until `lifetime` has passed on the real clock, which the API,
/// the database and the cache share.
pub(super) async fn past_lifetime(lifetime: Duration) {
    let started = Instant::now();
    eventually("the lifetime to pass", || async {
        (started.elapsed() > lifetime).then_some(())
    })
    .await;
}

/// Waits until the platform's readiness probe answers that it reaches its
/// dependencies again, after one of them was mended.
pub(super) async fn ready_again(stack: &Stack) {
    eventually("the platform to be ready again", || async {
        let probe = reqwest::get(format!("http://{}/health/ready", stack.internal_api()))
            .await
            .ok()?;
        probe.status().is_success().then_some(())
    })
    .await;
}
