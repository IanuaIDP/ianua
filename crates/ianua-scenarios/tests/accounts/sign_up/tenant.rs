//! What a founded company gets: a first tenant of its own, ready, with
//! its seeded roles, read by its owner and by nobody else; and no
//! notification to Ann or Sam about their own founding, nor about each
//! other's company.

use std::time::Instant;

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{TenantPath, roles, tenants};
use ianua_scenarios::expect::{Matrix, eventually, no_secret_leaked};
use ianua_scenarios::mail::Mail;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::onboarding::Founded;
use ianua_scenarios::wire::{Page, Status};
use serde::Deserialize;

use crate::support::{QUIET, founding_recorded_once, owner_signed_in, ready_tenant, requested};

/// The notification kinds that would tell a founder of their own doing:
/// their founding, their mailbox proof and their sign-in.
const PERSONAL_KINDS: [&str; 6] = [
    "Created",
    "TenantCreated",
    "SubscriptionStarted",
    "OrgUserCreated",
    "OrgUserEmailVerified",
    "OrgLoginSucceeded",
];

/// The roles the setup seeds in a first tenant.
const SEEDED_ROLES: [&str; 2] = ["Admin", "Member"];

/// One notification, as the organization's list answers it: its kind,
/// and everything else it says.
#[derive(Deserialize)]
struct Notice {
    /// The kind, as `{"Organization": "Created"}` for a founding.
    event_type: serde_json::Value,
    /// Everything else the notice says.
    #[serde(flatten)]
    rest: serde_json::Value,
}

/// One founder's company and the other's, to read the one's notices
/// against.
struct Founding<'a> {
    /// The founder, signed in.
    owner: &'a Founder,
    /// Their company.
    company: &'a Founded,
    /// The other founder's company, which their notices must not name.
    other: &'a Founded,
    /// The mail their link came in, whose token no notice may carry.
    proof: &'a Mail,
}

/// Ann founds Acme and Sam founds Globex; each opens their link again,
/// which is refused. For a while after, neither founder's notifications
/// say anything of their own founding, mailbox proof or sign-in, nothing
/// of the other's company, and no password or link; the setup's own
/// notices may come.
#[tokio::test]
async fn founders_are_not_notified_of_their_own_founding_or_of_another_company() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let mut sam = Founder::named(&stack, "Sam");
    let anns = requested(&stack, &ann, "Acme").await;
    let acme = confirm_ready_company(&stack, &mut ann, &anns).await;
    let sams = requested(&stack, &sam, "Globex").await;
    let globex = confirm_ready_company(&stack, &mut sam, &sams).await;

    assert_replayed_proof(&ann, &anns).await;
    assert_replayed_proof(&sam, &sams).await;
    let foundings = [
        Founding {
            owner: &ann,
            company: &acme,
            other: &globex,
            proof: &anns,
        },
        Founding {
            owner: &sam,
            company: &globex,
            other: &acme,
            proof: &sams,
        },
    ];
    watch_founding_notices(&foundings).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// The mailed proof creates the company, whose owner signs in before its tenant is ready.
async fn confirm_ready_company(stack: &Stack, founder: &mut Founder, proof: &Mail) -> Founded {
    let company = founder.confirmed_sign_up(proof).await.ok();
    owner_signed_in(stack, founder, &company).await;
    ready_tenant(founder, &company).await;
    company
}

/// The founder cannot reuse the proof after their company exists.
async fn assert_replayed_proof(founder: &Founder, proof: &Mail) {
    founder
        .confirmed_sign_up(proof)
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// Both founders' notifications stay free of personal events throughout the watch.
async fn watch_founding_notices(foundings: &[Founding<'_>]) {
    let watched_from = Instant::now();
    eventually("the notices to be watched for a while", || async {
        for founding in foundings {
            notices_say_nothing_personal(founding).await;
        }
        (watched_from.elapsed() > QUIET).then_some(())
    })
    .await;
}

/// Ann founds Acme and Sam founds Globex, each with a first tenant called
/// production. Both tenants are set up by the real worker; each owner
/// reads their own, with its seeded Admin and Member roles, and is
/// refused the other's. Each founding is recorded once, by its owner,
/// with no secret in it.
#[tokio::test]
async fn two_founded_companies_get_separate_usable_tenants() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let mut sam = Founder::named(&stack, "Sam");
    let anns = requested(&stack, &ann, "Acme").await;
    let sams = requested(&stack, &sam, "Globex").await;

    let acme = ann.confirmed_sign_up(&anns).await.ok();
    let globex = sam.confirmed_sign_up(&sams).await.ok();
    assert_eq!(acme.status, "provisioning", "the tenant's setup runs on");
    assert_eq!(
        acme.tenant_slug, globex.tenant_slug,
        "both first tenants have the same slug"
    );
    assert_ne!(acme.tenant_id, globex.tenant_id, "and are two tenants");

    owner_signed_in(&stack, &mut ann, &acme).await;
    owner_signed_in(&stack, &mut sam, &globex).await;
    let acmes = ready_tenant(&ann, &acme).await;
    let globexs = ready_tenant(&sam, &globex).await;
    for (tenant, owner, stranger) in [(&acmes, &ann, &sam), (&globexs, &sam, &ann)] {
        assert_tenant_access(tenant, owner, stranger).await;
    }

    founding_recorded_once(&ann, &acme, &anns.token_in("/signup/confirm")).await;
    founding_recorded_once(&sam, &globex, &sams.token_in("/signup/confirm")).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A ready tenant belongs to its founder alone and contains both seeded roles.
async fn assert_tenant_access(tenant: &TenantPath, owner: &Founder, stranger: &Founder) {
    Matrix::new("reading the ready tenant", tenants::get(tenant).call())
        .allowed(owner.client())
        .refused(stranger.client(), Status::FORBIDDEN, "forbidden")
        .run()
        .await;
    let seeded = roles::list(tenant).send(owner.client()).await.ok();
    for name in SEEDED_ROLES {
        assert!(
            seeded.items.iter().any(|role| role.name == name),
            "the setup seeds {name}"
        );
    }
}

/// The notices of `founding`'s company, as its owner reads them now, say
/// nothing personal, name nothing of the other company, and carry no
/// password or link token.
async fn notices_say_nothing_personal(founding: &Founding<'_>) {
    let path = format!(
        "/api/v1/organizations/{}/notifications?limit=100",
        founding.company.org_slug
    );
    let notices = founding
        .owner
        .client()
        .get::<Page<Notice>>(&path)
        .await
        .ok();
    for notice in notices.items {
        assert_notice_privacy(founding, &notice);
    }
}

/// A notification reveals no personal event, other company identifier or signup secret.
fn assert_notice_privacy(founding: &Founding<'_>, notice: &Notice) {
    let kind = notice
        .event_type
        .get("Organization")
        .and_then(serde_json::Value::as_str);
    assert!(
        !kind.is_some_and(|kind| PERSONAL_KINDS.contains(&kind)),
        "a founder is not told of their own {kind:?}"
    );
    let said = notice.rest.to_string();
    assert!(
        !said.contains(&founding.other.organization_id),
        "a notice names no other company"
    );
    assert!(
        !said.contains(&founding.other.tenant_id),
        "a notice names no other company's tenant"
    );
    no_secret_leaked(
        &said,
        &[
            FOUNDER_PASSWORD,
            &founding.proof.token_in("/signup/confirm"),
        ],
    );
}
