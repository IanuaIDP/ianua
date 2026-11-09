//! Money an agent moves, held at the gateway for two different people:
//! Tess declares the payments app's route as moving money, and Ann's grant
//! makes every call of Reporter's there wait. Bea and Cal, administrators
//! with authenticator apps, each answer a fresh code as they approve. One
//! approval moves nothing, the same person twice and a code already spent
//! are refused, and the second, different person releases the payment
//! once.

use std::time::Duration;

use ianua_scenarios::actors::Member;
use ianua_scenarios::agent::external::ExternalAgent;
use ianua_scenarios::api::agents::approvals;
use ianua_scenarios::api::{member_factors, routing};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::expect::{Waiting, eventually_paced};
use ianua_scenarios::net::Call;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::agents::approvals::{Approval, FreshCode};
use ianua_scenarios::wire::agents::authority::Capabilities;
use ianua_scenarios::wire::factors::ConfirmFactor;
use ianua_scenarios::wire::organization::OrgRole;
use ianua_scenarios::wire::routing::DeclaredAction;
use ianua_scenarios::wire::sign_in::{MemberFactorSetup, MemberProof};
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;
use serde_json::json;

use super::{App, VIEW_USERS, bound_grant, granted_agent, opened, proven};
use crate::support::{Witness, profile};

/// How long Reporter's payment is tried until the gateway holds it as one
/// moving money, and how often: each try is a payment of its own, well
/// under the requests a delegation may keep open.
const DECLARED: Waiting = Waiting {
    patience: Duration::from_secs(30),
    every: Duration::from_secs(2),
};

/// A colleague who may approve a call moving money: an administrator of
/// the organization, behind neither Reporter nor its grant, with an
/// authenticator app whose fresh code each approval takes.
struct Approver {
    member: Member,
    phone: TotpApp,
}

impl Approver {
    /// `display_name`, invited by Ann as an administrator, signed in to the
    /// tenant, who set up an authenticator app from that session.
    async fn joined(world: &World<'_>, name: &str, display_name: &str) -> Self {
        let mut member = world.colleague(name, display_name, OrgRole::Admin).await;
        member.land_in(world.tenant().slug());
        member.sign_in(world.stack()).await;
        let setup = MemberFactorSetup {
            proof: MemberProof {
                password: member.password().to_owned(),
                code: None,
            },
        };
        let begun = member_factors::begin_totp(world.org(), &setup)
            .send(member.client())
            .await
            .ok();
        let mut phone = TotpApp::scanning(&begun.otpauth_uri);
        let confirm = ConfirmFactor {
            code: phone.code().await,
            session_id: None,
        };
        member_factors::confirm_totp(world.org(), &confirm)
            .send(member.client())
            .await
            .ok();
        Self { member, phone }
    }

    /// Their approval of `held`, with the code their app shows now.
    async fn approves(&mut self, world: &World<'_>, held: &Approval) -> Answer<Approval> {
        let code = FreshCode {
            mfa_code: self.phone.code().await,
        };
        self.answered(world, held, &code).await
    }

    /// Their approval of `held` with the last code their app showed, which
    /// they already spent.
    async fn approves_with_a_spent_code(
        &self,
        world: &World<'_>,
        held: &Approval,
    ) -> Answer<Approval> {
        let code = FreshCode {
            mfa_code: self.phone.last_code_again(),
        };
        self.answered(world, held, &code).await
    }

    /// Their approval of `held` answering `code`.
    async fn answered(
        &self,
        world: &World<'_>,
        held: &Approval,
        code: &FreshCode,
    ) -> Answer<Approval> {
        approvals::approve_with_code(world.tenant(), &held.agent_id, &held.id, code)
            .send(self.member.client())
            .await
    }
}

/// A payment Reporter makes and the request holding it for two people.
struct HeldPayment {
    /// The payment's path on the app.
    path: String,
    /// The request two people must approve.
    approval: Approval,
}

/// What Reporter is told when it makes the payment at `path` on `app`.
async fn pays(reporter: &ExternalAgent, app: &App, path: &str) -> Answer<IgnoredAny> {
    let url = app.url(path);
    let payment = Call::post(url.as_str()).json(&json!({"amount": 120, "currency": "EUR"}));
    reporter
        .client()
        .send::<IgnoredAny>(proven(reporter, payment, "POST", &url))
        .await
}

/// A payment Reporter makes once the gateway holds it as moving money:
/// each try is a new payment, so a request held before Tess's declaration
/// reached the gateway is left behind rather than read as this one.
async fn held_payment(world: &World<'_>, reporter: &ExternalAgent, app: &App) -> HeldPayment {
    let mut tries = 0_u32;
    eventually_paced("a payment held for two people", DECLARED, || {
        tries += 1;
        let path = format!("/payments/{tries}");
        async move {
            pays(reporter, app, &path)
                .await
                .refused(Status::UNAUTHORIZED, "unauthenticated");
            let pending = approvals::list(world.tenant(), reporter.id(), Some("pending"))
                .send(world.admin().client())
                .await
                .ok();
            let approval = pending.into_iter().find(|approval| {
                approval.action.ends_with(&path) && approval.approvers_needed == 2
            })?;
            Some(HeldPayment { path, approval })
        }
    })
    .await
}

/// Tess declares the payments route as moving money, and Ann's grant makes
/// Reporter's every call there wait. Reporter's payment is held for two
/// people, and the platform names it a financial action. Bea approves with
/// a fresh code: the request still waits, naming her as the first, and the
/// payment is still held. Bea again, with another fresh code, is refused:
/// one person cannot be both. Cal, with a code he already spent setting up
/// his app, is refused. Cal with a fresh code approves, and the payment
/// goes through once; paying again is held anew. The app saw one payment.
#[tokio::test]
async fn money_moves_once_two_different_people_approve_it_each_with_a_fresh_code() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let app = opened(&stack, &world, "/payments/*", Vec::new()).await;
    let declared = DeclaredAction {
        action_class: "Financial".to_owned(),
    };
    routing::declare_action(world.tenant(), &app.route.route_id, &declared)
        .send(world.admin().client())
        .await
        .ok();
    let mut grant = bound_grant(
        app.service_id(),
        "Pay suppliers, asking each time",
        Capabilities::http(&[VIEW_USERS]),
    );
    grant.limits.requires_approval = true;
    let reporter = granted_agent(&stack, &world, "Reporter", &grant).await;
    let mut bea = Approver::joined(&world, "bea", "Bea Approver").await;
    let mut cal = Approver::joined(&world, "cal", "Cal Approver").await;
    let mut witness = Witness::of(&world).await;

    let held = held_payment(&world, &reporter, &app).await;
    assert_eq!(held.approval.purpose.as_deref(), Some("financial"));
    assert!(
        app.echo.arrivals().is_empty(),
        "a held payment reached the app"
    );

    let first = bea.approves(&world, &held.approval).await.ok();
    assert_eq!(first.status, "pending", "one approval moves no money");
    assert_eq!(
        first.first_approved_by.map(|by| by.id),
        Some(bea.member.id().to_owned()),
        "the request names Bea as the first to approve"
    );
    pays(&reporter, &app, &held.path)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    bea.approves(&world, &held.approval)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    cal.approves_with_a_spent_code(&world, &held.approval)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    assert!(
        app.echo.arrivals().is_empty(),
        "no payment went through yet"
    );

    let second = cal.approves(&world, &held.approval).await.ok();
    assert_eq!(second.status, "approved");
    witness.recorded("agents.approval_granted").await;
    pays(&reporter, &app, &held.path).await.ok();
    pays(&reporter, &app, &held.path)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_eq!(
        app.echo.arrivals().len(),
        1,
        "the payment went through once"
    );
    stack.stop().await.expect("the stack stops cleanly");
}
