//! Receiving an app sign-in request from the gateway.

use std::sync::Arc;

use ianua_domain::types::{IpAddress, UserAgent};

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::authentication::{NonceLedger, RequestSeal, WIRE_VERSION, WireRequest};
use crate::ports::shared::PreferredLanguages;
use crate::services::gateway_relay::{AnswerSeal, RelayReply, Relayed, opened};
use crate::tenancy::ScopedTenant;
use crate::use_case::{Command, Query};
use crate::use_cases::authentication::app_sign_in::relay::wire_command::{Received, command};
use crate::use_cases::authentication::app_sign_in::{
    AppSignInActions, AppSignInCommand, AppSignInContext, AppSignInOutcome,
    HandOverAppSessionUseCase,
};

/// The ports for receiving requests from the gateway.
#[derive(ianua_macros::Fakes)]
pub struct ReceivePorts {
    /// Port for checking the gateway's seal.
    pub seal: Arc<dyn RequestSeal>,
    /// Port for refusing a request sent twice.
    pub nonces: Arc<dyn NonceLedger>,
}

/// A request the gateway relayed, as it arrived.
pub struct ReceiveRequest {
    /// The request body, exactly as sealed.
    pub body: Vec<u8>,
    /// The gateway's seal over the body, if it sent one.
    pub seal: Option<String>,
}

/// Opens a sealed request from the gateway and carries it out.
pub struct ReceiveUseCase {
    ports: ReceivePorts,
    sign_in: Arc<AppSignInActions>,
    hand_over: Arc<HandOverAppSessionUseCase>,
}

impl ReceiveUseCase {
    /// A use case opening requests through `ports` and carrying them out
    /// with `sign_in`, or `hand_over` for a hop.
    #[must_use]
    pub fn new(
        ports: ReceivePorts,
        sign_in: Arc<AppSignInActions>,
        hand_over: Arc<HandOverAppSessionUseCase>,
    ) -> Self {
        Self {
            ports,
            sign_in,
            hand_over,
        }
    }

    /// Hands `command` to the use case for its action.
    // One arm per action, with no catch-all: a new action must be given its
    // use case here before it builds. Splitting it would bring a catch-all
    // back, and an action nobody answers would pass the compiler.
    #[allow(clippy::too_many_lines)]
    async fn carry_out(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
        command: AppSignInCommand,
    ) -> Result<AppSignInOutcome, AppError> {
        let actions = &self.sign_in;
        match command {
            AppSignInCommand::LogIn(request) => actions.log_in.execute(ctx, auditor, request).await,
            AppSignInCommand::CompleteMfa(request) => {
                actions.complete_mfa.execute(ctx, auditor, request).await
            }
            AppSignInCommand::ConfirmByEmail(request) => {
                actions
                    .confirm_by_email
                    .execute(ctx, auditor, request)
                    .await
            }
            AppSignInCommand::SignUp(request) => {
                actions.sign_up.execute(ctx, auditor, request).await
            }
            AppSignInCommand::Verify(token) => {
                actions.verify_email.execute(ctx, auditor, token).await
            }
            AppSignInCommand::LogOut(session) => {
                actions.log_out.execute(ctx, auditor, session).await
            }
            AppSignInCommand::IssueToken(request) => {
                actions.issue_token.execute(ctx, auditor, request).await
            }
            AppSignInCommand::IssueHop(request) => {
                actions.issue_hop.execute(ctx, auditor, request).await
            }
            AppSignInCommand::ShowPage(request) => {
                Query::execute(&actions.show_page, ctx, request).await
            }
            AppSignInCommand::SsoStart(request) => {
                actions.sso_start.execute(ctx, auditor, request).await
            }
            AppSignInCommand::SsoCallback(request) => {
                actions.sso_callback.execute(ctx, auditor, request).await
            }
            AppSignInCommand::PasskeyBegin(email) => {
                actions.passkey_begin.execute(ctx, auditor, email).await
            }
            AppSignInCommand::PasskeyConfirm(request) => {
                actions.passkey_confirm.execute(ctx, auditor, request).await
            }
            AppSignInCommand::ForgotPassword(email) => {
                actions.forgot_password.execute(ctx, auditor, email).await
            }
            AppSignInCommand::ResetPassword(request) => {
                actions.reset_password.execute(ctx, auditor, request).await
            }
            AppSignInCommand::ChangePassword(request) => {
                actions.change_password.execute(ctx, auditor, request).await
            }
        }
    }

    /// Carries out `request`, an opened request, for the client inside it.
    async fn answer(
        &self,
        auditor: &RequestAuditor,
        request: WireRequest,
    ) -> Result<AppSignInOutcome, AppError> {
        let ctx = context(&request);
        let languages =
            PreferredLanguages::from_accept_language(request.ctx.accept_language.as_deref());
        let auditor = auditor.with_request(ctx.ip_address.clone(), ctx.user_agent.clone());
        let outcome = match command(request.command)? {
            Received::OnOwnerHost(command) => self.carry_out(&ctx, &auditor, command).await,
            Received::Hop(landing) => self.hand_over.execute(&ctx, &auditor, landing).await,
        };
        outcome.map(|outcome| in_languages(outcome, languages))
    }
}

impl Command for ReceiveUseCase {
    type Caller = ();
    type Input = ReceiveRequest;
    type Output = RelayReply<AppSignInOutcome>;

    /// Checks that the body came from the gateway, recently and once,
    /// carries it out, and hands back the seal binding the outcome to the
    /// request.
    ///
    /// `auditor` arrives knowing nothing of the client: the address and user
    /// agent are inside the sealed body, and are added once it is opened.
    ///
    /// The outcome is an error when:
    ///
    /// - `AppError::Unauthenticated`: the seal is missing or wrong, the
    ///   request is stale or was seen before, or it cannot be read. Nothing
    ///   about it is trusted, so nothing more is said, and the reply
    ///   carries no seal.
    /// - `AppError::Domain`: what the person entered is not well formed.
    /// - Anything the action's use case or [`HandOverAppSessionUseCase`]
    ///   reports.
    async fn execute(
        &self,
        _: &(),
        auditor: &RequestAuditor,
        request: ReceiveRequest,
    ) -> RelayReply<AppSignInOutcome> {
        let ReceiveRequest { body, seal } = request;
        let relayed = Relayed {
            body: &body,
            seal: seal.as_deref(),
        };
        let request: WireRequest = match opened(
            self.ports.seal.as_ref(),
            self.ports.nonces.as_ref(),
            relayed,
            WIRE_VERSION,
        )
        .await
        {
            Ok(request) => request,
            Err(refused) => return RelayReply::unopened(refused),
        };
        let seal = AnswerSeal::new(request.ctx.nonce.clone(), self.ports.seal.clone());
        RelayReply {
            answer: self.answer(auditor, request).await,
            seal: Some(seal),
        }
    }
}

/// The request's context. The tenant is the one the gateway resolved from the
/// host the connection came in on. An address or client that does not read
/// as one is left unknown.
fn context(request: &WireRequest) -> AppSignInContext {
    let ctx = &request.ctx;
    AppSignInContext {
        tenant: ScopedTenant::from_request_host(ctx.tenant_id),
        service_id: ctx.service_id,
        host: ctx.host.clone(),
        ip_address: ctx.client_ip.clone().and_then(|ip| IpAddress::new(ip).ok()),
        user_agent: ctx
            .user_agent
            .clone()
            .and_then(|ua| UserAgent::new(ua).ok()),
    }
}

/// `outcome`, a page among them drawn in the languages the person reads.
fn in_languages(outcome: AppSignInOutcome, languages: PreferredLanguages) -> AppSignInOutcome {
    let AppSignInOutcome::Page(mut page) = outcome else {
        return outcome;
    };
    page.languages = languages;
    AppSignInOutcome::Page(page)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::routing::sign_in::app::{SignInAction, SignInPath};
    use ianua_domain::types::{DomainName, Nonce, ServiceId, TenantId};

    use super::*;
    use crate::ports::authentication::{MAX_SKEW_SECS, WireCommand, WireContext};
    use crate::ports::pages::SignInPage;
    use crate::test_support::authentication::{FakeNonceLedger, TagSeal};
    use crate::test_support::block_on;

    fn request(ts: i64, nonce: &str) -> WireRequest {
        WireRequest {
            v: WIRE_VERSION,
            ctx: WireContext {
                tenant_id: TenantId::new(),
                service_id: ServiceId::new(),
                host: DomainName::new("shop.example.com").unwrap(),
                client_ip: Some("203.0.113.7".to_owned()),
                user_agent: Some("Browser/1.0".to_owned()),
                accept_language: Some("de-AT, en;q=0.5".to_owned()),
                ts,
                nonce: Nonce::new(format!("{nonce}-nonce-of-length")).unwrap(),
            },
            command: WireCommand::LogOut { session: None },
        }
    }

    /// The gateway relays a request for the shop. Its context names the
    /// gateway's tenant, service, host and the client's address.
    #[test]
    fn the_context_names_the_gateways_tenant_service_and_host() {
        let req = request(0, "n");

        let ctx = context(&req);

        assert_eq!(*ctx.tenant, req.ctx.tenant_id);
        assert_eq!(ctx.service_id, req.ctx.service_id);
        assert_eq!(ctx.host.as_str(), "shop.example.com");
        assert_eq!(ctx.ip_address.unwrap().as_str(), "203.0.113.7");
    }

    /// Ann's browser asks for German. The page the use case answers with is
    /// to be drawn in German; any other outcome is left as it is.
    #[test]
    fn a_page_carries_the_languages_the_browser_asked_for() {
        let languages = PreferredLanguages::from_accept_language(Some("de-AT, en;q=0.5"));
        let path = |value: &str| SignInPath::new(value).unwrap();
        let page = SignInPage {
            action: SignInAction::LogIn,
            workspace: "Acme".to_owned(),
            branding: None,
            form_path: path("/.ianua/login"),
            log_in_path: path("/.ianua/login"),
            sign_up_path: None,
            forgot_password_path: None,
            passkey_path: None,
            passkey_script_path: None,
            sso_path: path("/.ianua/sso"),
            single_sign_on: Vec::new(),
            note: None,
            return_to: None,
            link_token: None,
            languages: PreferredLanguages::default(),
        };

        let outcome = in_languages(AppSignInOutcome::Page(Box::new(page)), languages);

        let AppSignInOutcome::Page(page) = outcome else {
            panic!("a page stays a page");
        };
        assert_eq!(page.languages.tags(), ["de-AT", "en"]);
        assert!(matches!(
            in_languages(AppSignInOutcome::Accepted, PreferredLanguages::default()),
            AppSignInOutcome::Accepted
        ));
    }

    fn now() -> i64 {
        ianua_domain::shared::clock::now().unix_timestamp()
    }

    fn body(req: &WireRequest) -> Vec<u8> {
        serde_json::to_vec(req).unwrap()
    }

    fn open_with(
        ledger: &FakeNonceLedger,
        body: &[u8],
        seal: Option<&str>,
    ) -> Result<WireRequest, AppError> {
        block_on(opened(
            &TagSeal,
            ledger,
            Relayed { body, seal },
            WIRE_VERSION,
        ))
    }

    /// The gateway relays a sealed request just now, for the first time. It
    /// opens.
    #[test]
    fn a_sealed_current_new_request_opens() {
        let body = body(&request(now(), "n1"));

        assert!(
            open_with(
                &FakeNonceLedger::default(),
                &body,
                Some(&TagSeal.seal(&body))
            )
            .is_ok()
        );
    }

    /// Missing, empty, and incorrect seals all leave a relayed request
    /// unauthenticated.
    #[test]
    fn an_unsealed_or_wrongly_sealed_request_is_refused() {
        let body = body(&request(now(), "n1"));

        for seal in [None, Some("tag:0"), Some("")] {
            assert!(matches!(
                open_with(&FakeNonceLedger::default(), &body, seal),
                Err(AppError::Unauthenticated)
            ));
        }
    }

    /// A seal made for one request does not open a different request body
    /// naming an attacker-controlled host.
    #[test]
    fn an_altered_body_is_refused() {
        let original = body(&request(now(), "n1"));
        let seal = TagSeal.seal(&original);
        let mut altered_request = request(now(), "n1");
        altered_request.ctx.host = DomainName::new("evil.example.com.attacker").unwrap();

        let altered = body(&altered_request);

        assert!(open_with(&FakeNonceLedger::default(), &altered, Some(&seal)).is_err());
    }

    /// A correctly sealed request older than the allowed clock skew is
    /// refused.
    #[test]
    fn a_stale_request_is_refused() {
        let body = body(&request(now() - MAX_SKEW_SECS - 1, "n1"));

        assert!(
            open_with(
                &FakeNonceLedger::default(),
                &body,
                Some(&TagSeal.seal(&body))
            )
            .is_err()
        );
    }

    /// A fresh sealed request opens once; repeating it with the same nonce
    /// returns unauthenticated.
    #[test]
    fn a_request_sent_twice_is_refused_the_second_time() {
        let ledger = FakeNonceLedger::default();
        let body = body(&request(now(), "n1"));
        let seal = TagSeal.seal(&body);

        assert!(open_with(&ledger, &body, Some(&seal)).is_ok());
        assert!(matches!(
            open_with(&ledger, &body, Some(&seal)),
            Err(AppError::Unauthenticated)
        ));
    }

    /// A request with a forged seal leaves the nonce ledger unspent.
    #[test]
    fn a_forged_request_spends_no_nonce() {
        let ledger = FakeNonceLedger::default();
        let body = body(&request(now(), "n1"));

        let _ = open_with(&ledger, &body, Some("forged"));

        assert_eq!(ledger.spent(), 0);
    }

    /// A correctly sealed request naming another protocol version is refused.
    #[test]
    fn another_protocol_version_is_refused() {
        let mut req = request(now(), "n1");
        req.v = WIRE_VERSION + 1;
        let body = body(&req);

        assert!(
            open_with(
                &FakeNonceLedger::default(),
                &body,
                Some(&TagSeal.seal(&body))
            )
            .is_err()
        );
    }
}
