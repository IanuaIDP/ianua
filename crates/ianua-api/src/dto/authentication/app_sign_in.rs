//! What the API answers the gateway with for a sign-in it relayed: plain
//! values it turns into cookies and redirects, and pages already drawn
//! through the [`PageRenderer`] port.

use axum::Extension;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ianua_app::error::AppError;
use ianua_app::ports::authentication::{WireHop, WireOutcome};
use ianua_app::ports::pages::{DrawnPage, PageRenderer, SignInPage};
use ianua_app::services::gateway_relay::AnswerSeal;
use ianua_app::use_cases::authentication::app_sign_in::AppSignInOutcome;

use crate::dto::authentication::password::proof_name;
use crate::error::app_sign_in::rejection;
use crate::middleware::answer_floor::HeldToLinkFloor;
use crate::response::relay::SealedAnswer;

/// The answer to a relayed sign-in.
///
/// A request the gateway did not seal, or sent before, is answered `401`
/// with an empty body. Everything else is answered `200` with a typed
/// outcome, refusals included, so the gateway can tell "the person was
/// refused" from "the API could not be asked".
pub(crate) enum RelayAnswer {
    /// The outcome, or the refusal, for the gateway to act on.
    Answered(WireOutcome),
    /// Unsealed, stale or seen before: nothing about it is trusted.
    Unsealed,
}

impl RelayAnswer {
    /// The answer to `outcome`, its page drawn through `pages`. A page that
    /// cannot be drawn is refused like any failure, never sent half drawn.
    #[must_use]
    pub(crate) fn new(
        outcome: Result<AppSignInOutcome, AppError>,
        pages: &dyn PageRenderer,
    ) -> Self {
        match outcome.and_then(|outcome| wire_outcome(outcome, pages)) {
            Ok(outcome) => Self::Answered(outcome),
            Err(AppError::Unauthenticated) => Self::Unsealed,
            Err(refused) => {
                let (status, code) = rejection(&refused);
                Self::Answered(WireOutcome::Rejected { status, code })
            }
        }
    }
}

impl RelayAnswer {
    /// The outcome as JSON sealed through `seal` for the request it
    /// answers, or a bare `401`. `Accepted` is the answer a sign-up or a
    /// request for a reset link gives whether or not the address has an
    /// account, so it is marked to be held to the link request floor, and
    /// its timing says nothing either.
    #[must_use]
    pub(crate) fn sealed(self, seal: Option<AnswerSeal>) -> Response {
        match self {
            Self::Answered(WireOutcome::Accepted) => (
                Extension(HeldToLinkFloor),
                SealedAnswer::new(WireOutcome::Accepted, seal),
            )
                .into_response(),
            Self::Answered(outcome) => SealedAnswer::new(outcome, seal).into_response(),
            Self::Unsealed => StatusCode::UNAUTHORIZED.into_response(),
        }
    }
}

/// The gateway's view of `outcome`, a page drawn through `pages`.
///
/// # Errors
///
/// `AppError::Internal` when the page cannot be drawn.
///
/// The exhaustive transport mapping keeps every outcome and its wire fields together.
#[allow(clippy::too_many_lines)]
fn wire_outcome(
    outcome: AppSignInOutcome,
    pages: &dyn PageRenderer,
) -> Result<WireOutcome, AppError> {
    Ok(match outcome {
        AppSignInOutcome::SignedIn {
            session,
            return_to,
            hops,
            remembered,
        } => WireOutcome::SignedIn {
            token: session.token.expose().to_owned(),
            expires_at: session.expires_at.unix_timestamp(),
            return_to: return_to.as_str().to_owned(),
            hops: hops.into_iter().map(|host| WireHop { host }).collect(),
            remembered_device: remembered.map(|secret| secret.as_str().to_owned()),
        },
        AppSignInOutcome::HopIssued(hop) => WireOutcome::HopIssued {
            host: hop.host,
            code: hop.code.expose().to_owned(),
        },
        AppSignInOutcome::HandedOver(session) => WireOutcome::HandedOver {
            token: session.token.expose().to_owned(),
            expires_at: session.expires_at.unix_timestamp(),
        },
        AppSignInOutcome::Token(issued) => WireOutcome::Token {
            access_token: issued.token.expose().to_owned(),
            expires_at: issued.expires_at.unix_timestamp(),
        },
        AppSignInOutcome::MfaRequired {
            challenge,
            expires_at,
        } => WireOutcome::MfaRequired {
            challenge: challenge.expose().to_owned(),
            expires_at: expires_at.unix_timestamp(),
        },
        AppSignInOutcome::ConfirmByEmail {
            challenge,
            expires_at,
        } => WireOutcome::ConfirmByEmail {
            challenge: challenge.expose().to_owned(),
            expires_at: expires_at.unix_timestamp(),
        },
        AppSignInOutcome::PasswordChangeRequired {
            challenge,
            proof,
            reason,
            expires_at,
        } => WireOutcome::PasswordChangeRequired {
            challenge: challenge.map(|token| token.expose().to_owned()),
            proof: proof_name(proof).to_owned(),
            reason: reason.as_str().to_owned(),
            expires_at: expires_at.unix_timestamp(),
        },
        AppSignInOutcome::SsoRedirect {
            url,
            binding,
            hand_back,
            return_to,
        } => WireOutcome::SsoRedirect {
            url: url.as_str().to_owned(),
            binding: binding.expose().to_owned(),
            hand_back: hand_back.expose().to_owned(),
            return_to: return_to.map(|path| path.as_str().to_owned()),
        },
        AppSignInOutcome::PasskeyChallenge(started) => WireOutcome::PasskeyChallenge {
            ceremony_id: started.ceremony_id,
            options: started.challenge,
        },
        AppSignInOutcome::SignedOut => WireOutcome::SignedOut,
        AppSignInOutcome::Accepted => WireOutcome::Accepted,
        AppSignInOutcome::Page(page) => wire_page(&page, pages)?,
    })
}

/// Draws the entire page before handing its HTML to the gateway.
fn wire_page(page: &SignInPage, pages: &dyn PageRenderer) -> Result<WireOutcome, AppError> {
    Ok(WireOutcome::Page {
        html: pages
            .sign_in_page(page)
            .map(DrawnPage::into_html)
            .map_err(AppError::from_domain)?,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_app::ports::authentication::{RequestSeal as _, SEAL_HEADER};
    use ianua_app::ports::pages::{ErrorPage, SignInPage};
    use ianua_app::test_support::authentication::TagSeal;
    use ianua_app::test_support::pages::FakePageRenderer;
    use ianua_app::use_cases::authentication::app_sign_in::Hop;
    use ianua_domain::domains::authentication::credentials::password_rules::ChangeReason;
    use ianua_domain::domains::authentication::recovery::change_proof::ChangeProof;
    use ianua_domain::domains::routing::sign_in::app::{SignInAction, SignInPath};
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{DomainName, Nonce};

    use super::*;

    /// A renderer whose templates are broken: it draws nothing.
    struct BrokenPageRenderer;

    impl PageRenderer for BrokenPageRenderer {
        fn sign_in_page(&self, _: &SignInPage) -> Result<DrawnPage, DomainError> {
            Err(DomainError::infra_msg("the template does not parse"))
        }

        fn error_page(&self, _: &ErrorPage) -> Result<DrawnPage, DomainError> {
            Err(DomainError::infra_msg("the template does not parse"))
        }
    }

    /// The answer to `outcome`, its pages drawn by the fake.
    fn relayed(outcome: Result<AppSignInOutcome, AppError>) -> RelayAnswer {
        RelayAnswer::new(outcome, &FakePageRenderer)
    }

    /// The login page of the Acme workspace, with nothing more on it.
    fn login_page() -> AppSignInOutcome {
        let path = |value: &str| SignInPath::new(value).unwrap();
        AppSignInOutcome::Page(Box::new(SignInPage {
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
            languages: ianua_app::ports::shared::PreferredLanguages::default(),
        }))
    }

    /// Ann opens the shop's login page. The gateway is handed the page the
    /// renderer drew for it.
    #[test]
    fn a_page_is_handed_over_as_drawn() {
        let answer = relayed(Ok(login_page()));

        let RelayAnswer::Answered(WireOutcome::Page { html }) = answer else {
            panic!("the page is handed to the gateway");
        };
        assert_eq!(html, "<p>LogIn on Acme</p>");
    }

    /// A renderer failure becomes a rejected answer with status 500.
    #[test]
    fn a_page_that_cannot_be_drawn_is_refused() {
        let answer = RelayAnswer::new(Ok(login_page()), &BrokenPageRenderer);

        let RelayAnswer::Answered(WireOutcome::Rejected { status, .. }) = answer else {
            panic!("an undrawn page is refused");
        };
        assert_eq!(status.code(), 500);
    }

    /// An unsealed, unauthenticated request receives 401 without an answer seal.
    #[test]
    fn an_unsealed_request_is_answered_401_with_nothing_more() {
        let response = relayed(Err(AppError::Unauthenticated)).sealed(None);

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(SEAL_HEADER).is_none());
    }

    /// Ann signs out on the shop. The gateway is handed the outcome sealed
    /// over the exact bytes sent and bound to the request's nonce, so no
    /// one else on the internal network can answer in the API's place.
    #[tokio::test]
    async fn an_outcome_goes_sealed_for_its_request() {
        let nonce = Nonce::new("sign-out-nonce-of-length").unwrap();
        let seal = AnswerSeal::new(nonce.clone(), Arc::new(TagSeal));

        let response = relayed(Ok(AppSignInOutcome::SignedOut)).sealed(Some(seal));

        assert_eq!(response.status(), StatusCode::OK);
        let sealed = response.headers()[SEAL_HEADER].to_str().unwrap().to_owned();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(TagSeal.verifies_answer(&nonce, &body, &sealed));
    }

    /// Ann tries to sign up where sign-up is off. The gateway hears `200`
    /// carrying the refusal's status and code, so it knows she was refused
    /// rather than that the API could not be asked.
    #[test]
    fn a_refusal_is_answered_200_with_its_status_and_code() {
        let answer = relayed(Err(AppError::Forbidden("sign-up is off".to_owned().into())));

        let RelayAnswer::Answered(WireOutcome::Rejected { status, code }) = answer else {
            panic!("a refusal is told to the gateway");
        };
        assert_eq!(status.code(), 403);
        assert_eq!(code, "forbidden");
    }

    /// Accepted link requests carry the response-floor marker; sign-out
    /// responses do not.
    #[test]
    fn an_accepted_answer_is_held_to_the_link_floor() {
        let accepted = relayed(Ok(AppSignInOutcome::Accepted)).sealed(None);
        let signed_out = relayed(Ok(AppSignInOutcome::SignedOut)).sealed(None);

        assert!(accepted.extensions().get::<HeldToLinkFloor>().is_some());
        assert!(signed_out.extensions().get::<HeldToLinkFloor>().is_none());
    }

    /// Ann's browser asks the shop for the API's hop code. The gateway is
    /// told the code and the host it is for.
    #[test]
    fn a_hop_code_is_told_with_its_host() {
        let host = DomainName::new("api.example.com").unwrap();
        let issued = relayed(Ok(AppSignInOutcome::HopIssued(Hop {
            host: host.clone(),
            code: Secret::new("hop-code"),
        })));

        let RelayAnswer::Answered(WireOutcome::HopIssued { host: told, code }) = issued else {
            panic!("the hop's code is told to the gateway");
        };
        assert_eq!(told, host);
        assert_eq!(code, "hop-code");
    }

    /// Ann signs out, and the gateway is told she signed out.
    #[test]
    fn signing_out_is_told_as_such() {
        let answer = relayed(Ok(AppSignInOutcome::SignedOut));

        assert!(matches!(
            answer,
            RelayAnswer::Answered(WireOutcome::SignedOut)
        ));
    }

    /// Sam set Bob's password, and Bob signs in on the shop. The gateway is
    /// told a new password is owed, why, and the token for the host's
    /// challenge cookie, with no session in it.
    #[test]
    fn a_password_change_owed_is_told_with_its_challenge() {
        let outcome = AppSignInOutcome::PasswordChangeRequired {
            challenge: Some(Secret::new("change-token")),
            proof: ChangeProof::OwnFactor,
            reason: ChangeReason::SetByAdmin,
            expires_at: time::OffsetDateTime::UNIX_EPOCH,
        };

        let answer = relayed(Ok(outcome));

        let RelayAnswer::Answered(WireOutcome::PasswordChangeRequired {
            challenge,
            proof,
            reason,
            ..
        }) = answer
        else {
            panic!("the change is told to the gateway");
        };
        assert_eq!(challenge.as_deref(), Some("change-token"));
        assert_eq!(proof, "own_factor");
        assert_eq!(reason, "set_by_admin");
    }
}
