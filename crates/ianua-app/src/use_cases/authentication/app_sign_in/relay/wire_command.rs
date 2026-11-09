//! Reading what a relayed request asks for: each wire command becomes the
//! command for its use case, with what the person entered checked first.

use ianua_domain::domains::authentication::device_trust::DeviceSecret;
use ianua_domain::domains::routing::sign_in::return_path::ReturnPath;
use ianua_domain::shared::config::DisplayNameLimits;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::shared::validation::ValidationError;
use ianua_domain::types::{
    Audience, CeremonyId, DisplayName, Email, PasskeyCredentialId, SamlRequestId,
};

use crate::error::AppError;
use crate::ports::authentication::{WireCommand, WirePage, WireSsoAnswer};
use crate::services::authentication::passkey_answer::PresentedAssertion;
use crate::use_cases::authentication::app_sign_in::{
    AppChangePasswordRequest, AppCompleteMfaRequest, AppConfirmByEmailRequest, AppHandOverRequest,
    AppIssueHopRequest, AppIssueTokenRequest, AppLogInRequest, AppPasskeyConfirmRequest,
    AppResetPasswordRequest, AppSignInCommand, AppSignInPageRequest, AppSignUpRequest,
    AppSsoAnswer, AppSsoCallbackRequest, AppSsoStartRequest, SignInNote,
};

/// What a request asks of the API: something on the host of the service that
/// owns the sign-in, or a hop arriving on the host of a service accepting it
/// with a cookie of its own.
pub(in crate::use_cases::authentication::app_sign_in) enum Received {
    /// An action on the owner's host.
    OnOwnerHost(AppSignInCommand),
    /// A hop, with the one-time code it carried and the browser it arrived
    /// in.
    Hop(AppHandOverRequest),
}

/// What the wire command asks for, with what the person entered checked.
///
/// # Errors
///
/// `AppError::Domain` when something the person entered is not well formed.
// One arm per wire command and nothing else; split up, the table of what
// each command becomes would be spread over several functions.
#[allow(clippy::too_many_lines)]
pub(in crate::use_cases::authentication::app_sign_in) fn command(
    command: WireCommand,
) -> Result<Received, AppError> {
    let command = match command {
        WireCommand::Hop { code, browser } => {
            return Ok(Received::Hop(AppHandOverRequest {
                code: Secret::new(code),
                browser: Secret::new(browser),
            }));
        }
        WireCommand::IssueHop {
            session,
            host,
            browser,
        } => AppSignInCommand::IssueHop(AppIssueHopRequest {
            session: session.map(Secret::new),
            host,
            browser: Secret::new(browser),
        }),
        WireCommand::LogIn {
            email,
            password,
            device,
            return_to,
        } => log_in(email, password, device, return_to)?,
        WireCommand::CompleteMfa {
            challenge,
            code,
            remember_device,
            return_to,
        } => complete_mfa(challenge, code, remember_device, return_to),
        WireCommand::ConfirmByEmail {
            challenge,
            link,
            return_to,
        } => confirm_by_email(challenge, link, return_to),
        WireCommand::SignUp {
            email,
            display_name,
            password,
        } => sign_up(email, display_name, password)?,
        WireCommand::Verify { token } => AppSignInCommand::Verify(Secret::new(token)),
        WireCommand::LogOut { session } => AppSignInCommand::LogOut(session.map(Secret::new)),
        WireCommand::ShowPage {
            page,
            note,
            return_to,
            token,
        } => show_page(page, note.as_deref(), return_to, token),
        WireCommand::IssueToken { session, audience } => issue_token(session, audience)?,
        WireCommand::Sso {
            connection_id,
            return_to,
        } => AppSignInCommand::SsoStart(AppSsoStartRequest {
            connection_id,
            return_to: return_path(return_to),
        }),
        WireCommand::SsoCallback {
            answer,
            binding,
            hand_back,
            return_to,
        } => AppSignInCommand::SsoCallback(AppSsoCallbackRequest {
            answer: sso_answer(answer)?,
            binding: Secret::new(binding),
            hand_back: Secret::new(hand_back),
            return_to: return_path(return_to),
        }),
        WireCommand::PasskeyBegin { email } => passkey_begin(email)?,
        WireCommand::PasskeyConfirm {
            ceremony_id,
            credential_id,
            response,
            return_to,
        } => passkey_confirm(
            PresentedPasskey {
                ceremony_id,
                credential_id,
                response,
            },
            return_to,
        )?,
        WireCommand::ForgotPassword { email } => {
            AppSignInCommand::ForgotPassword(Email::new(email).map_err(invalid)?)
        }
        WireCommand::ResetPassword {
            token,
            password,
            mfa_code,
        } => AppSignInCommand::ResetPassword(AppResetPasswordRequest {
            token: Secret::new(token),
            new_password: Secret::new(password),
            mfa_code,
        }),
        WireCommand::ChangePassword {
            challenge,
            password,
            mfa_code,
            device,
            return_to,
        } => AppSignInCommand::ChangePassword(AppChangePasswordRequest {
            challenge: Secret::new(challenge),
            new_password: Secret::new(password),
            code: mfa_code,
            device: device_secret(device),
            return_to: return_path(return_to),
        }),
    };
    Ok(Received::OnOwnerHost(command))
}

/// A password sign-in, once the address reads as one.
fn log_in(
    email: String,
    password: String,
    device: Option<String>,
    return_to: Option<String>,
) -> Result<AppSignInCommand, AppError> {
    Ok(AppSignInCommand::LogIn(AppLogInRequest {
        email: Email::new(email).map_err(invalid)?,
        password: Secret::new(password),
        device: device_secret(device),
        return_to: return_path(return_to),
    }))
}

/// The device cookie's secret, when it reads as one. A cookie that does
/// not is a device nobody remembered: it never refuses the sign-in, so a
/// value planted beside it cannot shut the person out.
fn device_secret(sent: Option<String>) -> Option<DeviceSecret> {
    sent.and_then(|secret| DeviceSecret::new(secret).ok())
}

/// A token for a service accepting the sign-in by token, once the audience
/// reads as one.
fn issue_token(session: Option<String>, audience: String) -> Result<AppSignInCommand, AppError> {
    Ok(AppSignInCommand::IssueToken(AppIssueTokenRequest {
        session: session.map(Secret::new),
        audience: Audience::new(audience).map_err(invalid)?,
    }))
}

/// A second-factor answer to the challenge the cookie holds.
fn complete_mfa(
    challenge: String,
    code: String,
    remember_device: Option<String>,
    return_to: Option<String>,
) -> AppSignInCommand {
    AppSignInCommand::CompleteMfa(AppCompleteMfaRequest {
        challenge: Secret::new(challenge),
        code,
        remember: device_secret(remember_device),
        return_to: return_path(return_to),
    })
}

/// A sign-in confirmed from the mailed link, in the browser whose cookie
/// holds it.
fn confirm_by_email(
    challenge: String,
    link: String,
    return_to: Option<String>,
) -> AppSignInCommand {
    AppSignInCommand::ConfirmByEmail(AppConfirmByEmailRequest {
        challenge: Secret::new(challenge),
        link: Secret::new(link),
        return_to: return_path(return_to),
    })
}

/// A sign-up, once the address and the name read as such.
fn sign_up(
    email: String,
    display_name: String,
    password: String,
) -> Result<AppSignInCommand, AppError> {
    Ok(AppSignInCommand::SignUp(AppSignUpRequest {
        email: Email::new(email).map_err(invalid)?,
        display_name: DisplayName::new(display_name, &DisplayNameLimits::default())
            .map_err(invalid)?,
        password,
    }))
}

/// The page asked for. Only the reset and change pages carry a mailed
/// link's token.
fn show_page(
    page: WirePage,
    note: Option<&str>,
    return_to: Option<String>,
    token: Option<String>,
) -> AppSignInCommand {
    let link_token = match page {
        WirePage::ResetPassword | WirePage::ChangePassword => token.map(Secret::new),
        WirePage::LogIn | WirePage::SignUp | WirePage::Mfa | WirePage::ForgotPassword => None,
    };
    AppSignInCommand::ShowPage(AppSignInPageRequest {
        action: page.into(),
        note: note.map(SignInNote::from_code),
        return_to: return_path(return_to),
        link_token,
    })
}

/// The provider's answer, once a SAML relay state reads as a request ID.
fn sso_answer(answer: WireSsoAnswer) -> Result<AppSsoAnswer, AppError> {
    let answer = match answer {
        WireSsoAnswer::Oidc { state, code } => AppSsoAnswer::Oidc {
            state: Secret::new(state),
            code: Secret::new(code),
        },
        WireSsoAnswer::Saml {
            relay_state,
            saml_response,
        } => AppSsoAnswer::Saml {
            relay_state: SamlRequestId::new(relay_state).map_err(invalid)?,
            saml_response,
        },
    };
    Ok(answer)
}

/// A passkey challenge, for the address typed if it reads as one.
fn passkey_begin(email: Option<String>) -> Result<AppSignInCommand, AppError> {
    let email = email.map(Email::new).transpose().map_err(invalid)?;
    Ok(AppSignInCommand::PasskeyBegin(email))
}

/// A passkey's answer as the gateway relayed it.
struct PresentedPasskey {
    ceremony_id: CeremonyId,
    credential_id: Vec<u8>,
    response: Vec<u8>,
}

/// A passkey's answer, once its credential id reads as one.
fn passkey_confirm(
    presented: PresentedPasskey,
    return_to: Option<String>,
) -> Result<AppSignInCommand, AppError> {
    let PresentedPasskey {
        ceremony_id,
        credential_id,
        response,
    } = presented;
    Ok(AppSignInCommand::PasskeyConfirm(AppPasskeyConfirmRequest {
        assertion: PresentedAssertion {
            ceremony_id,
            credential_id: PasskeyCredentialId::new(credential_id).map_err(invalid)?,
            response,
        },
        return_to: return_path(return_to),
    }))
}

/// A return path the person brought, or none if it would leave the host:
/// they still sign in, and land where the app sends people by default.
fn return_path(raw: Option<String>) -> Option<ReturnPath> {
    raw.and_then(|raw| ReturnPath::new(raw).ok())
}

/// Something the person entered that is not well formed, with why kept.
fn invalid(err: ValidationError) -> AppError {
    AppError::Domain(err.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mallory's link carries a return path to another site. It is dropped
    /// rather than refused: the person still signs in, and lands on the
    /// app's default.
    #[test]
    fn a_return_path_leaving_the_host_is_dropped() {
        assert!(return_path(Some("//evil.example".to_owned())).is_none());
        assert!(return_path(Some("/projects".to_owned())).is_some());
    }

    /// A malformed email address is rejected while parsing a relayed
    /// password sign-in command.
    #[test]
    fn a_malformed_address_is_refused_before_anything_runs() {
        let refused = command(WireCommand::LogIn {
            email: "not-an-address".to_owned(),
            password: "x".to_owned(),
            device: None,
            return_to: None,
        });

        assert!(matches!(refused, Err(AppError::Domain(_))));
    }

    /// Bob's browser sends the device cookie the shop's host keeps. Its
    /// secret is read with the sign-in; a cookie holding anything else is
    /// read as no device, never as a refusal.
    #[test]
    fn a_device_cookie_is_read_with_the_sign_in_or_dropped() {
        let log_in = |device: &str| {
            command(WireCommand::LogIn {
                email: "bob@acme.test".to_owned(),
                password: "x".to_owned(),
                device: Some(device.to_owned()),
                return_to: None,
            })
        };

        let held = log_in(&"ab".repeat(32));
        let planted = log_in("not-a-device");

        let Ok(Received::OnOwnerHost(AppSignInCommand::LogIn(held))) = held else {
            panic!("a sign-in is read as one");
        };
        let Ok(Received::OnOwnerHost(AppSignInCommand::LogIn(planted))) = planted else {
            panic!("a sign-in is read as one");
        };
        assert!(held.device.is_some());
        assert!(planted.device.is_none());
    }

    /// Bob asks to remember his laptop on the second-factor page. The
    /// secret the gateway made for it is read with his code.
    #[test]
    fn the_device_to_remember_is_read_with_the_code() {
        let received = command(WireCommand::CompleteMfa {
            challenge: "chal".to_owned(),
            code: "123456".to_owned(),
            remember_device: Some("cd".repeat(32)),
            return_to: None,
        });

        let Ok(Received::OnOwnerHost(AppSignInCommand::CompleteMfa(request))) = received else {
            panic!("a code is read as one");
        };
        assert!(request.remember.is_some());
    }

    /// Bob's sign-in owed a new password. The gateway relays it with the
    /// challenge cookie's token, and it becomes the change for that sign-in.
    #[test]
    fn a_new_password_is_read_with_its_challenge() {
        let received = command(WireCommand::ChangePassword {
            challenge: "change-token".to_owned(),
            password: "a quiet river after rain".to_owned(),
            mfa_code: Some("123456".to_owned()),
            device: None,
            return_to: Some("/projects".to_owned()),
        });

        let Ok(Received::OnOwnerHost(AppSignInCommand::ChangePassword(request))) = received else {
            panic!("a new password is read as one");
        };
        assert_eq!(request.challenge.expose(), "change-token");
        assert_eq!(request.code.as_deref(), Some("123456"));
        assert!(request.return_to.is_some());
    }

    /// A malformed email address is rejected while parsing a relayed
    /// password-reset request.
    #[test]
    fn a_malformed_reset_address_is_refused_before_anything_runs() {
        let refused = command(WireCommand::ForgotPassword {
            email: "not-an-address".to_owned(),
        });

        assert!(matches!(refused, Err(AppError::Domain(_))));
    }

    /// Reset and change page commands retain the supplied link token;
    /// a login page command drops it.
    #[test]
    fn only_the_reset_and_change_pages_carry_a_token() {
        let ask = |page| {
            command(WireCommand::ShowPage {
                page,
                note: None,
                return_to: None,
                token: Some("mailed-token".to_owned()),
            })
        };
        let carried = |received| match received {
            Ok(Received::OnOwnerHost(AppSignInCommand::ShowPage(request))) => {
                request.link_token.is_some()
            }
            _ => panic!("a page is asked for"),
        };

        assert!(carried(ask(WirePage::ResetPassword)));
        assert!(carried(ask(WirePage::ChangePassword)));
        assert!(!carried(ask(WirePage::LogIn)));
    }

    /// A hop arrives with its code and the digest of the browser's hop
    /// cookie. Both go to the hand-over, never one without the other.
    #[test]
    fn a_hop_is_read_with_the_browser_it_arrived_in() {
        let received = command(WireCommand::Hop {
            code: "code".to_owned(),
            browser: "browser-digest".to_owned(),
        });

        let Ok(Received::Hop(request)) = received else {
            panic!("a hop is read as one");
        };
        assert_eq!(request.code.expose(), "code");
        assert_eq!(request.browser.expose(), "browser-digest");
    }

    /// Ann's browser answers a passkey challenge. The answer becomes a
    /// passkey confirmation naming the ceremony it answers.
    #[test]
    fn a_passkey_answer_names_its_ceremony() {
        let ceremony_id = CeremonyId::new();

        let received = command(WireCommand::PasskeyConfirm {
            ceremony_id,
            credential_id: vec![1, 2, 3, 4],
            response: vec![0x01],
            return_to: None,
        });

        let answered = match received {
            Ok(Received::OnOwnerHost(AppSignInCommand::PasskeyConfirm(request))) => {
                request.assertion.ceremony_id
            }
            _ => panic!("a passkey confirmation"),
        };
        assert_eq!(answered, ceremony_id);
    }
}
