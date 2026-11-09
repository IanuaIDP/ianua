//! The values a sign-in page's template is filled with, and which template
//! draws each step.
//!
//! The words are the templates' own; this only hands over what the page
//! carries. A note goes over as its code, never as text, and the single
//! sign-on links are written here so where the person was headed stays one
//! query parameter.

use ianua_app::ports::pages::{Refusal, SignInNote, SignInPage, SsoChoice};
use ianua_domain::domains::routing::sign_in::app::{SignInAction, SignInPath};
use ianua_domain::domains::routing::sign_in::return_path::ReturnPath;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use minijinja::context;
use minijinja::value::Value;

use crate::pages::look::Look;

/// The template that draws the page of `action`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` for a step that has no page of its
/// own, which the app never asks for.
pub(crate) fn template_of(action: SignInAction) -> Result<&'static str, DomainError> {
    match action {
        SignInAction::LogIn => Ok("sign_in/log_in.html"),
        SignInAction::SignUp => Ok("sign_in/sign_up.html"),
        SignInAction::Mfa => Ok("sign_in/mfa.html"),
        SignInAction::ForgotPassword => Ok("sign_in/forgot_password.html"),
        SignInAction::ResetPassword => Ok("sign_in/reset_password.html"),
        SignInAction::ChangePassword => Ok("sign_in/change_password.html"),
        SignInAction::Verify
        | SignInAction::ConfirmSignIn
        | SignInAction::LogOut
        | SignInAction::Sso
        | SignInAction::SsoCallback
        | SignInAction::Passkey => Err(DomainError::infra_msg("this sign-in step has no page")),
    }
}

/// The values `page`'s template is filled with.
pub(crate) fn context_of(page: &SignInPage) -> Value {
    context! {
        look => look_of(page).value(),
        workspace => page.workspace.as_str(),
        form_path => page.form_path.as_str(),
        log_in_path => page.log_in_path.as_str(),
        sign_up_path => page.sign_up_path.as_ref().map(SignInPath::as_str),
        forgot_password_path => page.forgot_password_path.as_ref().map(SignInPath::as_str),
        passkey_path => page.passkey_path.as_ref().map(SignInPath::as_str),
        passkey_script_path => page.passkey_script_path.as_ref().map(SignInPath::as_str),
        single_sign_on => single_sign_on(page),
        note => page.note.map(note_of),
        return_to => page.return_to.as_ref().map(ReturnPath::as_str),
        link_token => page.link_token.as_ref().map(Secret::expose),
    }
}

/// What `page` wears: the workspace's branding, or the platform's look.
fn look_of(page: &SignInPage) -> Look<'_> {
    let branding = page.branding.as_ref();
    Look {
        name: &page.workspace,
        logo_url: branding.and_then(|b| b.logo_url()),
        primary: branding.and_then(|b| b.primary_color()),
        background: branding.and_then(|b| b.background_color()),
        custom_css: branding.and_then(|b| b.custom_css()),
    }
}

/// The identity providers the page offers, each with its link. Only the
/// login page offers any.
fn single_sign_on(page: &SignInPage) -> Vec<Value> {
    if page.action != SignInAction::LogIn {
        return Vec::new();
    }
    page.single_sign_on
        .iter()
        .map(|choice| {
            context! {
                href => sso_href(page, choice),
                name => choice.name.as_str(),
            }
        })
        .collect()
}

/// The link starting single sign-on through `choice`, carrying where to go
/// after.
fn sso_href(page: &SignInPage, choice: &SsoChoice) -> String {
    let href = format!(
        "{}?connection_id={}",
        page.sso_path.as_str(),
        choice.connection_id.as_uuid()
    );
    let Some(path) = &page.return_to else {
        return href;
    };
    format!("{href}&return_to={}", query_value(path.as_str()))
}

/// `value` written so it stays one query parameter: every byte but the
/// unreserved ones and `/` percent-encoded.
fn query_value(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                char::from(byte).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

/// `note` as the templates read it: its code, and whether it is a refusal.
fn note_of(note: SignInNote) -> Value {
    let (code, tone) = match note {
        SignInNote::CheckEmail => ("check_email", "info"),
        SignInNote::Verified => ("verified", "info"),
        SignInNote::PasswordReset => ("password_reset", "info"),
        SignInNote::PasswordChangeRequired => ("password_change_required", "info"),
        SignInNote::Refused(refusal) => (refusal_code(refusal), "refused"),
    };
    context! { code => code, tone => tone }
}

/// The code a refusal's words are kept under.
fn refusal_code(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::NotAccepted => "not_accepted",
        Refusal::Locked => "locked",
        Refusal::NotVerified => "not_verified",
        Refusal::TooMany => "too_many",
        Refusal::NotAllowed => "not_allowed",
        Refusal::Invalid => "invalid",
        Refusal::LinkExpired => "link_expired",
        Refusal::CodeNeeded => "code_needed",
        Refusal::Unavailable => "unavailable",
        Refusal::Failed => "failed",
    }
}
