//! What a request to a host with app sign-in is, from its method and path
//! alone, before anything else of it is read.

use http::{Method, StatusCode};
use ianua_domain::domains::routing::sign_in::app::{AppSignIn, SignInAction};

/// What a request on a host with app sign-in is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addressed {
    /// One of the sign-in addresses, asked the way it answers.
    SignIn(Asked),
    /// A path the gateway keeps for sign-in, asked something it does not
    /// answer. Never handed to the app.
    Refused(StatusCode),
    /// Not a sign-in address: the app's own.
    App,
}

/// What a sign-in address was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asked {
    /// To carry out the action.
    Submit(SignInAction),
    /// To show the action's page.
    Page(SignInAction),
    /// For a short-lived token for a service accepting the sign-in by token.
    Token,
    /// For the code of a hop, by a browser on its way through a host of a
    /// service accepting the sign-in with a cookie of its own.
    HopCode,
    /// For the script the login page signs in with a passkey through.
    PasskeyScript,
}

/// What `method` on `path` is on a host with `sign_in`.
///
/// Loading an action's address under the prefix shows its page. A link
/// opened from a mailbox is followed with a `GET`; so is starting a single
/// sign-on from the login page's links. A provider sends the browser back
/// with a `GET` (OIDC) or a `POST` (SAML). Every other action is a form or a
/// script posting. The token, hop and passkey script addresses each take
/// one method. Anything else under the prefix is refused and never reaches
/// the app; a moved address asked something else, such as the app's own
/// login page at `/login` loaded with `GET`, is the app's.
#[must_use]
pub fn addressed(sign_in: &AppSignIn, method: &Method, path: &str) -> Addressed {
    if let Some((takes, asked)) = fixed_address(sign_in, path) {
        return only_by(method, &takes, asked);
    }
    let Some(action) = sign_in.action_at(path) else {
        return reserved_or_app(sign_in, path, StatusCode::NOT_FOUND);
    };
    if *method == Method::GET && sign_in.shows_page(action) {
        return Addressed::SignIn(Asked::Page(action));
    }
    if answers(action, method) {
        return Addressed::SignIn(Asked::Submit(action));
    }
    reserved_or_app(sign_in, path, StatusCode::METHOD_NOT_ALLOWED)
}

/// The fixed address at `path`, if it is one: what it is asked for, and the
/// one method it takes.
fn fixed_address(sign_in: &AppSignIn, path: &str) -> Option<(Method, Asked)> {
    [
        (sign_in.token_path(), Method::POST, Asked::Token),
        (sign_in.hop_path(), Method::GET, Asked::HopCode),
        (sign_in.script_path(), Method::GET, Asked::PasskeyScript),
    ]
    .into_iter()
    .find(|(at, _, _)| at.as_str() == path)
    .map(|(_, takes, asked)| (takes, asked))
}

fn only_by(method: &Method, takes: &Method, asked: Asked) -> Addressed {
    if method == takes {
        return Addressed::SignIn(asked);
    }
    Addressed::Refused(StatusCode::METHOD_NOT_ALLOWED)
}

fn reserved_or_app(sign_in: &AppSignIn, path: &str, status: StatusCode) -> Addressed {
    if sign_in.reserves(path) {
        return Addressed::Refused(status);
    }
    Addressed::App
}

/// Whether `action` is carried out on a request with `method`.
fn answers(action: SignInAction, method: &Method) -> bool {
    match action {
        SignInAction::Verify | SignInAction::ConfirmSignIn => *method == Method::GET,
        SignInAction::Sso | SignInAction::SsoCallback => {
            *method == Method::GET || *method == Method::POST
        }
        SignInAction::LogIn
        | SignInAction::SignUp
        | SignInAction::Mfa
        | SignInAction::LogOut
        | SignInAction::Passkey
        | SignInAction::ForgotPassword
        | SignInAction::ResetPassword
        | SignInAction::ChangePassword => *method == Method::POST,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ianua_domain::domains::routing::sign_in::app::{
        AppSignInParams, SignInPath, SignedOutBrowsers,
    };
    use ianua_domain::types::{DomainName, Setting};

    use super::*;

    /// The shop's sign-in, with log in moved to the shop's own `/login`.
    fn sign_in() -> AppSignIn {
        let mut moved = BTreeMap::new();
        moved.insert(SignInAction::LogIn, SignInPath::new("/login").unwrap());
        AppSignIn::new(AppSignInParams {
            hosts: vec![DomainName::new("shop.example.com").unwrap()],
            prefix: Setting::Unset,
            moved,
            after_sign_in: Setting::Unset,
            signed_out_browsers: SignedOutBrowsers::Refuse,
        })
        .unwrap()
    }

    /// Every action the sign-in has is carried out at its address, by one
    /// method or another; none is left for the app to answer.
    #[test]
    fn every_action_is_answered_at_its_address() {
        let sign_in = sign_in();

        for action in SignInAction::ALL {
            let path = sign_in.path(action);
            let answered = [Method::GET, Method::POST].iter().any(|method| {
                addressed(&sign_in, method, path.as_str())
                    == Addressed::SignIn(Asked::Submit(action))
            });

            assert!(answered, "{action:?} is not answered at {path}");
        }
    }

    #[test]
    fn a_post_to_an_address_is_the_action() {
        let sign_in = sign_in();

        for (path, action) in [
            ("/login", SignInAction::LogIn),
            ("/.ianua/signup", SignInAction::SignUp),
            ("/.ianua/mfa", SignInAction::Mfa),
            ("/.ianua/logout", SignInAction::LogOut),
            ("/.ianua/sso", SignInAction::Sso),
            ("/.ianua/passkey", SignInAction::Passkey),
            ("/.ianua/forgot-password", SignInAction::ForgotPassword),
            ("/.ianua/reset-password", SignInAction::ResetPassword),
            ("/.ianua/change-password", SignInAction::ChangePassword),
        ] {
            assert_eq!(
                addressed(&sign_in, &Method::POST, path),
                Addressed::SignIn(Asked::Submit(action)),
                "{path}"
            );
        }
    }

    /// The app serves its own login page at a moved login address; loading it
    /// is the app's business.
    #[test]
    fn a_get_on_a_moved_address_is_the_apps() {
        assert_eq!(
            addressed(&sign_in(), &Method::GET, "/login"),
            Addressed::App
        );
    }

    #[test]
    fn a_mailed_link_is_answered_with_get() {
        assert_eq!(
            addressed(&sign_in(), &Method::GET, "/.ianua/verify"),
            Addressed::SignIn(Asked::Submit(SignInAction::Verify))
        );
    }

    /// The link confirming a sign-in lands on an address of its own, never
    /// on the verify address, so the two are never told apart by a cookie.
    #[test]
    fn a_confirm_link_lands_on_its_own_address() {
        let sign_in = sign_in();

        assert_eq!(
            addressed(&sign_in, &Method::GET, "/.ianua/confirm-sign-in"),
            Addressed::SignIn(Asked::Submit(SignInAction::ConfirmSignIn))
        );
    }

    /// The mailed change link opens the change page; the page's form posts
    /// back to the same address.
    #[test]
    fn the_change_address_shows_its_page_and_takes_its_form() {
        let sign_in = sign_in();

        assert_eq!(
            addressed(&sign_in, &Method::GET, "/.ianua/change-password"),
            Addressed::SignIn(Asked::Page(SignInAction::ChangePassword))
        );
        assert_eq!(
            addressed(&sign_in, &Method::POST, "/.ianua/change-password"),
            Addressed::SignIn(Asked::Submit(SignInAction::ChangePassword))
        );
    }

    /// A browser on its way through another host asks the owner's host for
    /// the hop's code with a `GET`; the login page loads its passkey script
    /// with one. Neither takes anything else.
    #[test]
    fn the_hop_and_script_addresses_take_a_get_and_nothing_else() {
        let sign_in = sign_in();

        assert_eq!(
            addressed(&sign_in, &Method::GET, "/.ianua/hop"),
            Addressed::SignIn(Asked::HopCode)
        );
        assert_eq!(
            addressed(&sign_in, &Method::GET, "/.ianua/passkey.js"),
            Addressed::SignIn(Asked::PasskeyScript)
        );
        for path in ["/.ianua/hop", "/.ianua/passkey.js"] {
            assert_eq!(
                addressed(&sign_in, &Method::POST, path),
                Addressed::Refused(StatusCode::METHOD_NOT_ALLOWED),
                "{path}"
            );
        }
    }

    /// Ann signs in to the shop through her company's provider. An OIDC
    /// provider sends her browser back with a GET, a SAML one with a POST;
    /// both returns are the callback, and neither is refused.
    #[test]
    fn a_single_sign_on_return_is_answered_by_get_and_by_post() {
        let sign_in = sign_in();
        let callback = sign_in.path(SignInAction::SsoCallback).as_str().to_owned();

        assert_eq!(
            addressed(&sign_in, &Method::GET, &callback),
            Addressed::SignIn(Asked::Submit(SignInAction::SsoCallback))
        );
        assert_eq!(
            addressed(&sign_in, &Method::POST, &callback),
            Addressed::SignIn(Asked::Submit(SignInAction::SsoCallback))
        );
    }

    /// The login page links to each provider, so a single sign-on starts
    /// with the `GET` of following that link.
    #[test]
    fn a_single_sign_on_starts_from_a_followed_link() {
        assert_eq!(
            addressed(&sign_in(), &Method::GET, "/.ianua/sso"),
            Addressed::SignIn(Asked::Submit(SignInAction::Sso))
        );
    }

    #[test]
    fn loading_an_address_under_the_prefix_shows_its_page() {
        let sign_in = sign_in();

        for (path, action) in [
            ("/.ianua/signup", SignInAction::SignUp),
            ("/.ianua/mfa", SignInAction::Mfa),
            ("/.ianua/forgot-password", SignInAction::ForgotPassword),
            ("/.ianua/reset-password", SignInAction::ResetPassword),
            ("/.ianua/change-password", SignInAction::ChangePassword),
        ] {
            assert_eq!(
                addressed(&sign_in, &Method::GET, path),
                Addressed::SignIn(Asked::Page(action)),
                "{path}"
            );
        }
    }

    #[test]
    fn nothing_under_the_prefix_reaches_the_app() {
        let sign_in = sign_in();

        for (method, path, status) in reserved_requests() {
            assert_eq!(
                addressed(&sign_in, &method, path),
                Addressed::Refused(status),
                "{method} {path}"
            );
        }
    }

    /// Missing reserved addresses and wrong methods stay within the gateway's sign-in boundary.
    fn reserved_requests() -> [(Method, &'static str, StatusCode); 9] {
        let missing = StatusCode::NOT_FOUND;
        let wrong_method = StatusCode::METHOD_NOT_ALLOWED;
        [
            (Method::GET, "/.ianua/unknown", missing),
            (Method::POST, "/.ianua/unknown", missing),
            (Method::GET, "/.ianua", missing),
            (Method::POST, "/.ianua/login", missing),
            (Method::POST, "/.ianua/confirm-sign-in", wrong_method),
            (Method::GET, "/.ianua/logout", wrong_method),
            (Method::GET, "/.ianua/passkey", wrong_method),
            (Method::POST, "/.ianua/verify", wrong_method),
            (Method::PUT, "/.ianua/sso-callback", wrong_method),
        ]
    }

    #[test]
    fn other_paths_are_the_apps() {
        assert_eq!(
            addressed(&sign_in(), &Method::POST, "/orders"),
            Addressed::App
        );
        assert_eq!(
            addressed(&sign_in(), &Method::GET, "/.ianuax/login"),
            Addressed::App
        );
    }

    #[test]
    fn the_token_address_takes_a_post_and_nothing_else() {
        let sign_in = sign_in();

        assert_eq!(
            addressed(&sign_in, &Method::POST, "/.ianua/token"),
            Addressed::SignIn(Asked::Token)
        );
        assert_eq!(
            addressed(&sign_in, &Method::GET, "/.ianua/token"),
            Addressed::Refused(StatusCode::METHOD_NOT_ALLOWED)
        );
    }
}
