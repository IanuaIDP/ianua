//! The pages the gateway shows at an app's sign-in addresses.
//!
//! What a page says and offers is decided here; how it looks is drawn
//! through the [`PageRenderer`](crate::ports::pages::PageRenderer) port,
//! which owns the page's types. A page never shows text a request brought:
//! a note is one of a fixed set, and a return path is held to the same rules
//! as when it is used. The token of a mailed reset or change link is carried
//! in the form it opened, never shown.

use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::sessions::sign_in_progress::FederatedMethod;
use ianua_domain::domains::branding::config::TenantBranding;
use ianua_domain::domains::federation::connection::FederatedIdpConnection;
use ianua_domain::domains::routing::sign_in::app::SignInAction;
use ianua_domain::domains::routing::sign_in::return_path::ReturnPath;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;

use crate::error::AppError;
pub use crate::ports::pages::{SignInPage, SsoChoice};
use crate::ports::shared::PreferredLanguages;
use crate::use_cases::authentication::app_sign_in::SignInNote;
use crate::use_cases::authentication::app_sign_in::relay::target::Target;

/// Which sign-in page to render, with any note and where to go after.
pub(in crate::use_cases::authentication::app_sign_in) struct PageAsk {
    /// The sign-in step the page is for.
    pub(in crate::use_cases::authentication::app_sign_in) action: SignInAction,
    /// A message to show above the form.
    pub(in crate::use_cases::authentication::app_sign_in) note: Option<SignInNote>,
    /// Where to send the person once signed in.
    pub(in crate::use_cases::authentication::app_sign_in) return_to: Option<ReturnPath>,
    /// The token of the mailed link the reset or change page was opened
    /// from.
    pub(in crate::use_cases::authentication::app_sign_in) link_token: Option<Secret>,
}

/// What a page wears and offers beyond the service's own settings.
pub(in crate::use_cases::authentication::app_sign_in) struct Dressing {
    /// The workspace's branding, if it set any.
    pub(in crate::use_cases::authentication::app_sign_in) branding:
        Option<TenantBranding<ResolvedTenant>>,
    /// The workspace's outside identity providers, turned on or off.
    pub(in crate::use_cases::authentication::app_sign_in) connections:
        Vec<FederatedIdpConnection<ResolvedTenant>>,
}

/// The page for `ask.action` on `target`'s host.
///
/// # Errors
///
/// - `AppError::NotFound` when the gateway shows no page for the action
///   there, or for the reset page opened without a mailed link's token.
/// - `AppError::Forbidden` for the sign-up page of a workspace that takes no
///   sign-ups, and for the password pages of one that takes no passwords.
pub(in crate::use_cases::authentication::app_sign_in) fn page(
    target: &Target,
    dressing: Dressing,
    ask: PageAsk,
) -> Result<SignInPage, AppError> {
    ensure_offered(target, &ask)?;
    let PageAsk {
        action,
        note,
        return_to,
        link_token,
    } = ask;
    let sign_in = &target.sign_in;
    let offered =
        |method: AuthMethod, at: SignInAction| takes(target, method).then(|| sign_in.path(at));
    let passkey_path = offered(AuthMethod::Passkey, SignInAction::Passkey);
    let passkey_script_path =
        (action == SignInAction::LogIn && passkey_path.is_some()).then(|| sign_in.script_path());
    Ok(SignInPage {
        action,
        workspace: target.tenant.display_name().as_str().to_owned(),
        branding: dressing.branding,
        form_path: sign_in.path(action),
        log_in_path: sign_in.path(SignInAction::LogIn),
        sign_up_path: takes_sign_ups(target).then(|| sign_in.path(SignInAction::SignUp)),
        forgot_password_path: offered(AuthMethod::Password, SignInAction::ForgotPassword),
        passkey_path,
        passkey_script_path,
        sso_path: sign_in.path(SignInAction::Sso),
        single_sign_on: sso_choices(target, &dressing.connections),
        note,
        return_to,
        link_token,
        languages: PreferredLanguages::default(),
    })
}

/// Refuses a page the workspace does not offer: one the gateway does not
/// show, sign-up where sign-ups are off, the password pages where passwords
/// are, and the reset page without the token of a mailed link. The change
/// page opens without one: the browser that signed in holds the change in
/// its challenge cookie.
fn ensure_offered(target: &Target, ask: &PageAsk) -> Result<(), AppError> {
    if !target.sign_in.shows_page(ask.action) {
        return Err(AppError::NotFound(message!(
            "authentication-no-page-here",
            "no page here"
        )));
    }
    let takes_passwords = takes(target, AuthMethod::Password);
    match ask.action {
        SignInAction::SignUp if !takes_sign_ups(target) => Err(not_offered("sign-up")),
        SignInAction::ForgotPassword
        | SignInAction::ResetPassword
        | SignInAction::ChangePassword
            if !takes_passwords =>
        {
            Err(not_offered("password sign-in"))
        }
        SignInAction::ResetPassword if ask.link_token.is_none() => Err(no_reset_link()),
        _ => Ok(()),
    }
}

/// The refusal for a page of something the workspace does not offer.
fn not_offered(what: &str) -> AppError {
    AppError::Forbidden(message!(
        "authentication-this-workspace-does-not-allow",
        format!("this workspace does not allow {what}")
    ))
}

/// The refusal for the reset page opened without a mailed link.
fn no_reset_link() -> AppError {
    AppError::NotFound(message!(
        "authentication-open-the-link-from-the-mail",
        "open the link from the mail to set a new password"
    ))
}

/// Whether the workspace takes sign-ups: they are switched on, and a
/// password policy for new accounts is set.
fn takes_sign_ups(target: &Target) -> bool {
    let config = target.tenant.auth_config();
    config.self_registration() && config.new_password_policy().is_some()
}

/// Whether the workspace takes sign-in with `method`.
fn takes(target: &Target, method: AuthMethod) -> bool {
    target.tenant.auth_config().is_method_enabled(method)
}

/// The providers among `connections` a person may pick: turned on, through
/// a protocol the workspace takes.
fn sso_choices(
    target: &Target,
    connections: &[FederatedIdpConnection<ResolvedTenant>],
) -> Vec<SsoChoice> {
    connections
        .iter()
        .filter(|connection| connection.is_active())
        .filter(|connection| {
            takes(
                target,
                AuthMethod::from(FederatedMethod::from(connection.protocol())),
            )
        })
        .map(|connection| SsoChoice {
            connection_id: *connection.id(),
            name: connection.provider_name().clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::routing::sign_in::app::SignInPath;
    use ianua_domain::types::{ConnectionId, DomainName};

    use super::*;
    use crate::test_support::authentication::{SHOP_HOST, app_sign_in_on, shop_with_app_sign_in};
    use crate::test_support::federation::test_connection;
    use crate::test_support::organization::test_org;
    use crate::test_support::tenant::test_tenant_for_ctx;
    use crate::test_support::test_ctx;

    /// The shop on [`SHOP_HOST`] in Acme's workspace, with its actions
    /// moved as `moved` says.
    fn target(moved: BTreeMap<SignInAction, SignInPath>) -> Target {
        Target {
            tenant: Arc::new(test_tenant_for_ctx()),
            org: Arc::new(test_org(test_ctx().organization_id(), "acme")),
            service: shop_with_app_sign_in(),
            sign_in: app_sign_in_on(&[SHOP_HOST], moved),
            host: DomainName::new(SHOP_HOST).unwrap(),
        }
    }

    /// A plain ask for the page of `action`, with no note, return path or
    /// reset token.
    fn asking(action: SignInAction) -> PageAsk {
        PageAsk {
            action,
            note: None,
            return_to: None,
            link_token: None,
        }
    }

    /// The page `ask` names on `target`, unbranded, among `connections`.
    fn shown(
        target: &Target,
        connections: Vec<FederatedIdpConnection<ResolvedTenant>>,
        ask: PageAsk,
    ) -> Result<SignInPage, AppError> {
        let dressing = Dressing {
            branding: None,
            connections,
        };
        page(target, dressing, ask)
    }

    /// Ann opens the shop's login page. Its form posts to the login address,
    /// it names her workspace, and it offers a forgotten password and a
    /// passkey, which the workspace takes.
    #[test]
    fn the_login_page_posts_to_the_login_address() {
        let login = shown(
            &target(BTreeMap::new()),
            Vec::new(),
            asking(SignInAction::LogIn),
        )
        .unwrap();

        assert_eq!(login.form_path.as_str(), "/.ianua/login");
        assert_eq!(login.workspace, "Acme");
        assert_eq!(
            login.forgot_password_path.unwrap().as_str(),
            "/.ianua/forgot-password"
        );
        assert_eq!(login.passkey_path.unwrap().as_str(), "/.ianua/passkey");
        assert_eq!(
            login.passkey_script_path.unwrap().as_str(),
            "/.ianua/passkey.js"
        );
    }

    /// Only the login page names the passkey script: the page for asking
    /// for a new password, in the same workspace, runs none.
    #[test]
    fn only_the_login_page_names_the_passkey_script() {
        let target = target(BTreeMap::new());

        let forgot = shown(&target, Vec::new(), asking(SignInAction::ForgotPassword)).unwrap();

        assert!(forgot.passkey_script_path.is_none());
    }

    /// Ann's password was set by an administrator, and her sign-in sent her
    /// browser to change it. The change page opens without a mailed link,
    /// its form posting to the change address.
    #[test]
    fn the_change_page_opens_without_a_mailed_link() {
        let change = shown(
            &target(BTreeMap::new()),
            Vec::new(),
            asking(SignInAction::ChangePassword),
        )
        .unwrap();

        assert_eq!(change.form_path.as_str(), "/.ianua/change-password");
        assert!(change.link_token.is_none());
    }

    /// A workspace with sign-ups closed refuses the sign-up page and omits
    /// its link from the login page.
    #[test]
    fn a_workspace_taking_no_sign_ups_has_no_sign_up_page_or_link() {
        let target = target(BTreeMap::new());

        let login = shown(&target, Vec::new(), asking(SignInAction::LogIn)).unwrap();
        let sign_up = shown(&target, Vec::new(), asking(SignInAction::SignUp));

        assert!(login.sign_up_path.is_none());
        assert!(matches!(sign_up, Err(AppError::Forbidden(_))));
    }

    /// The shop moved its login to a page of its own. The gateway shows no
    /// login page at its address.
    #[test]
    fn a_moved_action_has_no_page_here() {
        let mut moved = BTreeMap::new();
        moved.insert(SignInAction::LogIn, SignInPath::new("/login").unwrap());

        let login = shown(&target(moved), Vec::new(), asking(SignInAction::LogIn));

        assert!(matches!(login, Err(AppError::NotFound(_))));
    }

    /// Bob follows his reset link to the shop. The reset page carries the
    /// link's token in its form, which posts to the reset address.
    #[test]
    fn the_reset_page_carries_the_links_token() {
        let ask = PageAsk {
            link_token: Some(Secret::new("reset-token")),
            ..asking(SignInAction::ResetPassword)
        };

        let reset = shown(&target(BTreeMap::new()), Vec::new(), ask).unwrap();

        assert_eq!(reset.form_path.as_str(), "/.ianua/reset-password");
        assert_eq!(reset.link_token.unwrap().expose(), "reset-token");
    }

    /// Opening the reset page without a mailed link's token returns not found.
    #[test]
    fn the_reset_page_without_a_link_is_not_found() {
        let reset = shown(
            &target(BTreeMap::new()),
            Vec::new(),
            asking(SignInAction::ResetPassword),
        );

        assert!(matches!(reset, Err(AppError::NotFound(_))));
    }

    /// The login page omits both an active SAML connection whose protocol
    /// the workspace disables and a disabled connection.
    #[test]
    fn providers_the_workspace_does_not_take_are_not_offered() {
        let connections = vec![
            test_connection(ConnectionId::new(), ConnectionStatus::Active),
            test_connection(ConnectionId::new(), ConnectionStatus::Disabled),
        ];

        let login = shown(
            &target(BTreeMap::new()),
            connections,
            asking(SignInAction::LogIn),
        )
        .unwrap();

        assert!(login.single_sign_on.is_empty());
    }
}
