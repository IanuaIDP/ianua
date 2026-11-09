//! App sign-in settings on the wire: where people sign in on the hosts a
//! service is served on, and whose sign-in a service accepts instead.

use std::collections::BTreeMap;

use ianua_app::use_cases::routing::services::ConfigureAppSignInRequest;
use ianua_app::use_cases::routing::services::sign_in_checks::SignInSettings;
use ianua_domain::domains::routing::sign_in::accepted::{
    AcceptedSignIn, CookieHosts, SignInDelivery,
};
use ianua_domain::domains::routing::sign_in::app::{
    AppSignIn, AppSignInParams, SignInAction, SignInPath, SignedOutBrowsers,
};
use ianua_domain::types::{DomainName, ServiceId, Setting};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;

/// A service's app sign-in, as an administrator sets it.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AppSignInBody {
    /// The service's own app sign-in, or `null` for none.
    #[serde(default)]
    pub app_sign_in: Option<AppSignInSettings>,
    /// A service whose app sign-in this one accepts instead, or `null` for
    /// none.
    #[serde(default)]
    pub accepts_app_sign_in_of: Option<Uuid>,
    /// How that sign-in reaches this service. Defaults to `same_host`.
    #[serde(default)]
    pub delivery: Option<SignInDeliveryBody>,
}

impl AppSignInBody {
    /// The settings this body gives `service`.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::validation`] naming the first host or path that
    /// is not well formed, or a combination the settings' rules refuse.
    pub(crate) fn into_request(
        self,
        service: ServiceId,
    ) -> Result<ConfigureAppSignInRequest, ApiError> {
        let own = self.app_sign_in.map(AppSignIn::try_from).transpose()?;
        let delivery = self
            .delivery
            .map(SignInDelivery::try_from)
            .transpose()?
            .unwrap_or(SignInDelivery::SameHost);
        let accepted = self
            .accepts_app_sign_in_of
            .map(|owner| AcceptedSignIn::new(ServiceId::from_uuid(owner), delivery));
        Ok(ConfigureAppSignInRequest {
            service_id: service,
            settings: SignInSettings {
                own: Setting::from_stored(own),
                accepted: Setting::from_stored(accepted),
            },
        })
    }
}

/// How another service's sign-in reaches a service accepting it.
#[derive(Deserialize, Serialize, Clone, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum SignInDeliveryBody {
    /// On the owner's hosts, with the owner's cookie: the service is served
    /// there too, for example under `/api`.
    SameHost,
    /// A cookie of its own on these hosts, set as part of signing in. The
    /// hosts must be on the same site as the owner's for the browser to
    /// send it from the owner's pages.
    OwnCookie {
        /// The hosts the cookie is set on.
        hosts: Vec<String>,
    },
    /// Short-lived bearer tokens the owner's pages fetch from its token
    /// address.
    Tokens,
}

impl TryFrom<SignInDeliveryBody> for SignInDelivery {
    type Error = ApiError;

    fn try_from(body: SignInDeliveryBody) -> Result<Self, Self::Error> {
        match body {
            SignInDeliveryBody::SameHost => Ok(Self::SameHost),
            SignInDeliveryBody::Tokens => Ok(Self::Tokens),
            SignInDeliveryBody::OwnCookie { hosts } => {
                let hosts = domain_names(hosts)?;
                CookieHosts::new(hosts)
                    .map(Self::OwnCookie)
                    .map_err(ApiError::validation)
            }
        }
    }
}

impl From<&SignInDelivery> for SignInDeliveryBody {
    fn from(delivery: &SignInDelivery) -> Self {
        match delivery {
            SignInDelivery::SameHost => Self::SameHost,
            SignInDelivery::Tokens => Self::Tokens,
            SignInDelivery::OwnCookie(hosts) => Self::OwnCookie {
                hosts: hosts
                    .hosts()
                    .iter()
                    .map(|h| h.as_str().to_owned())
                    .collect(),
            },
        }
    }
}

/// Where and how people sign in on the hosts a service is served on.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct AppSignInSettings {
    /// The hosts the sign-in addresses answer on, each a verified domain of
    /// the tenant that a route of this service answers on.
    pub hosts: Vec<String>,
    /// The path the addresses answer under. Defaults to `/.ianua`.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Addresses moved to a path of their own, such as login at `/login`.
    #[serde(default)]
    pub paths: SignInPaths,
    /// Where people land after signing in, unless they came from somewhere.
    /// Defaults to `/`.
    #[serde(default)]
    pub after_sign_in: Option<String>,
    /// What happens to a signed-out browser on a page that needs sign-in.
    #[serde(default)]
    pub signed_out_browsers: SignedOutBrowsersBody,
}

impl TryFrom<AppSignInSettings> for AppSignIn {
    type Error = ApiError;

    fn try_from(settings: AppSignInSettings) -> Result<Self, Self::Error> {
        Self::new(AppSignInParams {
            hosts: domain_names(settings.hosts)?,
            prefix: Setting::from_stored(sign_in_path(settings.prefix)?),
            moved: settings.paths.into_moved()?,
            after_sign_in: Setting::from_stored(sign_in_path(settings.after_sign_in)?),
            signed_out_browsers: settings.signed_out_browsers.into(),
        })
        .map_err(ApiError::validation)
    }
}

impl From<&AppSignIn> for AppSignInSettings {
    fn from(sign_in: &AppSignIn) -> Self {
        Self {
            hosts: host_texts(sign_in.hosts()),
            prefix: Some(sign_in.prefix().as_str().to_owned()),
            paths: SignInPaths::moved_in(sign_in),
            after_sign_in: Some(sign_in.after_sign_in().as_str().to_owned()),
            signed_out_browsers: sign_in.signed_out_browsers().into(),
        }
    }
}

/// One path per sign-in address; `null` keeps the address under the prefix.
#[derive(Deserialize, Serialize, Default, utoipa::ToSchema)]
pub(crate) struct SignInPaths {
    /// Signing in.
    #[serde(default)]
    pub login: Option<String>,
    /// Creating an account, where the tenant allows it.
    #[serde(default)]
    pub signup: Option<String>,
    /// The second factor.
    #[serde(default)]
    pub mfa: Option<String>,
    /// Confirming an email address.
    #[serde(default)]
    pub verify: Option<String>,
    /// Finishing a sign-in from the link mailed for it.
    #[serde(default)]
    pub confirm_sign_in: Option<String>,
    /// Signing out.
    #[serde(default)]
    pub logout: Option<String>,
    /// Starting single sign-on through an outside identity provider.
    #[serde(default)]
    pub sso: Option<String>,
    /// Where the outside identity provider sends the person back.
    #[serde(default)]
    pub sso_callback: Option<String>,
    /// Signing in with a passkey.
    #[serde(default)]
    pub passkey: Option<String>,
    /// Asking for a link to set a new password.
    #[serde(default)]
    pub forgot_password: Option<String>,
    /// Setting a new password from the mailed link.
    #[serde(default)]
    pub reset_password: Option<String>,
    /// Setting the new password a sign-in owes.
    #[serde(default)]
    pub change_password: Option<String>,
}

impl SignInPaths {
    /// The addresses `sign_in` moved to a path of their own.
    fn moved_in(sign_in: &AppSignIn) -> Self {
        let moved = |action| {
            sign_in
                .moved()
                .get(&action)
                .map(|path| path.as_str().to_owned())
        };
        Self {
            login: moved(SignInAction::LogIn),
            signup: moved(SignInAction::SignUp),
            mfa: moved(SignInAction::Mfa),
            verify: moved(SignInAction::Verify),
            confirm_sign_in: moved(SignInAction::ConfirmSignIn),
            logout: moved(SignInAction::LogOut),
            sso: moved(SignInAction::Sso),
            sso_callback: moved(SignInAction::SsoCallback),
            passkey: moved(SignInAction::Passkey),
            forgot_password: moved(SignInAction::ForgotPassword),
            reset_password: moved(SignInAction::ResetPassword),
            change_password: moved(SignInAction::ChangePassword),
        }
    }

    /// The moved addresses as the domain holds them.
    fn into_moved(self) -> Result<BTreeMap<SignInAction, SignInPath>, ApiError> {
        let pairs = [
            (SignInAction::LogIn, self.login),
            (SignInAction::SignUp, self.signup),
            (SignInAction::Mfa, self.mfa),
            (SignInAction::Verify, self.verify),
            (SignInAction::ConfirmSignIn, self.confirm_sign_in),
            (SignInAction::LogOut, self.logout),
            (SignInAction::Sso, self.sso),
            (SignInAction::SsoCallback, self.sso_callback),
            (SignInAction::Passkey, self.passkey),
            (SignInAction::ForgotPassword, self.forgot_password),
            (SignInAction::ResetPassword, self.reset_password),
            (SignInAction::ChangePassword, self.change_password),
        ];
        let mut moved = BTreeMap::new();
        for (action, raw) in pairs {
            let Some(path) = sign_in_path(raw)? else {
                continue;
            };
            moved.insert(action, path);
        }
        Ok(moved)
    }
}

/// What happens to a signed-out browser on a page that needs sign-in.
#[derive(Deserialize, Serialize, Default, Clone, Copy, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SignedOutBrowsersBody {
    /// Answer `401`, as for any other client.
    #[default]
    Refuse,
    /// Send the browser to the login address, and back afterwards.
    Redirect,
}

impl From<SignedOutBrowsersBody> for SignedOutBrowsers {
    fn from(body: SignedOutBrowsersBody) -> Self {
        match body {
            SignedOutBrowsersBody::Refuse => Self::Refuse,
            SignedOutBrowsersBody::Redirect => Self::Redirect,
        }
    }
}

impl From<SignedOutBrowsers> for SignedOutBrowsersBody {
    fn from(setting: SignedOutBrowsers) -> Self {
        match setting {
            SignedOutBrowsers::Refuse => Self::Refuse,
            SignedOutBrowsers::Redirect => Self::Redirect,
        }
    }
}

/// A service's app sign-in, as the dashboard shows it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AppSignInView {
    /// The hosts the sign-in addresses answer on.
    pub hosts: Vec<String>,
    /// The path unmoved addresses answer under.
    pub prefix: String,
    /// The addresses moved to a path of their own.
    pub paths: SignInPaths,
    /// Every address, where it answers now.
    pub addresses: SignInAddresses,
    /// Where people land after signing in.
    pub after_sign_in: String,
    /// What happens to a signed-out browser on a page that needs sign-in.
    pub signed_out_browsers: SignedOutBrowsersBody,
}

/// Where each sign-in address answers.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SignInAddresses {
    /// Signing in.
    pub login: String,
    /// Creating an account.
    pub signup: String,
    /// The second factor.
    pub mfa: String,
    /// Confirming an email address.
    pub verify: String,
    /// Finishing a sign-in from the link mailed for it.
    pub confirm_sign_in: String,
    /// Signing out.
    pub logout: String,
    /// Starting single sign-on.
    pub sso: String,
    /// Where the outside identity provider sends the person back.
    pub sso_callback: String,
    /// Signing in with a passkey.
    pub passkey: String,
    /// Asking for a link to set a new password.
    pub forgot_password: String,
    /// Setting a new password from the mailed link.
    pub reset_password: String,
    /// Setting the new password a sign-in owes.
    pub change_password: String,
}

impl From<&AppSignIn> for AppSignInView {
    fn from(sign_in: &AppSignIn) -> Self {
        let at = |action| sign_in.path(action).as_str().to_owned();
        Self {
            hosts: host_texts(sign_in.hosts()),
            prefix: sign_in.prefix().as_str().to_owned(),
            paths: SignInPaths::moved_in(sign_in),
            addresses: SignInAddresses {
                login: at(SignInAction::LogIn),
                signup: at(SignInAction::SignUp),
                mfa: at(SignInAction::Mfa),
                verify: at(SignInAction::Verify),
                confirm_sign_in: at(SignInAction::ConfirmSignIn),
                logout: at(SignInAction::LogOut),
                sso: at(SignInAction::Sso),
                sso_callback: at(SignInAction::SsoCallback),
                passkey: at(SignInAction::Passkey),
                forgot_password: at(SignInAction::ForgotPassword),
                reset_password: at(SignInAction::ResetPassword),
                change_password: at(SignInAction::ChangePassword),
            },
            after_sign_in: sign_in.after_sign_in().as_str().to_owned(),
            signed_out_browsers: sign_in.signed_out_browsers().into(),
        }
    }
}

/// Reads host names, refusing the first one that is not well formed.
fn domain_names(hosts: Vec<String>) -> Result<Vec<DomainName>, ApiError> {
    hosts
        .into_iter()
        .map(DomainName::new)
        .collect::<Result<_, _>>()
        .map_err(ApiError::validation)
}

/// Host names as text.
fn host_texts(hosts: &[DomainName]) -> Vec<String> {
    hosts.iter().map(|h| h.as_str().to_owned()).collect()
}

/// Reads an optional sign-in path.
fn sign_in_path(raw: Option<String>) -> Result<Option<SignInPath>, ApiError> {
    raw.map(SignInPath::new)
        .transpose()
        .map_err(ApiError::validation)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The app sign-in body `json` describes.
    fn body(json: serde_json::Value) -> AppSignInBody {
        serde_json::from_value(json).unwrap()
    }

    /// The sign-in settings a body of `json` asks for, failing the test if
    /// they are refused.
    fn settings(json: serde_json::Value) -> SignInSettings {
        let Ok(request) = body(json).into_request(ServiceId::new()) else {
            panic!("the settings were refused");
        };
        request.settings
    }

    /// A service that accepts another service's sign-in but names no
    /// delivery takes the session on the owner's own hosts.
    #[test]
    fn accepting_without_a_delivery_means_on_the_owners_hosts() {
        let owner = Uuid::now_v7();

        let settings = settings(serde_json::json!({ "accepts_app_sign_in_of": owner }));

        let accepted = settings.accepted.value().unwrap();
        assert_eq!(accepted.owner().as_uuid(), &owner);
        assert_eq!(*accepted.delivery(), SignInDelivery::SameHost);
    }

    /// A service that wants a cookie of its own keeps the hosts it names
    /// for it.
    #[test]
    fn a_cookie_of_its_own_names_its_hosts() {
        let settings = settings(serde_json::json!({
            "accepts_app_sign_in_of": Uuid::now_v7(),
            "delivery": { "kind": "own_cookie", "hosts": ["api.example.com"] },
        }));

        assert_eq!(
            settings.accepted.value().unwrap().cookie_hosts()[0].as_str(),
            "api.example.com"
        );
    }

    /// A cookie of its own with no hosts to set it on is refused.
    #[test]
    fn a_cookie_of_its_own_without_hosts_is_refused() {
        let refused = body(serde_json::json!({
            "accepts_app_sign_in_of": Uuid::now_v7(),
            "delivery": { "kind": "own_cookie", "hosts": [] },
        }))
        .into_request(ServiceId::new());

        assert!(refused.is_err());
    }

    /// A shop moves its login to `/login`: the login answers there, sign-up
    /// stays at its usual address, and signed-out browsers are redirected.
    #[test]
    fn a_body_with_a_moved_login_becomes_settings_answering_there() {
        let settings = settings(serde_json::json!({
            "app_sign_in": {
                "hosts": ["shop.example.com"],
                "paths": { "login": "/login" },
                "signed_out_browsers": "redirect"
            }
        }));

        let sign_in = settings.own.value().unwrap();
        assert_eq!(sign_in.path(SignInAction::LogIn).as_str(), "/login");
        assert_eq!(
            sign_in.path(SignInAction::SignUp).as_str(),
            "/.ianua/signup"
        );
        assert_eq!(sign_in.signed_out_browsers(), SignedOutBrowsers::Redirect);
        assert!(settings.accepted.is_unset());
    }

    /// An empty body leaves the service with no app sign-in of its own and
    /// none accepted.
    #[test]
    fn an_empty_body_turns_app_sign_in_off() {
        let settings = settings(serde_json::json!({}));

        assert!(settings.own.is_unset());
        assert!(settings.accepted.is_unset());
    }

    /// A sign-in path that does not start with a slash is refused.
    #[test]
    fn a_malformed_path_is_refused() {
        let refused = body(serde_json::json!({
            "app_sign_in": { "hosts": ["shop.example.com"], "paths": { "login": "login" } }
        }))
        .into_request(ServiceId::new());

        assert!(refused.is_err());
    }

    /// The view lists every address sign-in answers at, while the paths
    /// show only the ones the owner moved.
    #[test]
    fn the_view_shows_every_address_where_it_answers() {
        let settings = settings(serde_json::json!({
            "app_sign_in": { "hosts": ["shop.example.com"], "paths": { "logout": "/bye" } }
        }));

        let view = AppSignInView::from(settings.own.value().unwrap());

        assert_eq!(view.addresses.login, "/.ianua/login");
        assert_eq!(view.addresses.logout, "/bye");
        assert_eq!(view.paths.logout.as_deref(), Some("/bye"));
        assert!(view.paths.login.is_none());
    }
}
