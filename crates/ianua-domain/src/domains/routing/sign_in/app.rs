//! App sign-in: signing people in on the domain of an app behind the gateway.
//!
//! A service can ask the gateway to answer a few sign-in addresses on the
//! hosts it is served on. They are log in, sign up, the second factor, email
//! verification, confirming a sign-in from the mailbox, log out, single
//! sign-on with the tenant's outside identity provider and its return,
//! passkeys, asking for and setting a new password, and changing the
//! password a sign-in owes. By default they sit under a prefix of their own,
//! `/.ianua`, so they never take a path the app already uses. Each one can be
//! moved, for an app that wants its login at `/login`.
//!
//! Each mailed link lands on an address of its own: verifying an address,
//! confirming a sign-in, resetting a password and changing one never share
//! one, so what a link does is never told apart by a cookie the browser
//! happens to hold.
//!
//! Under the prefix, the gateway also shows its own page for logging in,
//! signing up, the second factor and the password pages. An action moved to
//! a path of its own is the app's page to show. The gateway answers only the
//! form's post there.

use std::collections::BTreeMap;

use crate::domains::routing::sign_in::invalid;
use crate::message;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::shared::validation::{Charset, Rule, TextValue, ValidationError, Validator, text_value};
use crate::types::{DomainName, Setting};

/// One of the things a person can do at an app's sign-in addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum SignInAction {
    /// Sign in with an existing account.
    LogIn,
    /// Create an account, where the tenant allows it.
    SignUp,
    /// Complete sign-in with a second factor.
    Mfa,
    /// Confirm an email address from the link mailed to it.
    Verify,
    /// Finish a sign-in that waits on the mailbox, from the link mailed for
    /// it, in the browser that started it.
    ConfirmSignIn,
    /// End the session.
    LogOut,
    /// Start signing in with the tenant's outside identity provider: the
    /// browser is sent there.
    Sso,
    /// Where the outside identity provider sends the browser back, with the
    /// answer the sign-in is finished from.
    SsoCallback,
    /// Sign in with a passkey: the browser asks for a challenge and returns
    /// it signed.
    Passkey,
    /// Ask for a link to set a new password, mailed to the account's
    /// address.
    ForgotPassword,
    /// Set a new password from the mailed link.
    ResetPassword,
    /// Set the new password a sign-in owes, in the browser that signed in or
    /// from the link mailed for it.
    ChangePassword,
}

impl SignInAction {
    /// Every action, in a fixed order.
    pub const ALL: [Self; 12] = [
        Self::LogIn,
        Self::SignUp,
        Self::Mfa,
        Self::Verify,
        Self::ConfirmSignIn,
        Self::LogOut,
        Self::Sso,
        Self::SsoCallback,
        Self::Passkey,
        Self::ForgotPassword,
        Self::ResetPassword,
        Self::ChangePassword,
    ];

    /// The segment the action answers at under the prefix, unless moved.
    #[must_use]
    pub fn default_segment(self) -> &'static str {
        match self {
            Self::LogIn => "login",
            Self::SignUp => "signup",
            Self::Mfa => "mfa",
            Self::Verify => "verify",
            Self::ConfirmSignIn => "confirm-sign-in",
            Self::LogOut => "logout",
            Self::Sso => "sso",
            Self::SsoCallback => "sso-callback",
            Self::Passkey => "passkey",
            Self::ForgotPassword => "forgot-password",
            Self::ResetPassword => "reset-password",
            Self::ChangePassword => "change-password",
        }
    }

    /// Whether a person fills in a page for the action. Verifying an address
    /// and confirming a sign-in are links that are opened, and signing out a
    /// button that is pressed. Single sign-on and its return are redirects,
    /// and a passkey is asked for from the log in page.
    #[must_use]
    pub fn has_page(self) -> bool {
        matches!(
            self,
            Self::LogIn
                | Self::SignUp
                | Self::Mfa
                | Self::ForgotPassword
                | Self::ResetPassword
                | Self::ChangePassword
        )
    }
}

text_value! {
    /// An absolute path a sign-in address answers at, such as `/.ianua/login`.
    ///
    /// It is matched exactly, never as a prefix, so it keeps a plain shape. It
    /// starts with `/` and holds only unreserved URL characters. It has no
    /// empty, `.` or `..` segment, and does not end in `/`.
    pub struct SignInPath;
}

impl TextValue for SignInPath {
    const FIELD: &'static str = "path";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .url_path(256)
            .charset(
                Charset::LOWERCASE
                    | Charset::UPPERCASE
                    | Charset::DIGIT
                    | Charset::HYPHEN
                    | Charset::DOT
                    | Charset::UNDERSCORE
                    | Charset::TILDE
                    | Charset::SLASH,
            )
            .rule(&NoEmptySegment)
    }
}

impl SignInPath {
    /// The default prefix every unmoved action answers under.
    #[must_use]
    pub fn default_prefix() -> Self {
        Self("/.ianua".to_owned())
    }

    /// The root path, where people land after signing in unless told
    /// otherwise.
    #[must_use]
    pub fn root() -> Self {
        Self("/".to_owned())
    }

    /// This path with one more segment.
    fn join(&self, segment: &str) -> Self {
        Self(format!("{}/{segment}", self.0))
    }
}

/// What the gateway does with a signed-out browser on a protected page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SignedOutBrowsers {
    /// Answer `401`, as for any other client.
    #[default]
    Refuse,
    /// Send the browser to the login address, and back afterwards.
    Redirect,
}

/// The settings a service's app sign-in is built from.
pub struct AppSignInParams {
    /// The hosts the sign-in addresses answer on.
    pub hosts: Vec<DomainName>,
    /// Where unmoved actions answer. `/.ianua` when unset.
    pub prefix: Setting<SignInPath>,
    /// Actions moved to a path of their own.
    pub moved: BTreeMap<SignInAction, SignInPath>,
    /// Where people land after signing in when nothing asked otherwise. `/`
    /// when unset.
    pub after_sign_in: Setting<SignInPath>,
    /// What happens to a signed-out browser on a protected page.
    pub signed_out_browsers: SignedOutBrowsers,
}

/// How people sign in on the hosts a service is served on.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "AppSignInRecord", into = "AppSignInRecord")
)]
pub struct AppSignIn {
    hosts: Vec<DomainName>,
    prefix: SignInPath,
    moved: BTreeMap<SignInAction, SignInPath>,
    after_sign_in: SignInPath,
    signed_out_browsers: SignedOutBrowsers,
}

impl AppSignIn {
    /// Builds app sign-in settings.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when no host is named.
    /// - [`ValidationError`] when a host is a wildcard or named twice. The
    ///   session cookie belongs to one host.
    /// - [`ValidationError`] when the prefix is `/`, or an action is moved
    ///   to `/`.
    /// - [`ValidationError`] when two actions, or an action and the token,
    ///   hop or passkey script address, end up at the same path.
    /// - [`ValidationError`] when people would be sent after sign-in to a
    ///   sign-in address.
    pub fn new(params: AppSignInParams) -> Result<Self, ValidationError> {
        let sign_in = Self {
            hosts: params.hosts,
            prefix: match params.prefix {
                Setting::Set(prefix) => prefix,
                Setting::Unset => SignInPath::default_prefix(),
            },
            moved: params.moved,
            after_sign_in: match params.after_sign_in {
                Setting::Set(path) => path,
                Setting::Unset => SignInPath::root(),
            },
            signed_out_browsers: params.signed_out_browsers,
        };
        sign_in.check_hosts()?;
        sign_in.check_paths()?;
        Ok(sign_in)
    }

    fn check_hosts(&self) -> Result<(), ValidationError> {
        validate_count("hosts", self.hosts.len(), 1..=usize::MAX)?;
        if self.hosts.iter().any(DomainName::is_wildcard) {
            return Err(invalid(
                "hosts",
                "app sign-in cannot be served on a wildcard host; name each host",
            ));
        }
        if first_repeat(self.hosts.iter().map(DomainName::as_str)).is_some() {
            return Err(invalid("hosts", "a host is named more than once"));
        }
        Ok(())
    }

    fn check_paths(&self) -> Result<(), ValidationError> {
        let root = SignInPath::root();
        if self.prefix == root {
            return Err(invalid_path(
                "the prefix cannot be '/'; move single actions instead",
            ));
        }
        if self.moved.values().any(|moved| *moved == root) {
            return Err(invalid_path(
                "a sign-in action cannot take '/', the app's own home page",
            ));
        }
        let mut paths: Vec<SignInPath> = SignInAction::ALL.map(|action| self.path(action)).into();
        paths.extend([self.token_path(), self.hop_path(), self.script_path()]);
        if first_repeat(paths.iter().map(SignInPath::as_str)).is_some() {
            return Err(invalid_path("two sign-in actions answer at the same path"));
        }
        if paths.contains(&self.after_sign_in) {
            return Err(invalid_path(
                "people cannot be sent to a sign-in address after signing in",
            ));
        }
        Ok(())
    }

    /// The hosts the sign-in addresses answer on.
    #[must_use]
    pub fn hosts(&self) -> &[DomainName] {
        &self.hosts
    }

    /// Whether the sign-in addresses answer on `host`.
    #[must_use]
    pub fn serves(&self, host: &str) -> bool {
        self.hosts
            .iter()
            .any(|own| own.as_str().eq_ignore_ascii_case(host))
    }

    /// The prefix unmoved actions answer under.
    #[must_use]
    pub fn prefix(&self) -> &SignInPath {
        &self.prefix
    }

    /// The actions moved to a path of their own.
    #[must_use]
    pub fn moved(&self) -> &BTreeMap<SignInAction, SignInPath> {
        &self.moved
    }

    /// The path `action` answers at.
    #[must_use]
    pub fn path(&self, action: SignInAction) -> SignInPath {
        self.moved
            .get(&action)
            .cloned()
            .unwrap_or_else(|| self.prefix.join(action.default_segment()))
    }

    /// Where the owner's pages fetch short-lived tokens for services that
    /// accept this sign-in by token. Always under the prefix.
    #[must_use]
    pub fn token_path(&self) -> SignInPath {
        self.prefix.join(TOKEN_SEGMENT)
    }

    /// Where a service accepting this sign-in with a cookie of its own
    /// receives it, on that service's hosts, and where those hosts ask the
    /// owner's hosts for the code that carries it. Always under the prefix.
    #[must_use]
    pub fn hop_path(&self) -> SignInPath {
        self.prefix.join(HOP_SEGMENT)
    }

    /// Where the gateway serves the one script its login page runs, the one
    /// that signs in with a passkey. Always under the prefix, so nothing the
    /// app serves can stand in for it.
    #[must_use]
    pub fn script_path(&self) -> SignInPath {
        self.prefix.join(SCRIPT_SEGMENT)
    }

    /// Whether the gateway shows its own page for `action`. That is so for an
    /// action a person fills in that is left under the prefix. A moved
    /// action's page is the app's.
    #[must_use]
    pub fn shows_page(&self, action: SignInAction) -> bool {
        action.has_page() && !self.moved.contains_key(&action)
    }

    /// The action answering at exactly `path`, if any.
    #[must_use]
    pub fn action_at(&self, path: &str) -> Option<SignInAction> {
        SignInAction::ALL
            .into_iter()
            .find(|action| self.path(*action).as_str() == path)
    }

    /// Whether `path` is under the prefix, answered or not. Such a path is
    /// never handed to the app.
    #[must_use]
    pub fn reserves(&self, path: &str) -> bool {
        path.strip_prefix(self.prefix.as_str())
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    }

    /// Where people land after signing in when nothing asked otherwise.
    #[must_use]
    pub fn after_sign_in(&self) -> &SignInPath {
        &self.after_sign_in
    }

    /// What happens to a signed-out browser on a protected page.
    #[must_use]
    pub fn signed_out_browsers(&self) -> SignedOutBrowsers {
        self.signed_out_browsers
    }
}

/// [`AppSignIn`] as stored, read back through [`AppSignIn::new`] so stored
/// settings are held to the same rules as new ones.
#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct AppSignInRecord {
    hosts: Vec<DomainName>,
    prefix: SignInPath,
    #[serde(default)]
    moved: BTreeMap<SignInAction, SignInPath>,
    after_sign_in: SignInPath,
    #[serde(default)]
    signed_out_browsers: SignedOutBrowsers,
}

#[cfg(feature = "serde")]
impl TryFrom<AppSignInRecord> for AppSignIn {
    type Error = ValidationError;

    fn try_from(record: AppSignInRecord) -> Result<Self, Self::Error> {
        Self::new(AppSignInParams {
            hosts: record.hosts,
            prefix: Setting::Set(record.prefix),
            moved: record.moved,
            after_sign_in: Setting::Set(record.after_sign_in),
            signed_out_browsers: record.signed_out_browsers,
        })
    }
}

#[cfg(feature = "serde")]
impl From<AppSignIn> for AppSignInRecord {
    fn from(sign_in: AppSignIn) -> Self {
        Self {
            hosts: sign_in.hosts,
            prefix: sign_in.prefix,
            moved: sign_in.moved,
            after_sign_in: sign_in.after_sign_in,
            signed_out_browsers: sign_in.signed_out_browsers,
        }
    }
}

const TOKEN_SEGMENT: &str = "token";
const HOP_SEGMENT: &str = "hop";
const SCRIPT_SEGMENT: &str = "passkey.js";

fn invalid_path(message: &str) -> ValidationError {
    invalid("path", message)
}

/// Refuses an empty segment, so no `//` and no trailing `/`. The root `/`
/// itself is allowed.
struct NoEmptySegment;

impl Rule for NoEmptySegment {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let rest = value.strip_prefix('/')?;
        if rest.is_empty() || !rest.split('/').any(str::is_empty) {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "invalid_path".to_owned(),
            message: message!(
                "routing-a-sign-in-path-may-not",
                "a sign-in path may not end in '/' or hold an empty segment"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str) -> DomainName {
        DomainName::new(name).unwrap()
    }

    fn path(value: &str) -> SignInPath {
        SignInPath::new(value).unwrap()
    }

    fn params() -> AppSignInParams {
        AppSignInParams {
            hosts: vec![host("app.example.com")],
            prefix: Setting::Unset,
            moved: BTreeMap::new(),
            after_sign_in: Setting::Unset,
            signed_out_browsers: SignedOutBrowsers::Refuse,
        }
    }

    /// With nothing moved, log in, sign up and log out answer under
    /// `/.ianua`. People land on `/` after signing in.
    #[test]
    fn every_action_answers_under_the_default_prefix_unless_moved() {
        let sign_in = AppSignIn::new(params()).unwrap();

        assert_eq!(sign_in.path(SignInAction::LogIn).as_str(), "/.ianua/login");
        assert_eq!(
            sign_in.path(SignInAction::SignUp).as_str(),
            "/.ianua/signup"
        );
        assert_eq!(
            sign_in.path(SignInAction::LogOut).as_str(),
            "/.ianua/logout"
        );
        assert_eq!(sign_in.after_sign_in().as_str(), "/");
    }

    /// With nothing moved, single sign-on, its return, passkeys and the
    /// password reset pair answer under `/.ianua`, each at its own path.
    #[test]
    fn sso_passkey_and_password_reset_answer_under_the_prefix() {
        let sign_in = AppSignIn::new(params()).unwrap();

        assert_eq!(sign_in.action_at("/.ianua/sso"), Some(SignInAction::Sso));
        assert_eq!(
            sign_in.action_at("/.ianua/sso-callback"),
            Some(SignInAction::SsoCallback)
        );
        assert_eq!(
            sign_in.action_at("/.ianua/passkey"),
            Some(SignInAction::Passkey)
        );
        assert_eq!(
            sign_in.action_at("/.ianua/forgot-password"),
            Some(SignInAction::ForgotPassword)
        );
        assert_eq!(
            sign_in.action_at("/.ianua/reset-password"),
            Some(SignInAction::ResetPassword)
        );
    }

    /// Ann asks for a password reset and then sets one: both have a page the
    /// gateway shows. Passkeys and single sign-on have none of their own.
    #[test]
    fn the_password_reset_pair_has_pages_and_sso_does_not() {
        let sign_in = AppSignIn::new(params()).unwrap();

        assert!(sign_in.shows_page(SignInAction::ForgotPassword));
        assert!(sign_in.shows_page(SignInAction::ResetPassword));
        assert!(!sign_in.shows_page(SignInAction::Passkey));
        assert!(!sign_in.shows_page(SignInAction::Sso));
    }

    /// An app moves log in to `/login`. Log in answers there and not at
    /// `/.ianua/login`, while sign up stays under the prefix.
    #[test]
    fn a_moved_action_answers_only_at_its_new_path() {
        let mut moved = BTreeMap::new();
        moved.insert(SignInAction::LogIn, path("/login"));
        let sign_in = AppSignIn::new(AppSignInParams { moved, ..params() }).unwrap();

        assert_eq!(sign_in.action_at("/login"), Some(SignInAction::LogIn));
        assert_eq!(sign_in.action_at("/.ianua/login"), None);
        assert_eq!(
            sign_in.action_at("/.ianua/signup"),
            Some(SignInAction::SignUp)
        );
    }

    /// An app sets the prefix to `/account`. The second factor then answers
    /// at `/account/mfa`.
    #[test]
    fn a_prefix_moves_every_unmoved_action() {
        let sign_in = AppSignIn::new(AppSignInParams {
            prefix: Setting::Set(path("/account")),
            ..params()
        })
        .unwrap();

        assert_eq!(sign_in.path(SignInAction::Mfa).as_str(), "/account/mfa");
    }

    /// Neither `/.ianua/login/extra` nor `/.ianua/LOGIN` is the log in
    /// address. Only the exact path matches.
    #[test]
    fn an_action_is_matched_exactly_never_as_a_prefix() {
        let sign_in = AppSignIn::new(params()).unwrap();

        assert_eq!(sign_in.action_at("/.ianua/login/extra"), None);
        assert_eq!(sign_in.action_at("/.ianua/LOGIN"), None);
    }

    /// `/.ianua` and `/.ianua/unknown` are reserved and never reach the app.
    /// `/.ianuax/login` and `/login` are not.
    #[test]
    fn everything_under_the_prefix_is_reserved() {
        let sign_in = AppSignIn::new(params()).unwrap();

        assert!(sign_in.reserves("/.ianua/unknown"));
        assert!(sign_in.reserves("/.ianua"));
        assert!(!sign_in.reserves("/.ianuax/login"));
        assert!(!sign_in.reserves("/login"));
    }

    /// An app moves log in and sign up both to `/enter`. It is refused.
    #[test]
    fn two_actions_at_one_path_are_refused() {
        let mut moved = BTreeMap::new();
        moved.insert(SignInAction::LogIn, path("/enter"));
        moved.insert(SignInAction::SignUp, path("/enter"));

        assert!(AppSignIn::new(AppSignInParams { moved, ..params() }).is_err());
    }

    /// An app moves log out to `/.ianua/login`, where log in still answers.
    /// It is refused.
    #[test]
    fn a_moved_action_cannot_take_another_actions_default_path() {
        let mut moved = BTreeMap::new();
        moved.insert(SignInAction::LogOut, path("/.ianua/login"));

        assert!(AppSignIn::new(AppSignInParams { moved, ..params() }).is_err());
    }

    /// An app sets the landing page after sign-in to `/.ianua/login`. It is
    /// refused, since people would land back on the login.
    #[test]
    fn people_are_never_sent_to_a_sign_in_address_after_signing_in() {
        let result = AppSignIn::new(AppSignInParams {
            after_sign_in: Setting::Set(path("/.ianua/login")),
            ..params()
        });

        assert!(result.is_err());
    }

    /// An app sets the prefix to `/`. It is refused, since every path of the
    /// app would be reserved.
    #[test]
    fn a_root_prefix_is_refused() {
        let result = AppSignIn::new(AppSignInParams {
            prefix: Setting::Set(SignInPath::root()),
            ..params()
        });

        assert!(result.is_err());
    }

    /// App sign-in with no hosts, with one host twice in different case, or
    /// on `*.example.com` is refused.
    #[test]
    fn hosts_are_required_named_once_and_never_wildcards() {
        for hosts in [
            vec![],
            vec![host("app.example.com"), host("APP.example.com")],
            vec![host("*.example.com")],
        ] {
            assert!(AppSignIn::new(AppSignInParams { hosts, ..params() }).is_err());
        }
    }

    /// Sign-in on `app.example.com` serves `App.Example.com`. It does not
    /// serve `other.example.com`.
    #[test]
    fn a_host_is_served_whatever_its_case() {
        let sign_in = AppSignIn::new(params()).unwrap();

        assert!(sign_in.serves("App.Example.com"));
        assert!(!sign_in.serves("other.example.com"));
    }

    /// A sign-in path that is empty, relative, has an empty or dot segment,
    /// or holds `?`, a space, `%` or `\` is refused. `/`, `/.ianua/login`
    /// and `/Account/sign-in_v2~` are accepted.
    #[test]
    fn sign_in_paths_reject_every_unsafe_shape() {
        for value in [
            "",
            "login",
            "//login",
            "/login/",
            "/a//b",
            "/./login",
            "/../login",
            "/login?x=1",
            "/log in",
            "/login%2F",
            "/login\\x",
        ] {
            assert!(SignInPath::new(value).is_err(), "{value:?} must be refused");
        }
        assert!(SignInPath::new("/").is_ok());
        assert!(SignInPath::new("/.ianua/login").is_ok());
        assert!(SignInPath::new("/Account/sign-in_v2~").is_ok());
    }

    /// An app redirects signed-out browsers to log in. That is accepted with
    /// log in under the prefix, and with log in moved to the app's `/login`.
    #[test]
    fn browsers_may_be_sent_to_sign_in_under_the_prefix_or_at_an_app_page() {
        let under_prefix = AppSignIn::new(AppSignInParams {
            signed_out_browsers: SignedOutBrowsers::Redirect,
            ..params()
        });
        assert!(under_prefix.is_ok());

        let mut moved = BTreeMap::new();
        moved.insert(SignInAction::LogIn, path("/login"));
        let at_app_page = AppSignIn::new(AppSignInParams {
            moved,
            signed_out_browsers: SignedOutBrowsers::Redirect,
            ..params()
        });
        assert!(at_app_page.is_ok());
    }

    /// Log in is moved to `/login`. The gateway shows pages for sign up and
    /// the second factor only, not for moved log in, verify or log out.
    #[test]
    fn the_gateway_shows_pages_only_for_actions_left_under_the_prefix() {
        let mut moved = BTreeMap::new();
        moved.insert(SignInAction::LogIn, path("/login"));
        let sign_in = AppSignIn::new(AppSignInParams { moved, ..params() }).unwrap();

        assert!(!sign_in.shows_page(SignInAction::LogIn));
        assert!(sign_in.shows_page(SignInAction::SignUp));
        assert!(sign_in.shows_page(SignInAction::Mfa));
        assert!(!sign_in.shows_page(SignInAction::Verify));
        assert!(!sign_in.shows_page(SignInAction::LogOut));
    }

    /// Each mailed link lands on an address of its own: verifying an
    /// address, confirming a sign-in, resetting a password and changing one
    /// never share a path, so none is told apart by a cookie.
    #[test]
    fn every_mailed_link_lands_on_an_address_of_its_own() {
        let sign_in = AppSignIn::new(params()).unwrap();

        let landings = [
            SignInAction::Verify,
            SignInAction::ConfirmSignIn,
            SignInAction::ResetPassword,
            SignInAction::ChangePassword,
        ]
        .map(|action| sign_in.path(action).as_str().to_owned());

        assert_eq!(
            landings,
            [
                "/.ianua/verify",
                "/.ianua/confirm-sign-in",
                "/.ianua/reset-password",
                "/.ianua/change-password",
            ]
        );
    }

    /// Ann's password was set by an administrator: the change page is one
    /// the gateway shows. Confirming a sign-in is a link, with no page.
    #[test]
    fn the_change_page_is_shown_and_the_confirm_link_has_none() {
        let sign_in = AppSignIn::new(params()).unwrap();

        assert!(sign_in.shows_page(SignInAction::ChangePassword));
        assert!(!sign_in.shows_page(SignInAction::ConfirmSignIn));
    }

    /// The login page's passkey script is served under the prefix, which
    /// moves it along with everything else.
    #[test]
    fn the_passkey_script_is_served_under_the_prefix() {
        let sign_in = AppSignIn::new(AppSignInParams {
            prefix: Setting::Set(path("/account")),
            ..params()
        })
        .unwrap();

        assert_eq!(sign_in.script_path().as_str(), "/account/passkey.js");
        assert!(sign_in.reserves(sign_in.script_path().as_str()));
    }

    /// An app moves log in to `/.ianua/token`, `/.ianua/hop` or
    /// `/.ianua/passkey.js`. Each is refused, since those addresses are
    /// fixed.
    #[test]
    fn no_action_can_take_the_token_hop_or_script_address() {
        for taken in ["/.ianua/token", "/.ianua/hop", "/.ianua/passkey.js"] {
            let mut moved = BTreeMap::new();
            moved.insert(SignInAction::LogIn, path(taken));

            assert!(
                AppSignIn::new(AppSignInParams { moved, ..params() }).is_err(),
                "{taken}"
            );
        }
    }

    /// An app moves log in to `/`. It is refused, since `/` is the app's own
    /// home page.
    #[test]
    fn no_action_can_take_the_apps_home_page() {
        let mut moved = BTreeMap::new();
        moved.insert(SignInAction::LogIn, SignInPath::root());

        assert!(AppSignIn::new(AppSignInParams { moved, ..params() }).is_err());
    }

    /// Stored settings have the prefix `/`. Reading them is refused, as
    /// building them would be.
    #[cfg(feature = "serde")]
    #[test]
    fn stored_settings_are_held_to_the_same_rules() {
        let stored = serde_json::json!({
            "hosts": ["app.example.com"],
            "prefix": "/",
            "after_sign_in": "/",
        });

        assert!(serde_json::from_value::<AppSignIn>(stored).is_err());
    }

    /// Settings with log in moved to `/login` and browsers redirected are
    /// written to JSON and read back. They come back equal.
    #[cfg(feature = "serde")]
    #[test]
    fn settings_survive_a_round_trip() {
        let mut moved = BTreeMap::new();
        moved.insert(SignInAction::LogIn, path("/login"));
        let sign_in = AppSignIn::new(AppSignInParams {
            moved,
            signed_out_browsers: SignedOutBrowsers::Redirect,
            ..params()
        })
        .unwrap();

        let json = serde_json::to_value(&sign_in).unwrap();

        assert_eq!(serde_json::from_value::<AppSignIn>(json).unwrap(), sign_in);
    }
}
