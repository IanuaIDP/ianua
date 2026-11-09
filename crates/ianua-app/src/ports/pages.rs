//! Drawing the pages a person's browser is shown at an app's host: the
//! sign-in pages, and the page of a refused or failed request.
//!
//! What a page says and offers is decided inside: a sign-in page by the app
//! sign-in, an error page by whoever refused the request. The adapter only
//! draws it. A page holds no script of its own: the login page only names
//! the one script the gateway serves itself, for passkeys. Every value a
//! page prints is escaped, and an error page never carries the reason behind
//! a refusal, only its kind and a reference to find it by in the logs.

use ianua_domain::domains::branding::config::TenantBranding;
use ianua_domain::domains::routing::sign_in::app::{SignInAction, SignInPath};
use ianua_domain::domains::routing::sign_in::return_path::ReturnPath;
use ianua_domain::isolation::scope::{ResolvedTenant, TenantScope};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    ConnectionId, CorrelationId, DenialStatus, DisplayName, HexColor, HttpsUrl, Label,
};

use crate::ports::shared::PreferredLanguages;

/// Draws the pages the gateway shows a browser.
pub trait PageRenderer: Send + Sync {
    /// The HTML of the sign-in page `page`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the page cannot be drawn,
    /// such as for a step that has no page.
    fn sign_in_page(&self, page: &SignInPage) -> Result<DrawnPage, DomainError>;

    /// The HTML of the error page `page`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the page cannot be drawn.
    fn error_page(&self, page: &ErrorPage) -> Result<DrawnPage, DomainError>;
}

/// A page drawn as HTML, ready to be served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrawnPage(String);

impl DrawnPage {
    /// The page drawn as `html`.
    #[must_use]
    pub fn new(html: String) -> Self {
        Self(html)
    }

    /// The page's HTML.
    #[must_use]
    pub fn html(&self) -> &str {
        &self.0
    }

    /// The page's HTML, taken out.
    #[must_use]
    pub fn into_html(self) -> String {
        self.0
    }
}

/// A sign-in page, ready to be drawn. Holds the token of a mailed link, so
/// it has no `Debug`.
pub struct SignInPage {
    /// Which page: logging in, signing up, the second factor, asking for
    /// and setting a new password, or changing the one a sign-in owes.
    pub action: SignInAction,
    /// The workspace's name, as its people know it.
    pub workspace: String,
    /// The workspace's branding, if it set any.
    pub branding: Option<TenantBranding<ResolvedTenant>>,
    /// Where the page's form posts.
    pub form_path: SignInPath,
    /// The login address, for a link back to it.
    pub log_in_path: SignInPath,
    /// The sign-up address, when the workspace takes sign-ups.
    pub sign_up_path: Option<SignInPath>,
    /// The address for asking for a new password, when the workspace takes
    /// passwords.
    pub forgot_password_path: Option<SignInPath>,
    /// The passkey address, when the workspace takes passkeys.
    pub passkey_path: Option<SignInPath>,
    /// The address of the script that signs in with a passkey, served by
    /// the gateway, when the page offers passkeys.
    pub passkey_script_path: Option<SignInPath>,
    /// The single sign-on address the choices below lead to.
    pub sso_path: SignInPath,
    /// The outside identity providers a person may sign in through, on the
    /// login page. Empty elsewhere, or when the workspace offers none.
    pub single_sign_on: Vec<SsoChoice>,
    /// A note to show above the form.
    pub note: Option<SignInNote>,
    /// Where to send the person once they are in, carried in the form.
    pub return_to: Option<ReturnPath>,
    /// The token of the mailed link the page was opened from, carried in
    /// the reset or change form.
    pub link_token: Option<Secret>,
    /// The languages the person reads, most wanted first; the page is
    /// drawn in the first one shipped, else in English.
    pub languages: PreferredLanguages,
}

/// An outside identity provider a person may pick on the login page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoChoice {
    /// The connection to start the sign-in through.
    pub connection_id: ConnectionId,
    /// The provider's name, as the workspace set it.
    pub name: Label,
}

/// A note a sign-in page shows, from a fixed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInNote {
    /// A sign-up or a reset link was asked for; the next step is in the
    /// mailbox.
    CheckEmail,
    /// The address is confirmed; signing in works now.
    Verified,
    /// The new password is set; signing in with it works now.
    PasswordReset,
    /// The password was right, but it must be changed before the sign-in
    /// goes on.
    PasswordChangeRequired,
    /// The last attempt was refused.
    Refused(Refusal),
}

/// Why the last attempt was refused, as far as it is safe to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The details, or the code, were not accepted.
    NotAccepted,
    /// Too many failed attempts; the account is locked for a while.
    Locked,
    /// The address has not been confirmed yet.
    NotVerified,
    /// Too many requests from this address.
    TooMany,
    /// The workspace does not allow this.
    NotAllowed,
    /// Something entered is not well formed, such as a password too weak.
    Invalid,
    /// The emailed link ran out of time.
    LinkExpired,
    /// The account has a second factor, whose code must be given too.
    CodeNeeded,
    /// The workspace cannot be signed in to right now.
    Unavailable,
    /// Anything else.
    Failed,
}

/// The page a browser is shown for a request the gateway refused or could
/// not carry. It says what kind of trouble it was and how to find it in the
/// logs, never why: the reason is for the audit trail alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorPage {
    /// The status the page is answered with.
    pub status: DenialStatus,
    /// What went wrong, as the person is told it.
    pub kind: ErrorPageKind,
    /// The request's correlation id, shown so a person can quote it.
    pub reference: CorrelationId,
    /// The look of the tenant the host belongs to, when it is known.
    pub branding: Option<ErrorBranding>,
    /// The languages the person reads, most wanted first; the page is
    /// drawn in the first one shipped, else in English.
    pub languages: PreferredLanguages,
}

impl ErrorPage {
    /// The page of `kind` for the request `reference` names, answered with
    /// the kind's usual status, in the platform's look and in English.
    #[must_use]
    pub fn new(kind: ErrorPageKind, reference: CorrelationId) -> Self {
        Self {
            status: kind.status(),
            kind,
            reference,
            branding: None,
            languages: PreferredLanguages::default(),
        }
    }
}

/// What went wrong with a request, as the person who sent it is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorPageKind {
    /// The address needs a signed-in person, and none is.
    NotSignedIn,
    /// The person may not open the address.
    Forbidden,
    /// Nothing answers at the address.
    NotFound,
    /// The request is larger than the app takes.
    TooLarge,
    /// The person sent too many requests in a short time.
    TooManyRequests,
    /// The connection was made for another host.
    Misdirected,
    /// The app behind the host could not be reached.
    UpstreamDown,
    /// The app behind the host did not answer in time.
    UpstreamTimedOut,
    /// The gateway cannot take requests for the host right now.
    Unavailable,
    /// The request is not well formed.
    BadRequest,
}

impl ErrorPageKind {
    /// Every kind, in a fixed order.
    pub const ALL: [Self; 10] = [
        Self::NotSignedIn,
        Self::Forbidden,
        Self::NotFound,
        Self::TooLarge,
        Self::TooManyRequests,
        Self::Misdirected,
        Self::UpstreamDown,
        Self::UpstreamTimedOut,
        Self::Unavailable,
        Self::BadRequest,
    ];

    /// The status a request refused this way is usually answered with.
    #[must_use]
    pub fn status(self) -> DenialStatus {
        match self {
            Self::NotSignedIn => DenialStatus::UNAUTHORIZED,
            Self::Forbidden => DenialStatus::FORBIDDEN,
            Self::NotFound => DenialStatus::NOT_FOUND,
            Self::TooLarge => DenialStatus::CONTENT_TOO_LARGE,
            Self::TooManyRequests => DenialStatus::TOO_MANY_REQUESTS,
            Self::Misdirected => DenialStatus::MISDIRECTED_REQUEST,
            Self::UpstreamDown => DenialStatus::BAD_GATEWAY,
            Self::UpstreamTimedOut => DenialStatus::GATEWAY_TIMEOUT,
            Self::Unavailable => DenialStatus::SERVICE_UNAVAILABLE,
            Self::BadRequest => DenialStatus::BAD_REQUEST,
        }
    }

    /// The machine-readable code a script is told the kind by.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::NotSignedIn => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::TooLarge => "content_too_large",
            Self::TooManyRequests => "too_many_requests",
            Self::Misdirected => "misdirected_request",
            Self::UpstreamDown => "bad_gateway",
            Self::UpstreamTimedOut => "gateway_timeout",
            Self::Unavailable => "unavailable",
            Self::BadRequest => "bad_request",
        }
    }
}

/// The parts of a tenant's look an error page wears. Each colour is a
/// checked hex colour, so nothing else can reach the page's CSS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorBranding {
    /// The tenant's name, as its people know it.
    pub name: DisplayName,
    /// The tenant's logo.
    pub logo_url: Option<HttpsUrl>,
    /// The tenant's colour for buttons and links.
    pub primary_color: Option<HexColor>,
    /// The tenant's page background.
    pub background_color: Option<HexColor>,
}

impl ErrorBranding {
    /// The look of the tenant called `name`, from its `branding`.
    #[must_use]
    pub fn of<T: TenantScope>(name: DisplayName, branding: &TenantBranding<T>) -> Self {
        Self {
            name,
            logo_url: branding.logo_url().cloned(),
            primary_color: branding.primary_color().cloned(),
            background_color: branding.background_color().cloned(),
        }
    }
}
