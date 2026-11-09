//! Scope carried by the links sent out over email.
//!
//! A mailed link is clicked cold, from a mail client, with no session and no
//! referrer. The token alone identifies the request but not *where* it belongs,
//! and every tenant page in the frontend is addressed by org and tenant slug,
//! so a link without them cannot be routed. Building the query here keeps the
//! shape identical across every flow that mails one.

use ianua_domain::domains::routing::sign_in::app::{AppSignIn, SignInAction, SignInPath};
use ianua_domain::types::{DomainName, HttpsUrl, TenantSlug};

/// Where a mailed link should land.
///
/// It serializes so work queued for the worker, such as an import whose
/// accounts are mailed their links later, carries where those links land.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LinkScope {
    /// An organization-level page, above any tenant.
    Organization {
        /// The organization's slug.
        org: TenantSlug,
    },
    /// A page inside one tenant of an organization.
    Tenant {
        /// The organization's slug.
        org: TenantSlug,
        /// The tenant's slug.
        tenant: TenantSlug,
    },
    /// The sign-in addresses on the host of an app behind the gateway, for
    /// someone who signs in there. Each mailed link lands on the address of
    /// its own page: verifying an address, confirming a sign-in, resetting
    /// a password or changing one.
    App {
        /// The app's host the person signs in on.
        host: DomainName,
        /// Where the app's host answers each mailed link.
        landings: AppLandings,
        /// Where the app's host signs people in.
        login: SignInPath,
    },
}

/// Where an app's host answers each link mailed to someone who signs in
/// there. They never share an address, so what a link does is never told
/// apart by a cookie the browser holds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppLandings {
    /// Confirming an address.
    pub verify: SignInPath,
    /// Finishing a sign-in that waits on the mailbox.
    pub confirm_sign_in: SignInPath,
    /// Setting a new password after asking for one.
    pub reset_password: SignInPath,
    /// Setting the new password a sign-in owes.
    pub change_password: SignInPath,
}

impl AppLandings {
    /// The addresses of `sign_in`.
    fn of(sign_in: &AppSignIn) -> Self {
        Self {
            verify: sign_in.path(SignInAction::Verify),
            confirm_sign_in: sign_in.path(SignInAction::ConfirmSignIn),
            reset_password: sign_in.path(SignInAction::ResetPassword),
            change_password: sign_in.path(SignInAction::ChangePassword),
        }
    }

    /// Where the link to the dashboard page `page` lands instead, if an
    /// app's host answers such a link.
    fn for_page(&self, page: &str) -> Option<&SignInPath> {
        match page {
            "verify-email" => Some(&self.verify),
            "confirm-sign-in" => Some(&self.confirm_sign_in),
            "reset-password" => Some(&self.reset_password),
            "change-password" => Some(&self.change_password),
            _ => None,
        }
    }
}

impl LinkScope {
    /// An organization-level scope.
    #[must_use]
    pub fn organization(org: TenantSlug) -> Self {
        Self::Organization { org }
    }

    /// A tenant-level scope.
    #[must_use]
    pub fn tenant(org: TenantSlug, tenant: TenantSlug) -> Self {
        Self::Tenant { org, tenant }
    }

    /// The sign-in addresses of `sign_in` on `host`.
    ///
    /// Built from the service's stored settings and a host they name, never
    /// from anything a request carried, so a mailed link cannot be pointed at
    /// another site.
    #[must_use]
    pub fn app(sign_in: &AppSignIn, host: DomainName) -> Self {
        Self::App {
            host,
            landings: AppLandings::of(sign_in),
            login: sign_in.path(SignInAction::LogIn),
        }
    }

    /// The dashboard page `page` under `base`, carrying this scope, or for an
    /// app scope the app's own login address: its people have no dashboard.
    ///
    /// Slugs are validated to a DNS-safe alphabet, so they need no escaping.
    #[must_use]
    pub fn page_url(&self, base: &HttpsUrl, page: &str) -> String {
        match self {
            Self::Organization { org } => format!("{}/{page}?org={org}", base.as_str()),
            Self::Tenant { org, tenant } => {
                format!("{}/{page}?org={org}&tenant={tenant}", base.as_str())
            }
            Self::App { .. } => self.login_url(base),
        }
    }

    /// A link to `path` under `base`, carrying this scope and `token`.
    ///
    /// An app scope links to the address on its own host that answers that
    /// page's link instead, or to its login address, without the token, for
    /// a page whose link no app's host answers.
    #[must_use]
    pub fn action_url(&self, base: &HttpsUrl, path: &str, token: &str) -> String {
        match self {
            Self::App { host, landings, .. } => match landings.for_page(path) {
                Some(lands_at) => format!("https://{host}{lands_at}?token={token}"),
                None => self.login_url(base),
            },
            Self::Organization { .. } | Self::Tenant { .. } => {
                format!("{}&token={token}", self.page_url(base, path))
            }
        }
    }

    /// Where the people this scope covers sign in.
    ///
    /// Not [`action_url`](Self::action_url) with a `login` path: the sign-in
    /// pages are the one pair that does not read its scope from the query
    /// string. An organization signs in at `/login`, while a tenant has its
    /// own page nested under its slugs, and pointing a tenant user at the
    /// former lands them on the organization's form with their tenant named
    /// in parameters nothing reads.
    #[must_use]
    pub fn login_url(&self, base: &HttpsUrl) -> String {
        match self {
            Self::Organization { org } => format!("{}/login?org={org}", base.as_str()),
            Self::Tenant { org, tenant } => format!(
                "{}/organizations/{org}/tenants/{tenant}/login",
                base.as_str()
            ),
            Self::App { host, login, .. } => format!("https://{host}{login}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slug(value: &str) -> TenantSlug {
        TenantSlug::new(value, &ianua_domain::shared::config::SlugLimits::default()).unwrap()
    }

    fn base() -> HttpsUrl {
        HttpsUrl::new("https://app.example.com").unwrap()
    }

    /// Ann gets a password reset link for Acme's production tenant. It names
    /// both Acme and the tenant, and carries her token.
    #[test]
    fn a_tenant_link_carries_both_slugs_and_the_token() {
        let scope = LinkScope::tenant(slug("acme"), slug("production"));

        let url = scope.action_url(&base(), "reset-password", "tok_123");

        assert_eq!(
            url,
            "https://app.example.com/reset-password?org=acme&tenant=production&token=tok_123"
        );
    }

    /// Ann is invited to Acme itself. Her invitation link names Acme and no
    /// tenant.
    #[test]
    fn an_organization_link_names_no_tenant() {
        let scope = LinkScope::organization(slug("acme"));

        let url = scope.action_url(&base(), "accept-invite", "tok_123");

        assert_eq!(
            url,
            "https://app.example.com/accept-invite?org=acme&token=tok_123"
        );
    }

    fn app_scope() -> LinkScope {
        LinkScope::app(&app_sign_in(), DomainName::new("shop.example.com").unwrap())
    }

    /// The shop's sign-in on `shop.example.com`, with its login moved to
    /// `/login` and the rest under the default prefix.
    fn app_sign_in() -> AppSignIn {
        let mut moved = std::collections::BTreeMap::new();
        moved.insert(SignInAction::LogIn, SignInPath::new("/login").unwrap());
        AppSignIn::new(
            ianua_domain::domains::routing::sign_in::app::AppSignInParams {
                hosts: vec![DomainName::new("shop.example.com").unwrap()],
                prefix: ianua_domain::types::Setting::Unset,
                moved,
                after_sign_in: ianua_domain::types::Setting::Unset,
                signed_out_browsers:
                    ianua_domain::domains::routing::sign_in::app::SignedOutBrowsers::Refuse,
            },
        )
        .unwrap()
    }

    /// Someone who signed up on an app confirms their address there, not on
    /// the dashboard they have never seen.
    #[test]
    fn an_app_link_lands_on_the_apps_own_verify_address() {
        let url = app_scope().action_url(&base(), "verify-email", "tok_123");

        assert_eq!(url, "https://shop.example.com/.ianua/verify?token=tok_123");
    }

    /// Bob forgot his password on the shop. His reset link lands on the
    /// shop's own reset address, not on its verify address or the
    /// dashboard.
    #[test]
    fn an_app_reset_link_lands_on_the_apps_reset_address() {
        let url = app_scope().action_url(&base(), "reset-password", "tok_123");

        assert_eq!(
            url,
            "https://shop.example.com/.ianua/reset-password?token=tok_123"
        );
    }

    /// Ann's sign-in waits on her mailbox, and Bob's password was set by an
    /// administrator. One scope mails both links; each lands on an address
    /// of its own, never on the verify address, so neither is read by
    /// whichever cookie the browser holds.
    #[test]
    fn a_confirm_link_and_a_change_link_land_on_their_own_addresses() {
        let scope = app_scope();

        let confirm = scope.action_url(&base(), "confirm-sign-in", "tok_1");
        let change = scope.action_url(&base(), "change-password", "tok_2");

        assert_eq!(
            confirm,
            "https://shop.example.com/.ianua/confirm-sign-in?token=tok_1"
        );
        assert_eq!(
            change,
            "https://shop.example.com/.ianua/change-password?token=tok_2"
        );
    }

    /// A link for a page no app's host answers lands on the app's login,
    /// and carries no token there.
    #[test]
    fn an_app_link_for_a_page_it_does_not_answer_lands_on_its_login() {
        let url = app_scope().action_url(&base(), "accept-invite", "tok_123");

        assert_eq!(url, "https://shop.example.com/login");
    }

    /// Someone who uses an app is sent to sign in at the app's own login
    /// page, not at the dashboard.
    #[test]
    fn an_app_scope_signs_in_at_the_apps_login_address() {
        assert_eq!(
            app_scope().login_url(&base()),
            "https://shop.example.com/login"
        );
    }
}
