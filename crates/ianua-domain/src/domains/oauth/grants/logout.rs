//! Where a person goes after an app signs them out through ianua (OpenID
//! Connect RP-Initiated Logout).
//!
//! The app names an address to send the person back to. Only an address
//! the app registered for that is used: Mallory links people to the
//! sign-out address with her own site as the destination, and the platform
//! would otherwise send everyone who follows it there, signed out and
//! trusting the hop.

use crate::domains::oauth::clients::client::OAuthClient;
use crate::isolation::scope::TenantScope;
use crate::types::RedirectUri;

/// Where the person goes once signed out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AfterLogout {
    /// Back to this address the app registered.
    SendBack(RedirectUri),
    /// To ianua's own signed-out page: no app was named, or it named an
    /// address it did not register.
    SignedOutPage,
}

/// Where the person goes after `client` signs them out, asking to send them
/// to `asked`. Without a known client, or without an address, or with one
/// the client did not register, they stay on the signed-out page.
#[must_use]
pub fn after_logout<T: TenantScope>(
    client: Option<&OAuthClient<T>>,
    asked: Option<&RedirectUri>,
) -> AfterLogout {
    match (client, asked) {
        (Some(client), Some(asked)) if client.accepts_post_logout_redirect(asked) => {
            AfterLogout::SendBack(asked.clone())
        }
        _ => AfterLogout::SignedOutPage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::oauth::clients::client::{GrantType, NewOAuthClient};
    use crate::domains::oauth::clients::credential::ClientCredential;
    use crate::domains::oauth::clients::settings::ClientSettings;
    use crate::domains::oauth::control::tests::key_admin;
    use crate::isolation::scope::ResolvedTenant;
    use crate::types::{ClientId, OAuthClientId};

    /// Where Ann's app sends people after they sign out.
    const SIGNED_OUT: &str = "https://app.acme.com/goodbye";

    /// Ann's app, with its sign-out address registered.
    fn app() -> OAuthClient<ResolvedTenant> {
        OAuthClient::create(
            NewOAuthClient {
                id: OAuthClientId::new(),
                client_id_value: ClientId::new("web_app").unwrap(),
                credential: ClientCredential::Public,
                name: crate::test_support::builders::label("Web app"),
                redirect_uris: vec![RedirectUri::new("https://app.acme.com/cb").unwrap()],
                post_logout_redirect_uris: vec![RedirectUri::new(SIGNED_OUT).unwrap()],
                grant_types: vec![GrantType::AuthorizationCode],
                scopes: Vec::new(),
                settings: ClientSettings::platform_defaults(),
            },
            &key_admin(),
        )
        .unwrap()
    }

    /// Ann signs out of her app, which names its registered address. She is
    /// sent back there.
    #[test]
    fn a_registered_address_is_where_the_person_goes() {
        let client = app();
        let asked = RedirectUri::new(SIGNED_OUT).unwrap();

        assert_eq!(
            after_logout(Some(&client), Some(&asked)),
            AfterLogout::SendBack(asked)
        );
    }

    /// Requesting an unregistered logout destination keeps the person on the
    /// signed-out page even when the client is known.
    #[test]
    fn an_address_the_app_did_not_register_is_not_used() {
        let client = app();
        let theirs = RedirectUri::new("https://evil.test/").unwrap();

        assert_eq!(
            after_logout(Some(&client), Some(&theirs)),
            AfterLogout::SignedOutPage
        );
    }

    /// With no app named, or no address, the person stays on the signed-out
    /// page.
    #[test]
    fn without_an_app_or_an_address_the_person_stays() {
        let asked = RedirectUri::new(SIGNED_OUT).unwrap();

        assert_eq!(
            after_logout::<ResolvedTenant>(None, Some(&asked)),
            AfterLogout::SignedOutPage
        );
        assert_eq!(after_logout(Some(&app()), None), AfterLogout::SignedOutPage);
    }
}
