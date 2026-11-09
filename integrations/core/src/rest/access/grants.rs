//! Accounts holding a lasting grant, exchanged for a short-lived token
//! before each call: at a fixed API, as Google's are, or at the account's
//! own site, held to the sites the deployment allows, as Salesforce's are.
//! The grant goes only to the deployment's token address; only the token
//! goes to the API.

use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::shared::security::secret::Secret;
use serde::Deserialize;

use crate::ServiceEndpoint;
use crate::answer::failed;
use crate::rest::access::headers::bearer;
use crate::rest::access::sites::SiteApi;
use crate::rest::access::{Reached, endpoint_at};
use crate::rest::grant::{GrantAt, exchanged};
use crate::rest::sign_in::TokenBody;

/// The site an account holding a grant names as its own.
#[derive(Deserialize)]
struct GrantSite {
    site: String,
}

/// The reach of a Google account: its grant exchanged at `token`, and the
/// token sent to `endpoint`.
pub(super) async fn refreshed(
    client: &reqwest::Client,
    endpoint: &ServiceEndpoint,
    token: &ServiceEndpoint,
    credential: &Secret,
) -> Result<Reached, ActionOutcome> {
    let exchanged = exchanged(client, &form_at(token), credential).await?;
    Ok(Reached {
        endpoint: endpoint.clone(),
        authorization: bearer(&exchanged.access_token)?,
        place: None,
        acting_for: None,
        renewed: exchanged.renewed,
    })
}

/// The reach of a Salesforce account: refused unless its site is one
/// `target` allows, and then its grant exchanged at `token` and the token
/// sent to the site's API.
pub(super) async fn site_granted(
    client: &reqwest::Client,
    target: &SiteApi<'_>,
    token: &ServiceEndpoint,
    credential: &Secret,
) -> Result<Reached, ActionOutcome> {
    let Ok(held) = serde_json::from_str::<GrantSite>(credential.expose()) else {
        return Err(failed("the account names no site"));
    };
    let url = target.url(&held.site)?;
    let exchanged = exchanged(client, &form_at(token), credential).await?;
    Ok(Reached {
        endpoint: endpoint_at(url.as_str())?,
        authorization: bearer(&exchanged.access_token)?,
        place: None,
        acting_for: None,
        renewed: exchanged.renewed,
    })
}

/// Whether the account holding `credential` names a site `target` allows,
/// so its grant is worth exchanging at all.
pub(super) fn names_allowed_site(target: &SiteApi<'_>, credential: &Secret) -> bool {
    serde_json::from_str::<GrantSite>(credential.expose())
        .is_ok_and(|held| target.url(&held.site).is_ok())
}

/// The token address `token`, taking the grant as a form.
pub(super) fn form_at(token: &ServiceEndpoint) -> GrantAt {
    GrantAt {
        token: token.clone(),
        body: TokenBody::Form,
        scope: None,
    }
}
