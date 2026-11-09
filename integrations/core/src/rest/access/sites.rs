//! Accounts that name a site of their own, as a Jira one does: the site
//! held to the hosts the deployment allows, and reached with the account's
//! user and token, or through Atlassian's gateway with a grant for an
//! account that signed in.

use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::shared::security::secret::Secret;
use serde::Deserialize;

use crate::answer::failed;
use crate::rest::access::headers::{basic, bearer};
use crate::rest::access::{
    AllowedSites, AtlassianCloud, Reached, endpoint_at, held_place, holds_grant,
};
use crate::rest::grant::exchanged;
use crate::{Renewed, ServiceEndpoint};

/// A Jira account as sealed.
#[derive(Deserialize)]
struct SiteAccount {
    site: String,
    user: String,
    token: String,
}

/// The permitted account sites and API path resolved within each site.
pub(super) struct SiteApi<'a> {
    sites: &'a AllowedSites,
    api: &'a [&'a str],
}

impl<'a> SiteApi<'a> {
    /// Couples the allowed hosts with the API path appended after validation.
    pub(super) fn new(sites: &'a AllowedSites, api: &'a [&'a str]) -> Self {
        Self { sites, api }
    }

    /// Resolves the API beneath an account's validated site.
    pub(super) fn url(&self, site: &str) -> Result<url::Url, ActionOutcome> {
        allowed_root(self.sites, site)?.url(self.api)
    }
}

/// The reach of a Jira account: through Atlassian's gateway when it signed
/// in and the deployment lets people, or else its own site.
pub(super) async fn site_reach(
    client: &reqwest::Client,
    target: &SiteApi<'_>,
    cloud: Option<&AtlassianCloud>,
    credential: &Secret,
) -> Result<Reached, ActionOutcome> {
    let Some(cloud) = cloud.filter(|_| holds_grant(credential)) else {
        return site(target, credential);
    };
    let cloud_id = held_place(credential)?
        .cloud_id
        .ok_or_else(|| failed("the account names no Jira site"))?;
    let site = endpoint_at(
        cloud
            .gateway
            .url(&["ex", "jira", cloud_id.trim()])?
            .as_str(),
    )?;
    let url = site.url(target.api)?;
    let exchanged = exchanged(client, &cloud.grant, credential).await?;
    Ok(Reached {
        endpoint: endpoint_at(url.as_str())?,
        authorization: bearer(&exchanged.access_token)?,
        place: None,
        acting_for: None,
        renewed: exchanged.renewed,
    })
}

/// The reach of a Jira account, refused unless its site is allowed.
fn site(target: &SiteApi<'_>, credential: &Secret) -> Result<Reached, ActionOutcome> {
    let Ok(account) = serde_json::from_str::<SiteAccount>(credential.expose()) else {
        return Err(failed("the account holds no site, user and token"));
    };
    let url = target.url(&account.site)?;
    Ok(Reached {
        endpoint: endpoint_at(url.as_str())?,
        authorization: basic(&account.user, &account.token)?,
        place: None,
        acting_for: None,
        renewed: Renewed::Unchanged,
    })
}

/// The root of the site an account names, refused unless it is `https`,
/// names no user or password, and its host is one `sites` allows.
fn allowed_root(sites: &AllowedSites, named: &str) -> Result<ServiceEndpoint, ActionOutcome> {
    let Ok(site) = url::Url::parse(named.trim()) else {
        return Err(failed("the account's site is not an address"));
    };
    let reachable =
        site.scheme() == "https" && site.username().is_empty() && site.password().is_none();
    let authority = reachable.then(|| allowed_authority(sites, &site)).flatten();
    let Some(authority) = authority else {
        return Err(failed(
            "the account's site is not one this deployment allows",
        ));
    };
    endpoint_at(&format!("https://{authority}/"))
}

/// The host of `site`, with its port when the deployment listed that
/// port, that the account may be reached at; none when neither allows it.
fn allowed_authority(sites: &AllowedSites, site: &url::Url) -> Option<String> {
    let host = site.host_str()?;
    if let Some(port) = site.port().filter(|port| sites.allows_on_port(host, *port)) {
        return Some(format!("{host}:{port}"));
    }
    sites.allows(host).then(|| host.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A site the deployment listed together with its port keeps the port.
    #[test]
    fn a_listed_port_is_kept_on_the_address() {
        let sites = AllowedSites::new(["jira.acme.example:8443"]);

        let root = allowed_root(&sites, "https://jira.acme.example:8443/").unwrap();

        assert_eq!(root.base().as_str(), "https://jira.acme.example:8443/");
    }

    /// A port the deployment did not list falls back to the ordinary
    /// `https` port, as it always did, so a port can never be typed in.
    #[test]
    fn an_unlisted_port_goes_to_the_usual_port() {
        let sites = AllowedSites::new([".atlassian.net"]);

        let root = allowed_root(&sites, "https://acme.atlassian.net:9000").unwrap();

        assert_eq!(root.base().as_str(), "https://acme.atlassian.net/");
    }

    /// A host listed only with a port is not allowed without one, and the
    /// wrong port is not allowed either.
    #[test]
    fn a_host_listed_with_a_port_is_allowed_only_on_it() {
        let sites = AllowedSites::new(["jira.acme.example:8443"]);

        assert!(allowed_root(&sites, "https://jira.acme.example/").is_err());
        assert!(allowed_root(&sites, "https://jira.acme.example:9000/").is_err());
    }
}
