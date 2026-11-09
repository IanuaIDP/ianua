//! How a run is let onto the network: a ticket naming its version's hosts,
//! lasting as long as the run may, in the address of the network filter
//! its code is given as its proxy.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ianua_app::ports::workflows::CodeRan;
use ianua_domain::domains::workflows::execution::step::{CodeFailure, CodeOutcome};
use ianua_domain::domains::workflows::sandbox::network::NetworkAccess;
use ianua_domain::types::UntrustedText;

use crate::sandbox::proxy::ticket::{Ticket, TicketKey};

/// How runs reach the network filter.
#[derive(Debug, Clone)]
pub struct ProxyAccess {
    /// The filter's `host:port` as the sandboxes reach it, such as
    /// `172.31.0.2:3128`.
    pub address: String,
    /// The key tickets are signed with, shared with the filter.
    pub key: TicketKey,
}

impl ProxyAccess {
    /// This access with its address's name looked up, for sandboxes that
    /// may not look names up themselves.
    ///
    /// # Errors
    ///
    /// When the name leads to no address.
    pub(in crate::sandbox) async fn resolved(&self) -> Result<Self, String> {
        let address = tokio::net::lookup_host(self.address.as_str())
            .await
            .map_err(|error| format!("the network filter's address was not found: {error}"))?
            .next()
            .ok_or("the network filter's address leads nowhere")?;
        Ok(Self {
            address: address.to_string(),
            key: self.key.clone(),
        })
    }
}

/// What network a run gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::sandbox) enum RunNetwork {
    /// None at all: its version names no host.
    Closed,
    /// The filter, at this proxy address holding the run's ticket.
    Proxied(String),
}

/// The network a run of a version reaching `network` gets, through `access`
/// when the deployment has a filter, for `lasts`; or what to answer when a
/// version names hosts and the deployment gives code no network.
pub(in crate::sandbox) fn run_network(
    access: Option<&ProxyAccess>,
    network: &NetworkAccess,
    lasts: Duration,
) -> Result<RunNetwork, CodeRan> {
    if network.is_closed() {
        return Ok(RunNetwork::Closed);
    }
    let Some(access) = access else {
        return Err(CodeRan::Ran(CodeOutcome::Failed(CodeFailure::NotRun(
            UntrustedText::record(
                "this deployment gives code no network, so a version naming hosts cannot run",
            ),
        ))));
    };
    let ticket = Ticket {
        hosts: network
            .hosts()
            .iter()
            .map(|host| host.as_str().to_owned())
            .collect(),
        ends_at: seconds_now().saturating_add(lasts.as_secs()),
    };
    let signed = ticket.signed(&access.key);
    Ok(RunNetwork::Proxied(format!(
        "http://run:{signed}@{}",
        access.address
    )))
}

/// Seconds since the Unix epoch.
fn seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::sandbox::network::AllowedHost;

    use super::*;

    fn access() -> ProxyAccess {
        ProxyAccess {
            address: "172.31.0.2:3128".to_owned(),
            key: TicketKey::parse(&"ab".repeat(32)).unwrap(),
        }
    }

    fn github() -> NetworkAccess {
        NetworkAccess::new(vec![AllowedHost::new("api.github.com").unwrap()]).unwrap()
    }

    /// A version naming no host gets no network, filter or not.
    #[test]
    fn no_hosts_is_no_network() {
        let closed = run_network(Some(&access()), &NetworkAccess::closed(), Duration::ZERO);

        assert_eq!(closed, Ok(RunNetwork::Closed));
    }

    /// A version naming a host gets the filter, with a ticket naming that
    /// host and lasting as long as the run.
    #[test]
    fn a_named_host_is_reached_through_the_filter_with_a_ticket() {
        let Ok(RunNetwork::Proxied(url)) =
            run_network(Some(&access()), &github(), Duration::from_secs(60))
        else {
            panic!("the run got no filter");
        };

        let token = url
            .strip_prefix("http://run:")
            .and_then(|rest| rest.strip_suffix("@172.31.0.2:3128"))
            .unwrap();
        let ticket = Ticket::verified(&access().key, token, seconds_now()).unwrap();
        assert_eq!(ticket.hosts, ["api.github.com"]);
        assert!(ticket.ends_at <= seconds_now() + 60);
    }

    /// A version requiring network hosts receives a not-run failure when no filter is configured.
    #[test]
    fn hosts_with_no_filter_do_not_run() {
        let refused = run_network(None, &github(), Duration::from_secs(60));

        assert!(matches!(
            refused,
            Err(CodeRan::Ran(CodeOutcome::Failed(CodeFailure::NotRun(_))))
        ));
    }
}
