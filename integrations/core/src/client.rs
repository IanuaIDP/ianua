//! The client an integration calls its service with.

use std::sync::Arc;
use std::time::Duration;

use ianua_domain::shared::errors::DomainError;
use reqwest::dns::{Name, Resolve, Resolving};

/// How a deployment changes the way integrations look names up and whom
/// they trust. Left as [`Default`], Salesforce and Jira are reached through
/// the host's resolver and public roots alone, as every deployment in
/// production is. A scenario proving what Acme's Jira really receives sets
/// one up, naming its own name lookup and one extra authority.
#[derive(Clone, Default)]
pub struct ServiceReach {
    lookup: Option<Arc<dyn Resolve>>,
    extra_root: Option<reqwest::Certificate>,
}

impl ServiceReach {
    /// Reach that looks names up through `lookup` and trusts `extra_root`
    /// beside the public roots.
    #[must_use]
    pub fn through(lookup: Arc<dyn Resolve>, extra_root: reqwest::Certificate) -> Self {
        Self {
            lookup: Some(lookup),
            extra_root: Some(extra_root),
        }
    }
}

/// A client giving up on a call after `timeout` and following no
/// redirect: a service that answers with one is not followed to wherever
/// it points, with the account's token in hand.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built.
pub fn client(timeout: Duration) -> Result<reqwest::Client, DomainError> {
    client_reaching(timeout, &ServiceReach::default())
}

/// A client as [`client`] makes, looking names up and trusting as `reach`
/// says.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built.
pub fn client_reaching(
    timeout: Duration,
    reach: &ServiceReach,
) -> Result<reqwest::Client, DomainError> {
    let builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    let builder = match &reach.lookup {
        Some(lookup) => builder
            .no_proxy()
            .dns_resolver(Arc::new(SharedLookup(Arc::clone(lookup)))),
        None => builder,
    };
    let builder = match &reach.extra_root {
        Some(root) => builder.add_root_certificate(root.clone()),
        None => builder,
    };
    builder.build().map_err(DomainError::infra)
}

/// A lookup held as a trait object, handed to the client as one of its
/// own, since it takes a sized resolver.
struct SharedLookup(Arc<dyn Resolve>);

impl Resolve for SharedLookup {
    fn resolve(&self, name: Name) -> Resolving {
        self.0.resolve(name)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// A lookup that answers every name with the mock's address, counting
    /// how often it is asked.
    struct PointingAt {
        address: SocketAddr,
        asked: Arc<AtomicUsize>,
    }

    impl Resolve for PointingAt {
        fn resolve(&self, _name: Name) -> Resolving {
            let address = self.address;
            let asked = Arc::clone(&self.asked);
            Box::pin(async move {
                asked.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(std::iter::once(address)) as reqwest::dns::Addrs)
            })
        }
    }

    /// A name that resolves nowhere fails, with no lookup of the
    /// deployment's in its way.
    #[tokio::test]
    async fn an_unset_reach_leaves_the_clients_own_lookup() {
        let client = client_reaching(Duration::from_secs(2), &ServiceReach::default()).unwrap();

        let result = client.get("http://nowhere.invalid/").send().await;

        assert!(result.is_err());
    }

    /// A set reach is asked for every name, so a stand-in at a
    /// public-looking name is found through it.
    #[tokio::test]
    async fn a_set_reach_is_asked_for_the_names_it_calls() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let asked = Arc::new(AtomicUsize::new(0));
        let lookup = PointingAt {
            address: *server.address(),
            asked: Arc::clone(&asked),
        };
        let reach = ServiceReach {
            lookup: Some(Arc::new(lookup)),
            extra_root: None,
        };
        let client = client_reaching(Duration::from_secs(2), &reach).unwrap();

        let url = format!("http://jira.acme.example:{}/", server.address().port());
        let response = client.get(url).send().await.unwrap();

        assert_eq!(response.status().as_u16(), 204);
        assert_eq!(asked.load(Ordering::SeqCst), 1);
    }
}
