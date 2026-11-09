//! Where a cloud's APIs are reached: its own public hosts, or every one of
//! its services at a single address the deployment names, such as a
//! stand-in or a private gateway.

use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;

/// Where a cloud's APIs are reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudEndpoint {
    /// The cloud's own public hosts.
    Public,
    /// Every service of the cloud at this one address.
    At(url::Url),
}

impl CloudEndpoint {
    /// The URL of `segments` under `public`, the service's public base, or
    /// under the one address every service is reached at. Each segment is
    /// escaped as a path segment, so a value from a credential can never
    /// change the path it is placed in. An empty, `.` or `..` segment is
    /// refused, since the URL parser drops the dots, which would name
    /// another resource than the one asked for.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when a segment is empty, `.` or `..`.
    /// - `DomainError::Infrastructure` when the base is no URL that takes a
    ///   path.
    pub(crate) fn url(&self, public: &str, segments: &[&str]) -> Result<url::Url, DomainError> {
        if segments
            .iter()
            .any(|segment| matches!(*segment, "" | "." | ".."))
        {
            return Err(DomainError::invalid(message!(
                "infra-a-name-in-the-credential-cannot",
                "a name in the credential cannot be placed in a cloud's address"
            )));
        }
        let mut url = match self {
            Self::Public => url::Url::parse(public).map_err(DomainError::infra)?,
            Self::At(base) => base.clone(),
        };
        url.path_segments_mut()
            .map_err(|()| DomainError::infra_msg("the cloud's address takes no path"))?
            .pop_if_empty()
            .extend(segments);
        Ok(url)
    }

    /// The URL of `segments` under `public`, with `query` added.
    ///
    /// # Errors
    ///
    /// As [`Self::url`].
    pub(crate) fn url_with(
        &self,
        public: &str,
        segments: &[&str],
        query: &[(&str, &str)],
    ) -> Result<url::Url, DomainError> {
        let mut url = self.url(public, segments)?;
        url.query_pairs_mut().extend_pairs(query);
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A public endpoint places the segments under the service's host.
    #[test]
    fn a_public_endpoint_uses_the_service_host() {
        let url = CloudEndpoint::Public
            .url("https://api.digitalocean.com", &["v2", "account"])
            .unwrap();

        assert_eq!(url.as_str(), "https://api.digitalocean.com/v2/account");
    }

    /// An endpoint at one address places every service there.
    #[test]
    fn an_endpoint_at_one_address_takes_every_service() {
        let base = url::Url::parse("http://127.0.0.1:8080").unwrap();

        let url = CloudEndpoint::At(base)
            .url_with(
                "https://api.digitalocean.com",
                &["v2", "vpcs"],
                &[("per_page", "200")],
            )
            .unwrap();

        assert_eq!(url.as_str(), "http://127.0.0.1:8080/v2/vpcs?per_page=200");
    }

    /// Path separators and a question mark in a project ID stay escaped within one segment.
    #[test]
    fn a_segment_cannot_change_the_path() {
        let url = CloudEndpoint::Public
            .url("https://compute.googleapis.com", &["projects", "../x?y"])
            .unwrap();

        assert_eq!(url.path(), "/projects/..%2Fx%3Fy");
        assert!(url.query().is_none());
    }

    /// A literal `..` project ID returns a validation error instead of becoming a parent path.
    #[test]
    fn a_dot_segment_is_refused() {
        let result =
            CloudEndpoint::Public.url("https://compute.googleapis.com", &["projects", ".."]);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }
}
