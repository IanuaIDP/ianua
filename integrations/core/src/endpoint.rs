//! Where a service's API answers: its public address, or a stand-in.

use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::shared::errors::DomainError;

use crate::answer::failed;

/// The base address of a service's API, such as
/// `https://api.github.com/`, under which each call's path is placed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceEndpoint {
    base: url::Url,
}

impl ServiceEndpoint {
    /// The service's API at `base`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when `base` is no address that
    /// takes a path, or is neither `http` nor `https`.
    pub fn at(base: &str) -> Result<Self, DomainError> {
        let base = url::Url::parse(base).map_err(DomainError::infra)?;
        if base.cannot_be_a_base() || !matches!(base.scheme(), "http" | "https") {
            return Err(DomainError::infra_msg(
                "a service's address is an http or https address that takes a path",
            ));
        }
        Ok(Self { base })
    }

    /// The address of `segments` under the base. Each segment is escaped as
    /// a path segment, so a value a step gives, such as a repository's name,
    /// can never change the path it is placed in.
    ///
    /// # Errors
    ///
    /// A failed outcome when a segment is empty, `.` or `..`, which would
    /// name another resource than the one asked for.
    pub fn url(&self, segments: &[&str]) -> Result<url::Url, ActionOutcome> {
        if segments
            .iter()
            .any(|segment| matches!(*segment, "" | "." | ".."))
        {
            return Err(failed(
                "a name the step gave cannot be placed in the service's address",
            ));
        }
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|()| failed("the service's address takes no path"))?
            .pop_if_empty()
            .extend(segments);
        Ok(url)
    }

    /// The base address.
    #[must_use]
    pub fn base(&self) -> &url::Url {
        &self.base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A call's path goes under the base, each segment kept whole: a name
    /// with a slash stays one segment.
    #[test]
    fn segments_go_under_the_base_escaped() {
        let github = ServiceEndpoint::at("https://api.github.com/").unwrap();

        let url = github
            .url(&["repos", "acme", "web/../admin", "issues"])
            .unwrap();

        assert_eq!(
            url.as_str(),
            "https://api.github.com/repos/acme/web%2F..%2Fadmin/issues"
        );
    }

    /// A base with a path keeps it, such as Slack's `/api`.
    #[test]
    fn a_base_with_a_path_keeps_it() {
        let slack = ServiceEndpoint::at("https://slack.com/api/").unwrap();

        let url = slack.url(&["chat.postMessage"]).unwrap();

        assert_eq!(url.as_str(), "https://slack.com/api/chat.postMessage");
    }

    /// A repository named `..` is refused when constructing its request URL.
    #[test]
    fn a_dot_segment_is_refused() {
        let github = ServiceEndpoint::at("https://api.github.com/").unwrap();

        let url = github.url(&["repos", "acme", "..", "issues"]);

        assert!(matches!(url, Err(ActionOutcome::Failed(_))));
    }

    /// FTP and mail addresses are refused as service endpoint bases.
    #[test]
    fn a_base_that_is_no_web_address_is_refused() {
        assert!(ServiceEndpoint::at("ftp://files.example/").is_err());
        assert!(ServiceEndpoint::at("mailto:ops@example.test").is_err());
    }
}
