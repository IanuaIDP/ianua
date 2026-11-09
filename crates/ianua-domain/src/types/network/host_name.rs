use crate::shared::validation::{TextValue, Validator, text_value};

text_value! {
    /// A host to connect to. It is a DNS name, or an IP address written the
    /// ordinary way. A single label, such as a cluster service name, counts
    /// as a DNS name.
    ///
    /// A name a resolver would read as an address, such as `127.1`, is
    /// refused. So an address check on the host sees the address that is
    /// dialled.
    pub struct HostName;
}

impl TextValue for HostName {
    const FIELD: &'static str = "host";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.ascii_only().host_name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A single-label cluster service name, `redis`, is accepted as a host.
    #[test]
    fn a_cluster_service_name_is_a_host() {
        assert_eq!(HostName::new("redis").unwrap().as_str(), "redis");
    }

    /// Abbreviated and numeric spellings of loopback are refused as host
    /// names, keeping them from bypassing address checks.
    #[test]
    fn a_name_a_resolver_reads_as_loopback_is_refused() {
        assert!(HostName::new("127.1").is_err());
        assert!(HostName::new("2130706433").is_err());
    }
}
