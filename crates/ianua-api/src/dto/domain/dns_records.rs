//! Bodies for the records inside a delegated DNS zone.
//!
//! The wire shape is a record *set*: a name, a type, a TTL, and the values
//! answering it, because that is what DNS resolves and what a resolver
//! caches. Sending one value at a time would let a caller leave a zone
//! half-updated in a state no cache would ever reflect.

use ianua_app::use_cases::domain::dns_records::{ManagedRecordSet, RemoveRequest, SetRequest};
use ianua_domain::domains::tenant::custom_domains::dns_zone::{
    RecordKind, RecordName, RecordSet, RecordValue, Ttl,
};
use ianua_domain::types::DomainId;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// A record set to write.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SetDnsRecordBody {
    /// The name to answer for, fully qualified: `api.auth.acme.com`, not
    /// `api`. Must be the delegated hostname or a name beneath it.
    pub name: String,
    /// The record type: `A`, `AAAA`, `CNAME`, `TXT`, `MX`, `SRV` or `CAA`.
    pub record_type: String,
    /// How long a resolver may cache the answer, in seconds. Between 60
    /// and 3600. Omitted means 300.
    #[serde(default)]
    pub ttl_seconds: Option<u32>,
    /// Every answer to this question, as a zone file spells the value:
    /// `203.0.113.10` for `A`, `10 mail.acme.com` for `MX`,
    /// `10 5 443 sip.acme.com` for `SRV`, `0 issue "letsencrypt.org"` for
    /// `CAA`. Replaces whatever the name answered with before. A `CNAME`
    /// takes exactly one value; every other type may take several.
    pub values: Vec<String>,
}

impl SetDnsRecordBody {
    /// Writing the record set this body describes into the zone of
    /// `domain_id`.
    ///
    /// # Errors
    ///
    /// A validation error when the name, type, TTL or a value does not
    /// parse, or the values do not form a legal set.
    pub(crate) fn into_request(self, domain_id: DomainId) -> Result<SetRequest, ApiError> {
        Ok(SetRequest {
            domain_id,
            set: self.record_set()?,
        })
    }

    /// The record set this body describes, refused when any part of it
    /// does not parse.
    fn record_set(self) -> Result<RecordSet, ApiError> {
        let name = RecordName::new(self.name).map_err(ApiError::validation)?;
        let kind = RecordKind::parse(&self.record_type).map_err(ApiError::validation)?;
        let ttl = self
            .ttl_seconds
            .map_or_else(|| Ok(Ttl::standard()), Ttl::seconds)
            .map_err(ApiError::validation)?;
        let values = self
            .values
            .iter()
            .map(|value| RecordValue::parse(kind, value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(ApiError::validation)?;
        RecordSet::new(name, ttl, values).map_err(ApiError::validation)
    }
}

/// The record set to remove.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RemoveDnsRecordBody {
    /// The name to stop answering for, fully qualified.
    pub name: String,
    /// The record type to remove.
    pub record_type: String,
}

impl RemoveDnsRecordBody {
    /// Removing the set this body names from the zone of `domain_id`.
    ///
    /// # Errors
    ///
    /// A validation error when the name or type does not parse.
    pub(crate) fn into_request(self, domain_id: DomainId) -> Result<RemoveRequest, ApiError> {
        Ok(RemoveRequest {
            domain_id,
            name: RecordName::new(self.name).map_err(ApiError::validation)?,
            kind: RecordKind::parse(&self.record_type).map_err(ApiError::validation)?,
        })
    }
}

/// One record set in a delegated zone.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DnsRecordSetResponse {
    /// The name this set answers for, fully qualified.
    pub name: String,
    /// The record type, as a zone file spells it.
    pub record_type: &'static str,
    /// How long a resolver may cache the answer, in seconds.
    pub ttl_seconds: u32,
    /// Every answer, as a zone file spells the value.
    pub values: Vec<String>,
    /// Whether this set is one we maintain rather than the tenant: the
    /// address that routes the delegated hostname to the proxy, and the
    /// `_acme-challenge` names a certificate is issued through. Both are
    /// shown, but writing or removing them is refused.
    pub is_managed_by_ianua: bool,
}

impl From<ManagedRecordSet> for DnsRecordSetResponse {
    fn from(managed: ManagedRecordSet) -> Self {
        Self {
            name: managed.set.name().as_str().to_owned(),
            record_type: managed.set.kind().as_str(),
            ttl_seconds: managed.set.ttl().as_seconds(),
            values: managed
                .set
                .values()
                .iter()
                .map(RecordValue::as_presentation)
                .collect(),
            is_managed_by_ianua: managed.is_reserved,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body writing `values` for `name` and `record_type`, with no TTL.
    fn body(name: &str, record_type: &str, values: &[&str]) -> SetDnsRecordBody {
        SetDnsRecordBody {
            name: name.to_owned(),
            record_type: record_type.to_owned(),
            ttl_seconds: None,
            values: values.iter().map(|value| (*value).to_owned()).collect(),
        }
    }

    /// `ApiError` has no `Debug`, so a test insists on the happy path by
    /// hand.
    fn parsed(body: SetDnsRecordBody) -> RecordSet {
        let Ok(set) = body.record_set() else {
            panic!("the body should have parsed");
        };
        set
    }

    /// An address record for a name under the delegated host parses into
    /// one set with its one value.
    #[test]
    fn an_address_set_parses() {
        let set = parsed(body("api.auth.acme.com", "A", &["203.0.113.10"]));

        assert_eq!(set.kind(), RecordKind::A);
        assert_eq!(set.name().as_str(), "api.auth.acme.com");
        assert_eq!(set.values().len(), 1);
    }

    /// Omitting the TTL is the common case, and a caller who does not care
    /// should not have to invent a number.
    #[test]
    fn an_omitted_ttl_falls_back_to_the_standard_one() {
        let set = parsed(body("api.auth.acme.com", "A", &["203.0.113.10"]));

        assert_eq!(set.ttl(), Ttl::standard());
    }

    /// A TTL of five seconds is below the honoured range and is refused.
    #[test]
    fn a_ttl_outside_the_honoured_range_is_refused() {
        let mut body = body("api.auth.acme.com", "A", &["203.0.113.10"]);
        body.ttl_seconds = Some(5);

        assert!(body.record_set().is_err());
    }

    /// An address record whose value is not an address is refused.
    #[test]
    fn a_value_that_does_not_match_its_type_is_refused() {
        assert!(
            body("api.auth.acme.com", "A", &["not-an-address"])
                .record_set()
                .is_err()
        );
    }

    /// An empty set is not an answer of "nothing"; removing the set is how
    /// a caller says that, and the two must not be confusable.
    #[test]
    fn a_set_with_no_values_is_refused() {
        assert!(body("api.auth.acme.com", "A", &[]).record_set().is_err());
    }
}
