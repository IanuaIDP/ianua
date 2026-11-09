//! A consumer as its row holds it: read back into the aggregate, and
//! written out from it. Each credential, the one in use and the one a
//! rotation keeps, fills the columns of its kind.

use ianua_domain::domains::consumers::consumer::{Consumer, ConsumerRow};
use ianua_domain::domains::consumers::credential::ConsumerCredentialKind;
use ianua_domain::domains::consumers::credentials::{HeldCredential, PreviousCredential};
use ianua_domain::domains::consumers::quota::{ConsumerQuota, QuotaPeriod, RequestAllowance};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{
    CertificateFingerprint, ConsumerId, Expiry, FederatedSubject, HttpsUrl, Issuer, KeyPrefix,
    Label, TokenHash,
};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const CONSUMER: Stored = Stored("consumer");

const CREATED_BY: Kept = Kept {
    entity: CONSUMER.0,
    column: "created_by",
    shape: 1,
};

/// A consumer as it is read. The store's checked queries fill it.
pub(super) struct ConsumerRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) description: Option<String>,
    pub(super) credential_kind: String,
    pub(super) key_prefix: Option<String>,
    pub(super) key_hash: Option<String>,
    pub(super) cert_fingerprint: Option<String>,
    pub(super) jwt_issuer: Option<String>,
    pub(super) jwt_subject: Option<String>,
    pub(super) jwks_uri: Option<String>,
    pub(super) credential_expires_at: Option<OffsetDateTime>,
    pub(super) previous_kind: Option<String>,
    pub(super) previous_key_prefix: Option<String>,
    pub(super) previous_key_hash: Option<String>,
    pub(super) previous_cert_fingerprint: Option<String>,
    pub(super) previous_jwt_issuer: Option<String>,
    pub(super) previous_jwt_subject: Option<String>,
    pub(super) previous_jwks_uri: Option<String>,
    pub(super) previous_expires_at: Option<OffsetDateTime>,
    pub(super) previous_until: Option<OffsetDateTime>,
    pub(super) quota_requests: Option<i64>,
    pub(super) quota_period: Option<String>,
    pub(super) status: String,
    pub(super) clearance: String,
    pub(super) created_by: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

/// The columns one credential is read from.
struct CredentialParts<'a> {
    kind: &'a str,
    key_prefix: Option<&'a str>,
    key_hash: Option<&'a str>,
    cert_fingerprint: Option<&'a str>,
    jwt_issuer: Option<&'a str>,
    jwt_subject: Option<&'a str>,
    jwks_uri: Option<&'a str>,
}

impl ConsumerRecord {
    /// The consumer the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the consumer
    /// keeps.
    pub(super) fn into_consumer(self) -> Result<Consumer<ResolvedTenant>, DomainError> {
        let credential = HeldCredential::new(
            kind_from(&self.current_parts())?,
            expiry_of(self.credential_expires_at),
        );
        let previous_credential = self.previous()?;
        Consumer::reconstitute(ConsumerRow {
            id: ConsumerId::from_uuid(self.id),
            name: CONSUMER.value("name", Label::new("name", self.name))?,
            description: self
                .description
                .map(|text| CONSUMER.value("description", Label::new("description", text)))
                .transpose()?,
            credential,
            previous_credential,
            quota: quota_from(self.quota_requests, self.quota_period.as_deref())?,
            status: CONSUMER.choice(&self.status)?,
            clearance: DataClassLevel::from_stored(&self.clearance)?,
            created_by: CREATED_BY.open(self.created_by)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }

    fn current_parts(&self) -> CredentialParts<'_> {
        CredentialParts {
            kind: &self.credential_kind,
            key_prefix: self.key_prefix.as_deref(),
            key_hash: self.key_hash.as_deref(),
            cert_fingerprint: self.cert_fingerprint.as_deref(),
            jwt_issuer: self.jwt_issuer.as_deref(),
            jwt_subject: self.jwt_subject.as_deref(),
            jwks_uri: self.jwks_uri.as_deref(),
        }
    }

    /// The credential a rotation keeps working, or that none is kept.
    fn previous(&self) -> Result<PreviousCredential, DomainError> {
        let (kind, until) = match (self.previous_kind.as_deref(), self.previous_until) {
            (None, None) => return Ok(PreviousCredential::Retired),
            (Some(kind), Some(until)) => (kind, until),
            (Some(_), None) | (None, Some(_)) => {
                return Err(DomainError::corrupt_row(
                    CONSUMER.0,
                    "a kept credential without its overlap, or an overlap without one",
                ));
            }
        };
        let parts = CredentialParts {
            kind,
            key_prefix: self.previous_key_prefix.as_deref(),
            key_hash: self.previous_key_hash.as_deref(),
            cert_fingerprint: self.previous_cert_fingerprint.as_deref(),
            jwt_issuer: self.previous_jwt_issuer.as_deref(),
            jwt_subject: self.previous_jwt_subject.as_deref(),
            jwks_uri: self.previous_jwks_uri.as_deref(),
        };
        let credential =
            HeldCredential::new(kind_from(&parts)?, expiry_of(self.previous_expires_at));
        Ok(PreviousCredential::Overlapping { credential, until })
    }
}

/// The credential `parts` hold, each value through its own constructor.
fn kind_from(parts: &CredentialParts<'_>) -> Result<ConsumerCredentialKind, DomainError> {
    match parts.kind {
        "api_key" => Ok(ConsumerCredentialKind::ApiKey {
            prefix: CONSUMER.value("key prefix", KeyPrefix::new(part(parts.key_prefix)?))?,
            key_hash: TokenHash::from_stored(part(parts.key_hash)?.to_owned()),
        }),
        "client_cert" => Ok(ConsumerCredentialKind::ClientCert {
            fingerprint: CONSUMER.value(
                "certificate fingerprint",
                CertificateFingerprint::parse(part(parts.cert_fingerprint)?),
            )?,
        }),
        "jwt_bearer" => Ok(ConsumerCredentialKind::JwtBearer {
            issuer: CONSUMER.value("token issuer", Issuer::new(part(parts.jwt_issuer)?))?,
            subject: CONSUMER.value(
                "token subject",
                FederatedSubject::new(part(parts.jwt_subject)?),
            )?,
            jwks_uri: CONSUMER.value("key set address", HttpsUrl::new(part(parts.jwks_uri)?))?,
        }),
        _ => Err(DomainError::corrupt_row(
            CONSUMER.0,
            "an unknown credential kind",
        )),
    }
}

/// A part a credential of its kind always fills.
fn part(stored: Option<&str>) -> Result<&str, DomainError> {
    stored.ok_or_else(|| {
        DomainError::corrupt_row(CONSUMER.0, "a credential missing a part of its kind")
    })
}

fn expiry_of(stored: Option<OffsetDateTime>) -> Expiry {
    stored.map_or(Expiry::Never, Expiry::At)
}

/// The quota the two quota columns hold: unlimited when both are empty.
fn quota_from(requests: Option<i64>, period: Option<&str>) -> Result<ConsumerQuota, DomainError> {
    let (requests, period) = match (requests, period) {
        (None, None) => return Ok(ConsumerQuota::Unlimited),
        (Some(requests), Some(period)) => (requests, period),
        (Some(_), None) | (None, Some(_)) => {
            return Err(DomainError::corrupt_row(CONSUMER.0, "half a quota"));
        }
    };
    let requests = u64::try_from(requests)
        .map_err(|_| DomainError::corrupt_row(CONSUMER.0, "a negative quota"))?;
    let allowance = RequestAllowance::new(requests, QuotaPeriod::from_stored(period)?);
    Ok(ConsumerQuota::Limited(CONSUMER.value("quota", allowance)?))
}

/// The columns one credential is written to, all empty for a credential
/// not kept.
#[derive(Default)]
pub(super) struct CredentialColumns<'a> {
    pub(super) kind: Option<&'static str>,
    pub(super) key_prefix: Option<&'a str>,
    pub(super) key_hash: Option<&'a str>,
    pub(super) cert_fingerprint: Option<String>,
    pub(super) jwt_issuer: Option<&'a str>,
    pub(super) jwt_subject: Option<&'a str>,
    pub(super) jwks_uri: Option<&'a str>,
    pub(super) expires_at: Option<OffsetDateTime>,
}

impl<'a> CredentialColumns<'a> {
    /// The columns `held` is written to, those of its kind filled.
    fn of(held: &'a HeldCredential) -> Self {
        let expiring = Self {
            expires_at: held.expiry().instant(),
            ..Self::default()
        };
        match held.kind() {
            ConsumerCredentialKind::ApiKey { prefix, key_hash } => Self {
                kind: Some("api_key"),
                key_prefix: Some(prefix.as_str()),
                key_hash: Some(key_hash.as_str()),
                ..expiring
            },
            ConsumerCredentialKind::ClientCert { fingerprint } => Self {
                kind: Some("client_cert"),
                cert_fingerprint: Some(fingerprint.to_string()),
                ..expiring
            },
            ConsumerCredentialKind::JwtBearer {
                issuer,
                subject,
                jwks_uri,
            } => Self {
                kind: Some("jwt_bearer"),
                jwt_issuer: Some(issuer.as_str()),
                jwt_subject: Some(subject.as_str()),
                jwks_uri: Some(jwks_uri.as_str()),
                ..expiring
            },
        }
    }
}

/// A consumer's columns, as they are written.
pub(super) struct ConsumerColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) description: Option<&'a str>,
    /// The credential in use, whose kind is always filled.
    pub(super) current: CredentialColumns<'a>,
    /// The credential a rotation keeps working until `previous_until`.
    pub(super) previous: CredentialColumns<'a>,
    pub(super) previous_until: Option<OffsetDateTime>,
    pub(super) quota_requests: Option<i64>,
    pub(super) quota_period: Option<&'static str>,
    pub(super) status: &'static str,
    pub(super) clearance: &'static str,
    pub(super) created_by: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> ConsumerColumns<'a> {
    /// The columns `consumer` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when who made it cannot be
    /// written out as JSON, or the quota does not fit its column.
    pub(super) fn of(consumer: &'a Consumer<ResolvedTenant>) -> Result<Self, DomainError> {
        let (previous, previous_until) = match consumer.credentials().previous() {
            PreviousCredential::Retired => (CredentialColumns::default(), None),
            PreviousCredential::Overlapping { credential, until } => {
                (CredentialColumns::of(credential), Some(*until))
            }
        };
        let (quota_requests, quota_period) = quota_columns(consumer.quota())?;
        Ok(Self {
            id: consumer.id().as_uuid(),
            name: consumer.name().as_str(),
            description: consumer.description().map(Label::as_str),
            current: CredentialColumns::of(consumer.credentials().current()),
            previous,
            previous_until,
            quota_requests,
            quota_period,
            status: consumer.status().word(),
            clearance: consumer.clearance().as_str(),
            created_by: CREATED_BY.seal(consumer.created_by())?,
            created_at: consumer.created_at(),
            updated_at: consumer.updated_at(),
        })
    }
}

/// The two quota columns `quota` is written to: both empty when unlimited.
fn quota_columns(quota: ConsumerQuota) -> Result<(Option<i64>, Option<&'static str>), DomainError> {
    let ConsumerQuota::Limited(allowance) = quota else {
        return Ok((None, None));
    };
    let requests = i64::try_from(allowance.requests()).map_err(DomainError::infra)?;
    Ok((Some(requests), Some(allowance.per().as_str())))
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::types::{ActorRef, UserId};
    use serde_json::json;

    use super::*;

    /// Who made a consumer is written in the shape pinned here, and a row
    /// in that shape reads back the same.
    #[test]
    fn who_made_a_consumer_is_stored_in_its_pinned_shape() {
        let sam = UserId::from_uuid(Uuid::from_u128(7));
        let stored = json!({"v": 1, "value": {"User": "00000000-0000-0000-0000-000000000007"}});

        assert_eq!(CREATED_BY.seal(&ActorRef::User(sam)).unwrap(), stored);
        let read: ActorRef = CREATED_BY.open(stored.clone()).unwrap();
        assert_eq!(CREATED_BY.seal(&read).unwrap(), stored);
    }
}
