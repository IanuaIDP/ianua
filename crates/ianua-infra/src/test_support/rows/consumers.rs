//! Rows of the consumers context.

use ianua_domain::domains::consumers::consumer::{ConsumerRow, ConsumerStatus};
use ianua_domain::domains::consumers::credential::ConsumerCredentialKind;
use ianua_domain::domains::consumers::credentials::{HeldCredential, PreviousCredential};
use ianua_domain::domains::consumers::quota::ConsumerQuota;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::types::{
    ActorRef, CertificateFingerprint, ConsumerId, Expiry, FederatedSubject, HttpsUrl, Issuer,
    KeyPrefix, Label, TokenHash, UserId,
};

use crate::test_support::rows::at;

/// The API key credential shown as `prefix`, kept by a hash named after it.
///
/// # Panics
///
/// When `prefix` is not a valid key prefix, which is a mistake in the test.
#[must_use]
pub fn api_key(prefix: &str) -> ConsumerCredentialKind {
    ConsumerCredentialKind::ApiKey {
        prefix: KeyPrefix::new(prefix).expect("a valid key prefix"),
        key_hash: TokenHash::from_stored(format!("hash of {prefix}")),
    }
}

/// The client certificate credential whose digest is 32 bytes of `byte`.
#[must_use]
pub fn client_cert(byte: u8) -> ConsumerCredentialKind {
    ConsumerCredentialKind::ClientCert {
        fingerprint: CertificateFingerprint::from_digest([byte; 32]),
    }
}

/// The token credential of `subject` at the partner's issuer.
///
/// # Panics
///
/// When `subject` is not a valid subject, which is a mistake in the test.
#[must_use]
pub fn jwt_bearer(subject: &str) -> ConsumerCredentialKind {
    ConsumerCredentialKind::JwtBearer {
        issuer: Issuer::new("https://partner.example").expect("a valid issuer"),
        subject: FederatedSubject::new(subject).expect("a valid subject"),
        jwks_uri: HttpsUrl::new("https://partner.example/jwks").expect("a valid address"),
    }
}

/// An active, unlimited consumer named `name`, cleared for internal data,
/// signing in with the API key `<name>_key` that never expires, made at the
/// fixed moment by a tenant user.
///
/// # Panics
///
/// When `name` is not a valid label, which is a mistake in the test.
#[must_use]
pub fn consumer_row(name: &str) -> ConsumerRow {
    ConsumerRow {
        id: ConsumerId::new(),
        name: Label::new("name", name).expect("a valid name"),
        description: None,
        credential: HeldCredential::new(api_key(&format!("{name}_key")), Expiry::Never),
        previous_credential: PreviousCredential::Retired,
        quota: ConsumerQuota::Unlimited,
        status: ConsumerStatus::Active,
        clearance: DataClassLevel::Internal,
        created_by: ActorRef::User(UserId::new()),
        created_at: at(0),
        updated_at: at(0),
    }
}

/// The consumer named `name`, rotated at `at(10)` onto `credential`, its
/// old API key working for a day more.
#[must_use]
pub fn rotated_consumer_row(name: &str, credential: ConsumerCredentialKind) -> ConsumerRow {
    let old = HeldCredential::new(api_key(&format!("{name}_key")), Expiry::Never);
    ConsumerRow {
        credential: HeldCredential::new(credential, Expiry::At(at(1_000_000))),
        previous_credential: PreviousCredential::Overlapping {
            credential: old,
            until: at(86_410),
        },
        updated_at: at(10),
        ..consumer_row(name)
    }
}
