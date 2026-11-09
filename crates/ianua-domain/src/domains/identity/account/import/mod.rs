//! Opening accounts from another system's records, such as the export of
//! the identity provider a tenant is leaving, password hashes included.
//!
//! An imported account is opened like a registered one: it waits for its
//! holder to follow the link mailed to its address. The other system's
//! word that an address was verified proves nothing here, so no imported
//! address starts verified. The password hash goes to the credential
//! store, so the person signs in with the password they already have once
//! their address is confirmed.

/// A password hash brought over from another system.
pub mod password_hash;
/// Records an import set aside, with where each stood and why.
pub mod refusal;
/// One import as the worker goes through it, chunk by chunk.
pub mod run;
/// Where an import stands.
pub mod state;

use crate::domains::identity::account::import::password_hash::ImportedPasswordHash;
use crate::domains::identity::account::user_profile::{DirectoryRecords, PersonalDetails};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::ValidationError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::types::{DisplayName, Email};

/// The most records one import takes. A larger export is sent in parts.
pub(crate) const MAX_BATCH_RECORDS: usize = 10_000;

/// What another system says about one account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountImport {
    /// The account's address. It starts unverified.
    pub email: Email,
    /// The name it shows.
    pub display_name: DisplayName,
    /// The person's own details.
    pub details: PersonalDetails,
    /// What the company's directory records about them.
    pub records: DirectoryRecords,
}

/// The password an imported account brings with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportedPassword {
    /// None: the person sets one through a reset link, or signs in another
    /// way.
    NotCarried,
    /// The hash the other system kept, which the person's password still
    /// matches.
    Hash(ImportedPasswordHash),
}

/// One account to open, with the password it brings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportRecord {
    /// The account itself.
    pub account: AccountImport,
    /// Its password, when the export carries one.
    pub password: ImportedPassword,
}

/// The records of one import, checked as a whole.
///
/// Each address and each external id appears once. Two records for one
/// address would open one account and throw the other's data away, or open
/// the second for whoever controls the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportBatch {
    records: Vec<ImportRecord>,
}

impl ImportBatch {
    /// The records of one import.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when there are none, or more than
    ///   `MAX_BATCH_RECORDS`.
    /// - [`DomainError::Validation`] when two records name the same address
    ///   or the same external id.
    pub fn new(records: Vec<ImportRecord>) -> Result<Self, DomainError> {
        validate_count("records", records.len(), 1..=MAX_BATCH_RECORDS)?;
        let addresses = records.iter().map(|record| &record.account.email);
        if first_repeat(addresses).is_some() {
            return Err(repeated("an address"));
        }
        let external_ids = records
            .iter()
            .filter_map(|record| record.account.records.external_id.value());
        if first_repeat(external_ids).is_some() {
            return Err(repeated("an external id"));
        }
        Ok(Self { records })
    }

    /// The records, in the order they came.
    #[must_use]
    pub fn records(&self) -> &[ImportRecord] {
        &self.records
    }

    /// The records, to open one account from each.
    #[must_use]
    pub fn into_records(self) -> Vec<ImportRecord> {
        self.records
    }
}

/// A batch refused for naming `what` twice.
fn repeated(what: &str) -> DomainError {
    ValidationError::Custom {
        field: "records",
        code: "repeated_record".to_owned(),
        message: message!(
            "identity-two-records-name-the-same",
            format!("two records name the same {what}")
        ),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::identity::account::profile_values::ExternalId;
    use crate::shared::config::DisplayNameLimits;
    use crate::types::Setting;

    fn record(email: &str) -> ImportRecord {
        ImportRecord {
            account: AccountImport {
                email: Email::new(email).unwrap(),
                display_name: DisplayName::new("Ann", &DisplayNameLimits::default()).unwrap(),
                details: PersonalDetails::default(),
                records: DirectoryRecords::default(),
            },
            password: ImportedPassword::NotCarried,
        }
    }

    fn with_external_id(email: &str, id: &str) -> ImportRecord {
        let mut imported = record(email);
        imported.account.records.external_id = Setting::Set(ExternalId::new(id).unwrap());
        imported
    }

    /// Two records for different people make a batch of two, in the order
    /// they came.
    #[test]
    fn records_for_different_people_make_a_batch() {
        let batch = ImportBatch::new(vec![record("ann@acme.com"), record("bob@acme.com")]).unwrap();

        assert_eq!(batch.records().len(), 2);
        assert_eq!(batch.records()[0].account.email.as_str(), "ann@acme.com");
    }

    /// An import batch containing the same email address twice is rejected
    /// as invalid.
    #[test]
    fn a_batch_naming_an_address_twice_is_refused() {
        let batch = ImportBatch::new(vec![record("ann@acme.com"), record("ann@acme.com")]);

        assert!(matches!(batch, Err(DomainError::Validation(_))));
    }

    /// Two records sharing Okta's id `00u1` are refused, since the directory
    /// would match both to one person.
    #[test]
    fn a_batch_naming_an_external_id_twice_is_refused() {
        let batch = ImportBatch::new(vec![
            with_external_id("ann@acme.com", "00u1"),
            with_external_id("bob@acme.com", "00u1"),
        ]);

        assert!(matches!(batch, Err(DomainError::Validation(_))));
    }

    /// An empty import is refused, so a mistaken upload is not read as done.
    #[test]
    fn an_empty_batch_is_refused() {
        assert!(ImportBatch::new(Vec::new()).is_err());
    }
}
