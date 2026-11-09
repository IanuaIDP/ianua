//! The nameserver names one registration is delegated to, and no other.
//!
//! # Why the names differ per registration
//!
//! A delegation proves that whoever runs the parent zone handed a name over.
//! On its own it cannot say *who* handed it. If every tenant pointed at the
//! same two nameservers, all their `NS` records would look the same. "This
//! name points at us" would then be true for a name somebody else delegated.
//!
//! Say Acme deletes its registration for `auth.acme.com` but leaves the `NS`
//! records in place. Eve registers the same name. With shared nameservers
//! she would verify at once and get a certificate for a name she never
//! owned.
//!
//! So each registration gets nameserver names of its own, at no extra work
//! for the tenant. Only someone who can write in the parent zone can point a
//! name at them, and only this registration was told what they are. The one
//! record the tenant already writes proves both control and identity.
//!
//! DNS hosts work the same way. The nameserver pair a provider hands you is
//! yours alone.
//!
//! # Why they must also be served
//!
//! A resolver asked for a zone's `NS` records answers from the zone itself,
//! not from the parent's referral. A zone answering with the shared names
//! would report those, and a check for the assigned pair would never match.
//! So these names are what the zone answers with, as well as what the parent
//! points at.

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_count;
use crate::shared::validation::{Charset, Validator};
use crate::types::{DomainId, DomainName};

/// The label that makes a registration's nameservers its own.
///
/// It is worked out from the registration's id, so the two cannot disagree.
/// A name deleted and registered again is a new registration with new
/// nameservers. So the old delegation, still published, proves nothing about
/// the new one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationLabel(String);

impl DelegationLabel {
    /// The label belonging to the registration with this id.
    ///
    /// It is the id's 32 hex characters. That is a legal DNS label, under the
    /// 63 the format allows and only letters and digits.
    #[must_use]
    pub fn for_registration(id: &DomainId) -> Self {
        Self(id.as_uuid().as_simple().to_string())
    }

    /// Rebuilds a label from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when `value` is not a legal DNS
    ///   label. Such a label could never have been served, so the stored
    ///   data is corrupt.
    pub fn from_stored(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();

        Validator::new("delegation_label", &value)
            .identifier(
                1..=63,
                Charset::LOWERCASE | Charset::UPPERCASE | Charset::DIGIT,
            )
            .validate_first()
            .map_err(|_| {
                DomainError::corrupt_row("DNS delegation", "a label that is not a DNS label")
            })?;

        Ok(Self(value))
    }

    /// The label itself.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// This registration's nameserver names, one per shared base name.
    ///
    /// `ns1.ianua.io` becomes `<label>.ns1.ianua.io`. They all resolve to the
    /// same hosts. Only the name differs, and the name is what the parent
    /// zone points at and nobody else was given.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `bases` is empty.
    /// - [`DomainError::Validation`] when a base with this label in front is
    ///   not a valid domain name, because the base is too long.
    pub fn nameservers(&self, bases: &[DomainName]) -> Result<Vec<DomainName>, DomainError> {
        validate_count("nameserver_bases", bases.len(), 1..=usize::MAX)?;

        bases
            .iter()
            .map(|base| {
                DomainName::new(format!("{}.{}", self.0, base.as_str())).map_err(|e| {
                    DomainError::invalid(message!(
                        "tenant-cannot-assign-a-nameserver-under",
                        format!("cannot assign a nameserver under {}: {e}", base.as_str())
                    ))
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn bases() -> Vec<DomainName> {
        vec![
            DomainName::new("ns1.ianua.io").unwrap(),
            DomainName::new("ns2.ianua.io").unwrap(),
        ]
    }

    fn label() -> DelegationLabel {
        DelegationLabel::for_registration(&DomainId::from_uuid(
            Uuid::parse_str("019e4f00-0000-7000-0000-000000000001").unwrap(),
        ))
    }

    /// A registration is given nameservers under `ns1.ianua.io` and
    /// `ns2.ianua.io`. Each name is the registration's 32 hex characters in
    /// front of a base.
    #[test]
    fn a_registration_gets_its_own_name_under_every_base() {
        let assigned = label().nameservers(&bases()).unwrap();

        assert_eq!(
            assigned.iter().map(DomainName::as_str).collect::<Vec<_>>(),
            [
                "019e4f00000070000000000000000001.ns1.ianua.io",
                "019e4f00000070000000000000000001.ns2.ianua.io",
            ]
        );
    }

    /// Two distinct registration identifiers produce different nameserver
    /// names under the same bases.
    #[test]
    fn two_registrations_never_share_nameservers() {
        let one = DelegationLabel::for_registration(&DomainId::new());
        let other = DelegationLabel::for_registration(&DomainId::new());

        assert_ne!(
            one.nameservers(&bases()).unwrap(),
            other.nameservers(&bases()).unwrap()
        );
    }

    /// A new registration's label is non-empty, at most 63 characters and
    /// only letters and digits. So it works as a DNS label without escaping
    /// or cutting.
    #[test]
    fn a_label_is_a_legal_dns_label() {
        let label = DelegationLabel::for_registration(&DomainId::new());

        assert!(!label.as_str().is_empty());
        assert!(label.as_str().len() <= 63);
        assert!(label.as_str().bytes().all(|b| b.is_ascii_alphanumeric()));
    }

    /// Nameservers are asked for with no base names. It is refused, since
    /// the tenant would have nothing to delegate to.
    #[test]
    fn assigning_under_no_base_is_refused() {
        assert!(label().nameservers(&[]).is_err());
    }

    /// A registration's label is stored and read back. It equals the
    /// original.
    #[test]
    fn a_stored_label_round_trips() {
        let original = label();

        let read_back = DelegationLabel::from_stored(original.as_str()).unwrap();

        assert_eq!(read_back, original);
    }

    /// Stored labels that are empty, hold a dot or hyphen, or run to 64
    /// characters are refused as infrastructure faults. Such a label could
    /// never have been served, so the data is corrupt.
    #[test]
    fn a_stored_label_that_is_not_a_label_is_infrastructure_corruption() {
        for bad in ["", "has.a.dot", "has-a-hyphen", &"x".repeat(64)] {
            assert!(matches!(
                DelegationLabel::from_stored(bad),
                Err(DomainError::Infrastructure(_))
            ));
        }
    }
}
