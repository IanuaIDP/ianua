//! The record types a delegated zone answers with.

use crate::message;
use crate::shared::errors::DomainError;

/// A DNS record type.
///
/// It covers only the types a delegated hostname needs. A nameserver builds
/// a zone's own `SOA` and `NS` records from the zone itself. Nothing a
/// tenant writes may contradict them, so neither can be named here.
///
/// `A` and `AAAA` are two types, as they are on the wire. A resolver asks
/// for one or the other, and gets nothing back for the wrong one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RecordKind {
    /// An IPv4 address.
    A,
    /// An IPv6 address.
    Aaaa,
    /// An alias to another name. It must stand alone, see
    /// [`RecordKind::is_exclusive`].
    Cname,
    /// Free text, such as verification tokens, `SPF`, `DKIM` and `DMARC`.
    Txt,
    /// Where mail for this name goes.
    Mx,
    /// Where a named service on this name runs.
    Srv,
    /// Which certificate authorities may issue for this name.
    Caa,
}

impl RecordKind {
    /// Every type a tenant may write, in the order a zone file lists them.
    pub const ALL: [Self; 7] = [
        Self::A,
        Self::Aaaa,
        Self::Cname,
        Self::Txt,
        Self::Mx,
        Self::Srv,
        Self::Caa,
    ];

    /// The type as a zone file spells it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Txt => "TXT",
            Self::Mx => "MX",
            Self::Srv => "SRV",
            Self::Caa => "CAA",
        }
    }

    /// The type a zone file spelling names, in any case and with spaces
    /// trimmed.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when no type has that spelling. The
    ///   message lists the types that exist, since a tenant typed it.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let upper = value.trim().to_ascii_uppercase();

        Self::ALL
            .into_iter()
            .find(|kind| kind.as_str() == upper)
            .ok_or_else(|| {
                let known = Self::ALL.map(Self::as_str).join(", ");
                DomainError::invalid(message!(
                    "tenant-unknown-dns-record-type-expected-one",
                    format!("unknown DNS record type '{value}'; expected one of {known}")
                ))
            })
    }

    /// Whether a record of this type must be alone at its name.
    ///
    /// Only `CNAME` must. A `CNAME` says "this name *is* that name", so
    /// anything beside it would be a second answer that contradicts it. RFC
    /// 1034 forbids the pairing.
    #[must_use]
    pub fn is_exclusive(self) -> bool {
        matches!(self, Self::Cname)
    }

    /// Whether a name may hold more than one answer of this type.
    ///
    /// `CNAME` is the only single-valued type. Every other type is a set. Two
    /// `A` records share the load, two `MX` records are a primary and a
    /// backup, and two `CAA` records allow two issuers.
    #[must_use]
    pub fn allows_multiple(self) -> bool {
        !self.is_exclusive()
    }
}

impl std::fmt::Display for RecordKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each of the seven types is spelled as a zone file writes it and parsed
    /// back as the same type.
    #[test]
    fn every_kind_round_trips_through_its_zone_file_spelling() {
        for kind in RecordKind::ALL {
            assert_eq!(RecordKind::parse(kind.as_str()).unwrap(), kind);
        }
    }

    /// A tenant types `cname`, or `  Aaaa ` with spaces. Each parses as the
    /// type it names, since DNS type names ignore case.
    #[test]
    fn a_kind_parses_regardless_of_case_or_surrounding_space() {
        assert_eq!(RecordKind::parse("cname").unwrap(), RecordKind::Cname);
        assert_eq!(RecordKind::parse("  Aaaa ").unwrap(), RecordKind::Aaaa);
    }

    /// A tenant types `PTR`, which a zone does not offer. The refusal names
    /// `PTR` and lists the types they could use, such as `CNAME`.
    #[test]
    fn an_unknown_kind_is_refused_with_the_known_ones_named() {
        let err = RecordKind::parse("PTR").unwrap_err();

        let DomainError::Validation(error) = err else {
            panic!("expected a validation error");
        };
        let message = error.to_string();
        assert!(message.contains("PTR"), "{message}");
        assert!(message.contains("CNAME"), "{message}");
    }

    /// The tenant record-kind parser rejects the zone's structural `NS` and
    /// `SOA` types.
    #[test]
    fn the_zones_own_structural_records_are_not_expressible() {
        assert!(RecordKind::parse("NS").is_err());
        assert!(RecordKind::parse("SOA").is_err());
    }

    /// `CNAME` must stand alone and holds one value. Every other type may
    /// sit beside others and hold a set.
    #[test]
    fn only_cname_is_exclusive_and_single_valued() {
        assert!(RecordKind::Cname.is_exclusive());
        assert!(!RecordKind::Cname.allows_multiple());

        for kind in RecordKind::ALL
            .into_iter()
            .filter(|k| *k != RecordKind::Cname)
        {
            assert!(!kind.is_exclusive(), "{kind} should not be exclusive");
            assert!(kind.allows_multiple(), "{kind} should allow a set");
        }
    }

    /// Each type prints as its zone file spelling, such as `CNAME`, and that
    /// text parses back to the same type. Zone files and operator logs show
    /// this text.
    #[test]
    fn a_kind_displays_as_the_spelling_it_parses_back_from() {
        for kind in RecordKind::ALL {
            assert_eq!(kind.to_string(), kind.as_str());
            assert_eq!(RecordKind::parse(&kind.to_string()).unwrap(), kind);
        }
        assert_eq!(RecordKind::Cname.to_string(), "CNAME");
    }
}
