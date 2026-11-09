//! How sensitive data is, from public to restricted.

use crate::message;
use crate::shared::errors::DomainError;

/// How sensitive data is, ordered from least to most sensitive.
///
/// The proxy uses it to decide what to redact. Agent tools and runs carry
/// it too, and it decides where their data may be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DataClassLevel {
    /// Data anyone may see.
    Public,
    /// Data for people inside the tenant only.
    Internal,
    /// Personal or financial data.
    Confidential,
    /// Secrets and health records.
    Restricted,
}

impl DataClassLevel {
    /// The name stored for the level.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Confidential => "confidential",
            Self::Restricted => "restricted",
        }
    }

    /// The level's rank, from 0 for public to 3 for restricted.
    ///
    /// It is stored where the database has to compare levels.
    #[must_use]
    pub fn rank(self) -> i16 {
        match self {
            Self::Public => 0,
            Self::Internal => 1,
            Self::Confidential => 2,
            Self::Restricted => 3,
        }
    }

    /// The level at `rank`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] for a rank no level has. Only a
    ///   corrupt row holds one.
    pub fn from_rank(rank: i16) -> Result<Self, DomainError> {
        match rank {
            0 => Ok(Self::Public),
            1 => Ok(Self::Internal),
            2 => Ok(Self::Confidential),
            3 => Ok(Self::Restricted),
            _ => Err(DomainError::corrupt_row("data class", "an unknown rank")),
        }
    }

    /// Reads a value a caller sent.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] naming the value when it is not one of
    ///   the known names.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        Self::named(value).ok_or_else(|| {
            DomainError::invalid(message!(
                "data_classification-unknown-data-class-level",
                format!("unknown data class level: {value}")
            ))
        })
    }

    /// Reads a stored value.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the stored name is not one of
    ///   the known names. The row is corrupt, not the caller's input.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        Self::named(value).ok_or_else(|| DomainError::corrupt_row("data class", "an unknown name"))
    }

    /// The value a name stands for.
    fn named(value: &str) -> Option<Self> {
        match value {
            "public" => Some(Self::Public),
            "internal" => Some(Self::Internal),
            "confidential" => Some(Self::Confidential),
            "restricted" => Some(Self::Restricted),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each level ranks above the one less sensitive, and each rank reads
    /// back as its level. The database compares ranks, so a stored rank of 4
    /// reads as a corrupt row.
    #[test]
    fn ranks_follow_sensitivity_and_round_trip() {
        let levels = [
            DataClassLevel::Public,
            DataClassLevel::Internal,
            DataClassLevel::Confidential,
            DataClassLevel::Restricted,
        ];
        for pair in levels.windows(2) {
            assert!(pair[0] < pair[1]);
            assert!(pair[0].rank() < pair[1].rank());
        }
        for level in levels {
            assert_eq!(DataClassLevel::from_rank(level.rank()).unwrap(), level);
        }
        assert!(matches!(
            DataClassLevel::from_rank(4),
            Err(DomainError::Infrastructure(_))
        ));
    }

    /// Each level is stored by its name and reads back as the same level. A
    /// stored name like "secret" is a corrupt row, not bad input.
    #[test]
    fn every_data_class_level_round_trips_through_its_stored_name() {
        let levels = [
            (DataClassLevel::Public, "public"),
            (DataClassLevel::Internal, "internal"),
            (DataClassLevel::Confidential, "confidential"),
            (DataClassLevel::Restricted, "restricted"),
        ];

        for (level, name) in levels {
            assert_eq!(level.as_str(), name);
            assert_eq!(DataClassLevel::from_stored(name).unwrap(), level);
        }

        assert!(matches!(
            DataClassLevel::from_stored("secret"),
            Err(DomainError::Infrastructure(_))
        ));
    }

    /// A caller sends "secret" as a level. That is a mistake in the request,
    /// not a fault in the server. "restricted" reads as restricted.
    #[test]
    fn an_unknown_data_class_a_caller_sent_is_bad_input() {
        assert!(matches!(
            DataClassLevel::parse("secret"),
            Err(DomainError::Validation(_))
        ));
        assert_eq!(
            DataClassLevel::parse("restricted").unwrap(),
            DataClassLevel::Restricted
        );
    }
}
