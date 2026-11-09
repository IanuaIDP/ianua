//! An agent's mark as its row holds it: the rank of the most sensitive
//! data it has touched, read back into the domain's level.

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::shared::errors::DomainError;

/// The mark a stored rank stands for: public when the agent has none.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` for a rank no level has.
pub(super) fn into_level(rank: Option<i16>) -> Result<DataClassLevel, DomainError> {
    rank.map_or(Ok(DataClassLevel::Public), DataClassLevel::from_rank)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An agent with no mark has touched nothing, and each rank reads back
    /// as its level.
    #[test]
    fn a_rank_reads_back_as_its_level() {
        assert_eq!(into_level(None).unwrap(), DataClassLevel::Public);
        for level in [
            DataClassLevel::Public,
            DataClassLevel::Internal,
            DataClassLevel::Confidential,
            DataClassLevel::Restricted,
        ] {
            assert_eq!(into_level(Some(level.rank())).unwrap(), level);
        }
    }

    /// An unknown data classification rank returns a corruption error.
    #[test]
    fn an_unknown_rank_is_refused() {
        assert!(matches!(
            into_level(Some(9)),
            Err(DomainError::Infrastructure(_))
        ));
    }
}
