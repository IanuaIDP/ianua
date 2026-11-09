//! How far a tenant's audit chain is known to hold.
//!
//! Each verified link is one record's sequence number and the hash it was
//! written with. The last one a walk verified is its checkpoint: the next
//! walk starts after it, taking that hash as the link before the first
//! record it reads, so a record is rehashed once, not on every sweep.

use crate::shared::errors::DomainError;

/// The length of a link's hash, a SHA-256 digest.
const HASH_LEN: usize = 32;

/// The hash one audit record was chained with.
#[derive(Clone, PartialEq, Eq)]
pub struct ChainHash([u8; HASH_LEN]);

impl ChainHash {
    /// Reads a stored hash back.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when it is not 32 bytes long.
    pub fn from_stored(bytes: &[u8]) -> Result<Self, DomainError> {
        let hash = <[u8; HASH_LEN]>::try_from(bytes).map_err(|_| {
            DomainError::infra_msg(format!(
                "a stored audit chain hash is {} bytes, not {HASH_LEN}",
                bytes.len()
            ))
        })?;
        Ok(Self(hash))
    }

    /// The hash's bytes, as storage keeps them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for ChainHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChainHash({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

/// The last link a walk verified: a record's sequence number and its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainCheckpoint {
    seq: i64,
    hash: ChainHash,
}

impl ChainCheckpoint {
    /// Reads a stored checkpoint back, or builds one from the link an
    /// adapter just verified.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when `seq` is below 1; the first
    ///   record of a chain is record 1.
    pub fn from_stored(seq: i64, hash: ChainHash) -> Result<Self, DomainError> {
        if seq < 1 {
            return Err(DomainError::infra_msg(format!(
                "an audit chain checkpoint at record {seq}, before the first record"
            )));
        }
        Ok(Self { seq, hash })
    }

    /// The sequence number of the last verified record.
    #[must_use]
    pub fn seq(&self) -> i64 {
        self.seq
    }

    /// The hash that record was chained with.
    #[must_use]
    pub fn hash(&self) -> &ChainHash {
        &self.hash
    }
}

/// Where a walk of the chain begins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStart {
    /// At the first record, after the genesis link, or the anchor a purge
    /// left.
    Genesis,
    /// After a link an earlier walk verified.
    After(ChainCheckpoint),
}

impl ChainStart {
    /// The sequence number of the last record known to hold, if any is.
    #[must_use]
    pub fn verified_through(&self) -> Option<i64> {
        match self {
            Self::Genesis => None,
            Self::After(checkpoint) => Some(checkpoint.seq()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A digest of 32 bytes reads back as the same bytes. One of 31, cut
    /// short in storage, is refused.
    #[test]
    fn a_hash_is_thirty_two_bytes() {
        let hash = ChainHash::from_stored(&[7; 32]).unwrap();

        assert_eq!(hash.as_bytes(), &[7; 32]);
        assert!(matches!(
            ChainHash::from_stored(&[7; 31]),
            Err(DomainError::Infrastructure(_))
        ));
    }

    /// A checkpoint at record 0 would sit before the chain's first record.
    /// It is refused; one at record 1 is kept.
    #[test]
    fn a_checkpoint_names_a_record_of_the_chain() {
        let hash = ChainHash::from_stored(&[1; 32]).unwrap();

        assert!(ChainCheckpoint::from_stored(0, hash.clone()).is_err());
        assert_eq!(ChainCheckpoint::from_stored(1, hash).unwrap().seq(), 1);
    }

    /// A walk from the start has verified nothing yet. One after record 40
    /// has verified through 40.
    #[test]
    fn a_start_says_how_far_the_chain_is_verified() {
        let after = ChainCheckpoint::from_stored(40, ChainHash::from_stored(&[2; 32]).unwrap());

        assert_eq!(ChainStart::Genesis.verified_through(), None);
        assert_eq!(
            ChainStart::After(after.unwrap()).verified_through(),
            Some(40)
        );
    }
}
