//! A chain verdict as its row holds it: read back into the domain's
//! verdict once its seal holds, and written out from it with the bytes its
//! seal is made over.

use ianua_domain::domains::audit::checkpoint::{ChainCheckpoint, ChainHash, ChainStart};
use ianua_domain::domains::audit::verdict::{ChainVerdict, ChainVerdictRow};
use ianua_domain::domains::audit::walk::ChainStanding;
use ianua_domain::shared::errors::DomainError;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::AuditChainSeals;
use crate::postgres::foundation::audit_chain::verdict_holds;

const VERDICT: &str = "audit chain verdict";

/// A verdict as it is read.
pub(super) struct VerdictRecord {
    pub(super) verified_at: OffsetDateTime,
    pub(super) standing: String,
    pub(super) broken_at_seq: Option<i64>,
    pub(super) checkpoint_seq: Option<i64>,
    pub(super) checkpoint_hash: Option<Vec<u8>>,
    pub(super) seal: Vec<u8>,
}

impl VerdictRecord {
    /// The verdict the record holds for `tenant_id`, rebuilt through the
    /// domain's checks, once its seal holds under `heads`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the seal is not one the
    /// platform made for this tenant and these columns, the standing is
    /// unknown or names no break, the checkpoint does not read, or the row
    /// breaks a rule the verdict keeps.
    pub(super) fn into_sealed_verdict(
        mut self,
        tenant_id: Uuid,
        heads: &AuditChainSeals,
    ) -> Result<ChainVerdict, DomainError> {
        let seal = std::mem::take(&mut self.seal);
        let verdict = self.into_verdict()?;
        let over = VerdictColumns::of(&verdict).sealed_over();
        if !verdict_holds(heads, tenant_id, &[&over], &seal) {
            return Err(DomainError::corrupt_row(
                VERDICT,
                "a seal the platform did not make",
            ));
        }
        Ok(verdict)
    }

    fn into_verdict(self) -> Result<ChainVerdict, DomainError> {
        let standing = standing_of(&self.standing, self.broken_at_seq)?;
        let checkpoint = match (self.checkpoint_seq, self.checkpoint_hash) {
            (Some(seq), Some(hash)) => ChainStart::After(ChainCheckpoint::from_stored(
                seq,
                ChainHash::from_stored(&hash)?,
            )?),
            (None, None) => ChainStart::Genesis,
            _ => return Err(DomainError::corrupt_row(VERDICT, "half a checkpoint")),
        };
        ChainVerdict::reconstitute(ChainVerdictRow {
            verified_at: self.verified_at,
            standing,
            checkpoint,
        })
    }
}

/// The standing `word` and `broken_at` keep.
fn standing_of(word: &str, broken_at: Option<i64>) -> Result<ChainStanding, DomainError> {
    match (word, broken_at) {
        ("intact", None) => Ok(ChainStanding::Intact),
        ("intact_so_far", None) => Ok(ChainStanding::IntactSoFar),
        ("broken", Some(seq)) => Ok(ChainStanding::BrokenAt(seq)),
        _ => Err(DomainError::corrupt_row(VERDICT, "an unknown standing")),
    }
}

/// A verdict's columns, as they are written.
pub(super) struct VerdictColumns {
    pub(super) verified_at: OffsetDateTime,
    pub(super) standing: &'static str,
    pub(super) broken_at_seq: Option<i64>,
    pub(super) checkpoint_seq: Option<i64>,
    pub(super) checkpoint_hash: Option<Vec<u8>>,
}

impl VerdictColumns {
    /// The columns `verdict` is written to.
    pub(super) fn of(verdict: &ChainVerdict) -> Self {
        let standing = verdict.standing();
        let broken_at_seq = match standing {
            ChainStanding::BrokenAt(seq) => Some(seq),
            ChainStanding::Intact | ChainStanding::IntactSoFar => None,
        };
        let (checkpoint_seq, checkpoint_hash) = match verdict.checkpoint() {
            ChainStart::Genesis => (None, None),
            ChainStart::After(link) => (Some(link.seq()), Some(link.hash().as_bytes().to_vec())),
        };
        Self {
            verified_at: verdict.verified_at(),
            standing: standing.as_str(),
            broken_at_seq,
            checkpoint_seq,
            checkpoint_hash,
        }
    }

    /// The bytes the verdict's seal is made over: every column, each at a
    /// fixed width or ended, so no two verdicts write out the same. The
    /// time is taken to the microsecond the database keeps.
    pub(super) fn sealed_over(&self) -> Vec<u8> {
        let micros = self.verified_at.unix_timestamp_nanos().div_euclid(1_000);
        micros
            .to_be_bytes()
            .into_iter()
            .chain(self.standing.bytes())
            .chain(std::iter::once(0))
            .chain(optional(self.broken_at_seq))
            .chain(optional(self.checkpoint_seq))
            .chain(self.checkpoint_hash.iter().flatten().copied())
            .collect()
    }
}

/// `seq` written out at a fixed width, after a byte saying whether it is
/// there.
fn optional(seq: Option<i64>) -> Vec<u8> {
    match seq {
        Some(seq) => std::iter::once(1).chain(seq.to_be_bytes()).collect(),
        None => vec![0],
    }
}
