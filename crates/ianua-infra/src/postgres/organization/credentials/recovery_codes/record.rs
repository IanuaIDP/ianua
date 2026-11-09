//! A member's recovery codes as their rows hold them: the set's row and one
//! row per code, read back into the set, and written out from it.

use ianua_domain::domains::authentication::recovery::codes::{
    RecoveryCode, RecoveryCodeRow, RecoveryCodeSet, RecoveryCodeSetRow,
};
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgUserId, PrincipalId, TokenHash, Usage};
use time::OffsetDateTime;
use uuid::Uuid;

/// A set of codes as its own row is read.
pub(super) struct SetRecord {
    pub(super) org_user_id: Uuid,
    pub(super) generated_at: OffsetDateTime,
}

/// One code of a set as it is read.
pub(super) struct CodeRecord {
    pub(super) code_hash: String,
    pub(super) used_at: Option<OffsetDateTime>,
}

impl SetRecord {
    /// The set the record and its `codes` hold, rebuilt through the
    /// domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the rows break a rule the
    /// set keeps, such as a set with no codes.
    pub(super) fn into_code_set(
        self,
        codes: Vec<CodeRecord>,
    ) -> Result<RecoveryCodeSet<ResolvedOrganization>, DomainError> {
        let codes = codes
            .into_iter()
            .map(|code| {
                RecoveryCode::reconstitute(RecoveryCodeRow {
                    hash: TokenHash::from_stored(code.code_hash),
                    usage: Usage::from_stored(code.used_at),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        RecoveryCodeSet::reconstitute(RecoveryCodeSetRow {
            subject_id: PrincipalId::from(OrgUserId::from_uuid(self.org_user_id)),
            codes,
            generated_at: self.generated_at,
        })
    }
}

/// A set of codes as the columns it is written to: the set's row, and one
/// list per column of its codes.
pub(super) struct SetColumns<'a> {
    pub(super) org_user_id: &'a Uuid,
    pub(super) generated_at: OffsetDateTime,
    pub(super) code_hashes: Vec<String>,
    pub(super) used_at: Vec<Option<OffsetDateTime>>,
}

impl<'a> SetColumns<'a> {
    /// The columns `codes` is written to, as `org_user_id`'s.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when the set is another person's:
    /// it would be written where it does not belong.
    pub(super) fn of(
        org_user_id: &'a OrgUserId,
        codes: &RecoveryCodeSet<ResolvedOrganization>,
    ) -> Result<Self, DomainError> {
        ensure_owned_by(org_user_id, codes)?;
        Ok(Self {
            org_user_id: org_user_id.as_uuid(),
            generated_at: codes.generated_at(),
            code_hashes: codes
                .codes()
                .iter()
                .map(|code| code.hash().as_str().to_owned())
                .collect(),
            used_at: codes.codes().iter().map(RecoveryCode::used_at).collect(),
        })
    }
}

/// When the code with `hash` in `codes`, `org_user_id`'s set, was just
/// spent.
///
/// # Errors
///
/// Returns `DomainError::Validation` when the set is another person's, or
/// holds no spent code with that digest: there is nothing to record.
pub(super) fn spent_at(
    org_user_id: &OrgUserId,
    codes: &RecoveryCodeSet<ResolvedOrganization>,
    hash: &TokenHash,
) -> Result<OffsetDateTime, DomainError> {
    ensure_owned_by(org_user_id, codes)?;
    codes
        .codes()
        .iter()
        .find(|code| code.hash() == hash)
        .and_then(RecoveryCode::used_at)
        .ok_or_else(|| {
            DomainError::invalid(message!(
                "infra-the-code-to-record-is-not",
                "the code to record is not spent in this set"
            ))
        })
}

fn ensure_owned_by(
    org_user_id: &OrgUserId,
    codes: &RecoveryCodeSet<ResolvedOrganization>,
) -> Result<(), DomainError> {
    if codes.subject_id() != PrincipalId::from(*org_user_id) {
        return Err(DomainError::invalid(message!(
            "infra-recovery-codes-are-saved-for-the",
            "recovery codes are saved for the member they belong to"
        )));
    }
    Ok(())
}
