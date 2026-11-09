//! A tenant's clearance rules as their row holds them: read back into the
//! aggregate, and written out from it.
//!
//! Entry n of the permissions and of the levels is one rule.

use ianua_domain::domains::authorization::clearance::{ClearanceRules, ClearanceRulesRow};
use ianua_domain::domains::authorization::permission::CustomPermission;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use time::OffsetDateTime;

use crate::postgres::foundation::stored::Stored;

const CLEARANCE: Stored = Stored("clearance rules");

/// The levels a rule may clear for, the only ones a row may hold.
const CLEARABLE: [DataClassLevel; 2] = [DataClassLevel::Confidential, DataClassLevel::Restricted];

/// The rules as they are read. The store's checked queries fill it.
pub(super) struct ClearanceRecord {
    pub(super) permissions: Vec<String>,
    pub(super) levels: Vec<String>,
    pub(super) updated_at: OffsetDateTime,
}

impl ClearanceRecord {
    /// The rules the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the two lists differ in
    /// length, an entry does not read, or the rules break one the domain
    /// keeps.
    pub(super) fn into_rules(self) -> Result<ClearanceRules<ResolvedTenant>, DomainError> {
        if self.permissions.len() != self.levels.len() {
            return Err(DomainError::corrupt_row(
                CLEARANCE.0,
                "a permission without its level",
            ));
        }
        let rules = self
            .permissions
            .iter()
            .zip(&self.levels)
            .map(|(permission, level)| rule_from(permission, level))
            .collect::<Result<Vec<_>, _>>()?;
        ClearanceRules::reconstitute(ClearanceRulesRow {
            rules,
            updated_at: self.updated_at,
        })
    }
}

/// One rule as its two entries hold it.
fn rule_from(
    permission: &str,
    level: &str,
) -> Result<(CustomPermission, DataClassLevel), DomainError> {
    let permission = CustomPermission::parse(permission)
        .ok_or_else(|| DomainError::corrupt_row(CLEARANCE.0, "an unknown permission"))?;
    let level = CLEARABLE
        .into_iter()
        .find(|clearable| clearable.as_str() == level)
        .ok_or_else(|| DomainError::corrupt_row(CLEARANCE.0, "an unknown level"))?;
    Ok((permission, level))
}

/// The rules' columns, as they are written.
pub(super) struct ClearanceColumns {
    pub(super) permissions: Vec<String>,
    pub(super) levels: Vec<String>,
    pub(super) updated_at: OffsetDateTime,
}

impl ClearanceColumns {
    /// The columns `rules` are written to.
    pub(super) fn of(rules: &ClearanceRules<ResolvedTenant>) -> Self {
        let (permissions, levels) = rules
            .rules()
            .iter()
            .map(|rule| {
                (
                    rule.permission().to_string(),
                    rule.up_to().as_str().to_owned(),
                )
            })
            .unzip();
        Self {
            permissions,
            levels,
            updated_at: rules.updated_at(),
        }
    }
}
