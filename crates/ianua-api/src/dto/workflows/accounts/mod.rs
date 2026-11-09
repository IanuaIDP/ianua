//! Integration accounts on the wire. A credential is taken in and never
//! given back. Connecting one by signing in at its service is in
//! [`connections`], and setting up an account's one address for a service's
//! events is in [`channels`].

pub mod channels;
pub mod connections;

use ianua_app::use_cases::workflows::accounts::{AccountChange, ChangeRequest, ConnectRequest};
use ianua_domain::domains::workflows::account::{
    AccountSharing, AccountStatus, IntegrationAccount, OperationScope, ScopedOperations,
};
use ianua_domain::domains::workflows::integration::{IntegrationKey, OperationKey};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{IntegrationAccountId, Label};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::workflows::data::person_label;
use crate::error::ApiError;

/// Who may have workflows act through an account.
#[derive(Serialize, Deserialize, utoipa::ToSchema, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SharingBody {
    /// Only its owner's workflows.
    #[default]
    OwnerOnly,
    /// Workflows run for anyone in the tenant.
    Tenant,
}

/// One integration account of the tenant.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AccountResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// The integration it is for, such as `google-sheets`.
    pub integration: String,
    /// Its name for people.
    pub name: String,
    /// Who connected it, as `<kind>:<uuid>`.
    pub owner: String,
    /// Who may have workflows act through it.
    pub sharing: SharingBody,
    /// The operations it may be used for; `null` for every one.
    pub operations: Option<Vec<String>>,
    /// `active` or `disabled`.
    pub status: String,
    /// When it was connected.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<IntegrationAccount<ResolvedTenant>> for AccountResponse {
    fn from(account: IntegrationAccount<ResolvedTenant>) -> Self {
        Self {
            id: *account.id().as_uuid(),
            integration: account.integration().as_str().to_owned(),
            name: account.name().as_str().to_owned(),
            owner: person_label(account.owner()),
            sharing: account.sharing().into(),
            operations: match account.scope() {
                OperationScope::All => None,
                OperationScope::Only(scoped) => Some(
                    scoped
                        .operations()
                        .iter()
                        .map(|operation| operation.as_str().to_owned())
                        .collect(),
                ),
            },
            status: match account.status() {
                AccountStatus::Active => "active",
                AccountStatus::Disabled => "disabled",
            }
            .to_owned(),
            created_at: Aggregate::created_at(&account),
            updated_at: Aggregate::updated_at(&account),
        }
    }
}

impl From<AccountSharing> for SharingBody {
    fn from(sharing: AccountSharing) -> Self {
        match sharing {
            AccountSharing::OwnerOnly => Self::OwnerOnly,
            AccountSharing::Tenant => Self::Tenant,
        }
    }
}

impl From<SharingBody> for AccountSharing {
    fn from(body: SharingBody) -> Self {
        match body {
            SharingBody::OwnerOnly => Self::OwnerOnly,
            SharingBody::Tenant => Self::Tenant,
        }
    }
}

/// Request body for connecting an account.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ConnectAccountBody {
    /// The integration it is for, such as `google-sheets`.
    pub integration: String,
    /// Its name for people.
    pub name: String,
    /// The credential the integration takes, in the clear. It is sealed
    /// before it is kept and never shown again.
    pub credential: String,
    /// Who may have workflows act through it; `owner_only` when left out.
    #[serde(default)]
    pub sharing: SharingBody,
    /// The operations it may be used for; every one when left out.
    #[serde(default)]
    pub operations: Option<Vec<String>>,
}

impl TryFrom<ConnectAccountBody> for ConnectRequest {
    type Error = ApiError;

    fn try_from(body: ConnectAccountBody) -> Result<Self, ApiError> {
        Ok(Self {
            integration: IntegrationKey::new(body.integration).map_err(ApiError::validation)?,
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            credential: Secret::new(body.credential),
            sharing: body.sharing.into(),
            scope: operation_scope(body.operations)?,
        })
    }
}

/// One change to an account, named by `change`.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(tag = "change", rename_all = "snake_case")]
pub(crate) enum ChangeAccountBody {
    /// Lets it be used again.
    Enable,
    /// Stops it being used.
    Disable,
    /// Supplies a new secret for subsequent calls through this account.
    ReplaceCredential {
        /// The new credential, in the clear. It is sealed before it is
        /// kept.
        credential: String,
    },
    /// Lets workflows run for anyone in the tenant act through it.
    ShareWithTenant,
    /// Keeps it to its owner's workflows.
    KeepToOwner,
    /// Changes which operations it may be used for.
    LimitTo {
        /// The operations; `null` for every one.
        operations: Option<Vec<String>>,
    },
    /// Changes the label people see when selecting this account.
    Rename {
        /// The new name.
        name: String,
    },
}

impl ChangeAccountBody {
    /// The change to make to `account_id`.
    ///
    /// # Errors
    ///
    /// - `422` when a value in the body is not valid.
    pub(crate) fn request(
        self,
        account_id: IntegrationAccountId,
    ) -> Result<ChangeRequest, ApiError> {
        let change = match self {
            Self::Enable => AccountChange::Enable,
            Self::Disable => AccountChange::Disable,
            Self::ReplaceCredential { credential } => {
                AccountChange::ReplaceCredential(Secret::new(credential))
            }
            Self::ShareWithTenant => AccountChange::ShareWithTenant,
            Self::KeepToOwner => AccountChange::KeepToOwner,
            Self::LimitTo { operations } => AccountChange::LimitTo(operation_scope(operations)?),
            Self::Rename { name } => {
                AccountChange::Rename(Label::new("name", name).map_err(ApiError::validation)?)
            }
        };
        Ok(ChangeRequest { account_id, change })
    }
}

/// The operations an account is limited to: all of them when none are
/// named, otherwise only those.
pub(crate) fn operation_scope(operations: Option<Vec<String>>) -> Result<OperationScope, ApiError> {
    let Some(operations) = operations else {
        return Ok(OperationScope::All);
    };
    let operations = operations
        .into_iter()
        .map(|operation| OperationKey::new(operation).map_err(ApiError::validation))
        .collect::<Result<Vec<_>, _>>()?;
    ScopedOperations::new(operations)
        .map(OperationScope::Only)
        .map_err(ApiError::validation)
}
