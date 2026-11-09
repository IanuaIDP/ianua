//! Operator bodies: operator accounts, an operator's keys and their
//! impersonation grants, and the jobs the platform gave up on.

use ianua_app::email::LinkScope;
use ianua_app::error::AppError;
use ianua_app::listing::{PageRequest, SortOrder};
use ianua_app::ports::operator::{OperatorFilter, OperatorSortField};
use ianua_app::use_cases::operator::accounts::{
    ChangeOperatorEmailRequest, CreateOperatorRequest, ListOperatorsRequest,
};
use ianua_app::use_cases::operator::keys::{OperatorKeyCreated, OperatorSignInRequest};
use ianua_app::use_cases::scheduling::DeadJob;
use ianua_domain::domains::authentication::credentials::password::PasswordHasher;
use ianua_domain::domains::operator::identity::Operator;
use ianua_domain::domains::operator::impersonation::ImpersonationTerms;
use ianua_domain::domains::operator::status::OperatorStatus;
use ianua_domain::shared::config::SlugLimits;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    Email, Expiry, Fact, ImpersonationGrantId, OperatorId, TenantId, TenantSlug, Text, UserId,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;
use crate::extractors::callers::RequestMeta;

/// A new operator's account. Holds a password, so it has no `Debug`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateOperatorBody {
    /// The address the operator signs in with.
    pub email: String,
    /// The initial credential to hash before saving the operator account.
    #[schema(format = Password)]
    pub password: String,
}

impl CreateOperatorBody {
    /// The account to create, its password hashed by `hasher`.
    ///
    /// # Errors
    ///
    /// `422` for an invalid address or a password the hasher refuses.
    pub(crate) fn request(
        self,
        hasher: &dyn PasswordHasher,
    ) -> Result<CreateOperatorRequest, ApiError> {
        let email = Email::new(&self.email).map_err(ApiError::validation)?;
        let password_hash = hasher.hash(&self.password).map_err(AppError::from_domain)?;
        Ok(CreateOperatorRequest {
            email,
            password_hash,
        })
    }
}

/// The operator just created.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreateOperatorResponse {
    /// The new operator's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: OperatorId,
}

/// The impersonation grant just made.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct GrantImpersonationResponse {
    /// The grant's id, named in the `ianua-operator-impersonation` header
    /// of every request made as the user.
    #[schema(value_type = String, format = Uuid)]
    pub id: ImpersonationGrantId,
}

/// A platform operator.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OperatorResponse {
    /// Unique identifier.
    #[schema(value_type = String, format = Uuid)]
    pub id: OperatorId,
    /// The address the operator signs in with.
    pub email: String,
    /// `Active` or `Disabled`.
    #[schema(schema_with = crate::dto::schemas::operator_status)]
    pub status: OperatorStatus,
    /// When the operator was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<Operator> for OperatorResponse {
    fn from(operator: Operator) -> Self {
        Self {
            id: *operator.id(),
            email: operator.email().as_str().to_owned(),
            status: operator.status(),
            created_at: operator.created_at(),
        }
    }
}

/// Query parameters for filtering an operator listing.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct OperatorFilterParams {
    /// Filter by account status (`Active` or `Disabled`). Omit to return
    /// operators of every status.
    #[param(value_type = Option<String>)]
    pub status: Option<OperatorStatus>,
}

impl OperatorFilterParams {
    /// The listing asked for: these operators, in `sort` order, the page
    /// `pagination` names.
    #[must_use]
    pub(crate) fn listing(
        self,
        sort: SortOrder<OperatorSortField>,
        pagination: PageRequest,
    ) -> ListOperatorsRequest {
        ListOperatorsRequest {
            filter: OperatorFilter {
                status: self.status,
            },
            sort,
            page: pagination,
        }
    }
}

/// Another operator's new address.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeOperatorEmailBody {
    /// The address asked for.
    pub new_email: String,
    /// The organization whose dashboard pages the mailed links open. The
    /// links' tokens alone name the change.
    pub org_slug: String,
}

impl ChangeOperatorEmailBody {
    /// The change of `operator`'s address this body asks for.
    ///
    /// # Errors
    ///
    /// `422` for an invalid address or slug.
    pub(crate) fn request(
        self,
        operator: OperatorId,
    ) -> Result<ChangeOperatorEmailRequest, ApiError> {
        let new_email = Email::new(&self.new_email).map_err(ApiError::validation)?;
        let org = TenantSlug::new(&self.org_slug, &SlugLimits::default())
            .map_err(ApiError::validation)?;
        Ok(ChangeOperatorEmailRequest {
            operator,
            new_email,
            scope: LinkScope::organization(org),
        })
    }
}

/// When a new operator key stops working.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateOperatorKeyBody {
    /// The instant (RFC 3339) the key stops working. Omit it, or send no
    /// body, for a key that never ends.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

impl CreateOperatorKeyBody {
    /// When the key asked for by `body` ends: never, when no body or no
    /// instant was sent.
    #[must_use]
    pub(crate) fn expiry(body: Option<Self>) -> Expiry {
        match body.and_then(|body| body.expires_at) {
            Some(at) => Expiry::At(at),
            None => Expiry::Never,
        }
    }
}

/// An operator signing in with their password for a short-lived key.
/// Holds the password, so it has no `Debug`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OperatorSignInBody {
    /// The address the operator signs in with.
    pub email: String,
    /// The credential checked before issuing a short-lived operator key.
    #[schema(format = Password)]
    pub password: String,
}

impl OperatorSignInBody {
    /// The sign-in this body asks for, made from where `meta` says the
    /// request came from.
    ///
    /// # Errors
    ///
    /// `422` when the address is malformed.
    pub(crate) fn into_request(self, meta: RequestMeta) -> Result<OperatorSignInRequest, ApiError> {
        Ok(OperatorSignInRequest {
            email: Email::new(&self.email).map_err(ApiError::validation)?,
            password: Secret::new(self.password),
            ip_address: Fact::from_option(meta.ip_address),
        })
    }
}

/// A key just made, shown once.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreateOperatorKeyResponse {
    /// The raw API key: shown once, never again.
    pub raw_key: String,
    /// The key prefix for identification and revocation.
    pub key_prefix: String,
}

impl From<OperatorKeyCreated> for CreateOperatorKeyResponse {
    fn from(created: OperatorKeyCreated) -> Self {
        Self {
            raw_key: created.raw_key.expose().to_owned(),
            key_prefix: created.key_prefix.as_str().to_owned(),
        }
    }
}

/// How many keys a revoke-all ended.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RevokeAllKeysResponse {
    /// Number of keys revoked.
    pub revoked: u64,
}

/// A job that used up its tries, as an operator reads it. Its payload is
/// left out: only its handler reads it, and it may name what only its
/// tenant should see.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DeadJobResponse {
    /// The job's id.
    pub id: Uuid,
    /// What kind of work it was, such as `mail.deliver`.
    pub job_type: String,
    /// The tenant it worked for, or `null` for the platform's own work.
    pub tenant_id: Option<Uuid>,
    /// How many times it ran.
    pub attempts: u32,
    /// Why its last run failed, as its handler reported it.
    pub reason: String,
    /// When it was queued.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last ran.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_attempted_at: Option<OffsetDateTime>,
}

impl From<DeadJob> for DeadJobResponse {
    fn from(job: DeadJob) -> Self {
        Self {
            id: *job.id.as_uuid(),
            job_type: job.job_type.as_str().to_owned(),
            tenant_id: job.tenant_id.map(|tenant| *tenant.as_uuid()),
            attempts: job.attempts,
            reason: job.reason,
            created_at: job.created_at,
            last_attempted_at: job.last_attempted_at,
        }
    }
}

/// The user an operator asks to act as, and why.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct GrantImpersonationBody {
    /// The tenant the user belongs to.
    pub tenant_id: String,
    /// The user to act as.
    pub user_id: String,
    /// Why, kept in the audit trail.
    pub reason: String,
    /// When the grant ends (RFC 3339), at most 24 hours ahead.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

impl TryFrom<GrantImpersonationBody> for ImpersonationTerms {
    type Error = ApiError;

    fn try_from(body: GrantImpersonationBody) -> Result<Self, Self::Error> {
        let tenant_id = Uuid::parse_str(&body.tenant_id).map_err(ApiError::rejected)?;
        let user_id = Uuid::parse_str(&body.user_id).map_err(ApiError::rejected)?;
        Ok(Self {
            tenant_id: TenantId::from_uuid(tenant_id),
            user_id: UserId::from_uuid(user_id),
            reason: Text::new("reason", body.reason).map_err(ApiError::validation)?,
            expires_at: body.expires_at,
        })
    }
}
