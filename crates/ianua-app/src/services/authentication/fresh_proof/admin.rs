//! Proving again whoever changes how a tenant is protected, its audit
//! streams or its mail: a user of the tenant signed in to it, or a member of
//! its organization signed in to the organization.

use ianua_domain::domains::authentication::sessions::fresh_sign_in::FreshSignIn;
use ianua_domain::domains::tenant::access::sign_in_gate::SavedFrom;
use ianua_domain::message;

use crate::acting::TenantAuthorities;
use crate::acting::tenant::SignedInAccount;
use crate::context::{CallerContext, CallerIdentity, Credential};
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgUserStore, OrganizationStore};
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof};

/// Where the person changing a tenant's protection is proved from.
#[derive(Clone, Copy)]
pub(crate) struct AdminProofSources<'a> {
    /// Who is signed in to a tenant session.
    pub(crate) authorities: &'a dyn TenantAuthorities,
    /// Turns what the person typed again into a fresh proof of them.
    pub(crate) proofs: &'a dyn FreshProofs,
    /// Organization members, for a member acting in the tenant.
    pub(crate) members: &'a dyn OrgUserStore,
    /// Organizations, for a member's lockout settings.
    pub(crate) organizations: &'a dyn OrganizationStore,
}

/// The person changing a tenant's protection, proved again just now.
pub(crate) enum ProvedAdmin {
    /// A user of the tenant, signed in to it.
    TenantUser {
        /// The user and their session.
        person: Box<SignedInAccount>,
        /// The fresh proof of them.
        fresh: FreshSignIn,
    },
    /// A member of the tenant's organization, signed in to the
    /// organization.
    Member {
        /// The fresh proof of them.
        fresh: FreshSignIn,
    },
}

impl ProvedAdmin {
    /// The fresh proof of the person.
    pub(crate) fn fresh(&self) -> &FreshSignIn {
        match self {
            Self::TenantUser { fresh, .. } | Self::Member { fresh } => fresh,
        }
    }

    /// Where the change is saved from, so the tenant's new settings never
    /// shut out the sign-in making it.
    pub(crate) fn saved_from(&self) -> SavedFrom<'_> {
        match self {
            Self::TenantUser { person, .. } => SavedFrom::from_session(&person.session),
            Self::Member { .. } => SavedFrom::Organization,
        }
    }
}

/// The person `caller` came as, proved again by `proof`.
///
/// The caller's authority in the tenant is resolved first, by the use case:
/// this step proves only who they are.
///
/// # Errors
///
/// - `AppError::Forbidden` when the caller came with a key, a directory
///   bind or an impersonation rather than a signed-in session, or the
///   proof is refused.
/// - `AppError::Unauthenticated` when the session, the member or their
///   organization no longer exists or counts.
/// - The errors of [`FreshProofs::prove`] and [`FreshProofs::prove_member`].
pub(crate) async fn proved_admin(
    sources: AdminProofSources<'_>,
    caller: &CallerContext,
    proof: ReenteredProof,
) -> Result<ProvedAdmin, AppError> {
    match caller.credential() {
        Credential::TenantSession(_) => proved_tenant_user(sources, caller, proof).await,
        Credential::OrgSession(_) => proved_member(sources, caller, proof).await,
        Credential::TenantApiKey(_)
        | Credential::DirectoryBind(_)
        | Credential::OrgApiKey(_)
        | Credential::OperatorKey(_)
        | Credential::Impersonation { .. }
        | Credential::SupportImpersonation { .. }
        | Credential::WorkflowRun(_) => Err(AppError::Forbidden(message!(
            "tenant-this-changes-only-from-a-signed",
            "this changes only from a signed-in session"
        ))),
    }
}

async fn proved_tenant_user(
    sources: AdminProofSources<'_>,
    caller: &CallerContext,
    proof: ReenteredProof,
) -> Result<ProvedAdmin, AppError> {
    let person = sources.authorities.signed_in(caller).await?;
    let fresh = sources
        .proofs
        .prove(&caller.tenant(), &person.account, proof, caller.origin())
        .await?;
    Ok(ProvedAdmin::TenantUser {
        person: Box::new(person),
        fresh,
    })
}

async fn proved_member(
    sources: AdminProofSources<'_>,
    caller: &CallerContext,
    proof: ReenteredProof,
) -> Result<ProvedAdmin, AppError> {
    let CallerIdentity::OrgUser(member_id) = caller.identity() else {
        return Err(AppError::Unauthenticated);
    };
    let member = sources
        .members
        .find_by_id_in_org(&caller.organization_id(), member_id)
        .await
        .or_internal()?
        .ok_or(AppError::Unauthenticated)?;
    let organization = sources
        .organizations
        .find_by_id(&caller.organization_id())
        .await
        .or_internal()?
        .ok_or(AppError::Unauthenticated)?;
    let fresh = sources
        .proofs
        .prove_member(&member, &organization, proof, caller.origin())
        .await?;
    Ok(ProvedAdmin::Member { fresh })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
    use ianua_domain::types::{ApiKeyId, ImpersonationGrantId, KeyPrefix, OperatorId, UserId};

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::authentication::{FakeFreshProofs, directory_bound, right_password};
    use crate::test_support::identity::stored_user;
    use crate::test_support::{Fake, block_on, test_ctx};

    /// A caller of the test tenant who came as `identity` with `credential`.
    fn came_with(identity: CallerIdentity, credential: Credential) -> CallerContext {
        CallerContext::new(
            identity,
            credential,
            test_ctx().organization_id(),
            test_ctx().tenant_id(),
            OrganizationPlan::Free.default_limits(),
        )
        .unwrap()
    }

    /// What proving `caller` again with the right password comes to, where
    /// every caller holds every right in the tenant.
    fn proving(caller: &CallerContext) -> Result<ProvedAdmin, AppError> {
        let authorities = FakeTenantAuthorities::holding_everything();
        let members: Arc<dyn OrgUserStore> = Fake::fake();
        let organizations: Arc<dyn OrganizationStore> = Fake::fake();
        let sources = AdminProofSources {
            authorities: &authorities,
            proofs: &FakeFreshProofs,
            members: members.as_ref(),
            organizations: organizations.as_ref(),
        };
        block_on(proved_admin(sources, caller, right_password()))
    }

    /// Ann, signed in to the tenant, types her password again. She is
    /// proved, as the user she is.
    #[test]
    fn a_signed_in_user_is_proved() {
        let proved = proving(&test_ctx()).unwrap();

        assert!(matches!(proved, ProvedAdmin::TenantUser { .. }));
    }

    /// A tenant API key cannot obtain admin proof even when the proof
    /// fixture would accept the password and grant every permission.
    #[test]
    fn an_api_key_cannot_change_how_the_tenant_is_protected() {
        let mallory = came_with(
            CallerIdentity::TenantUser(UserId::new()),
            Credential::TenantApiKey(ApiKeyId::new()),
        );

        let result = proving(&mallory);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A directory-bound caller is forbidden from obtaining admin proof
    /// through the session-only path.
    #[test]
    fn a_directory_bind_cannot_change_how_the_tenant_is_protected() {
        let ann = stored_user(UserId::new(), "ann@acme.test", UserStatus::Active);
        let mallory = came_with(
            CallerIdentity::TenantUser(*ann.id()),
            Credential::DirectoryBind(directory_bound(&ann)),
        );

        let result = proving(&mallory);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Operator impersonation cannot provide admin proof of the tenant
    /// user; the credential is refused as forbidden.
    #[test]
    fn an_impersonation_cannot_change_how_the_tenant_is_protected() {
        let mallory = came_with(
            CallerIdentity::Operator(OperatorId::new()),
            Credential::Impersonation {
                key: KeyPrefix::new("opk_mallory").unwrap(),
                grant: ImpersonationGrantId::new(),
                user: UserId::new(),
            },
        );

        let result = proving(&mallory);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
