//! Who is acting, worked out from the stored records for the caller's
//! credential, as the proofs the domain asks for.
//!
//! A use case never builds a proof from what the request says. It asks one
//! of the traits here, which in production are answered by the resolvers in
//! [`tenant`], [`organization`], [`operator`], [`agent`], [`consumer`],
//! [`scim`] and [`directory`]: they load the session, key, bind, token or
//! credential the caller came with, run the domain's own checks on it, and
//! hand back what the domain made of it. A test answers them with what the
//! test says someone holds.

pub mod agent;
pub mod consumer;
pub mod directory;
pub mod operator;
pub mod organization;
pub mod scim;
pub mod tenant;

use async_trait::async_trait;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::consumers::authority::ConsumerAuthority;
use ianua_domain::domains::federation::scim::ScimEndpoint;
use ianua_domain::domains::operator::control::{OperatorAuthority, OperatorSignIn};
use ianua_domain::domains::operator::identity::Operator;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{Audience, SessionId};

use crate::acting::agent::{SignInAttempt, SignedInAgent};
use crate::acting::organization::OrgActor;
use crate::acting::tenant::{AccountHolder, SignedInAccount};
use crate::context::{
    AgentAssertion, CallerContext, ConsumerCaller, OperatorCaller, OrgCaller, ScimCaller,
};
use crate::error::AppError;
use crate::tenancy::ScopedTenant;

/// What a caller holds inside the tenant they act in.
#[async_trait]
pub trait TenantAuthorities: Send + Sync {
    /// What `caller` holds in their tenant now.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session or key the caller came
    ///   with no longer exists, or no longer counts.
    /// - `AppError::Forbidden` when the credential cannot act inside a
    ///   tenant (an organization key, or an operator without a grant), or the
    ///   domain refuses it.
    /// - `AppError::Internal` when a store fails or a record is broken.
    async fn authority(&self, caller: &CallerContext) -> Result<TenantAuthority, AppError>;

    /// The person signed in to `caller`'s own tenant session, with their
    /// account, while the session check admits it.
    ///
    /// For what someone does to their own account: consent, their sessions,
    /// their passkeys and devices.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or the session no longer exists or no longer counts.
    /// - `AppError::Internal` when a store fails or a record is broken.
    async fn signed_in(&self, caller: &CallerContext) -> Result<SignedInAccount, AppError>;

    /// The holder of `caller`'s own account, as their credential proves
    /// them now: signed in to their own session, or bound to the directory
    /// over a certificate still in force.
    ///
    /// For what someone does to their own account from either: changing
    /// their password.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with neither a
    ///   tenant session nor a directory bind, or it no longer counts: the
    ///   session ended, or the bind's certificate was revoked or ran out, or
    ///   the account may no longer sign in.
    /// - `AppError::Internal` when a store fails or a record is broken.
    async fn holder(&self, caller: &CallerContext) -> Result<AccountHolder, AppError>;

    /// The person signed in on the session `session_id` of `tenant`, with
    /// their account, while the session check admits it.
    ///
    /// For a step that follows a sign-in on an app's host, where the
    /// session is the one the sign-in just opened, not one a caller came
    /// with: remembering the device the sign-in came from.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session or its account no
    ///   longer exists, or the session no longer counts.
    /// - `AppError::TenantUnavailable` when the tenant is not open.
    /// - `AppError::Internal` when a store fails or a record is broken.
    async fn signed_in_on(
        &self,
        tenant: &ScopedTenant,
        session_id: &SessionId,
    ) -> Result<SignedInAccount, AppError>;
}

/// Who acts on an organization, and through what.
#[async_trait]
pub trait OrgActors: Send + Sync {
    /// The organization `caller` acts on and the member acting, with what
    /// they act through, loaded fresh.
    ///
    /// The organization comes back on its own, so a use case may change it
    /// while it holds the member's control.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the member, their session or key,
    ///   or the organization no longer exists, or the session no longer
    ///   passes its check.
    /// - `AppError::Forbidden` when the member is not an active member of
    ///   the organization, the organization's status keeps them out, or the
    ///   session or key is another member's, another organization's, or a
    ///   key revoked or run out.
    /// - `AppError::Internal` when a store fails or a record is broken.
    async fn actor(&self, caller: &OrgCaller) -> Result<(Organization, OrgActor), AppError>;
}

/// An agent acting in its own name.
#[async_trait]
pub trait AgentActors: Send + Sync {
    /// What the attempt of the agent `presented` names to sign in by an
    /// assertion its own key signed for `audience` came to: signed in, the
    /// assertion spent here so it signs in once, or refused, with why and
    /// the agent it named, so a refusal that looks like an attack can be
    /// told apart from the agent's own slip.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` on storage failure, or when the agent's key
    ///   cannot be read. A refusal is an answer, never an error.
    async fn attempted(
        &self,
        tenant: &ScopedTenant,
        presented: &AgentAssertion,
        audience: &Audience,
    ) -> Result<SignInAttempt, AppError>;

    /// The agent `presented` names, signed in by an assertion its own key
    /// signed for `audience`, spent here so it signs in once.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the agent is unknown, the assertion
    ///   names no key of the agent's, the key may not sign it in now, the
    ///   assertion does not verify or names another agent, or it was used
    ///   before.
    /// - `AppError::Internal` on storage failure.
    async fn signed_in(
        &self,
        tenant: &ScopedTenant,
        presented: &AgentAssertion,
        audience: &Audience,
    ) -> Result<SignedInAgent, AppError> {
        match self.attempted(tenant, presented, audience).await? {
            SignInAttempt::SignedIn(signed) => Ok(*signed),
            SignInAttempt::Refused(refused) => Err(refused.forbidden()),
        }
    }
}

/// What an operator may do on the platform.
#[async_trait]
pub trait OperatorAuthorities: Send + Sync {
    /// What `caller` may do on the platform now.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the operator or the key no longer
    ///   exists.
    /// - `AppError::Forbidden` when the key is another operator's, no longer
    ///   works, or its operator is disabled.
    /// - `AppError::Internal` when a store fails or a record is broken.
    async fn authority(&self, caller: &OperatorCaller) -> Result<OperatorAuthority, AppError>;

    /// What `operator` may do on the platform now, on the strength of the
    /// password they gave just now, as `sign_in` proves.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when `sign_in` is another operator's, or the
    ///   operator is disabled.
    async fn signed_in(
        &self,
        operator: &Operator,
        sign_in: &OperatorSignIn,
    ) -> Result<OperatorAuthority, AppError>;
}

/// What a consumer's roles give it, once its own credential signed it in.
#[async_trait]
pub trait ConsumerAuthorities: Send + Sync {
    /// What `caller`'s roles give it now, once its credential signed it in.
    ///
    /// Every refusal of the credential is the same `Unauthenticated`, so a
    /// caller guessing keys learns nothing about why.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when no consumer of the tenant has the
    ///   credential, the consumer is disabled, or the credential is not its
    ///   own.
    /// - `AppError::Internal` when a store fails or the records name a role
    ///   that is not there.
    async fn authority(&self, caller: &ConsumerCaller) -> Result<ConsumerAuthority, AppError>;
}

/// The SCIM endpoint a tenant's directory signed in to with its token.
#[async_trait]
pub trait ScimAuthorities: Send + Sync {
    /// The endpoint `caller` signed in to, once its token is the one the
    /// tenant holds now and SCIM is switched on.
    ///
    /// Every refusal is the same `Unauthenticated`, so a caller learns
    /// nothing about whether the tenant has SCIM at all.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the request carries no token, the
    ///   tenant never set SCIM up or switched it off, or the token is not
    ///   the current one.
    /// - `AppError::Internal` when the endpoint cannot be read.
    async fn endpoint(&self, caller: &ScimCaller)
    -> Result<ScimEndpoint<ResolvedTenant>, AppError>;
}
