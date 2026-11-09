//! Finishing a sign-in an identity provider vouched for, the same for OIDC
//! and SAML: the account found, linked or made, its session opened owing
//! what the tenant asks, and the session handed back as a one-time code.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::sessions::session::{CreateSessionParams, Session};
use ianua_domain::domains::authentication::sessions::sign_in_code::{CodeHolders, SignInCode};
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInRefused;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::federation::connection::{FederatedIdpConnection, ProviderGroupName};
use ianua_domain::domains::federation::vouched_identity::VouchedIdentity;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    ActorRef, EventLabel, Fact, SessionId, SessionIndex, Setting, TokenHash,
};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{MfaEnrollmentStore, PasskeyStore, SignInCodeStore};
use crate::ports::authorization::{
    AccessRecordStore, GroupMembershipStore, RoleAssignmentStore, RoleStore, SeparationRuleStore,
};
use crate::ports::federation::{
    FederatedLinkStore, MappedHoldingsStore, ProviderSession, ProviderSessionStore,
};
use crate::ports::identity::UserStore;
use crate::ports::limits::{LimitEnforcer, PlanLimitsSource};
use crate::ports::oauth::CodeHasher;
use crate::ports::shared::{Mailer, SessionStore};
use crate::services::authentication::sign_in_gate::ClientOrigin;
use crate::tenancy::ScopedTenant;
use crate::use_cases::authentication::federation::federated_user::{
    Arrival, Arriving, FederatedUser, FederatedUserPorts, signing_in,
};
use crate::use_cases::authentication::federation::mapped_roles::{
    GroupedArrival, MappedAccess, Settled,
};
use crate::use_cases::authentication::federation::single_sign_on::{SsoPolicy, SsoSignIn};
use crate::use_cases::authentication::held_factors::FactorSources;
use crate::use_cases::authentication::signed_in_event::record_login;
use crate::use_cases::authentication::timing::elapsed_millis;

/// The ports a vouched-for sign-in is finished with, the same for OIDC and
/// SAML.
#[derive(ianua_macros::Fakes)]
pub struct SsoCompletionPorts {
    /// What the account a provider vouched for is found, made or linked through, with the roles and groups its mapping gives.
    pub accounts: SsoAccountPorts,
    /// The person's own factors, which decide how strong their session is, and the mail telling them of a new link.
    pub factors: SsoFactorPorts,
    /// What opens the session and hands back the one-time code standing in for it.
    pub session: SsoSessionPorts,
}

/// What the account a provider vouched for is found, made or linked through, with the roles and groups its mapping gives.
#[derive(ianua_macros::Fakes)]
pub struct SsoAccountPorts {
    /// The tenant's users: found, or made on a first sign-in.
    pub users: Arc<dyn UserStore>,
    /// The roles a new account starts with.
    pub roles: Arc<dyn RoleStore>,
    /// Records the roles a new account is given.
    pub assignments: Arc<dyn RoleAssignmentStore>,
    /// The links between accounts and who they are at a provider.
    pub links: Arc<dyn FederatedLinkStore>,
    /// Who holds what in the tenant, which decides whether an account may
    /// be linked and how far the provider's word counts.
    pub access: Arc<dyn AccessRecordStore>,
    /// The tenant's separation rules, which every role and group a provider
    /// hands out is held to.
    pub separation_rules: Arc<dyn SeparationRuleStore>,
    /// Records the groups the provider's groups map to.
    pub memberships: Arc<dyn GroupMembershipStore>,
    /// What each connection's group mapping gave each person.
    pub mapped_holdings: Arc<dyn MappedHoldingsStore>,
    /// Holds the tenant to its plan's user limit.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// The tenant's plan limits.
    pub plan_limits: Arc<dyn PlanLimitsSource>,
}

/// The person's own factors, which decide how strong their session is, and the mail telling them of a new link.
#[derive(ianua_macros::Fakes)]
pub struct SsoFactorPorts {
    /// Whether the account has an authenticator app of its own.
    pub mfa_enrollments: Arc<dyn MfaEnrollmentStore>,
    /// Whether the account has passkeys of its own.
    pub passkeys: Arc<dyn PasskeyStore>,
    /// Tells the owner of a newly linked account.
    pub mailer: Arc<dyn Mailer>,
}

/// What opens the session and hands back the one-time code standing in for it.
#[derive(ianua_macros::Fakes)]
pub struct SsoSessionPorts {
    /// Stores the session.
    pub sessions: Arc<dyn SessionStore>,
    /// Keeps the provider's session behind it, for single logout.
    pub provider_sessions: Arc<dyn ProviderSessionStore>,
    /// Mints the refresh token of a session nobody is shown.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// Makes the one-time code and its hash.
    pub code_hasher: Arc<dyn CodeHasher>,
    /// Keeps the one-time codes.
    pub sign_in_codes: Arc<dyn SignInCodeStore>,
}

/// A sign-in an identity provider vouched for, ready to become a session.
pub(in crate::use_cases::authentication::federation) struct VouchedSignIn<'a> {
    /// The tenant the sign-in is for.
    pub(in crate::use_cases::authentication::federation) scope: &'a ScopedTenant,
    /// The tenant, whose sign-in rules the session is held to.
    pub(in crate::use_cases::authentication::federation) tenant: &'a Tenant,
    /// The connection that vouched.
    pub(in crate::use_cases::authentication::federation) connection:
        &'a FederatedIdpConnection<ResolvedTenant>,
    /// What the provider vouched for.
    pub(in crate::use_cases::authentication::federation) identity: &'a VouchedIdentity,
    /// Where the request came from.
    pub(in crate::use_cases::authentication::federation) origin: &'a ClientOrigin,
    /// When the callback began, for the authentication-time metric.
    pub(in crate::use_cases::authentication::federation) started: Instant,
    /// Hash of the value the dashboard that started the sign-in keeps; the
    /// one-time code works only with it.
    pub(in crate::use_cases::authentication::federation) dashboard_hash: TokenHash,
    /// The groups the provider names for the person, which the connection's
    /// group mapping reads.
    pub(in crate::use_cases::authentication::federation) provider_groups: &'a [ProviderGroupName],
    /// The session the provider keeps for the person, which a logout names,
    /// when it named one.
    pub(in crate::use_cases::authentication::federation) provider_session: Setting<SessionIndex>,
}

/// Finishes vouched-for sign-ins through `ports`, under `policy`.
pub(in crate::use_cases::authentication::federation) struct SignInCompletion<'a> {
    pub(in crate::use_cases::authentication::federation) ports: &'a SsoCompletionPorts,
    pub(in crate::use_cases::authentication::federation) policy: &'a SsoPolicy,
}

impl SignInCompletion<'_> {
    /// Signs in the account the provider vouched for, linking or making it
    /// on a first sign-in, opens its session, records the sign-in, and
    /// returns the one-time code standing in for the session.
    ///
    /// A first sign-in whose session is then refused, as one short of the
    /// strength the tenant asks for, keeps the account it made or linked:
    /// the provider did vouch for the person. So the account made or the
    /// link is recorded, and its owner told of a link, on that path too.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the provider may not vouch for the
    ///   person, the account may not sign in, the plan has no room for a new
    ///   account, or the sign-in falls short of what the tenant requires.
    /// - `AppError::NotFound` if the linked account no longer exists.
    /// - `AppError::Conflict` if another sign-in linked the account first.
    /// - `AppError::Internal` on persistence failure.
    pub(in crate::use_cases::authentication::federation) async fn complete(
        &self,
        auditor: &RequestAuditor,
        vouched: VouchedSignIn<'_>,
    ) -> Result<SsoSignIn, AppError> {
        let mut user = signing_in(self.user_ports(), self.arriving(&vouched)).await?;
        let mut session = match self.open_session(&vouched, &user).await {
            Ok(session) => session,
            Err(refused) => {
                return Err(self
                    .arrived_anyway(auditor, &vouched, &mut user, refused)
                    .await);
            }
        };
        let users = self.ports.accounts.users.as_ref();
        record_login(users, vouched.scope, session.user_id()).await?;
        let mapped = self.provider_follow_up(&vouched, &user, &session).await?;
        let code = self
            .code_for(vouched.scope, &session, vouched.dashboard_hash.clone())
            .await?;
        session.record_sign_in(elapsed_millis(vouched.started));
        let mut events = recorded(&vouched, &mut user, &mut session);
        events.extend(mapped.raised);
        dispatch(auditor, &mapped.ended, &holder_of(&user), events).await?;
        self.tell_linked(&vouched, &user).await;
        Ok(SsoSignIn {
            code,
            user_id: *user.account.id(),
            jit_provisioned: user.arrival == Arrival::Provisioned,
            second_factor: session.owed(),
        })
    }

    /// `refused`, once a first sign-in that opened no session has its
    /// arrival recorded and its link told to the account's owner, or the
    /// audit failure when the arrival cannot be recorded.
    async fn arrived_anyway(
        &self,
        auditor: &RequestAuditor,
        vouched: &VouchedSignIn<'_>,
        user: &mut FederatedUser,
        refused: AppError,
    ) -> AppError {
        let arrived = user.link.take_events(vouched.scope);
        if arrived.is_empty() {
            return refused;
        }
        let recorded = auditor.dispatch_by(&holder_of(user), arrived).await;
        if let Err(unrecorded) = recorded.or_internal() {
            return unrecorded;
        }
        self.tell_linked(vouched, user).await;
        refused
    }

    /// Brings the roles and groups the person's provider groups map to in
    /// step with what the provider says now, and keeps the provider's
    /// session behind `session` for single logout. Returns what giving and
    /// taking back raised, with the ends of run-out holds a grant cleared
    /// apart, for the platform to record.
    async fn provider_follow_up(
        &self,
        vouched: &VouchedSignIn<'_>,
        user: &FederatedUser,
        session: &Session<ResolvedTenant>,
    ) -> Result<Settled, AppError> {
        self.keep_provider_session(vouched, session).await?;
        let mapped = MappedAccess {
            records: self.ports.accounts.access.as_ref(),
            rules: self.ports.accounts.separation_rules.as_ref(),
            assignments: self.ports.accounts.assignments.as_ref(),
            memberships: self.ports.accounts.memberships.as_ref(),
            holdings: self.ports.accounts.mapped_holdings.as_ref(),
        };
        mapped
            .settle(&GroupedArrival {
                tenant: vouched.scope,
                connection: vouched.connection,
                user: *user.account.id(),
                label: EventLabel::of(user.account.email().as_str()),
                groups: vouched.provider_groups,
            })
            .await
    }

    /// Keeps the session the provider named for the person behind
    /// `session`, so a logout can reach it. A provider that named none is
    /// not reached.
    async fn keep_provider_session(
        &self,
        vouched: &VouchedSignIn<'_>,
        session: &Session<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let Setting::Set(session_index) = &vouched.provider_session else {
            return Ok(());
        };
        let kept = ProviderSession {
            session_id: *session.id(),
            connection_id: *vouched.connection.id(),
            subject: vouched.identity.subject().clone(),
            session_index: session_index.clone(),
        };
        self.ports
            .session
            .provider_sessions
            .save(vouched.scope, &kept)
            .await
            .or_internal()
    }

    fn user_ports(&self) -> FederatedUserPorts<'_> {
        FederatedUserPorts {
            users: self.ports.accounts.users.as_ref(),
            roles: self.ports.accounts.roles.as_ref(),
            assignments: self.ports.accounts.assignments.as_ref(),
            links: self.ports.accounts.links.as_ref(),
            access: self.ports.accounts.access.as_ref(),
            separation_rules: self.ports.accounts.separation_rules.as_ref(),
            limit_enforcer: self.ports.accounts.limit_enforcer.as_ref(),
            plan_limits: self.ports.accounts.plan_limits.as_ref(),
        }
    }

    fn arriving<'v>(&'v self, vouched: &VouchedSignIn<'v>) -> Arriving<'v> {
        Arriving {
            tenant: vouched.scope,
            connection: vouched.connection,
            identity: vouched.identity,
            display_names: &self.policy.display_names,
        }
    }

    /// Stores a session for the account whose refresh token is never shown:
    /// the browser gets a one-time code instead. It opens through the link
    /// the person signed in by, owing what the tenant asks of them.
    async fn open_session(
        &self,
        vouched: &VouchedSignIn<'_>,
        user: &FederatedUser,
    ) -> Result<Session<ResolvedTenant>, AppError> {
        let config = vouched.tenant.auth_config();
        let owed = self.owed(vouched, user).await?;
        let sign_in = vouched
            .connection
            .vouched_sign_in(vouched.identity, user.privilege);
        let may_sign_in = user
            .link
            .sign_in(sign_in, owed, config.step_up_policy())
            .map_err(refused_sign_in)?;
        let generator = self.ports.session.token_generator.as_ref();
        let (_, unshown_hash) = generator.generate().or_internal()?.into_parts();
        let session = Session::create(
            may_sign_in,
            CreateSessionParams {
                id: SessionId::new(),
                refresh_token_hash: unshown_hash,
                ip_address: vouched.origin.ip_address.clone(),
                user_agent: Fact::from_option(vouched.origin.user_agent.clone()),
                timeout: config.session_timeout().map_err(AppError::from_domain)?,
            },
        );
        self.ports
            .session
            .sessions
            .save(vouched.scope, &session)
            .await
            .or_internal()?;
        Ok(session)
    }

    /// What the sign-in owes under the tenant's policy, given every second
    /// factor the person holds here. A factor the provider proved is the
    /// domain's to count, through the connection's trust.
    async fn owed(
        &self,
        vouched: &VouchedSignIn<'_>,
        user: &FederatedUser,
    ) -> Result<SecondFactor, AppError> {
        let sources = FactorSources {
            enrollments: self.ports.factors.mfa_enrollments.as_ref(),
            passkeys: self.ports.factors.passkeys.as_ref(),
        };
        let enrolment = sources
            .enrolment_of(vouched.scope, user.account.id())
            .await?;
        let policy = vouched.tenant.auth_config().mfa_policy();
        Ok(SecondFactor::for_enrolment(policy, enrolment))
    }

    /// Issues the one-time code standing in for `session`, for the
    /// dashboard whose value hashes to `dashboard`.
    async fn code_for(
        &self,
        scope: &ScopedTenant,
        session: &Session<ResolvedTenant>,
        dashboard: TokenHash,
    ) -> Result<Secret, AppError> {
        let (code, code_hash) = self
            .ports
            .session
            .code_hasher
            .generate_code()
            .await
            .or_internal()?;
        let holders = CodeHolders {
            code: code_hash,
            dashboard,
        };
        let issued = SignInCode::issue(session, holders, self.policy.code_lifetime)
            .map_err(AppError::from_domain)?;
        self.ports
            .session
            .sign_in_codes
            .save(scope, &issued)
            .await
            .or_internal()?;
        Ok(code)
    }

    /// Tells the account's owner it can now be signed in to through the
    /// provider, so a link they did not make does not go unnoticed. Delivery
    /// is best effort: the sign-in has already happened.
    async fn tell_linked(&self, vouched: &VouchedSignIn<'_>, user: &FederatedUser) {
        if user.arrival != Arrival::Linked {
            return;
        }
        let variables = linked_notice(vouched, user);
        let sent = self
            .ports
            .factors
            .mailer
            .send(
                user.account.email(),
                Some(*vouched.scope),
                EmailTemplateType::AccountLinked,
                &variables,
            )
            .await;
        if let Err(error) = sent {
            tracing::warn!(%error, "could not send the account-linked notice");
        }
    }
}

/// Why a provider sign-in does not open a session.
fn refused_sign_in(refused: SignInRefused) -> AppError {
    match refused {
        SignInRefused::BelowBaseline(_) => AppError::Forbidden(message!(
            "authentication-this-workspace-asks-for-a-stronger",
            "this workspace asks for a stronger sign-in than this provider gave"
        )),
        SignInRefused::NotAccepted { .. }
        | SignInRefused::AlreadyProved
        | SignInRefused::ForAnotherAccount
        | SignInRefused::AccountMayNotSignIn
        | SignInRefused::WayInNotAllowed => AppError::Forbidden(refused.to_string().into()),
    }
}

/// What the account-linked notice says: whose account, which provider,
/// and from where.
fn linked_notice(
    vouched: &VouchedSignIn<'_>,
    user: &FederatedUser,
) -> HashMap<TemplateVariable, String> {
    let mut variables = HashMap::from([
        (
            TemplateVariable::UserName,
            user.account.display_name().as_str().to_owned(),
        ),
        (
            TemplateVariable::ProviderName,
            vouched.connection.provider_name().as_str().to_owned(),
        ),
    ]);
    if let Some(ip) = vouched.origin.ip_address.known() {
        variables.insert(TemplateVariable::IpAddress, ip.as_str().to_owned());
    }
    variables
}

/// Records the ends of run-out holds as the platform's, then `events` as
/// done by `holder`.
///
/// # Errors
///
/// - `AppError::Internal` if either cannot be recorded.
async fn dispatch(
    auditor: &RequestAuditor,
    ended: &[DomainEvent],
    holder: &ActorRef,
    events: Vec<DomainEvent>,
) -> Result<(), AppError> {
    auditor.dispatch(ended).await.or_internal()?;
    auditor.dispatch_by(holder, events).await.or_internal()
}

/// The person signing in, who is the actor on every record of it.
fn holder_of(user: &FederatedUser) -> ActorRef {
    ActorRef::User(*user.account.id())
}

/// What the sign-in raised, in order: the sign-in, then how a first
/// sign-in brought the person in, through the link it made. A returning
/// person's link raised nothing.
fn recorded(
    vouched: &VouchedSignIn<'_>,
    user: &mut FederatedUser,
    session: &mut Session<ResolvedTenant>,
) -> Vec<DomainEvent> {
    let mut events = session.take_events(vouched.scope);
    events.extend(user.link.take_events(vouched.scope));
    events
}
