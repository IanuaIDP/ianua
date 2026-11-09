//! Finishing a member's sign-in that waits for them to confirm it from
//! their mailbox.
//!
//! The browser that began the sign-in holds the pending session's refresh
//! token. The member follows the link mailed to their address. Together
//! they answer what the sign-in owes: the link proves the mailbox, and the
//! token shows which sign-in it confirms. Neither alone finishes anything.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::sessions::proved_factor::ProvedFactor;
use ianua_domain::domains::authentication::sessions::status::SessionStatus;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::tokens::sign_in_confirmation::SignInConfirmation;
use ianua_domain::domains::organization::access::session::OrgSession;
use ianua_domain::domains::organization::events::access::OrgMfaVerified;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, SessionId};

use crate::auditor::RequestAuditor;
use crate::email::refused_link;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::organization::{OrgSessionStore, OrgTokenStore, OrgUserStore, OrganizationStore};
use crate::use_case::Command;
use crate::use_cases::authentication::password::sign_in::email_confirmation::{
    answer_refusal, ensure_owes_confirmation,
};
use crate::use_cases::organization::lookup::{existing_member, existing_organization};

/// The ports [`OrgConfirmUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgConfirmPorts {
    /// Members' sessions, the pending one among them.
    pub sessions: Arc<dyn OrgSessionStore>,
    /// The organization, for its step-up policy.
    pub organizations: Arc<dyn OrganizationStore>,
    /// The member signing in, as they stand now.
    pub members: Arc<dyn OrgUserStore>,
    /// The confirmation links mailed out.
    pub links: Arc<dyn OrgTokenStore<SignInConfirmation>>,
    /// Hashes a presented link or refresh token the way it was stored.
    pub token_hasher: Arc<dyn RefreshTokenGenerator>,
}

/// A followed confirmation link, with the sign-in it confirms. Holds both
/// tokens, so it has no `Debug`.
pub struct OrgConfirmRequest {
    /// The link's token, as followed.
    pub link: Secret,
    /// The refresh token of the session waiting for the confirmation.
    pub session_token: Secret,
}

/// A member's sign-in the mailbox confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrgConfirmed {
    /// The session confirmed.
    pub session_id: SessionId,
    /// What the sign-in still owes: nothing, or a factor to set up when the
    /// organization requires one.
    pub second_factor: SecondFactor,
}

/// Finishes a member's sign-in by the link mailed to them.
pub struct OrgConfirmUseCase {
    ports: OrgConfirmPorts,
}

impl OrgConfirmUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: OrgConfirmPorts) -> Self {
        Self { ports }
    }

    /// The session whose refresh token is `token`.
    async fn pending_session(&self, token: &Secret) -> Result<OrgSession, AppError> {
        let hash = self.ports.token_hasher.hash_raw(token.expose());
        self.ports
            .sessions
            .find_by_refresh_token_hash(&hash)
            .await
            .or_internal()?
            .or_not_found(message!(
                "authentication-sign-in-not-found",
                "sign-in not found"
            ))
    }

    /// The member `session` belongs to, as they stand now.
    async fn member_of(&self, session: &OrgSession) -> Result<OrgUser, AppError> {
        existing_member(
            self.ports.members.as_ref(),
            session.organization_id(),
            session.org_user_id(),
        )
        .await
    }

    /// Spends the confirmation link `raw` for `member`, giving back the
    /// mailbox it proves. A link another request spent a moment before is
    /// answered as one nobody holds.
    async fn followed(&self, member: &OrgUser, raw: &Secret) -> Result<ProvedFactor, AppError> {
        let hash = self.ports.token_hasher.hash_raw(raw.expose());
        let links = self.ports.links.as_ref();
        let mut link = links
            .find_by_hash(&hash)
            .await
            .or_internal()?
            .ok_or_else(invalid_link)?;
        let proof = link.confirm(member, clock::now()).map_err(refused_link)?;
        if !links.spend(&link).await.or_internal()? {
            return Err(invalid_link());
        }
        Ok(proof)
    }

    /// Records the answered sign-in.
    async fn keep(&self, session: &OrgSession) -> Result<(), AppError> {
        self.ports.sessions.save(session).await.or_internal()
    }
}

impl Command for OrgConfirmUseCase {
    type Caller = ();
    type Input = OrgConfirmRequest;
    type Output = Result<OrgConfirmed, AppError>;

    /// Answers what the session holding `request.session_token` owes with
    /// the link `request.link`, and records `organization.org_mfa_verified`.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when no live session holds the token, or its
    ///   organization or member is gone.
    /// - `AppError::Conflict` when the sign-in owes nothing.
    /// - `AppError::Forbidden` when the sign-in owes another factor, or the
    ///   link is unknown, used, or another member's, or the member may not
    ///   sign in now.
    /// - `AppError::LinkExpired` when the link ran out or went to an address
    ///   the member has since left.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        _: &(),
        auditor: &RequestAuditor,
        request: OrgConfirmRequest,
    ) -> Result<OrgConfirmed, AppError> {
        let mut session = self.pending_session(&request.session_token).await?;
        ensure_live(&session)?;
        ensure_owes_confirmation(session.owed())?;
        let organizations = self.ports.organizations.as_ref();
        let organization = existing_organization(organizations, session.organization_id()).await?;
        let member = self.member_of(&session).await?;
        let proof = self.followed(&member, &request.link).await?;
        session
            .answer(&member, proof, organization.auth_config().step_up_policy())
            .map_err(answer_refusal)?;
        self.keep(&session).await?;
        auditor
            .dispatch_by(
                &ActorRef::OrgUser(*session.org_user_id()),
                vec![OrgMfaVerified::observed(&session)],
            )
            .await
            .or_internal()?;
        Ok(OrgConfirmed {
            session_id: *session.id(),
            second_factor: session.owed(),
        })
    }
}

/// Refuses a sign-in that was signed out of or ran out, as not found.
///
/// # Errors
///
/// - `AppError::NotFound` when the session is not active or expired.
fn ensure_live(session: &OrgSession) -> Result<(), AppError> {
    let live = session.status() == SessionStatus::Active && clock::now() < session.expires_at();
    if !live {
        return Err(AppError::NotFound(message!(
            "authentication-sign-in-not-found",
            "sign-in not found"
        )));
    }
    Ok(())
}

/// The answer to a confirmation link nobody holds, or one another request
/// spent a moment before.
fn invalid_link() -> AppError {
    AppError::NotFound(message!("app-invalid-link", "invalid link"))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::sessions::mfa_factor::FactorProved;
    use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use ianua_domain::domains::organization::access::session::{OrgSessionRow, SessionPlace};
    use ianua_domain::domains::organization::access::token::{
        NewOrgToken, OrgSignInConfirmationToken, OrgTokenRow,
    };
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::{
        CredentialChange, Email, Fact, Lifetime, OrgUserId, OrganizationId, TenantId, Usage,
    };

    use super::*;
    use crate::test_support::identity::hash_of_link;
    use crate::test_support::organization::{
        FakeOrgTokenStore, RecordingOrgSessionStore, org_store_with, org_user_store_with, test_org,
        test_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    const OLIVIA: &str = "olivia@acme.test";
    const LINK: &str = "fake_refresh_link";
    const SESSION_TOKEN: &str = "fake_refresh_session";
    const MALLORYS_TOKEN: &str = "fake_refresh_mallory";

    struct Fixture {
        olivia: OrgUserId,
        organization_id: OrganizationId,
        sessions: Arc<RecordingOrgSessionStore>,
        links: Arc<FakeOrgTokenStore<SignInConfirmation>>,
        audit: Arc<FakeEventDispatcher>,
        use_case: OrgConfirmUseCase,
    }

    impl Fixture {
        /// Olivia's sign-in owing `owed`, with the link `link` mailed for it.
        fn with(
            owed: SecondFactor,
            link: impl FnOnce(OrgUserId) -> OrgSignInConfirmationToken,
        ) -> Self {
            Self::keeping(owed, link, |link| FakeOrgTokenStore::holding([link]))
        }

        /// The same, the link kept in the store `kept` makes of it.
        fn keeping(
            owed: SecondFactor,
            link: impl FnOnce(OrgUserId) -> OrgSignInConfirmationToken,
            kept: impl FnOnce(OrgSignInConfirmationToken) -> FakeOrgTokenStore<SignInConfirmation>,
        ) -> Self {
            let organization_id = OrganizationId::new();
            let member = test_org_user(organization_id, OLIVIA, OrgRole::Member);
            let olivia = *member.id();
            let sessions = Arc::new(RecordingOrgSessionStore::holding([waiting_sign_in(
                olivia,
                organization_id,
                owed,
                SESSION_TOKEN,
            )]));
            let links = Arc::new(kept(link(olivia)));
            let use_case = OrgConfirmUseCase::new(OrgConfirmPorts {
                sessions: sessions.clone(),
                organizations: org_store_with([test_org(organization_id, "acme")]),
                members: Arc::new(org_user_store_with([member])),
                links: links.clone(),
                ..OrgConfirmPorts::fakes()
            });
            Self {
                olivia,
                organization_id,
                sessions,
                links,
                audit: Arc::new(FakeEventDispatcher::new()),
                use_case,
            }
        }

        fn owing(owed: SecondFactor) -> Self {
            Self::with(owed, link_for)
        }

        fn confirm(&self, session_token: &str) -> Result<OrgConfirmed, AppError> {
            let request = OrgConfirmRequest {
                link: Secret::new(LINK),
                session_token: Secret::new(session_token),
            };
            block_on(
                self.use_case
                    .execute(&(), &test_auditor(self.audit.clone()), request),
            )
        }

        fn link_spent(&self) -> bool {
            block_on(self.links.find_by_hash(&hash_of_link(LINK)))
                .unwrap()
                .is_some_and(|link| link.consumed_at().is_some())
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// A fresh password sign-in of `member`, owing `owed`, whose refresh
    /// token is `token`.
    fn waiting_sign_in(
        member: OrgUserId,
        organization_id: OrganizationId,
        owed: SecondFactor,
        token: &str,
    ) -> OrgSession {
        let now = clock::now();
        OrgSession::reconstitute(OrgSessionRow {
            id: SessionId::new(),
            org_user_id: member,
            organization_id,
            place: SessionPlace::Tenant(TenantId::new()),
            refresh_token_hash: hash_of_link(token),
            progress: SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::NoneYet,
                owed,
            },
            ip_address: Fact::Unknown,
            user_agent: Fact::Unknown,
            status: SessionStatus::Active,
            created_at: now,
            last_active_at: now,
            expires_at: now + time::Duration::hours(8),
            kept_through: CredentialChange::Never,
        })
        .unwrap()
    }

    /// A confirmation link [`LINK`] mailed to Olivia's address for `member`.
    fn link_for(member: OrgUserId) -> OrgSignInConfirmationToken {
        OrgSignInConfirmationToken::issue(NewOrgToken {
            token_hash: hash_of_link(LINK),
            org_user_id: member,
            sent_to: Email::new(OLIVIA).unwrap(),
            lifetime: Lifetime::seconds(900).unwrap(),
        })
        .unwrap()
    }

    /// A confirmation link [`LINK`] for `member` that ran out an hour ago.
    fn expired_link_for(member: OrgUserId) -> OrgSignInConfirmationToken {
        let now = clock::now();
        OrgSignInConfirmationToken::reconstitute(OrgTokenRow {
            token_hash: hash_of_link(LINK),
            org_user_id: member,
            sent_to: Email::new(OLIVIA).unwrap(),
            created_at: now - time::Duration::hours(2),
            expires_at: now - time::Duration::hours(1),
            usage: Usage::from_stored(None),
        })
        .unwrap()
    }

    /// Olivia's sign-in from a new device waits for her to confirm it. She
    /// follows the link in the browser she signed in with, and her sign-in
    /// is finished, the link spent and the confirmation recorded.
    #[test]
    fn following_the_link_finishes_the_sign_in() {
        let fixture = Fixture::owing(SecondFactor::ConfirmByEmail);

        let confirmed = fixture.confirm(SESSION_TOKEN).unwrap();

        assert_eq!(confirmed.second_factor, SecondFactor::NotOwed);
        assert!(fixture.link_spent());
        assert_eq!(fixture.recorded(), ["organization.org_mfa_verified"]);
    }

    /// Olivia's organization requires a second factor she has not set up.
    /// Confirming by email leaves her sign-in waiting for her to set one up.
    #[test]
    fn a_confirmation_then_asks_for_a_factor_to_set_up() {
        let fixture = Fixture::owing(SecondFactor::ConfirmThenEnrol);

        let confirmed = fixture.confirm(SESSION_TOKEN).unwrap();

        assert_eq!(confirmed.second_factor, SecondFactor::Enrol);
    }

    /// Replaying Olivia's consumed link for a second session returns not
    /// found and leaves that session owing email confirmation.
    #[test]
    fn a_replayed_link_is_refused() {
        let fixture = Fixture::owing(SecondFactor::ConfirmByEmail);
        let mallorys = waiting_sign_in(
            fixture.olivia,
            fixture.organization_id,
            SecondFactor::ConfirmByEmail,
            MALLORYS_TOKEN,
        );
        let mallorys_id = *mallorys.id();
        block_on(fixture.sessions.save(&mallorys)).unwrap();
        fixture.confirm(SESSION_TOKEN).unwrap();

        let result = fixture.confirm(MALLORYS_TOKEN);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        let still = block_on(fixture.sessions.find_by_id(&mallorys_id))
            .unwrap()
            .unwrap();
        assert_eq!(still.owed(), SecondFactor::ConfirmByEmail);
    }

    /// When the store reports that another request consumed the link first,
    /// confirmation returns not found and records no audit event.
    #[test]
    fn a_link_spent_by_another_request_a_moment_before_is_refused() {
        let fixture = Fixture::keeping(SecondFactor::ConfirmByEmail, link_for, |link| {
            FakeOrgTokenStore::raced([link])
        });

        let result = fixture.confirm(SESSION_TOKEN);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// Following a link that expired an hour ago returns a link-expired error.
    #[test]
    fn an_expired_link_is_refused() {
        let fixture = Fixture::with(SecondFactor::ConfirmByEmail, expired_link_for);

        let result = fixture.confirm(SESSION_TOKEN);

        assert!(matches!(result, Err(AppError::LinkExpired(_))));
    }

    /// Using another member's link for Olivia's session returns not found
    /// and leaves the link unconsumed.
    #[test]
    fn a_link_for_another_member_is_refused() {
        let fixture = Fixture::with(SecondFactor::ConfirmByEmail, |_| link_for(OrgUserId::new()));

        let result = fixture.confirm(SESSION_TOKEN);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(!fixture.link_spent());
    }

    /// A session owing no further proof returns a conflict and leaves the
    /// confirmation link unconsumed.
    #[test]
    fn a_sign_in_that_owes_nothing_is_refused() {
        let fixture = Fixture::owing(SecondFactor::NotOwed);

        let result = fixture.confirm(SESSION_TOKEN);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(!fixture.link_spent());
    }

    /// A session owing factor verification refuses email confirmation with
    /// a forbidden error and leaves the link unconsumed.
    #[test]
    fn a_sign_in_owing_a_code_is_refused() {
        let fixture = Fixture::owing(SecondFactor::Verify);

        let result = fixture.confirm(SESSION_TOKEN);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!fixture.link_spent());
    }

    /// An unknown session token returns not found and leaves the confirmation
    /// link unconsumed.
    #[test]
    fn an_unknown_session_token_is_not_found() {
        let fixture = Fixture::owing(SecondFactor::ConfirmByEmail);

        let result = fixture.confirm("fake_refresh_nobody");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(!fixture.link_spent());
    }
}
