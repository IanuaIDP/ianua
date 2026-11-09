//! A member following the sign-in link mailed to them.
//!
//! Following a link mailed to the member's own address proves the mailbox.
//! The link is spent only once the sign-in can begin, so one refused for
//! the organization's settings stays usable after they change; a spent,
//! lapsed or superseded one opens nothing. The organization's single
//! sign-on is held to here too: a member it signs in through its provider
//! is not let in by mail.

use std::sync::Arc;

use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::tokens::magic_link::MagicLink;
use ianua_domain::domains::organization::access::sign_in_start::OrgSignInStart;
use ianua_domain::domains::organization::access::token::OrgMagicLinkToken;
use ianua_domain::domains::organization::events::access::OrgSignInMethod;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::TenantSlug;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::input::validate_token;
use crate::ports::organization::{OrgTokenStore, OrgUserStore, OrganizationStore};
use crate::services::authentication::sign_in_gate::ClientOrigin;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_organization;
use crate::use_cases::organization::sign_in::OrgLoginSuccess;
use crate::use_cases::organization::sign_in::steps::finishing::{
    Arrival, FinishingPorts, start_refused,
};
use crate::use_cases::organization::sign_in_record::org_sign_in_record;

/// A followed sign-in link. Holds the link's token, so it has no `Debug`.
pub struct OrgMagicLinkRequest {
    /// The token from the link.
    pub token: Secret,
    /// The tenant to land in. Without it the session lands in the first
    /// active tenant the member reaches.
    pub tenant_slug: Option<TenantSlug>,
    /// Where the request came from.
    pub origin: ClientOrigin,
}

/// The ports [`OrgMagicLinkUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgMagicLinkPorts {
    /// Members' sign-in links.
    pub links: Arc<dyn OrgTokenStore<MagicLink>>,
    /// Hashes the link's token the way it was stored.
    pub link_hasher: Arc<dyn RefreshTokenGenerator>,
    /// The member a link was mailed for.
    pub members: Arc<dyn OrgUserStore>,
    /// The member's organization, which sets the sign-in's rules.
    pub organizations: Arc<dyn OrganizationStore>,
    /// What finishes the sign-in.
    pub finish: FinishingPorts,
}

/// Signs a member in to the dashboard by the link mailed to them.
pub struct OrgMagicLinkUseCase {
    ports: OrgMagicLinkPorts,
}

/// A followed link and the member it was mailed for.
struct Followed {
    link: OrgMagicLinkToken,
    member: OrgUser,
}

impl OrgMagicLinkUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: OrgMagicLinkPorts) -> Self {
        Self { ports }
    }

    /// The link `token` names and the member it was mailed for, when both
    /// still exist.
    async fn followed(&self, token: &Secret) -> Result<Followed, AppError> {
        validate_token("token", token.expose())?;
        let hash = self.ports.link_hasher.hash_raw(token.expose());
        let link = self
            .ports
            .links
            .find_by_hash(&hash)
            .await
            .or_internal()?
            .ok_or_else(invalid_link)?;
        let member = self
            .ports
            .members
            .find_by_id(link.org_user_id())
            .await
            .or_internal()?
            .ok_or_else(invalid_link)?;
        Ok(Followed { link, member })
    }

    /// The sign-in the link begins for its member, spending the link, once
    /// the organization lets them in by mail. A link another request spent
    /// a moment before is answered as one nobody holds.
    async fn begun(
        &self,
        followed: &mut Followed,
        organization: &Organization,
    ) -> Result<OrgSignInStart, AppError> {
        let member = &followed.member;
        let way_in = followed
            .link
            .sign_in(member, clock::now())
            .map_err(|_| invalid_link())?;
        let owed = self.ports.finish.owed(member, organization).await?;
        let start = OrgSignInStart::new(member, way_in, owed, organization.auth_config())
            .map_err(start_refused)?;
        if !self.ports.links.spend(&followed.link).await.or_internal()? {
            return Err(invalid_link());
        }
        Ok(start)
    }

    /// Signs the member `followed` names in, once their organization takes
    /// the link from where `request` came.
    async fn session_opened(
        &self,
        followed: &mut Followed,
        request: &OrgMagicLinkRequest,
    ) -> Result<OrgLoginSuccess, AppError> {
        let organization = existing_organization(
            self.ports.organizations.as_ref(),
            followed.member.organization_id(),
        )
        .await?;
        ensure_links_admitted(&organization, &request.origin)?;
        let start = self.begun(followed, &organization).await?;
        let arrival = Arrival {
            member: &followed.member,
            organization: &organization,
            tenant_slug: request.tenant_slug.as_ref(),
            origin: &request.origin,
        };
        self.ports.finish.finish(arrival, start).await
    }
}

impl Command for OrgMagicLinkUseCase {
    type Caller = ();
    type Input = OrgMagicLinkRequest;
    type Output = Result<OrgLoginSuccess, AppError>;

    /// Spends the mailed link, opening a session in the requested or first reachable tenant.
    /// An enrolled second factor remains owed. Records `organization.org_login_succeeded`
    /// by link or `organization.org_login_failed` for a known member's refusal;
    /// an unowned link records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` for unknown, spent, expired or replaced links, a changed
    ///   mailbox, a member barred from sign-in, or a tenant slug absent from the organization.
    /// - `AppError::Forbidden` when the organization does not allow sign-in
    ///   links, not from where the request came, signs the member in
    ///   through its provider, keeps them out, or they named a tenant they
    ///   do not reach.
    /// - `AppError::Domain` when the token is empty or too long, or the
    ///   organization's session lifetime is out of range.
    /// - `AppError::Internal` on storage, token or audit failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        request: OrgMagicLinkRequest,
    ) -> Result<OrgLoginSuccess, AppError> {
        let mut followed = self.followed(&request.token).await?;
        let outcome = self.session_opened(&mut followed, &request).await;
        let member = &followed.member;
        if let Some(event) = org_sign_in_record(member, OrgSignInMethod::MagicLink, &outcome) {
            auditor.dispatch(&[event]).await.or_internal()?;
        }
        outcome
    }
}

/// Refuses a link the organization does not take, or not from where
/// `origin` came.
///
/// # Errors
///
/// - `AppError::Forbidden` when the organization's settings rule it out.
/// - `AppError::Domain` when they cannot be read.
fn ensure_links_admitted(
    organization: &Organization,
    origin: &ClientOrigin,
) -> Result<(), AppError> {
    organization
        .auth_config()
        .admits(AuthMethod::MagicLink, origin.ip_address.as_ref())
        .map(|_| ())
        .map_err(AppError::from_domain)
}

/// The one answer for a link that opens nothing, whatever the reason.
fn invalid_link() -> AppError {
    AppError::NotFound(message!(
        "authentication-invalid-or-expired-sign-in-link",
        "invalid or expired sign-in link"
    ))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::risk_engine::step_up::StepUpPolicy;
    use ianua_domain::domains::organization::access::auth_config::{
        OrganizationAuthSettings, SsoEnforcement,
    };
    use ianua_domain::domains::organization::access::token::NewOrgToken;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::status::Suspension;
    use ianua_domain::types::{Fact, Lifetime, OrganizationId};

    use super::*;
    use crate::test_support::identity::hash_of_link;
    use crate::test_support::organization::{
        FakeOrgTokenStore, OrgShape, RecordingOrgSessionStore, org_shaped, org_store_with,
        org_user_store_with, test_org_user,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_in};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    const RAW: &str = "raw-link-token";
    const ALICE: &str = "alice@acme.test";

    struct Setup {
        uc: OrgMagicLinkUseCase,
        links: Arc<FakeOrgTokenStore<MagicLink>>,
        sessions: Arc<RecordingOrgSessionStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn allowing_links() -> OrganizationAuthSettings {
        OrganizationAuthSettings {
            enabled_methods: vec![
                AuthMethod::Password,
                AuthMethod::MagicLink,
                AuthMethod::Saml,
            ],
            step_up_policy: StepUpPolicy::relaxed(),
            ..OrganizationAuthSettings::default()
        }
    }

    /// Alice of Acme in `role`, holding a live link [`RAW`], under
    /// `settings`.
    fn setup(settings: OrganizationAuthSettings, role: OrgRole) -> Setup {
        setup_keeping(settings, role, |link| FakeOrgTokenStore::holding([link]))
    }

    /// The same, the link kept in the store `kept` makes of it.
    fn setup_keeping(
        settings: OrganizationAuthSettings,
        role: OrgRole,
        kept: impl FnOnce(OrgMagicLinkToken) -> FakeOrgTokenStore<MagicLink>,
    ) -> Setup {
        let acme = OrganizationId::new();
        let alice = test_org_user(acme, ALICE, role);
        let tenant = test_tenant_in(acme, "production", "production.com");
        let organization = org_shaped(
            acme,
            OrgShape {
                tenants: vec![*tenant.id()],
                settings,
                suspension: Suspension::NotSuspended,
            },
        );
        let links = Arc::new(kept(mailed_link(&alice)));
        let sessions = Arc::new(RecordingOrgSessionStore::new());
        let uc = OrgMagicLinkUseCase::new(OrgMagicLinkPorts {
            links: links.clone(),
            members: Arc::new(org_user_store_with([alice])),
            organizations: org_store_with([organization]),
            finish: FinishingPorts {
                tenants: Arc::new(FakeTenantStore::holding_all([tenant])),
                sessions: sessions.clone(),
                ..FinishingPorts::fakes()
            },
            ..OrgMagicLinkPorts::fakes()
        });
        Setup {
            uc,
            links,
            sessions,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    /// Issues the fixture's live sign-in link to the member's current mailbox.
    fn mailed_link(member: &OrgUser) -> OrgMagicLinkToken {
        OrgMagicLinkToken::issue(NewOrgToken {
            token_hash: hash_of_link(RAW),
            org_user_id: *member.id(),
            sent_to: member.email().clone(),
            lifetime: Lifetime::seconds(900).unwrap(),
        })
        .unwrap()
    }

    impl Setup {
        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }

        fn follow(&self, raw: &str) -> Result<OrgLoginSuccess, AppError> {
            block_on(self.uc.execute(
                &(),
                &test_auditor(self.audit.clone()),
                OrgMagicLinkRequest {
                    token: Secret::new(raw),
                    tenant_slug: None,
                    origin: ClientOrigin {
                        ip_address: Fact::Unknown,
                        user_agent: None,
                    },
                },
            ))
        }

        fn spent(&self) -> bool {
            block_on(self.links.find_by_hash(&hash_of_link(RAW)))
                .unwrap()
                .unwrap()
                .consumed_at()
                .is_some()
        }
    }

    /// Alice, Acme's owner, follows the link mailed to her. Her session
    /// opens in the `production` tenant and the link is spent.
    #[test]
    fn a_followed_link_signs_the_member_in_and_is_spent() {
        let setup = setup(allowing_links(), OrgRole::Owner);

        let success = setup.follow(RAW).unwrap();

        assert_eq!(success.tenant.slug().unwrap().as_str(), "production");
        assert_eq!(setup.sessions.count(), 1);
        assert!(setup.spent());
        assert_eq!(setup.recorded(), ["organization.org_login_succeeded"]);
    }

    /// Replaying Alice's followed link adds a failed-sign-in event after the
    /// original success event.
    #[test]
    fn a_replayed_link_is_recorded_as_a_refused_sign_in() {
        let setup = setup(allowing_links(), OrgRole::Owner);
        setup.follow(RAW).unwrap();

        let _ = setup.follow(RAW);

        assert_eq!(
            setup.recorded(),
            [
                "organization.org_login_succeeded",
                "organization.org_login_failed"
            ]
        );
    }

    /// Following an unknown link records no audit event.
    #[test]
    fn a_guessed_link_records_nothing() {
        let setup = setup(allowing_links(), OrgRole::Owner);

        let _ = setup.follow("guessed-token");

        assert!(setup.recorded().is_empty());
    }

    /// Replaying Alice's consumed link returns not found and leaves only the
    /// session opened by the first request.
    #[test]
    fn a_spent_link_opens_nothing() {
        let setup = setup(allowing_links(), OrgRole::Owner);
        setup.follow(RAW).unwrap();

        let replayed = setup.follow(RAW);

        assert!(matches!(replayed, Err(AppError::NotFound(_))));
        assert_eq!(setup.sessions.count(), 1);
    }

    /// When the store reports that another request consumed the link first,
    /// following it returns not found and opens no session.
    #[test]
    fn a_link_spent_by_another_request_a_moment_before_opens_nothing() {
        let setup = setup_keeping(allowing_links(), OrgRole::Owner, |link| {
            FakeOrgTokenStore::raced([link])
        });

        let result = setup.follow(RAW);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.sessions.count(), 0);
    }

    /// An unknown link returns not found and opens no session.
    #[test]
    fn an_unknown_link_opens_nothing() {
        let setup = setup(allowing_links(), OrgRole::Owner);

        let result = setup.follow("guessed-token");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.sessions.count(), 0);
    }

    /// Acme stopped taking sign-in links after Alice's was mailed. It opens
    /// nothing and stays unspent.
    #[test]
    fn a_link_the_organization_no_longer_takes_opens_nothing() {
        let passwords_only = OrganizationAuthSettings {
            enabled_methods: vec![AuthMethod::Password],
            ..allowing_links()
        };
        let setup = setup(passwords_only, OrgRole::Owner);

        let result = setup.follow(RAW);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.sessions.count(), 0);
        assert!(!setup.spent());
    }

    /// Under enforced SSO, a member's mailed link returns a forbidden error,
    /// opens no session and remains unconsumed.
    #[test]
    fn a_member_signed_in_through_sso_is_not_let_in_by_mail() {
        let enforcing = OrganizationAuthSettings {
            sso: SsoEnforcement::Enforced,
            ..allowing_links()
        };
        let setup = setup(enforcing, OrgRole::Member);

        let result = setup.follow(RAW);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.sessions.count(), 0);
        assert!(!setup.spent());
    }
}
