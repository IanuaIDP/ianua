//! A member asks for their data to be deleted for good, under GDPR Article
//! 17, or someone who may remove members asks it for them.
//!
//! The account closes at once, its sessions and the delegations it granted
//! end, a grace period starts, and a link to cancel goes to the member's
//! address: they cannot sign in meanwhile, so the link is how they change
//! their mind. The organization keeps an owner: its last active owner is
//! never erased.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::identity::privacy::erasure::{GracePeriod, RequestErasureParams};
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::account_control::{
    OrgAccountControl, ensure_may_act_on_others,
};
use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::owners::Owners;
use ianua_domain::domains::organization::members::privacy::erasure::OrgErasureRequest;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    ActorRef, ErasureRequestId, HttpsUrl, OrgUserId, OrganizationId, Text, TokenHash,
};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgErasureRequestStore, OrgSessionStore, OrgUserStore};
use crate::ports::shared::Mailer;
use crate::services::authorization::grant_revocation::OrgGrantRevocation;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::{current_owners, existing_member};
use crate::use_cases::organization::privacy::lookup::ensure_no_erasure_under_way;
use crate::use_cases::organization::privacy::whose::OrgWhose;
use crate::use_cases::organization::sign_in::sessions::sign_out::sign_out_member;

/// How members' erasures are asked for.
#[derive(Debug, Clone)]
pub struct OrgErasurePolicy {
    /// How long the member has to cancel before deletion starts.
    pub grace_period: GracePeriod,
    /// The address the cancel link is built on.
    pub base_url: HttpsUrl,
}

/// Whose data to erase, and why.
pub struct RequestOrgErasureRequest {
    /// Whose data it is.
    pub whose: OrgWhose,
    /// The reason given, if any.
    pub reason: Option<Text>,
}

/// The ports [`RequestOrgErasureUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestOrgErasurePorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The organization's members, the one closing among them.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Members' erasure requests.
    pub erasures: Arc<dyn OrgErasureRequestStore>,
    /// Members' sessions, ended as the account closes.
    pub org_sessions: Arc<dyn OrgSessionStore>,
    /// Revokes what the member granted, in every tenant.
    pub grant_revocation: OrgGrantRevocation,
    /// Mails the cancel link.
    pub mailer: Arc<dyn Mailer>,
    /// Makes cancel links.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// The grace period and the address cancel links are built on.
    pub policy: OrgErasurePolicy,
}

/// Asks for a member's data to be erased.
pub struct RequestOrgErasureUseCase {
    ports: RequestOrgErasurePorts,
}

impl RequestOrgErasureUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: RequestOrgErasurePorts) -> Self {
        Self { ports }
    }

    /// A new cancel link: its raw token and the hash the request keeps.
    fn cancel_token(&self) -> Result<(Secret, TokenHash), AppError> {
        let made = self.ports.token_generator.generate().or_internal()?;
        Ok(made.into_parts())
    }

    /// The request to erase `member_id`, made in person when the caller is
    /// that member and for them otherwise, with the account it closes.
    async fn submitted(
        &self,
        control: &OrgControl<'_>,
        organization_id: &OrganizationId,
        member_id: OrgUserId,
        params: RequestErasureParams,
    ) -> Result<(OrgErasureRequest, OrgUser), AppError> {
        ensure_may_erase(control, organization_id, &member_id)?;
        let users = self.ports.org_users.as_ref();
        let standing_owners = current_owners(users, organization_id).await?;
        let target = existing_member(users, organization_id, &member_id).await?;
        let mut member = existing_member(users, organization_id, &member_id).await?;
        ensure_no_erasure_under_way(self.ports.erasures.as_ref(), organization_id, &member_id)
            .await?;
        let owners = Owners::of(&standing_owners);
        let submitted = match control.is_member(&member_id) {
            true => OrgErasureRequest::submit(params, &mut member, control, owners),
            false => {
                let on_them = OrgAccountControl::new(*control, &target);
                OrgErasureRequest::submit_for(params, &mut member, &on_them, owners)
            }
        };
        let request = submitted.map_err(AppError::from_domain)?;
        Ok((request, member))
    }

    /// Ends the closing member's sessions and revokes what they granted,
    /// returning the records of what was revoked.
    async fn cut_off(&self, member: &OrgUser, by: &ActorRef) -> Result<Vec<DomainEvent>, AppError> {
        let revoked = self
            .ports
            .grant_revocation
            .revoke_all_granted_by(member.organization_id(), member.id(), by)
            .await
            .or_internal()?;
        sign_out_member(self.ports.org_sessions.as_ref(), member.id()).await?;
        Ok(revoked)
    }

    /// Mails the cancel link to the address the account has.
    async fn mail_cancel_link(
        &self,
        organization: &Organization,
        member: &OrgUser,
        request: &OrgErasureRequest,
        raw_token: &Secret,
    ) -> Result<(), AppError> {
        let scope = LinkScope::organization(organization.slug().clone());
        let action_url = scope.action_url(
            &self.ports.policy.base_url,
            "cancel-erasure",
            raw_token.expose(),
        );
        let variables = HashMap::from([
            (
                TemplateVariable::UserName,
                member.display_name().as_str().to_owned(),
            ),
            (TemplateVariable::ActionUrl, action_url),
            (
                TemplateVariable::ErasureDate,
                request.scheduled_at().date().to_string(),
            ),
        ]);
        self.ports
            .mailer
            .send(
                member.email(),
                None,
                EmailTemplateType::ErasureConfirmation,
                &variables,
            )
            .await
            .map_err(AppError::upstream)
    }
}

impl Command for RequestOrgErasureUseCase {
    type Caller = OrgCaller;
    type Input = RequestOrgErasureRequest;
    type Output = Result<ErasureRequestId, AppError>;

    /// Asks for the data of the member `request.whose` names to be erased
    /// once the grace period passes, and records
    /// `organization.org_user_erasure_requested`, with a record for each
    /// delegation revoked.
    ///
    /// The member asks from their own signed-in session, or someone who
    /// may remove them asks for them. Their account closes at once, and a
    /// link to cancel goes to its address.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for a member acting through a key or missing removal rights.
    /// - `AppError::Conflict` for an existing erasure or last active owner; `NotFound` for a missing organization member.
    /// - `AppError::Upstream` for refused cancel-link mail after creating the request; `Internal` on persistence, token or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: RequestOrgErasureRequest,
    ) -> Result<ErasureRequestId, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let (raw_token, cancel_token_hash) = self.cancel_token()?;
        let params = RequestErasureParams {
            reason: request.reason,
            grace_period: self.ports.policy.grace_period,
            cancel_token_hash,
        };
        let member_id = request.whose.member(caller.member());
        let (mut erasure, member) = self
            .submitted(&control, organization.id(), member_id, params)
            .await?;
        self.ports.erasures.save(&erasure).await.or_internal()?;
        self.ports.org_users.save(&member).await.or_internal()?;
        let by = ActorRef::OrgUser(*caller.member());
        let revoked = self.cut_off(&member, &by).await?;
        let mut events = erasure.take_events();
        events.extend(revoked);
        auditor.dispatch_by(&by, events).await.or_internal()?;
        self.mail_cancel_link(&organization, &member, &erasure, &raw_token)
            .await?;
        Ok(*erasure.id())
    }
}

/// Refuses asking erasure for someone else unless `control` may remove
/// members, before their record is read, so someone without the right is
/// refused the same for a member who exists and one who does not. A
/// member asking for their own needs no right.
fn ensure_may_erase(
    control: &OrgControl<'_>,
    organization_id: &OrganizationId,
    member_id: &OrgUserId,
) -> Result<(), AppError> {
    if control.is_member(member_id) {
        return Ok(());
    }
    ensure_may_act_on_others(control, organization_id, AccountAction::Erase)
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
    use ianua_domain::types::Scope;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeOrgErasureStore, FakeOrgUserStore, RecordingOrgSessionStore, org_user_store_with,
        stored_caller, test_org_user,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeMailer, block_on, test_auditor, test_org_caller,
    };

    struct Setup {
        uc: RequestOrgErasureUseCase,
        users: Arc<FakeOrgUserStore>,
        erasures: Arc<FakeOrgErasureStore>,
        sessions: Arc<RecordingOrgSessionStore>,
        mailer: Arc<FakeMailer>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn holding(actors: FakeOrgActors, members: Vec<OrgUser>) -> Self {
            let users = Arc::new(org_user_store_with(members));
            let erasures = Arc::new(FakeOrgErasureStore::empty());
            let sessions = Arc::new(RecordingOrgSessionStore::new());
            let mailer = Arc::new(FakeMailer::new());
            Self {
                uc: RequestOrgErasureUseCase::new(RequestOrgErasurePorts {
                    org_actors: Arc::new(actors),
                    org_users: users.clone(),
                    erasures: erasures.clone(),
                    org_sessions: sessions.clone(),
                    mailer: mailer.clone(),
                    ..RequestOrgErasurePorts::fakes()
                }),
                users,
                erasures,
                sessions,
                mailer,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ask(&self, whose: OrgWhose) -> Result<ErasureRequestId, AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                RequestOrgErasureRequest {
                    whose,
                    reason: None,
                },
            ))
        }

        fn status_of(&self, member: &OrgUserId) -> Option<OrgUserStatus> {
            self.users.get_status(member)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn in_acme(email: &str, role: OrgRole) -> OrgUser {
        test_org_user(test_org_caller().organization_id(), email, role)
    }

    fn caller() -> OrgUserId {
        *test_org_caller().member()
    }

    /// Sam, a member, asks to be forgotten. His account closes, he is
    /// signed out, a cancel link goes to him, and the request is recorded.
    #[test]
    fn a_member_asks_to_be_forgotten() {
        let setup = Setup::holding(
            FakeOrgActors::in_role(OrgRole::Member),
            vec![stored_caller(OrgRole::Member, "pw")],
        );

        setup.ask(OrgWhose::Own).unwrap();

        assert_eq!(setup.erasures.count(), 1);
        assert_eq!(setup.status_of(&caller()), Some(OrgUserStatus::Closing));
        assert!(setup.sessions.revoked(&caller()));
        assert_eq!(setup.mailer.recipients(), ["caller@example.test"]);
        assert_eq!(
            setup.recorded(),
            ["organization.org_user_erasure_requested"]
        );
    }

    /// Olivia, an owner, asks for Sam's data to be erased. His account
    /// closes and the cancel link goes to him.
    #[test]
    fn an_owner_asks_for_a_member_to_be_forgotten() {
        let sam = in_acme("sam@acme.test", OrgRole::Member);
        let sam_id = *sam.id();
        let setup = Setup::holding(FakeOrgActors::in_role(OrgRole::Owner), vec![sam]);

        setup.ask(OrgWhose::Member(sam_id)).unwrap();

        assert_eq!(setup.status_of(&sam_id), Some(OrgUserStatus::Closing));
        assert_eq!(setup.mailer.recipients(), ["sam@acme.test"]);
    }

    /// The last owner's erasure conflicts with keeping an active owner;
    /// the account stays active with no erasure or audit record saved.
    #[test]
    fn the_last_owner_is_not_erased() {
        let setup = Setup::holding(
            FakeOrgActors::in_role(OrgRole::Owner),
            vec![stored_caller(OrgRole::Owner, "pw")],
        );

        let result = setup.ask(OrgWhose::Own);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(setup.erasures.count(), 0);
        assert_eq!(setup.status_of(&caller()), Some(OrgUserStatus::Active));
        assert!(setup.recorded().is_empty());
    }

    /// A member cannot request an owner's erasure; the owner's account
    /// stays active and no cancellation link is mailed.
    #[test]
    fn a_member_erasing_another_is_refused() {
        let olivia = in_acme("olivia@acme.test", OrgRole::Owner);
        let olivia_id = *olivia.id();
        let setup = Setup::holding(FakeOrgActors::in_role(OrgRole::Member), vec![olivia]);

        let result = setup.ask(OrgWhose::Member(olivia_id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.status_of(&olivia_id), Some(OrgUserStatus::Active));
        assert!(setup.mailer.recipients().is_empty());
    }

    /// An admin cannot erase an owner, and no erasure request is saved.
    #[test]
    fn an_admin_erasing_an_owner_is_refused() {
        let olivia = in_acme("olivia@acme.test", OrgRole::Owner);
        let olivia_id = *olivia.id();
        let setup = Setup::holding(FakeOrgActors::in_role(OrgRole::Admin), vec![olivia]);

        let result = setup.ask(OrgWhose::Member(olivia_id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.erasures.count(), 0);
    }

    /// An API key cannot request its member's own erasure, even with removal
    /// scope; the member's account stays active.
    #[test]
    fn a_key_never_asks_in_person() {
        let scope = Scope::new("org:members:remove").unwrap();
        let setup = Setup::holding(
            FakeOrgActors::through_key(OrgRole::Member, vec![scope]),
            vec![stored_caller(OrgRole::Member, "pw")],
        );

        let result = setup.ask(OrgWhose::Own);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.status_of(&caller()), Some(OrgUserStatus::Active));
    }

    /// Olivia names a member Acme does not have. It is not found.
    #[test]
    fn an_unknown_member_is_not_found() {
        let setup = Setup::holding(FakeOrgActors::in_role(OrgRole::Owner), Vec::new());

        let result = setup.ask(OrgWhose::Member(OrgUserId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A member requesting another member's erasure receives a forbidden
    /// response even when the target ID does not exist.
    #[test]
    fn a_member_naming_an_unknown_member_is_refused_the_same() {
        let setup = Setup::holding(FakeOrgActors::in_role(OrgRole::Member), Vec::new());

        let result = setup.ask(OrgWhose::Member(OrgUserId::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot request erasure, and no request is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::holding(FakeOrgActors::refusing(Refusal::SignedOut), Vec::new());

        let result = setup.ask(OrgWhose::Own);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(setup.erasures.count(), 0);
    }
}
