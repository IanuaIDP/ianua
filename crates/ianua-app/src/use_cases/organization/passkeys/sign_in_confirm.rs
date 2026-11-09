//! Finishing a member's passkey sign-in: the browser's answer is checked
//! against the ceremony kept on the server, and the passkey's member gets
//! a session in a tenant they may reach.
//!
//! The sign-in page carries no organization, so the passkey that answers
//! is what names the member, and through them the organization. A passkey
//! is something its holder has and unlocks, so it proves a second factor
//! on its own; the session records it.

use std::sync::Arc;

use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::sessions::fresh_sign_in::SpentPasskey;
use ianua_domain::domains::authentication::sessions::proved_factor::ProvedFactor;
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInRefused;
use ianua_domain::domains::authentication::sessions::way_in::WayIn;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::organization::access::auth_config::OrganizationAuthConfig;
use ianua_domain::domains::organization::access::landing::SignInLanding;
use ianua_domain::domains::organization::access::session::OrgSession;
use ianua_domain::domains::organization::access::sign_in_start::OrgSignInStart;
use ianua_domain::domains::organization::events::access::OrgSignInMethod;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::PasskeyVerifier;
use crate::ports::authorization::RoleStore;
use crate::ports::organization::{
    OrgPasskeyCeremonyStore, OrgPasskeyStore, OrgSessionStore, OrgTenantGrantStore, OrgUserStore,
    OrganizationStore,
};
use crate::ports::tenant::TenantStore;
use crate::services::authentication::passkey_answer::{
    AnsweredMemberPasskey, MemberPasskeyAnswering, PresentedAssertion,
};
use crate::services::authentication::sign_in_gate::ClientOrigin;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_organization;
use crate::use_cases::organization::members::rights::access::AccessSources;
use crate::use_cases::organization::sign_in::OrgLoginSuccess;
use crate::use_cases::organization::sign_in::steps::landing::{LandedTenant, Landing};
use crate::use_cases::organization::sign_in::steps::opening::{Opening, SessionOpener};
use crate::use_cases::organization::sign_in_record::org_sign_in_record;

/// What the browser sends back to finish a member's passkey sign-in.
pub struct OrgLoginConfirmRequest {
    /// The passkey's answer to the challenge.
    pub assertion: PresentedAssertion,
    /// Where the request came from.
    pub origin: ClientOrigin,
}

/// The ports [`OrgLoginConfirmUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgLoginConfirmPorts {
    /// Members' passkeys, whose use is counted.
    pub passkey_store: Arc<dyn OrgPasskeyStore>,
    /// Checks the passkey's answer.
    pub verifier: Arc<dyn PasskeyVerifier>,
    /// The ceremonies in flight, spent here.
    pub ceremony_store: Arc<dyn OrgPasskeyCeremonyStore>,
    /// The passkey owners' records.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// The owners' organizations, which admit the sign-in and set its rules.
    pub org_store: Arc<dyn OrganizationStore>,
    /// The organization's tenants, one of which the session lands in.
    pub tenant_store: Arc<dyn TenantStore>,
    /// The tenants and roles plain members were granted.
    pub grant_store: Arc<dyn OrgTenantGrantStore>,
    /// The tenants' roles, for what the member may reach.
    pub role_store: Arc<dyn RoleStore>,
    /// Where the new session is kept.
    pub org_session_store: Arc<dyn OrgSessionStore>,
    /// Makes the session's refresh token.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Signs the member a passkey belongs to in once it answered a challenge.
pub struct OrgLoginConfirmUseCase {
    ports: OrgLoginConfirmPorts,
}

/// Where a passkey sign-in lands: the member's organization, and a tenant
/// or the organization alone.
struct Destination {
    organization: Organization,
    place: SignInLanding,
}

impl OrgLoginConfirmUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: OrgLoginConfirmPorts) -> Self {
        Self { ports }
    }

    fn answering(&self) -> MemberPasskeyAnswering<'_> {
        MemberPasskeyAnswering {
            passkeys: self.ports.passkey_store.as_ref(),
            ceremonies: self.ports.ceremony_store.as_ref(),
            members: self.ports.org_user_store.as_ref(),
            verifier: self.ports.verifier.as_ref(),
        }
    }

    fn opener(&self) -> SessionOpener<'_> {
        SessionOpener {
            members: self.ports.org_user_store.as_ref(),
            sessions: self.ports.org_session_store.as_ref(),
            grants: self.ports.grant_store.as_ref(),
            token_generator: self.ports.token_generator.as_ref(),
        }
    }

    /// The member's organization, once it admits a passkey sign-in from
    /// where the request came, and the tenant the member lands in.
    async fn destination(
        &self,
        member: &OrgUser,
        origin: &ClientOrigin,
    ) -> Result<Destination, AppError> {
        let organization =
            existing_organization(self.ports.org_store.as_ref(), member.organization_id()).await?;
        organization
            .auth_config()
            .admits(AuthMethod::Passkey, origin.ip_address.as_ref())
            .map_err(AppError::from_domain)?;
        let landing = Landing {
            tenants: self.ports.tenant_store.as_ref(),
            grants: self.ports.grant_store.as_ref(),
        };
        let place = landing.place_for(member, &organization, None).await?;
        Ok(Destination {
            organization,
            place,
        })
    }

    /// Opens the member's session where `to` says, and records on it the
    /// factor the passkey proved.
    async fn opened(
        &self,
        answered: &AnsweredMemberPasskey,
        to: &Destination,
        origin: &ClientOrigin,
    ) -> Result<(OrgSession, Secret), AppError> {
        let config = to.organization.auth_config();
        let policy = config.step_up_policy();
        let opening = Opening {
            member: &answered.member,
            organization: &to.organization,
            place: to.place.place(),
            start: begun_by_passkey(&answered.member, &answered.spent, config)?,
            origin,
        };
        let opened = self.opener().open(opening).await?;
        let mut session = opened.session;
        let factor = ProvedFactor::by_passkey(&answered.spent).map_err(AppError::from_domain)?;
        session
            .answer(&answered.member, factor, policy)
            .map_err(refused_by_organization)?;
        self.ports
            .org_session_store
            .save(&session)
            .await
            .or_internal()?;
        Ok((session, opened.refresh_token))
    }

    /// Signs the passkey's member in, once their account and organization
    /// let them.
    async fn sign_in_outcome(
        &self,
        answered: &AnsweredMemberPasskey,
        origin: &ClientOrigin,
    ) -> Result<OrgLoginSuccess, AppError> {
        ensure_signs_in_by_passkey(&answered.member)?;
        let to = self.destination(&answered.member, origin).await?;
        let (session, refresh_token) = self.opened(answered, &to, origin).await?;
        let reach = AccessSources {
            tenants: self.ports.tenant_store.as_ref(),
            roles: self.ports.role_store.as_ref(),
            grants: self.ports.grant_store.as_ref(),
        };
        let access = reach.reach_of(&answered.member).await?;
        Ok(OrgLoginSuccess {
            session_id: *session.id(),
            org_user_id: *answered.member.id(),
            refresh_token,
            second_factor: session.owed(),
            tenant: LandedTenant::from(&to.place),
            organization_id: *to.organization.id(),
            org_slug: to.organization.slug().clone(),
            organization_name: to.organization.name().clone(),
            display_name: answered.member.display_name().clone(),
            access: Some(access),
        })
    }
}

impl Command for OrgLoginConfirmUseCase {
    type Caller = ();
    type Input = OrgLoginConfirmRequest;
    type Output = Result<OrgLoginSuccess, AppError>;

    /// Spends the ceremony before checking the passkey, then replaces the member's
    /// earlier sessions. A named ceremony accepts only that member; an unnamed one
    /// identifies the member from the passkey. Records `organization.org_login_succeeded`
    /// or, for a known member's refusal, `organization.org_login_failed`.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the ceremony or the passkey is unknown,
    ///   or the member may not sign in or has an unconfirmed address, all
    ///   alike on purpose.
    /// - `AppError::Domain` when the ceremony expired, was used, or was
    ///   opened for a registration.
    /// - `AppError::Forbidden` when the answer does not verify, comes from
    ///   another member's passkey than the ceremony was opened for, the
    ///   passkey's counter went backwards, the organization does not take
    ///   passkeys or not from where the request came, keeps the member out,
    ///   or the passkey falls short of the assurance it requires.
    /// - `AppError::Internal` when a store fails or no token can be made.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        request: OrgLoginConfirmRequest,
    ) -> Result<OrgLoginSuccess, AppError> {
        let answered = self.answering().answered(&request.assertion).await?;
        let outcome = self.sign_in_outcome(&answered, &request.origin).await;
        if let Some(event) =
            org_sign_in_record(&answered.member, OrgSignInMethod::Passkey, &outcome)
        {
            auditor.dispatch(&[event]).await.or_internal()?;
        }
        outcome
    }
}

/// Refuses a member who may not sign in now, or whose address was never
/// confirmed, with the same answer as an unknown passkey.
fn ensure_signs_in_by_passkey(member: &OrgUser) -> Result<(), AppError> {
    if member.email_verified() && member.status().can_authenticate() {
        return Ok(());
    }
    Err(AppError::NotFound(message!(
        "authentication-invalid-credentials",
        "invalid credentials"
    )))
}

/// The sign-in the spent passkey begins for `member`, owing the factor the
/// passkey then proves.
fn begun_by_passkey(
    member: &OrgUser,
    spent: &SpentPasskey,
    config: &OrganizationAuthConfig,
) -> Result<OrgSignInStart, AppError> {
    let way_in = WayIn::by_passkey(spent).map_err(AppError::from_domain)?;
    OrgSignInStart::new(member, way_in, SecondFactor::Verify, config)
        .map_err(refused_by_organization)
}

/// What a sign-in the organization refused answers. A member who may not
/// sign in answers like a wrong credential.
fn refused_by_organization(refused: SignInRefused) -> AppError {
    match refused {
        SignInRefused::ForAnotherAccount | SignInRefused::AccountMayNotSignIn => {
            AppError::NotFound(message!(
                "authentication-invalid-credentials",
                "invalid credentials"
            ))
        }
        SignInRefused::BelowBaseline(_) => AppError::Forbidden(message!(
            "organization-this-passkey-does-not-reach-the",
            "this passkey does not reach the assurance the organization requires"
        )),
        SignInRefused::AlreadyProved | SignInRefused::NotAccepted { .. } => {
            AppError::Forbidden(message!(
                "organization-this-passkey-does-not-finish-the",
                "this passkey does not finish the sign-in to the organization"
            ))
        }
        SignInRefused::WayInNotAllowed => AppError::Forbidden(message!(
            "organization-the-organization-signs-this-member-in",
            "the organization signs this member in through its identity provider"
        )),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::passkey_ceremony::TargetedPurpose;
    use ianua_domain::domains::organization::access::auth_config::{
        OrganizationAuthConfig, OrganizationAuthSettings,
    };
    use ianua_domain::domains::organization::access::session::SessionPlace;
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
    use ianua_domain::domains::organization::lifecycle::OrganizationRow;
    use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::domains::tenant::status::{Archival, PlatformHold, TenantStatus};
    use ianua_domain::types::{
        ActedBy, CeremonyId, CidrRange, Fact, IpAddress, OrgUserId, OrganizationId,
    };

    use super::*;
    use crate::test_support::authentication::{
        FakePasskeyVerifier, VerifiedAs, passkey_credential_id,
    };
    use crate::test_support::organization::{
        FakeOrgPasskeyCeremonyStore, FakeOrgPasskeyStore, FakeOrgUserStore,
        RecordingOrgSessionStore, discoverable_member_ceremony, kept_member_ceremony,
        member_ceremony, org_store_with, org_user_store_with, test_org_member_at, test_org_on,
        test_org_owner,
    };
    use crate::test_support::tenant::{FakeTenantStore, tenant_for_ctx_standing, test_tenant_in};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const ADDRESS: &str = "olivia@acme.test";

    struct Fixture {
        olivia: OrgUserId,
        organization: Organization,
        passkeys: Arc<FakeOrgPasskeyStore>,
        members: Arc<FakeOrgUserStore>,
        tenants: Arc<FakeTenantStore>,
        ceremonies: Arc<FakeOrgPasskeyCeremonyStore>,
        verifier: Arc<FakePasskeyVerifier>,
        sessions: Arc<RecordingOrgSessionStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        /// Acme, on Business, owning `tenants`, with Olivia, as `olivia`
        /// makes her, holding a passkey.
        fn with(tenants: Vec<Tenant>, olivia: impl FnOnce(OrganizationId) -> OrgUser) -> Self {
            let mut organization = test_org_on(
                test_ctx().organization_id(),
                "acme",
                OrganizationPlan::Business,
            );
            for tenant in &tenants {
                organization.add_tenant(tenant, ActedBy::Platform).unwrap();
            }
            let olivia = olivia(*organization.id());
            Self {
                olivia: *olivia.id(),
                passkeys: Arc::new(FakeOrgPasskeyStore::with_passkey(
                    *organization.id(),
                    *olivia.id(),
                )),
                members: Arc::new(org_user_store_with([olivia])),
                tenants: Arc::new(FakeTenantStore::holding_all(tenants)),
                organization,
                ceremonies: Arc::new(FakeOrgPasskeyCeremonyStore::new()),
                verifier: Arc::new(FakePasskeyVerifier::succeeding()),
                sessions: Arc::new(RecordingOrgSessionStore::new()),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// Acme owning `tenants`, with Olivia as an owner.
        fn owning(tenants: Vec<Tenant>) -> Self {
            Self::with(tenants, |organization_id| {
                test_org_owner(organization_id, ADDRESS, "irrelevant")
            })
        }

        fn production() -> Tenant {
            test_tenant_in(
                test_ctx().organization_id(),
                "production",
                "production.test",
            )
        }

        fn new() -> Self {
            Self::owning(vec![Self::production()])
        }

        /// Acme, with Olivia deactivated.
        fn deactivated() -> Self {
            Self::with(vec![Self::production()], |organization_id| {
                test_org_member_at(organization_id, ADDRESS, OrgUserStatus::Deactivated)
            })
        }

        fn signing_in_with(self, change: impl FnOnce(&mut OrganizationAuthSettings)) -> Self {
            let mut settings = self.organization.auth_config().settings().clone();
            change(&mut settings);
            let organization = Organization::reconstitute(OrganizationRow {
                auth_config: OrganizationAuthConfig::new(settings).unwrap(),
                ..row_of(&self.organization)
            })
            .unwrap();
            Self {
                organization,
                ..self
            }
        }

        fn open_for(&self, member: OrgUserId) -> CeremonyId {
            kept_member_ceremony(
                &self.ceremonies,
                &member_ceremony(member, TargetedPurpose::Authentication),
            )
        }

        fn open_for_nobody(&self) -> CeremonyId {
            kept_member_ceremony(&self.ceremonies, &discoverable_member_ceremony())
        }

        fn confirm_from(
            &self,
            ceremony_id: CeremonyId,
            ip: Fact<IpAddress>,
        ) -> Result<OrgLoginSuccess, AppError> {
            let use_case = OrgLoginConfirmUseCase::new(OrgLoginConfirmPorts {
                passkey_store: self.passkeys.clone(),
                verifier: self.verifier.clone(),
                ceremony_store: self.ceremonies.clone(),
                org_user_store: self.members.clone(),
                org_store: org_store_with([self.organization.clone()]),
                tenant_store: self.tenants.clone(),
                org_session_store: self.sessions.clone(),
                ..OrgLoginConfirmPorts::fakes()
            });
            block_on(use_case.execute(
                &(),
                &test_auditor(self.audit.clone()),
                OrgLoginConfirmRequest {
                    assertion: PresentedAssertion {
                        ceremony_id,
                        credential_id: passkey_credential_id(),
                        response: b"signed".to_vec(),
                    },
                    origin: ClientOrigin {
                        ip_address: ip,
                        user_agent: None,
                    },
                },
            ))
        }

        fn recorded(&self, event_type: &str) -> bool {
            self.audit
                .records
                .lock()
                .unwrap()
                .iter()
                .any(|recorded| recorded == event_type)
        }
    }

    /// The stored fields of `organization`.
    fn row_of(organization: &Organization) -> OrganizationRow {
        OrganizationRow {
            id: *organization.id(),
            slug: organization.slug().clone(),
            name: organization.name().clone(),
            contact_email: organization.contact_email().clone(),
            display_name: organization.display_name().clone(),
            plan: organization.plan(),
            terms: organization.terms().clone(),
            status: organization.status(),
            suspended_by: organization.suspended_by(),
            tenant_ids: organization.tenant_ids().to_vec(),
            auth_config: organization.auth_config().clone(),
            created_at: organization.created_at(),
            updated_at: organization.updated_at(),
        }
    }

    /// Olivia answers the ceremony opened for her with her passkey. She is
    /// signed in, the passkey counts as her second factor, and the sign-in
    /// is recorded.
    #[test]
    fn a_member_signs_in_with_her_passkey() {
        let fixture = Fixture::new();
        let ceremony = fixture.open_for(fixture.olivia);

        let signed_in = fixture.confirm_from(ceremony, Fact::Unknown);

        let signed_in = signed_in.unwrap();
        assert_eq!(signed_in.second_factor, SecondFactor::NotOwed);
        assert!(!signed_in.refresh_token.expose().is_empty());
        assert_eq!(
            fixture.verifier.verified_as(),
            vec![VerifiedAs::BoundToUser]
        );
        assert!(fixture.recorded("organization.org_login_succeeded"));
    }

    /// A browser offered Olivia's passkey from the empty sign-in field. The
    /// ceremony for nobody signs in the passkey's member, checked as a
    /// discoverable answer.
    #[test]
    fn a_discoverable_ceremony_signs_in_the_passkeys_member() {
        let fixture = Fixture::new();
        let ceremony = fixture.open_for_nobody();

        let signed_in = fixture.confirm_from(ceremony, Fact::Unknown).unwrap();

        assert_eq!(signed_in.org_user_id, fixture.olivia);
        assert_eq!(
            fixture.verifier.verified_as(),
            vec![VerifiedAs::Discoverable]
        );
    }

    /// Olivia's organization has a tenant still being set up and an active
    /// one. The sign-in lands in the active one.
    #[test]
    fn a_sign_in_lands_in_an_active_tenant() {
        let organization_id = test_ctx().organization_id();
        let staging = test_tenant_in(organization_id, "staging", "staging.test");
        let production = tenant_for_ctx_standing(
            TenantStatus::Active,
            PlatformHold::Free,
            Archival::NotArchived,
        );
        let fixture = Fixture::owning(vec![staging, production]);
        let ceremony = fixture.open_for_nobody();

        let signed_in = fixture.confirm_from(ceremony, Fact::Unknown).unwrap();

        let LandedTenant::Tenant { id, .. } = signed_in.tenant else {
            panic!("Olivia lands in a tenant");
        };
        assert_eq!(id, test_ctx().tenant_id());
    }

    /// Olivia is a plain member nobody granted a tenant yet. Her passkey
    /// signs her in to the organization alone.
    #[test]
    fn a_member_without_a_tenant_signs_in_to_the_organization_alone() {
        let fixture = Fixture::with(vec![Fixture::production()], |organization_id| {
            test_org_member_at(organization_id, ADDRESS, OrgUserStatus::Active)
        });
        let ceremony = fixture.open_for(fixture.olivia);

        let signed_in = fixture.confirm_from(ceremony, Fact::Unknown).unwrap();

        assert_eq!(signed_in.tenant, LandedTenant::NoTenantAccess);
        assert_eq!(
            fixture.sessions.saved()[0].place(),
            SessionPlace::Organization
        );
    }

    /// A successful passkey sign-in spends its ceremony, so replaying the
    /// answer is rejected.
    #[test]
    fn a_ceremony_signs_in_once() {
        let fixture = Fixture::new();
        let ceremony = fixture.open_for_nobody();
        fixture.confirm_from(ceremony, Fact::Unknown).unwrap();

        let replayed = fixture.confirm_from(ceremony, Fact::Unknown);

        assert!(matches!(replayed, Err(AppError::Domain(_))));
    }

    /// An unknown passkey ceremony is not found and opens no session.
    #[test]
    fn an_unknown_ceremony_is_not_found() {
        let fixture = Fixture::new();

        let result = fixture.confirm_from(CeremonyId::new(), Fact::Unknown);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.sessions.count(), 0);
    }

    /// A passkey cannot answer a ceremony bound to another member, and no
    /// session is created.
    #[test]
    fn a_ceremony_for_another_member_is_refused() {
        let fixture = Fixture::new();
        let ceremony = fixture.open_for(OrgUserId::new());

        let result = fixture.confirm_from(ceremony, Fact::Unknown);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.sessions.count(), 0);
    }

    /// A registration ceremony cannot serve as a sign-in ceremony, so no
    /// session is created.
    #[test]
    fn a_registration_ceremony_is_refused() {
        let fixture = Fixture::new();
        let ceremony = kept_member_ceremony(
            &fixture.ceremonies,
            &member_ceremony(fixture.olivia, TargetedPurpose::Registration),
        );

        let result = fixture.confirm_from(ceremony, Fact::Unknown);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.sessions.count(), 0);
    }

    /// A deactivated member's passkey receives a not-found refusal; no
    /// session is created and the failed sign-in is recorded.
    #[test]
    fn a_deactivated_member_cannot_sign_in() {
        let fixture = Fixture::deactivated();
        let ceremony = fixture.open_for_nobody();

        let result = fixture.confirm_from(ceremony, Fact::Unknown);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.sessions.count(), 0);
        assert!(fixture.recorded("organization.org_login_failed"));
    }

    /// An organization with passkeys disabled rejects passkey sign-in and
    /// creates no session.
    #[test]
    fn an_organization_that_turned_passkeys_off_refuses_them() {
        let fixture = Fixture::new()
            .signing_in_with(|settings| settings.enabled_methods = vec![AuthMethod::Password]);
        let ceremony = fixture.open_for_nobody();

        let result = fixture.confirm_from(ceremony, Fact::Unknown);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.sessions.count(), 0);
    }

    /// A passkey sign-in from outside the organization's IP allowlist is
    /// forbidden and creates no session.
    #[test]
    fn a_sign_in_from_outside_the_allowlist_is_refused() {
        let fixture = Fixture::new().signing_in_with(|settings| {
            settings.ip_allowlist = vec![CidrRange::new("10.0.0.0/8").unwrap()];
        });
        let ceremony = fixture.open_for_nobody();

        let result = fixture.confirm_from(
            ceremony,
            Fact::Known(IpAddress::new("203.0.113.7").unwrap()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.sessions.count(), 0);
    }
}
