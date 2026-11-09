//! A member beginning to add a passkey: a registration ceremony is opened
//! for them and kept on the server, and the browser gets only its
//! challenge.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::passkey_ceremony::TargetedPurpose;
use ianua_domain::domains::organization::access::passkey::OrgPasskeyCeremony;
use ianua_domain::domains::organization::events::access::OrgPasskeyRegistrationStarted;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::types::{ActorRef, Lifetime, UserId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::PasskeyVerifier;
use crate::ports::organization::OrgPasskeyCeremonyStore;
use crate::use_case::Command;
use crate::use_cases::organization::passkeys::challenge::OrgPasskeyStarted;
use crate::use_cases::organization::passkeys::registrant::{
    MemberRegistrant, MemberRegistrantPorts,
};

/// The ports [`OrgRegisterBeginUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgRegisterBeginPorts {
    /// Finds out who is adding the passkey.
    pub registrant: MemberRegistrantPorts,
    /// Makes the `WebAuthn` challenge.
    pub verifier: Arc<dyn PasskeyVerifier>,
    /// Keeps the ceremony's state the client must not see.
    pub ceremony_store: Arc<dyn OrgPasskeyCeremonyStore>,
}

/// Opens a ceremony to add a passkey to the registrant's own membership.
pub struct OrgRegisterBeginUseCase {
    ttl: Lifetime,
    ports: OrgRegisterBeginPorts,
}

impl OrgRegisterBeginUseCase {
    /// A use case opening ceremonies that last `ttl`, through `ports`.
    #[must_use]
    pub fn new(ttl: Lifetime, ports: OrgRegisterBeginPorts) -> Self {
        Self { ttl, ports }
    }
}

impl Command for OrgRegisterBeginUseCase {
    type Caller = MemberRegistrant;
    type Input = ();
    type Output = Result<OrgPasskeyStarted, AppError>;

    /// Opens a registration ceremony for the registrant and hands back the
    /// browser's challenge. Records
    /// `organization.org_passkey_registration_started`.
    ///
    /// The ceremony is bound to the member, so only they can add a passkey
    /// with it. The name the authenticator shows comes from the member's
    /// record, never from the request: the browser shows it as given, on
    /// the one screen the person is meant to trust.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the registrant's session no
    ///   longer counts, they act through a key, or their sign-in does not
    ///   wait for a factor.
    /// - `AppError::Forbidden` when the session is another member's.
    /// - `AppError::NotFound` when the member is gone.
    /// - `AppError::Internal` when the challenge cannot be made or the
    ///   ceremony cannot be stored or recorded.
    async fn execute(
        &self,
        registrant: &MemberRegistrant,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<OrgPasskeyStarted, AppError> {
        let member = self.ports.registrant.registering(registrant).await?.member;
        let started = self
            .ports
            .verifier
            .start_registration(&webauthn_handle(&member), member.email())
            .await
            .or_internal()?;
        let ceremony = OrgPasskeyCeremony::open(
            *member.id(),
            TargetedPurpose::Registration,
            started.server_state,
            self.ttl,
        );
        self.ports
            .ceremony_store
            .save(&ceremony)
            .await
            .or_internal()?;
        let started_record = OrgPasskeyRegistrationStarted::observed(&member);
        auditor
            .dispatch_by(&ActorRef::OrgUser(*member.id()), vec![started_record])
            .await
            .or_internal()?;
        Ok(OrgPasskeyStarted {
            ceremony_id: *ceremony.id(),
            challenge: started.client_payload,
        })
    }
}

/// The handle the authenticator files the member's passkey under: their
/// own id, in the form the `WebAuthn` port takes.
fn webauthn_handle(member: &OrgUser) -> UserId {
    UserId::from_uuid(*member.id().as_uuid())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::ports::organization::{OrgSessionStore, OrgUserStore};
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::{WAITING_REFRESH_TOKEN, ceremony_lifetime};
    use crate::test_support::organization::{
        FakeOrgPasskeyCeremonyStore, FakeOrgUserStore, RecordingOrgSessionStore,
        member_sign_in_waiting_for_a_factor, org_store_with, stored_caller, test_org,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};
    use crate::use_cases::organization::passkeys::registrant::PendingMemberToken;

    struct Fixture {
        use_case: OrgRegisterBeginUseCase,
        ceremonies: Arc<FakeOrgPasskeyCeremonyStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn with(registrant: MemberRegistrantPorts) -> Self {
            let ceremonies = Arc::new(FakeOrgPasskeyCeremonyStore::new());
            Self {
                use_case: OrgRegisterBeginUseCase::new(
                    ceremony_lifetime(),
                    OrgRegisterBeginPorts {
                        registrant,
                        ceremony_store: ceremonies.clone(),
                        ..OrgRegisterBeginPorts::fakes()
                    },
                ),
                ceremonies,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn signed_in() -> Self {
            let members = FakeOrgUserStore::empty();
            block_on(members.save(&stored_caller(OrgRole::Member, "irrelevant"))).unwrap();
            Self::with(MemberRegistrantPorts {
                members: Arc::new(members),
                ..MemberRegistrantPorts::fakes()
            })
        }

        fn begin(&self, registrant: &MemberRegistrant) -> Result<OrgPasskeyStarted, AppError> {
            block_on(
                self.use_case
                    .execute(registrant, &test_auditor(self.audit.clone()), ()),
            )
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Olivia, signed in, starts adding a passkey. A ceremony is kept for
    /// her, and the start is recorded.
    #[test]
    fn a_signed_in_member_opens_a_ceremony_for_herself() {
        let fixture = Fixture::signed_in();

        let started = fixture
            .begin(&MemberRegistrant::SignedIn(test_org_caller()))
            .unwrap();

        let kept = block_on(fixture.ceremonies.find_by_id(&started.ceremony_id))
            .unwrap()
            .unwrap();
        assert_eq!(kept.org_user_id(), Some(test_org_caller().member()));
        assert_eq!(
            fixture.recorded(),
            vec!["organization.org_passkey_registration_started"]
        );
    }

    /// Olivia's sign-in waits for her to set up the second factor her
    /// organization requires. She starts adding a passkey from it.
    #[test]
    fn a_sign_in_waiting_for_a_factor_opens_a_ceremony() {
        let olivia = stored_caller(OrgRole::Member, "irrelevant");
        let members = FakeOrgUserStore::empty();
        block_on(members.save(&olivia)).unwrap();
        let sessions = RecordingOrgSessionStore::new();
        block_on(sessions.save(&member_sign_in_waiting_for_a_factor(
            &olivia,
            TenantId::new(),
        )))
        .unwrap();
        let fixture = Fixture::with(MemberRegistrantPorts {
            members: Arc::new(members),
            sessions: Arc::new(sessions),
            organizations: org_store_with([test_org(*olivia.organization_id(), "acme")]),
            ..MemberRegistrantPorts::fakes()
        });

        let started = fixture.begin(&MemberRegistrant::SettingUpFactor(PendingMemberToken {
            refresh_token: Secret::new(WAITING_REFRESH_TOKEN),
        }));

        assert!(started.is_ok());
        assert_eq!(fixture.ceremonies.count(), 1);
    }

    /// An unknown pending sign-in token cannot authorize registration, and
    /// no passkey ceremony is opened.
    #[test]
    fn an_unknown_waiting_sign_in_is_refused() {
        let fixture = Fixture::signed_in();

        let started = fixture.begin(&MemberRegistrant::SettingUpFactor(PendingMemberToken {
            refresh_token: Secret::new("fake_refresh_nobody"),
        }));

        assert!(matches!(started, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.ceremonies.count(), 0);
    }

    /// A signed-out session cannot start registration, and no ceremony is opened.
    #[test]
    fn a_signed_out_member_is_refused() {
        let fixture = Fixture::with(MemberRegistrantPorts {
            org_actors: Arc::new(FakeOrgActors::refusing(Refusal::SignedOut)),
            ..MemberRegistrantPorts::fakes()
        });

        let started = fixture.begin(&MemberRegistrant::SignedIn(test_org_caller()));

        assert!(matches!(started, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.ceremonies.count(), 0);
    }

    /// Registration propagates the organization actor's forbidden response.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let fixture = Fixture::with(MemberRegistrantPorts {
            org_actors: Arc::new(FakeOrgActors::refusing(Refusal::Forbidden)),
            ..MemberRegistrantPorts::fakes()
        });

        let started = fixture.begin(&MemberRegistrant::SignedIn(test_org_caller()));

        assert!(matches!(started, Err(AppError::Forbidden(_))));
    }

    /// An API key cannot start passkey registration even for an owner, and
    /// no ceremony is opened.
    #[test]
    fn a_key_caller_is_refused() {
        let fixture = Fixture::with(MemberRegistrantPorts {
            org_actors: Arc::new(FakeOrgActors::through_key(OrgRole::Owner, Vec::new())),
            ..MemberRegistrantPorts::fakes()
        });

        let started = fixture.begin(&MemberRegistrant::SignedIn(test_org_caller()));

        assert!(matches!(started, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.ceremonies.count(), 0);
    }
}
