//! Marking the session or key an organization member came with as used,
//! once a request it carried was let in.
//!
//! A session left alone past the organization's idle timeout stops
//! counting, so one a member works in must be marked each time, or it
//! times out mid-work. A key shows its owners when it last signed in, so a
//! forgotten one can be spotted and revoked.

use std::sync::Arc;

use ianua_domain::message;
use ianua_domain::types::{OrgApiKeyId, OrgUserId, OrganizationId, SessionId};

use crate::acting::{OrgActors, TenantAuthorities};
use crate::auditor::RequestAuditor;
use crate::context::{CallerContext, CallerIdentity, Credential, OrgCaller, OrgCredential};
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgApiKeyStore, OrgSessionStore};
use crate::use_case::Command;
use crate::use_cases::organization::lookup::{existing_api_key, existing_org_session};

/// The member whose credential was used, on the plane they came in on.
pub enum OrgCredentialBearer {
    /// A member acting on their organization.
    Organization(OrgCaller),
    /// A member acting inside one of the organization's tenants.
    Tenant(CallerContext),
}

/// The ports [`MarkCredentialUsedUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct MarkCredentialUsedPorts {
    /// Members' sessions.
    pub sessions: Arc<dyn OrgSessionStore>,
    /// Members' API keys.
    pub api_keys: Arc<dyn OrgApiKeyStore>,
    /// Who acts on an organization, so only a credential that still counts
    /// is marked.
    pub org_actors: Arc<dyn OrgActors>,
    /// What a caller holds in a tenant, for a member who came in there.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Marks a member's session active now, or records that their key signed
/// in now.
///
/// The request middleware calls it once per request it let in on an
/// organization credential. A session that already stopped counting is
/// never marked, so marking cannot bring an idle one back.
pub struct MarkCredentialUsedUseCase {
    ports: MarkCredentialUsedPorts,
}

/// The credential a member came with.
#[derive(Clone, Copy)]
enum Used {
    /// Their own session.
    Session(SessionId),
    /// A key they made.
    Key(OrgApiKeyId),
}

/// Whose credential it is, in which organization, and which one.
struct Bearing {
    member: OrgUserId,
    organization_id: OrganizationId,
    used: Used,
}

impl MarkCredentialUsedUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: MarkCredentialUsedPorts) -> Self {
        Self { ports }
    }

    async fn ensure_still_counts(&self, bearer: &OrgCredentialBearer) -> Result<(), AppError> {
        match bearer {
            OrgCredentialBearer::Organization(caller) => {
                self.ports.org_actors.actor(caller).await.map(|_| ())
            }
            OrgCredentialBearer::Tenant(caller) => self
                .ports
                .tenant_authorities
                .authority(caller)
                .await
                .map(|_| ()),
        }
    }

    async fn touch_session(&self, bearing: &Bearing, id: &SessionId) -> Result<(), AppError> {
        let store = self.ports.sessions.as_ref();
        let mut session = existing_org_session(store, &bearing.organization_id, id).await?;
        ensure_held_by(session.org_user_id(), bearing)?;
        session.touch();
        store.save(&session).await.or_internal()
    }

    async fn record_key_use(&self, bearing: &Bearing, id: &OrgApiKeyId) -> Result<(), AppError> {
        let store = self.ports.api_keys.as_ref();
        let mut key = existing_api_key(store, &bearing.organization_id, id).await?;
        ensure_held_by(key.created_by(), bearing)?;
        key.record_usage();
        store.save(&key).await.or_internal()
    }
}

impl Command for MarkCredentialUsedUseCase {
    type Caller = OrgCredentialBearer;
    type Input = ();
    type Output = Result<(), AppError>;

    /// Marks the session `bearer` came with active now, or records that
    /// the key they came with signed in now. Nothing is audited: using a
    /// credential is what every request does.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session or key no longer
    ///   counts.
    /// - `AppError::Forbidden` when the caller came with no organization
    ///   credential, or it is another member's.
    /// - `AppError::NotFound` when the organization has no such session or
    ///   key.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        bearer: &OrgCredentialBearer,
        _: &RequestAuditor,
        (): (),
    ) -> Result<(), AppError> {
        let bearing = bearing_of(bearer)?;
        self.ensure_still_counts(bearer).await?;
        match bearing.used {
            Used::Session(id) => self.touch_session(&bearing, &id).await,
            Used::Key(id) => self.record_key_use(&bearing, &id).await,
        }
    }
}

/// Refuses a session or key that is not the bearer's own.
fn ensure_held_by(owner: &OrgUserId, bearing: &Bearing) -> Result<(), AppError> {
    if *owner != bearing.member {
        return Err(AppError::Forbidden(message!(
            "organization-the-credential-is-another-member-s",
            "the credential is another member's"
        )));
    }
    Ok(())
}

/// The member, organization and credential `bearer` came with.
fn bearing_of(bearer: &OrgCredentialBearer) -> Result<Bearing, AppError> {
    match bearer {
        OrgCredentialBearer::Organization(caller) => Ok(Bearing {
            member: *caller.member(),
            organization_id: caller.organization_id(),
            used: used_on_organization(caller.credential()),
        }),
        OrgCredentialBearer::Tenant(caller) => tenant_bearing(caller),
    }
}

fn used_on_organization(credential: &OrgCredential) -> Used {
    match credential {
        OrgCredential::Session(id) => Used::Session(*id),
        OrgCredential::ApiKey(id) => Used::Key(*id),
    }
}

/// The member and credential of a caller inside a tenant, when they came
/// as a member with an organization credential.
fn tenant_bearing(caller: &CallerContext) -> Result<Bearing, AppError> {
    let used = match caller.credential() {
        Credential::OrgSession(id) => Used::Session(*id),
        Credential::OrgApiKey(id) => Used::Key(*id),
        _ => return Err(no_member_credential()),
    };
    let CallerIdentity::OrgUser(member) = caller.identity() else {
        return Err(no_member_credential());
    };
    Ok(Bearing {
        member: *member,
        organization_id: caller.organization_id(),
        used,
    })
}

fn no_member_credential() -> AppError {
    AppError::Forbidden(message!(
        "organization-the-caller-came-with-no-organization",
        "the caller came with no organization credential"
    ))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::access::api_key::MintedThrough;
    use ianua_domain::domains::organization::access::session::OrgSession;
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
    use ianua_domain::shared::clock;
    use ianua_domain::types::TenantId;
    use time::Duration;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, FakeTenantAuthorities, Refusal};
    use crate::test_support::organization::{
        FakeOrgApiKeyStore, RecordingOrgSessionStore, org_session_idle_for, stored_org_api_key,
    };
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_org_caller,
    };

    const IDLE: Duration = Duration::minutes(10);

    struct Fixture {
        sessions: Arc<RecordingOrgSessionStore>,
        keys: Arc<FakeOrgApiKeyStore>,
        session: SessionId,
        key: OrgApiKeyId,
    }

    impl Fixture {
        fn olivias() -> Self {
            Self::held_by(*test_org_caller().member())
        }

        fn held_by(member: OrgUserId) -> Self {
            let organization = test_org_caller().organization_id();
            let session = org_session_idle_for(member, organization, IDLE);
            let key = stored_org_api_key(organization, member, "deploy", MintedThrough::Session);
            Self {
                session: *session.id(),
                key: *key.id(),
                sessions: Arc::new(RecordingOrgSessionStore::holding([session])),
                keys: Arc::new(FakeOrgApiKeyStore::holding([key])),
            }
        }

        fn mark(&self, bearer: &OrgCredentialBearer) -> Result<(), AppError> {
            self.mark_as(bearer, MarkCredentialUsedPorts::fakes())
        }

        fn mark_as(
            &self,
            bearer: &OrgCredentialBearer,
            ports: MarkCredentialUsedPorts,
        ) -> Result<(), AppError> {
            let use_case = MarkCredentialUsedUseCase::new(MarkCredentialUsedPorts {
                sessions: self.sessions.clone(),
                api_keys: self.keys.clone(),
                ..ports
            });
            let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
            block_on(use_case.execute(bearer, &auditor, ()))
        }

        fn session(&self) -> OrgSession {
            self.sessions
                .saved()
                .into_iter()
                .find(|session| session.id() == &self.session)
                .unwrap()
        }

        fn idle_for(&self) -> Duration {
            clock::now() - self.session().last_active_at()
        }

        fn in_tenant(&self) -> OrgCredentialBearer {
            let caller = test_org_caller();
            OrgCredentialBearer::Tenant(
                CallerContext::new(
                    CallerIdentity::OrgUser(*caller.member()),
                    Credential::OrgSession(self.session),
                    caller.organization_id(),
                    TenantId::new(),
                    OrganizationPlan::Free.default_limits(),
                )
                .unwrap(),
            )
        }
    }

    fn on_organization(credential: OrgCredential) -> OrgCredentialBearer {
        let caller = test_org_caller();
        OrgCredentialBearer::Organization(OrgCaller::new(
            *caller.member(),
            credential,
            caller.organization_id(),
        ))
    }

    fn refusing_actors() -> MarkCredentialUsedPorts {
        MarkCredentialUsedPorts {
            org_actors: Arc::new(FakeOrgActors::refusing(Refusal::SignedOut)),
            ..MarkCredentialUsedPorts::fakes()
        }
    }

    /// Olivia works in the organization console on a session she last used
    /// ten minutes ago. Her request marks it active now, so it does not
    /// time out while she works.
    #[test]
    fn a_session_in_use_is_marked_active_now() {
        let fixture = Fixture::olivias();
        let bearer = on_organization(OrgCredential::Session(fixture.session));

        fixture.mark(&bearer).unwrap();

        assert!(fixture.idle_for() < Duration::minutes(1));
    }

    /// Olivia's deploy key signs a request in. The key now shows when it
    /// last signed in.
    #[test]
    fn a_key_in_use_records_when_it_signed_in() {
        let fixture = Fixture::olivias();
        let bearer = on_organization(OrgCredential::ApiKey(fixture.key));

        fixture.mark(&bearer).unwrap();

        let key = fixture.keys.stored(&fixture.key).unwrap();
        assert!(key.last_used_at().is_some());
    }

    /// Olivia works inside one of the organization's tenants on her
    /// organization session. That marks the session active too.
    #[test]
    fn a_session_used_inside_a_tenant_is_marked_active_now() {
        let fixture = Fixture::olivias();

        fixture.mark(&fixture.in_tenant()).unwrap();

        assert!(fixture.idle_for() < Duration::minutes(1));
    }

    /// A signed-out organization caller receives an unauthenticated error,
    /// and the session's idle time is not reset.
    #[test]
    fn a_session_that_no_longer_counts_is_not_marked() {
        let fixture = Fixture::olivias();
        let bearer = on_organization(OrgCredential::Session(fixture.session));

        let result = fixture.mark_as(&bearer, refusing_actors());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(fixture.idle_for() >= IDLE);
    }

    /// A signed-out tenant caller receives an unauthenticated error, and the
    /// organization session's idle time is not reset.
    #[test]
    fn a_session_that_no_longer_counts_in_a_tenant_is_not_marked() {
        let fixture = Fixture::olivias();
        let ports = MarkCredentialUsedPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..MarkCredentialUsedPorts::fakes()
        };

        let result = fixture.mark_as(&fixture.in_tenant(), ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(fixture.idle_for() >= IDLE);
    }

    /// Naming another member's session returns a forbidden error and leaves
    /// its idle time unreset.
    #[test]
    fn another_members_session_is_not_marked() {
        let fixture = Fixture::held_by(OrgUserId::new());
        let bearer = on_organization(OrgCredential::Session(fixture.session));

        let result = fixture.mark(&bearer);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(fixture.idle_for() >= IDLE);
    }

    /// Naming another member's key returns a forbidden error and records no
    /// use of the key.
    #[test]
    fn another_members_key_records_no_use() {
        let fixture = Fixture::held_by(OrgUserId::new());
        let bearer = on_organization(OrgCredential::ApiKey(fixture.key));

        let result = fixture.mark(&bearer);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        let key = fixture.keys.stored(&fixture.key).unwrap();
        assert!(key.last_used_at().is_none());
    }

    /// Ann signs in to the tenant with her own tenant session. It is no
    /// organization credential, so there is nothing here to mark.
    #[test]
    fn a_tenant_users_own_session_is_refused() {
        let fixture = Fixture::olivias();

        let result = fixture.mark(&OrgCredentialBearer::Tenant(test_ctx()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Looking up a session through another organization returns not found
    /// and leaves the session's idle time unreset.
    #[test]
    fn a_session_of_another_organization_is_not_found() {
        let fixture = Fixture::olivias();
        let bearer = OrgCredentialBearer::Organization(OrgCaller::new(
            *test_org_caller().member(),
            OrgCredential::Session(fixture.session),
            OrganizationId::new(),
        ));

        let result = fixture.mark(&bearer);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.idle_for() >= IDLE);
    }
}
