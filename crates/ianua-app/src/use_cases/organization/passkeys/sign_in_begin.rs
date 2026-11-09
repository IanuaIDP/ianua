//! Beginning a member's passkey sign-in from the address they typed: a
//! ceremony is opened over their passkeys and kept on the server, and the
//! browser gets only its challenge.
//!
//! The sign-in page carries no organization. An address is unique within an
//! organization only, so it may name a member in several. When one of them
//! holds passkeys, the ceremony is bound to that member. When several do,
//! the ceremony opens for nobody, as a discoverable one does, and the
//! passkey that answers names its member: the choice of organization is
//! bound to the proof.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::passkey::PasskeyCredential;
use ianua_domain::domains::authentication::credentials::passkey_ceremony::TargetedPurpose;
use ianua_domain::domains::organization::access::passkey::OrgPasskeyCeremony;
use ianua_domain::domains::organization::events::access::{
    OrgPasskeyChallengeIssued, OrgPasskeySignInStarted,
};
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::types::{ActorRef, CeremonyId, Email, Lifetime, OrgUserId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::PasskeyVerifier;
use crate::ports::organization::{OrgPasskeyCeremonyStore, OrgPasskeyStore, OrgUserStore};
use crate::use_case::Command;
use crate::use_cases::organization::passkeys::challenge::{OrgPasskeyStarted, opened_for_nobody};

/// The ports [`OrgLoginBeginUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgLoginBeginPorts {
    /// Finds the member an address names.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// The member's passkeys.
    pub passkey_store: Arc<dyn OrgPasskeyStore>,
    /// Makes the `WebAuthn` challenge.
    pub verifier: Arc<dyn PasskeyVerifier>,
    /// Keeps the ceremony's state the client must not see.
    pub ceremony_store: Arc<dyn OrgPasskeyCeremonyStore>,
}

/// Opens a passkey sign-in for the member an address names.
pub struct OrgLoginBeginUseCase {
    ttl: Lifetime,
    ports: OrgLoginBeginPorts,
}

/// A member holding passkeys under an address, with their passkeys.
type PasskeyHolder = (OrgUser, Vec<PasskeyCredential<ResolvedOrganization>>);

impl OrgLoginBeginUseCase {
    /// A use case opening ceremonies that last `ttl`, through `ports`.
    #[must_use]
    pub fn new(ttl: Lifetime, ports: OrgLoginBeginPorts) -> Self {
        Self { ttl, ports }
    }

    /// Every member `email` names who holds passkeys, one per
    /// organization, with their passkeys.
    async fn holders_with_passkeys(&self, email: &Email) -> Result<Vec<PasskeyHolder>, AppError> {
        let members = self
            .ports
            .org_user_store
            .find_all_by_email(email)
            .await
            .or_internal()?;
        if members.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<_> = members.iter().map(|member| *member.id()).collect();
        let keys = self
            .ports
            .passkey_store
            .list_by_users(&ids)
            .await
            .or_internal()?;
        let mut by_member: HashMap<OrgUserId, Vec<_>> = HashMap::new();
        for key in keys {
            by_member.entry(*key.user_id()).or_default().push(key);
        }
        Ok(members
            .into_iter()
            .filter_map(|member| by_member.remove(member.id()).map(|keys| (member, keys)))
            .collect())
    }

    /// Opens and keeps a ceremony for nobody, for the passkey that answers
    /// to name its member among several, and records the challenge.
    async fn opened_for_any(
        &self,
        auditor: &RequestAuditor,
    ) -> Result<OrgPasskeyStarted, AppError> {
        let verifier = self.ports.verifier.as_ref();
        let ceremonies = self.ports.ceremony_store.as_ref();
        let started = opened_for_nobody(verifier, ceremonies, self.ttl).await?;
        auditor
            .dispatch_by(
                &ActorRef::System,
                vec![OrgPasskeyChallengeIssued::observed()],
            )
            .await
            .or_internal()?;
        Ok(started)
    }

    /// Opens the ceremony bound to `member` over `passkeys`, and records
    /// the start against them.
    async fn opened_bound(
        &self,
        auditor: &RequestAuditor,
        member: &OrgUser,
        passkeys: &[PasskeyCredential<ResolvedOrganization>],
    ) -> Result<OrgPasskeyStarted, AppError> {
        let started = self.opened_for(member, passkeys).await?;
        auditor
            .dispatch_by(
                &ActorRef::System,
                vec![OrgPasskeySignInStarted::observed(member)],
            )
            .await
            .or_internal()?;
        Ok(started)
    }

    /// Opens and keeps a ceremony for `member` over `passkeys`, handing
    /// back the browser's challenge for it.
    async fn opened_for(
        &self,
        member: &OrgUser,
        passkeys: &[PasskeyCredential<ResolvedOrganization>],
    ) -> Result<OrgPasskeyStarted, AppError> {
        let keys: Vec<Vec<u8>> = passkeys.iter().map(|p| p.public_key().to_vec()).collect();
        let started = self
            .ports
            .verifier
            .start_authentication(&keys)
            .await
            .or_internal()?;
        let ceremony = OrgPasskeyCeremony::open(
            *member.id(),
            TargetedPurpose::Authentication,
            started.server_state,
            self.ttl,
        );
        self.ports
            .ceremony_store
            .save(&ceremony)
            .await
            .or_internal()?;
        Ok(OrgPasskeyStarted {
            ceremony_id: *ceremony.id(),
            challenge: started.client_payload,
        })
    }
}

impl Command for OrgLoginBeginUseCase {
    type Caller = ();
    type Input = Email;
    type Output = Result<OrgPasskeyStarted, AppError>;

    /// Opens a ceremony over the passkeys of the member `email` names and
    /// hands back the browser's challenge. Records
    /// `organization.org_passkey_sign_in_started`. When members of several
    /// organizations hold passkeys under the address, the ceremony opens
    /// for nobody and records `organization.org_passkey_challenge_issued`:
    /// the passkey that answers names the member.
    ///
    /// An unknown address, or a member without passkeys, gets a decoy of
    /// the same shape, no stored ceremony and no record, so neither the
    /// answer nor the audit log tells which addresses have accounts.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the challenge cannot be made or the
    ///   ceremony cannot be stored or recorded.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        email: Email,
    ) -> Result<OrgPasskeyStarted, AppError> {
        let holders = self.holders_with_passkeys(&email).await?;
        match holders.as_slice() {
            [] => unanswerable_challenge(self.ports.verifier.as_ref(), &email).await,
            [(member, passkeys)] => self.opened_bound(auditor, member, passkeys).await,
            _ => self.opened_for_any(auditor).await,
        }
    }
}

/// A real, fresh challenge naming a ceremony that was never kept, for
/// `email`, which cannot answer one. Confirming it reports an unknown
/// challenge, as a real one does once it expires, and it lists a
/// credential as a real member's does, so it looks like any other.
async fn unanswerable_challenge(
    verifier: &dyn PasskeyVerifier,
    email: &Email,
) -> Result<OrgPasskeyStarted, AppError> {
    let started = verifier
        .start_decoy_authentication(email)
        .await
        .or_internal()?;
    Ok(OrgPasskeyStarted {
        ceremony_id: CeremonyId::new(),
        challenge: started.client_payload,
    })
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::authentication::{another_yubikey, ceremony_lifetime};
    use crate::test_support::organization::{
        FakeOrgPasskeyCeremonyStore, FakeOrgPasskeyStore, org_user_store_with, test_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    const ADDRESS: &str = "olivia@acme.test";

    struct Fixture {
        use_case: OrgLoginBeginUseCase,
        ceremonies: Arc<FakeOrgPasskeyCeremonyStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn olivia_holding(passkeys: impl FnOnce(&OrgUser) -> FakeOrgPasskeyStore) -> Self {
            let olivia = test_org_user(OrganizationId::new(), ADDRESS, OrgRole::Member);
            let store = passkeys(&olivia);
            let ceremonies = Arc::new(FakeOrgPasskeyCeremonyStore::new());
            let members = org_user_store_with([olivia]);
            Self {
                use_case: OrgLoginBeginUseCase::new(
                    ceremony_lifetime(),
                    OrgLoginBeginPorts {
                        org_user_store: Arc::new(members),
                        passkey_store: Arc::new(store),
                        ceremony_store: ceremonies.clone(),
                        ..OrgLoginBeginPorts::fakes()
                    },
                ),
                ceremonies,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn begin(&self, address: &str) -> OrgPasskeyStarted {
            block_on(self.use_case.execute(
                &(),
                &test_auditor(self.audit.clone()),
                Email::new(address).unwrap(),
            ))
            .unwrap()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn holding_one(member: &OrgUser) -> FakeOrgPasskeyStore {
        FakeOrgPasskeyStore::with_passkey(*member.organization_id(), *member.id())
    }

    /// Keeps a passkey for each account sharing Olivia's address.
    fn holding_both(acme: &OrgUser, globex: &OrgUser) -> Arc<FakeOrgPasskeyStore> {
        let passkeys = Arc::new(holding_one(acme));
        let globex_key: PasskeyCredential<ResolvedOrganization> = another_yubikey(*globex.id());
        block_on(passkeys.save(globex.organization_id(), globex.id(), &globex_key)).unwrap();
        passkeys
    }

    /// Olivia types her address. A ceremony bound to her is kept and the
    /// start recorded.
    #[test]
    fn a_member_with_a_passkey_gets_a_ceremony_bound_to_her() {
        let fixture = Fixture::olivia_holding(holding_one);

        let started = fixture.begin(ADDRESS);

        let kept = block_on(fixture.ceremonies.find_by_id(&started.ceremony_id))
            .unwrap()
            .unwrap();
        assert!(kept.org_user_id().is_some());
        assert_eq!(
            fixture.recorded(),
            vec!["organization.org_passkey_sign_in_started"]
        );
    }

    /// Olivia holds passkeys at Acme and at Globex under one address. The
    /// ceremony opens for nobody, so the passkey she answers with names
    /// the organization she signs in to.
    #[test]
    fn an_address_with_passkeys_in_two_organizations_opens_for_nobody() {
        let acme = test_org_user(OrganizationId::new(), ADDRESS, OrgRole::Member);
        let globex = test_org_user(OrganizationId::new(), ADDRESS, OrgRole::Member);
        let passkeys = holding_both(&acme, &globex);
        let ceremonies = Arc::new(FakeOrgPasskeyCeremonyStore::new());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = OrgLoginBeginUseCase::new(
            ceremony_lifetime(),
            OrgLoginBeginPorts {
                org_user_store: Arc::new(org_user_store_with([acme, globex])),
                passkey_store: passkeys.clone(),
                ceremony_store: ceremonies.clone(),
                ..OrgLoginBeginPorts::fakes()
            },
        );

        let started = block_on(use_case.execute(
            &(),
            &test_auditor(audit.clone()),
            Email::new(ADDRESS).unwrap(),
        ))
        .unwrap();

        let kept = block_on(ceremonies.find_by_id(&started.ceremony_id))
            .unwrap()
            .unwrap();
        assert!(kept.org_user_id().is_none());
        assert_eq!(passkeys.member_reads(), 1);
        assert_eq!(
            *audit.records.lock().unwrap(),
            vec!["organization.org_passkey_challenge_issued"]
        );
    }

    /// An unknown address receives a challenge without a stored ceremony
    /// or audit record.
    #[test]
    fn an_unknown_address_gets_a_decoy() {
        let fixture = Fixture::olivia_holding(holding_one);

        fixture.begin("nobody@acme.test");

        assert_eq!(fixture.ceremonies.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// A member without passkeys receives a challenge without a stored
    /// ceremony or audit record, as an unknown address does.
    #[test]
    fn a_member_without_passkeys_gets_a_decoy() {
        let fixture = Fixture::olivia_holding(|_| FakeOrgPasskeyStore::empty());

        fixture.begin(ADDRESS);

        assert_eq!(fixture.ceremonies.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// The verifier's decoy challenge matches its challenge for a member
    /// with a passkey.
    #[test]
    fn a_decoy_lists_credentials_as_a_real_challenge_does() {
        let fixture = Fixture::olivia_holding(holding_one);

        let real = fixture.begin(ADDRESS);
        let decoy = fixture.begin("nobody@acme.test");

        assert_eq!(decoy.challenge, real.challenge);
    }
}
