//! Confirm installer: the person who installed the platform presents the
//! setup token the install showed them, and the first owner's address is
//! confirmed without a mail server.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::tokens::installation_setup::InstallationSetup;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, OrgUserId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgTokenStore, OrgUserStore};
use crate::use_case::Command;
use crate::use_cases::organization::invitations::offers::address_link::AddressLinks;

/// The ports [`ConfirmInstallerUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ConfirmInstallerPorts {
    /// Loads and saves the first owner.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// The setup token the install issued.
    pub setup_token_store: Arc<dyn OrgTokenStore<InstallationSetup>>,
    /// Hashes the token that was presented.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Confirms the installation's first owner with the setup token.
pub struct ConfirmInstallerUseCase {
    ports: ConfirmInstallerPorts,
}

impl ConfirmInstallerUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ConfirmInstallerPorts) -> Self {
        Self { ports }
    }
}

impl Command for ConfirmInstallerUseCase {
    type Caller = ();
    type Input = String;
    type Output = Result<OrgUserId, AppError>;

    /// Spends the setup token `raw_token` for the first owner it was issued
    /// to, marks their address confirmed and records
    /// `organization.org_user_email_verified`. The token also vouches for
    /// the owner's first sign-in, which may then set up a second factor
    /// even with no mail server to confirm it.
    ///
    /// No session is needed: the token was shown once, to whoever ran the
    /// install, and only founding an installation issues one. It works once,
    /// for at most a day, and only while the owner still has the address it
    /// was issued for.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed.
    /// - `AppError::NotFound` if the token is unknown or already used, or
    ///   the owner is gone.
    /// - `AppError::LinkExpired` if the token ran out, or the owner moved to
    ///   another address since.
    /// - `AppError::Conflict` if the member it names never joined.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        raw_token: String,
    ) -> Result<OrgUserId, AppError> {
        let setup_links = AddressLinks {
            members: self.ports.org_user_store.as_ref(),
            tokens: self.ports.setup_token_store.as_ref(),
            token_generator: self.ports.token_generator.as_ref(),
        };
        let mut owner = setup_links.confirm_installer(&raw_token).await?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*owner.id()), owner.take_events())
            .await
            .or_internal()?;
        Ok(*owner.id())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::address::AddressStanding;
    use ianua_domain::domains::identity::account::vouching::Vouching;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user::{
        OrgPassword, OrgUser, OrgUserRow,
    };
    use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{
        CredentialChange, DisplayName, Email, Joining, OrganizationId, Preference,
    };
    use time::Duration;

    use super::*;
    use crate::test_support::organization::{
        FakeOrgTokenStore, FakeOrgUserStore, cfg, org_user_store_with, stored_org_token,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    const SETUP_TOKEN: &str = "fake_refresh_setup";

    struct Setup {
        uc: ConfirmInstallerUseCase,
        olive: OrgUserId,
        members: Arc<FakeOrgUserStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    /// Olive, the first owner, with her address unconfirmed and a setup
    /// token that runs out `expires_in` from now.
    fn setup(expires_in: Duration) -> Setup {
        let olive = owner_waiting_to_confirm();
        let token =
            stored_org_token::<InstallationSetup>(&olive, SETUP_TOKEN, clock::now() + expires_in);
        let olive_id = *olive.id();
        let members = Arc::new(org_user_store_with([olive]));
        Setup {
            uc: ConfirmInstallerUseCase::new(ConfirmInstallerPorts {
                org_user_store: members.clone(),
                setup_token_store: Arc::new(FakeOrgTokenStore::holding([token])),
                ..ConfirmInstallerPorts::fakes()
            }),
            olive: olive_id,
            members,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    /// The owner the install made: active, with an address nobody has
    /// confirmed yet, and nothing vouching for her.
    fn owner_waiting_to_confirm() -> OrgUser {
        let now = clock::now();
        OrgUser::reconstitute(OrgUserRow {
            id: OrgUserId::new(),
            organization_id: OrganizationId::new(),
            email: Email::new("olive@acme.test").unwrap(),
            display_name: DisplayName::new("Olive", &cfg().display_name).unwrap(),
            password_hash: OrgPassword::NotSet,
            status: OrgUserStatus::Active,
            role: OrgRole::Owner,
            email_standing: AddressStanding::Unverified,
            locale: Preference::Inherited,
            timezone: Preference::Inherited,
            created_at: now,
            updated_at: now,
            joining: Joining::Joined { at: now },
            credentials_changed_at: CredentialChange::Never,
            vouching: Vouching::Absent,
        })
        .unwrap()
    }

    fn confirm(setup: &Setup) -> Result<OrgUserId, AppError> {
        block_on(setup.uc.execute(
            &(),
            &test_auditor(setup.audit.clone()),
            SETUP_TOKEN.to_owned(),
        ))
    }

    fn olive(setup: &Setup) -> OrgUser {
        block_on(setup.members.find_by_id(&setup.olive))
            .unwrap()
            .unwrap()
    }

    fn olive_is_confirmed(setup: &Setup) -> bool {
        olive(setup).email_verified()
    }

    /// Olive presents the setup token her install printed. Her address is
    /// confirmed without any mail, the token vouches for her first sign-in,
    /// and it is recorded.
    #[test]
    fn the_setup_token_confirms_the_first_owner() {
        let setup = setup(Duration::hours(1));

        let confirmed = confirm(&setup).unwrap();

        assert_eq!(confirmed, setup.olive);
        assert!(olive_is_confirmed(&setup));
        assert_eq!(olive(&setup).vouching(), Vouching::Fresh);
        assert_eq!(
            setup.audit.records.lock().unwrap().clone(),
            vec!["organization.org_user_email_verified"]
        );
    }

    /// Replaying the installation setup token after confirmation returns not found.
    #[test]
    fn a_replayed_setup_token_is_refused() {
        let setup = setup(Duration::hours(1));
        confirm(&setup).unwrap();

        let replayed = confirm(&setup);

        assert!(matches!(replayed, Err(AppError::NotFound(_))));
    }

    /// An expired setup token is rejected and leaves the first owner's
    /// address unconfirmed.
    #[test]
    fn an_expired_setup_token_is_refused() {
        let setup = setup(Duration::hours(-1));

        let result = confirm(&setup);

        assert!(matches!(result, Err(AppError::LinkExpired(_))));
        assert!(!olive_is_confirmed(&setup));
    }

    /// An unknown installation setup token cannot confirm an owner.
    #[test]
    fn an_unknown_setup_token_is_not_found() {
        let uc = ConfirmInstallerUseCase::new(ConfirmInstallerPorts::fakes());

        let result = block_on(uc.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            SETUP_TOKEN.to_owned(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
