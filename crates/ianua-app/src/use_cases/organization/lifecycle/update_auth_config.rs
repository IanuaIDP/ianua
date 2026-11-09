//! Replacing an organization's sign-in settings.
//!
//! Everything about how members reach the management plane: which methods
//! are allowed, how strong a password has to be, whether a second factor is
//! demanded, how long sessions last, when an account locks, where members
//! may sign in from, and when a sign-in must clear more than a password.
//!
//! Replaced whole rather than patched: the settings are checked when they
//! are built, and their rules only hold across the whole. The owner proves
//! who they are again first, so a stolen session alone never weakens how
//! the organization is protected.

use std::sync::Arc;

use ianua_domain::domains::organization::access::auth_config::OrganizationAuthConfig;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::domains::organization::members::permission::{OrgPermission, OrganizationAction};
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::ActorRef;

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::TextMessaging;
use crate::ports::organization::OrganizationStore;
use crate::ports::shared::MailSetup;
use crate::services::authentication::channels::Channels;
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof};
use crate::use_case::Command;

/// New sign-in settings, with what the caller gave to prove who they are.
pub struct UpdateOrganizationAuthConfigRequest {
    /// The complete settings that replace the current ones.
    pub config: OrganizationAuthConfig,
    /// What the caller typed again just now to prove who they are.
    pub proof: ReenteredProof,
}

/// The ports [`UpdateOrganizationAuthConfigUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdateOrganizationAuthConfigPorts {
    /// Loads and saves the organization's sign-in policy.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// Turns what the caller typed again into a fresh proof of them.
    pub fresh_proofs: Arc<dyn FreshProofs>,
    /// Whether codes can be texted here, before texted codes are offered.
    pub text_messaging: Arc<dyn TextMessaging>,
    /// Whether anything can be mailed here, before mailed codes or magic
    /// links are offered.
    pub mail: Arc<dyn MailSetup>,
}

/// Replaces the caller's organization's sign-in settings.
pub struct UpdateOrganizationAuthConfigUseCase {
    ports: UpdateOrganizationAuthConfigPorts,
}

impl UpdateOrganizationAuthConfigUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: UpdateOrganizationAuthConfigPorts) -> Self {
        Self { ports }
    }

    /// Refuses `after` when it newly offers a factor or a way in this
    /// deployment cannot deliver: texted codes with nothing to text them,
    /// mailed codes or magic links with no mail server.
    fn ensure_deliverable(
        &self,
        before: &OrganizationAuthConfig,
        after: &OrganizationAuthConfig,
    ) -> Result<(), AppError> {
        let channels = Channels::of(&self.ports.text_messaging, &self.ports.mail);
        channels.ensure_newly_deliverable(before.into(), after.into())
    }
}

impl Command for UpdateOrganizationAuthConfigUseCase {
    type Caller = OrgCaller;
    type Input = UpdateOrganizationAuthConfigRequest;
    type Output = Result<(), AppError>;

    /// Puts `request.config` in force for `caller`'s organization once they
    /// proved who they are again, and records
    /// `organization.auth_config_updated`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without settings rights, through an API key, for inadequate proof or settings excluding the caller's sign-in.
    /// - `AppError::StepUpRequired` for a missing factor code; `AccountLocked` after too many wrong codes.
    /// - `AppError::Domain` for a closed organization or newly offered text/mail factors or magic links without their delivery provider.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: UpdateOrganizationAuthConfigRequest,
    ) -> Result<(), AppError> {
        let (mut organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        ensure_may_set_sign_in(&control, &organization)?;
        self.ports
            .fresh_proofs
            .prove_member(
                actor.member(),
                &organization,
                request.proof,
                caller.origin(),
            )
            .await?;
        self.ensure_deliverable(organization.auth_config(), &request.config)?;
        organization
            .replace_auth_config(request.config, &control)
            .map_err(AppError::from_domain)?;
        self.ports
            .organizations
            .save(&organization)
            .await
            .or_internal()?;
        let by = ActorRef::OrgUser(*actor.member().id());
        auditor
            .dispatch_by(&by, organization.take_events())
            .await
            .or_internal()
    }
}

/// Refuses a member who may not set how `organization`'s members sign in.
fn ensure_may_set_sign_in(
    control: &OrgControl<'_>,
    organization: &Organization,
) -> Result<(), AppError> {
    control
        .ensure_may(
            organization.id(),
            OrgPermission::Organization(OrganizationAction::AuthConfig),
        )
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::organization::access::auth_config::OrganizationAuthSettings;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::Scope;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::{right_password, wrong_password};
    use crate::test_support::organization::FakeOrganizationStore;
    use crate::test_support::{
        Fake, FakeEventDispatcher, FakeMailSetup, block_on, test_auditor, test_org_caller,
    };

    struct Setup {
        uc: UpdateOrganizationAuthConfigUseCase,
        orgs: Arc<FakeOrganizationStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn as_member(actors: FakeOrgActors) -> Self {
            Self::reaching(actors, Fake::fake())
        }

        fn reaching(actors: FakeOrgActors, mail: Arc<dyn MailSetup>) -> Self {
            let orgs = Arc::new(FakeOrganizationStore::empty());
            Self {
                uc: UpdateOrganizationAuthConfigUseCase::new(UpdateOrganizationAuthConfigPorts {
                    organizations: orgs.clone(),
                    org_actors: Arc::new(actors),
                    mail,
                    ..UpdateOrganizationAuthConfigPorts::fakes()
                }),
                orgs,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn owner() -> Self {
            Self::as_member(FakeOrgActors::in_role(OrgRole::Owner))
        }

        /// Acme's owner, on a deployment with no mail server.
        fn owner_without_mail() -> Self {
            Self::reaching(
                FakeOrgActors::in_role(OrgRole::Owner),
                FakeMailSetup::not_set_up(),
            )
        }

        fn save(&self, request: UpdateOrganizationAuthConfigRequest) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                request,
            ))
        }

        fn stored(&self) -> Option<OrganizationAuthConfig> {
            self.orgs
                .stored(&test_org_caller().organization_id())
                .map(|organization| organization.auth_config().clone())
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn three_attempts() -> OrganizationAuthConfig {
        OrganizationAuthConfig::new(OrganizationAuthSettings {
            max_login_attempts: 3,
            ..OrganizationAuthSettings::default()
        })
        .unwrap()
    }

    fn passkeys_only() -> OrganizationAuthConfig {
        OrganizationAuthConfig::new(OrganizationAuthSettings {
            enabled_methods: vec![AuthMethod::Passkey],
            ..OrganizationAuthSettings::default()
        })
        .unwrap()
    }

    fn proved(config: OrganizationAuthConfig) -> UpdateOrganizationAuthConfigRequest {
        UpdateOrganizationAuthConfigRequest {
            config,
            proof: right_password(),
        }
    }

    /// Olivia, Acme's owner, types her password again and allows three
    /// attempts before a lockout. The settings are saved and the change
    /// recorded.
    #[test]
    fn a_saved_config_is_the_one_that_comes_back() {
        let setup = Setup::owner();

        setup.save(proved(three_attempts())).unwrap();

        assert_eq!(setup.stored().unwrap().max_login_attempts(), 3);
        assert_eq!(setup.recorded(), vec!["organization.auth_config_updated"]);
    }

    /// An owner signed in by password cannot restrict sign-in to passkeys;
    /// no settings are saved and no change is recorded.
    #[test]
    fn settings_that_shut_out_the_caller_are_refused() {
        let setup = Setup::owner();

        let result = setup.save(proved(passkeys_only()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.stored().is_none());
        assert!(setup.recorded().is_empty());
    }

    fn magic_links() -> OrganizationAuthConfig {
        OrganizationAuthConfig::new(OrganizationAuthSettings {
            enabled_methods: vec![
                AuthMethod::Password,
                AuthMethod::Passkey,
                AuthMethod::MagicLink,
            ],
            ..OrganizationAuthSettings::default()
        })
        .unwrap()
    }

    /// Enabling magic links without mail delivery is refused, with no settings
    /// save or audit record.
    #[test]
    fn newly_enabling_magic_links_where_nothing_is_mailed_is_refused() {
        let setup = Setup::owner_without_mail();

        let result = setup.save(proved(magic_links()));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.stored().is_none());
        assert!(setup.recorded().is_empty());
    }

    /// With a mail server set up, Olivia may switch magic links on.
    #[test]
    fn magic_links_are_allowed_where_mail_goes_out() {
        let setup = Setup::owner();

        setup.save(proved(magic_links())).unwrap();

        assert!(
            setup
                .stored()
                .unwrap()
                .is_method_enabled(AuthMethod::MagicLink)
        );
    }

    /// An incorrect password proof prevents changing the lockout settings,
    /// and no settings are saved.
    #[test]
    fn a_wrong_password_is_refused() {
        let setup = Setup::owner();

        let result = setup.save(UpdateOrganizationAuthConfigRequest {
            config: three_attempts(),
            proof: wrong_password(),
        });

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.stored().is_none());
    }

    /// A plain member cannot replace the organization's sign-in settings.
    #[test]
    fn a_plain_member_is_refused() {
        let setup = Setup::as_member(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.save(proved(three_attempts()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An API key cannot replace sign-in settings even with the matching
    /// scope and correct password; no settings are saved.
    #[test]
    fn a_key_is_refused() {
        let auth_config = OrgPermission::Organization(OrganizationAction::AuthConfig);
        let setup = Setup::as_member(FakeOrgActors::through_key(
            OrgRole::Owner,
            vec![Scope::new(auth_config.to_string()).unwrap()],
        ));

        let result = setup.save(proved(three_attempts()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.stored().is_none());
    }

    /// A signed-out caller must authenticate before replacing sign-in settings.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::as_member(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.save(proved(three_attempts()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents replacing sign-in settings.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let setup = Setup::as_member(FakeOrgActors::refusing(Refusal::Forbidden));

        let result = setup.save(proved(three_attempts()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
