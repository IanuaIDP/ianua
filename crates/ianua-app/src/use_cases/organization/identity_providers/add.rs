//! Add identity provider: connect the organization's company directory, for
//! its members to sign in to the dashboard through.
//!
//! The provider starts switched off and trusting nothing it says, so nobody
//! is signed in through it before an owner checked it and switched it on.

use std::sync::Arc;

use ianua_domain::domains::organization::access::identity_provider::{
    NewOrgIdentityProvider, OrgIdentityProvider,
};
use ianua_domain::message;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, ConnectionId, Label, OrganizationId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::federation::OidcValidator;
use crate::ports::organization::OrgIdentityProviderStore;
use crate::use_case::Command;
use crate::use_cases::federation::connections::ProviderConfig;
use crate::use_cases::organization::identity_providers::lookup::ensure_manages_sign_in;
use crate::use_cases::organization::identity_providers::provider_config::{
    ProviderSealing, provider_secret_place,
};

/// The provider to add. Holds an OIDC client secret in plain text, so it
/// has no `Debug`.
pub struct AddOrgRequest {
    /// The name members see on the sign-in page.
    pub name: Label,
    /// How it is reached, over SAML or OIDC.
    pub config: ProviderConfig,
}

/// The ports [`AddOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AddOrgPorts {
    /// Organizations' identity providers.
    pub providers: Arc<dyn OrgIdentityProviderStore>,
    /// Seals an OIDC client secret before it is kept.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Checks an OIDC issuer publishes its configuration.
    pub oidc_validator: Arc<dyn OidcValidator>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Adds the organization's identity provider.
pub struct AddOrgUseCase {
    ports: AddOrgPorts,
}

impl AddOrgUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AddOrgPorts) -> Self {
        Self { ports }
    }

    /// What a configuration is checked and sealed with.
    fn sealing(&self) -> ProviderSealing<'_> {
        ProviderSealing {
            encryptor: self.ports.encryptor.as_ref(),
            oidc_validator: self.ports.oidc_validator.as_ref(),
        }
    }
}

impl Command for AddOrgUseCase {
    type Caller = OrgCaller;
    type Input = AddOrgRequest;
    type Output = Result<OrgIdentityProvider, AppError>;

    /// Adds `request`'s provider to the caller's organization, switched off
    /// and untrusted, and records `organization.org_identity_provider_added`.
    /// An OIDC client secret is kept sealed, and never recorded.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the
    ///   organization's sign-in settings.
    /// - `AppError::Conflict` when the organization has a provider already.
    /// - `AppError::Domain` when an OIDC issuer publishes no usable
    ///   configuration, or SAML settings ask for signed sign-in requests,
    ///   which an organization holds no key to sign.
    /// - `AppError::Internal` on storage, sealing or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: AddOrgRequest,
    ) -> Result<OrgIdentityProvider, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        ensure_manages_sign_in(&control, organization.id())?;
        ensure_none_yet(self.ports.providers.as_ref(), organization.id()).await?;
        let id = ConnectionId::new();
        let place = provider_secret_place(organization.id(), &id);
        let config = self.sealing().stored(request.config, &place).await?;
        let new = NewOrgIdentityProvider {
            id,
            organization_id: *organization.id(),
            name: request.name,
            config,
        };
        let mut provider =
            OrgIdentityProvider::add(new, &control).map_err(AppError::from_domain)?;
        self.ports.providers.save(&provider).await.or_internal()?;
        let by = ActorRef::OrgUser(*actor.member().id());
        auditor
            .dispatch_by(&by, provider.take_events())
            .await
            .or_internal()?;
        Ok(provider)
    }
}

/// Refuses a second provider: the organization signs its members in
/// through one directory.
///
/// # Errors
///
/// - `AppError::Conflict` when the organization has a provider already.
/// - `AppError::Internal` on storage failure.
async fn ensure_none_yet(
    store: &dyn OrgIdentityProviderStore,
    organization_id: &OrganizationId,
) -> Result<(), AppError> {
    let existing = store
        .find_for_organization(organization_id)
        .await
        .or_internal()?;
    match existing {
        None => Ok(()),
        Some(_) => Err(AppError::Conflict(message!(
            "organization-the-organization-has-an-identity-provider",
            "the organization has an identity provider already"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::federation::connection::{
        AssuranceTrust, ConnectionConfig, EmailTrust,
    };
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::HttpsUrl;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::federation::test_saml_provider_config;
    use crate::test_support::organization::{
        FakeOrgIdentityProviderStore, OrgProviderShape, org_provider_secret_place,
        stored_org_provider,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};
    use crate::use_cases::federation::connections::OidcProviderConfig;

    struct Setup {
        uc: AddOrgUseCase,
        providers: Arc<FakeOrgIdentityProviderStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(actors: FakeOrgActors, providers: FakeOrgIdentityProviderStore) -> Self {
            let providers = Arc::new(providers);
            Self {
                uc: AddOrgUseCase::new(AddOrgPorts {
                    providers: providers.clone(),
                    org_actors: Arc::new(actors),
                    ..AddOrgPorts::fakes()
                }),
                providers,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn as_role(role: OrgRole) -> Self {
            Self::with(
                FakeOrgActors::in_role(role),
                FakeOrgIdentityProviderStore::empty(),
            )
        }

        fn add(&self, config: ProviderConfig) -> Result<OrgIdentityProvider, AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                AddOrgRequest {
                    name: Label::new("name", "Acme Okta").unwrap(),
                    config,
                },
            ))
        }

        fn stored(&self) -> Option<OrgIdentityProvider> {
            self.providers.stored(&test_org_caller().organization_id())
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn okta_saml() -> ProviderConfig {
        test_saml_provider_config()
    }

    fn okta_oidc() -> ProviderConfig {
        ProviderConfig::Oidc(OidcProviderConfig {
            issuer: HttpsUrl::new("https://acme.okta.com").unwrap(),
            client_id: Label::new("client_id", "ianua-dashboard").unwrap(),
            client_secret: Secret::new("typed-client-secret"),
            scopes: Vec::new(),
        })
    }

    /// Ann, Acme's owner, adds Acme's Okta over SAML. It is kept switched
    /// off and trusting nothing, and the addition is recorded.
    #[test]
    fn a_new_provider_is_kept_switched_off_and_untrusted() {
        let setup = Setup::as_role(OrgRole::Owner);

        setup.add(okta_saml()).unwrap();

        let stored = setup.stored().unwrap();
        assert_eq!(stored.status(), ConnectionStatus::Disabled);
        assert_eq!(stored.email_trust(), EmailTrust::Unverified);
        assert_eq!(stored.assurance_trust(), AssuranceTrust::Untrusted);
        assert_eq!(
            setup.recorded(),
            vec!["organization.org_identity_provider_added"]
        );
    }

    /// Ann adds Okta over OIDC with the client secret Okta gave her. Only
    /// its sealed form is kept.
    #[test]
    fn an_oidc_client_secret_is_kept_sealed() {
        let setup = Setup::as_role(OrgRole::Owner);

        setup.add(okta_oidc()).unwrap();

        let stored = setup.stored().unwrap();
        let ConnectionConfig::Oidc(kept) = stored.config().clone() else {
            panic!("an OIDC provider was added");
        };
        let place = org_provider_secret_place(*stored.organization_id(), stored.id());
        assert_eq!(
            kept.encrypted_client_secret,
            FakeEncryptor::sealed_for("typed-client-secret", &place)
        );
    }

    /// Ann adds a second directory while Okta is connected. It is refused
    /// as a conflict and the first stays.
    #[test]
    fn a_second_provider_is_refused() {
        let acme = test_org_caller().organization_id();
        let okta = stored_org_provider(acme, OrgProviderShape::saml());
        let okta_id = *okta.id();
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Owner),
            FakeOrgIdentityProviderStore::holding(okta),
        );

        let result = setup.add(okta_oidc());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(setup.stored().unwrap().id(), &okta_id);
        assert!(setup.recorded().is_empty());
    }

    /// A plain member cannot add an identity provider; none is stored and
    /// no addition is recorded.
    #[test]
    fn a_member_without_the_sign_in_right_is_refused() {
        let setup = Setup::as_role(OrgRole::Member);

        let result = setup.add(okta_saml());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.providers.count(), 0);
        assert!(setup.recorded().is_empty());
    }

    /// A signed-out caller cannot add a provider, leaving the store empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(
            FakeOrgActors::refusing(Refusal::SignedOut),
            FakeOrgIdentityProviderStore::empty(),
        );

        let result = setup.add(okta_saml());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(setup.providers.count(), 0);
    }
}
