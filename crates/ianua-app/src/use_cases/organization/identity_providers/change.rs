//! Change identity provider: rename the organization's provider, reach it
//! another way, or decide how far its word on addresses and factors counts.
//!
//! Trusting the provider lets it speak for more members, so the caller
//! proves who they are again first: a stolen session alone never widens
//! who the directory signs in.

use std::sync::Arc;

use ianua_domain::domains::federation::connection::{AssuranceTrust, EmailTrust};
use ianua_domain::domains::organization::access::identity_provider::{
    OrgIdentityProvider, OrgIdentityProviderChange,
};
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, Label};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{SealedFor, SecretEncryptor};
use crate::ports::federation::OidcValidator;
use crate::ports::organization::OrgIdentityProviderStore;
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof};
use crate::use_case::Command;
use crate::use_cases::federation::connections::ProviderConfig;
use crate::use_cases::organization::identity_providers::lookup::{
    ensure_manages_sign_in, existing_provider,
};
use crate::use_cases::organization::identity_providers::provider_config::{
    ProviderSealing, provider_secret_place,
};

/// One change to the provider, as the caller gives it.
pub enum OrgProviderEdit {
    /// A new name.
    Rename(Label),
    /// New settings for reaching it, an OIDC client secret in plain text.
    Reconfigure(ProviderConfig),
    /// Whether its addresses are taken on its word.
    TrustEmail(EmailTrust),
    /// Whether its report of factors is taken on its word.
    TrustAssurance(AssuranceTrust),
}

/// The changes to make, with what the caller gave to prove who they are.
pub struct ChangeOrgRequest {
    /// Every change, made together.
    pub edits: Vec<OrgProviderEdit>,
    /// What the caller typed again just now to prove who they are.
    pub proof: ReenteredProof,
}

/// The ports [`ChangeOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeOrgPorts {
    /// Organizations' identity providers.
    pub providers: Arc<dyn OrgIdentityProviderStore>,
    /// Seals a new OIDC client secret before it is kept.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Checks a new OIDC issuer publishes its configuration.
    pub oidc_validator: Arc<dyn OidcValidator>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// Turns what the caller typed again into a fresh proof of them.
    pub fresh_proofs: Arc<dyn FreshProofs>,
}

/// Changes the organization's identity provider.
pub struct ChangeOrgUseCase {
    ports: ChangeOrgPorts,
}

impl ChangeOrgUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeOrgPorts) -> Self {
        Self { ports }
    }

    /// The domain's changes for `edits` to `provider`, a new configuration
    /// checked and sealed.
    async fn changes(
        &self,
        provider: &OrgIdentityProvider,
        edits: Vec<OrgProviderEdit>,
    ) -> Result<Vec<OrgIdentityProviderChange>, AppError> {
        let sealing = ProviderSealing {
            encryptor: self.ports.encryptor.as_ref(),
            oidc_validator: self.ports.oidc_validator.as_ref(),
        };
        let place = provider_secret_place(provider.organization_id(), provider.id());
        let mut changes = Vec::with_capacity(edits.len());
        for edit in edits {
            changes.push(change_of(&sealing, edit, &place).await?);
        }
        Ok(changes)
    }
}

impl Command for ChangeOrgUseCase {
    type Caller = OrgCaller;
    type Input = ChangeOrgRequest;
    type Output = Result<OrgIdentityProvider, AppError>;

    /// Makes every change in `request` once the caller proved who they are
    /// again, and records one `organization.org_identity_provider_changed`.
    /// No change records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without sign-in-settings rights or adequate fresh proof.
    /// - `AppError::StepUpRequired` for a missing factor code; `NotFound` for no organization provider.
    /// - `AppError::Domain` for unusable OIDC configuration or SAML settings requiring signed requests without an organization key.
    /// - `AppError::Internal` on storage, sealing or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: ChangeOrgRequest,
    ) -> Result<OrgIdentityProvider, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        ensure_manages_sign_in(&control, organization.id())?;
        let store = self.ports.providers.as_ref();
        let mut provider = existing_provider(store, organization.id()).await?;
        self.ports
            .fresh_proofs
            .prove_member(
                actor.member(),
                &organization,
                request.proof,
                caller.origin(),
            )
            .await?;
        let changes = self.changes(&provider, request.edits).await?;
        provider
            .change(changes, &control)
            .map_err(AppError::from_domain)?;
        store.save(&provider).await.or_internal()?;
        let by = ActorRef::OrgUser(*actor.member().id());
        auditor
            .dispatch_by(&by, provider.take_events())
            .await
            .or_internal()?;
        Ok(provider)
    }
}

/// The domain's change for `edit`, a new configuration checked and sealed
/// for `place`.
///
/// # Errors
///
/// - `AppError::Domain` when a new OIDC issuer publishes no usable
///   configuration.
/// - `AppError::Internal` when a secret cannot be sealed.
async fn change_of(
    sealing: &ProviderSealing<'_>,
    edit: OrgProviderEdit,
    place: &SealedFor,
) -> Result<OrgIdentityProviderChange, AppError> {
    Ok(match edit {
        OrgProviderEdit::Rename(name) => OrgIdentityProviderChange::Rename(name),
        OrgProviderEdit::Reconfigure(config) => {
            OrgIdentityProviderChange::Reconfigure(sealing.stored(config, place).await?)
        }
        OrgProviderEdit::TrustEmail(trust) => OrgIdentityProviderChange::TrustEmail(trust),
        OrgProviderEdit::TrustAssurance(trust) => OrgIdentityProviderChange::TrustAssurance(trust),
    })
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::{right_password, wrong_password};
    use crate::test_support::organization::{
        FakeOrgIdentityProviderStore, OrgProviderShape, stored_org_provider,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: ChangeOrgUseCase,
        providers: Arc<FakeOrgIdentityProviderStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(actors: FakeOrgActors, providers: FakeOrgIdentityProviderStore) -> Self {
            let providers = Arc::new(providers);
            Self {
                uc: ChangeOrgUseCase::new(ChangeOrgPorts {
                    providers: providers.clone(),
                    org_actors: Arc::new(actors),
                    ..ChangeOrgPorts::fakes()
                }),
                providers,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn connected(role: OrgRole) -> Self {
            let okta = stored_org_provider(acme(), OrgProviderShape::oidc());
            Self::with(
                FakeOrgActors::in_role(role),
                FakeOrgIdentityProviderStore::holding(okta),
            )
        }

        fn change(
            &self,
            edits: Vec<OrgProviderEdit>,
            proof: ReenteredProof,
        ) -> Result<OrgIdentityProvider, AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                ChangeOrgRequest { edits, proof },
            ))
        }

        fn email_trust(&self) -> EmailTrust {
            self.providers.stored(&acme()).unwrap().email_trust()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn acme() -> OrganizationId {
        test_org_caller().organization_id()
    }

    fn trust_addresses() -> Vec<OrgProviderEdit> {
        vec![OrgProviderEdit::TrustEmail(EmailTrust::Authoritative)]
    }

    /// Ann, Acme's owner, knows Okta assigns every address, types her
    /// password again and trusts its addresses. The change is kept and
    /// recorded once.
    #[test]
    fn a_proven_owner_trusts_the_providers_addresses() {
        let setup = Setup::connected(OrgRole::Owner);

        setup.change(trust_addresses(), right_password()).unwrap();

        assert_eq!(setup.email_trust(), EmailTrust::Authoritative);
        assert_eq!(
            setup.recorded(),
            vec!["organization.org_identity_provider_changed"]
        );
    }

    /// Ann renames Okta. Only the name changes.
    #[test]
    fn a_rename_keeps_the_trust() {
        let setup = Setup::connected(OrgRole::Owner);
        let name = Label::new("name", "Acme Directory").unwrap();

        let changed = setup
            .change(
                vec![OrgProviderEdit::Rename(name.clone())],
                right_password(),
            )
            .unwrap();

        assert_eq!(changed.name(), &name);
        assert_eq!(setup.email_trust(), EmailTrust::Unverified);
    }

    /// An incorrect password proof prevents trusting provider addresses;
    /// they remain unverified and no change is recorded.
    #[test]
    fn a_wrong_password_changes_nothing() {
        let setup = Setup::connected(OrgRole::Owner);

        let result = setup.change(trust_addresses(), wrong_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.email_trust(), EmailTrust::Unverified);
        assert!(setup.recorded().is_empty());
    }

    /// A plain member cannot trust provider addresses, which remain unverified.
    #[test]
    fn a_member_without_the_sign_in_right_is_refused() {
        let setup = Setup::connected(OrgRole::Member);

        let result = setup.change(trust_addresses(), right_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.email_trust(), EmailTrust::Unverified);
    }

    /// Ann changes a provider Acme never added. It is not found.
    #[test]
    fn no_provider_is_not_found() {
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Owner),
            FakeOrgIdentityProviderStore::empty(),
        );

        let result = setup.change(trust_addresses(), right_password());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller must authenticate before changing provider trust.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let okta = stored_org_provider(acme(), OrgProviderShape::oidc());
        let setup = Setup::with(
            FakeOrgActors::refusing(Refusal::SignedOut),
            FakeOrgIdentityProviderStore::holding(okta),
        );

        let result = setup.change(trust_addresses(), right_password());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
