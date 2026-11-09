//! The integrations this deployment has installed, each under its own key.

use std::sync::Arc;

use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::domains::workflows::integration::events::ServiceEventSpec;
use ianua_domain::domains::workflows::integration::profile::IntegrationProfile;
use ianua_domain::shared::errors::DomainError;
use ianua_integration::Integration;

/// The installed integrations, each key once, shared by the catalog, the
/// runner and the account checks so all read the same set.
pub struct Installed {
    integrations: Vec<Arc<dyn Integration>>,
}

impl Installed {
    /// The set of `integrations`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the wiring is wrong: two
    /// share a key, so a step could reach an integration it was not checked
    /// against; one declares an operation or an event under another
    /// integration's key; one explains its operations or events other than
    /// one guide each, naming exactly the inputs or filters each takes, so a
    /// builder would be told about inputs that do not exist; one fills a
    /// form's picker from an operation it does not offer as a read; or one offers
    /// events with nothing to register them, or the other way round.
    pub fn new(integrations: Vec<Arc<dyn Integration>>) -> Result<Self, DomainError> {
        for (place, integration) in integrations.iter().enumerate() {
            ensure_declares_its_own(integration.as_ref())?;
            ensure_explains_each(integration.as_ref())?;
            ensure_events_fit(integration.as_ref())?;
            let twice = integrations
                .iter()
                .skip(place.saturating_add(1))
                .any(|other| other.key() == integration.key());
            if twice {
                return Err(DomainError::infra_msg(
                    "two integrations are installed under one key",
                ));
            }
        }
        Ok(Self { integrations })
    }

    /// How every integration presents itself, each once.
    pub(crate) fn profiles(&self) -> Vec<IntegrationProfile> {
        self.integrations
            .iter()
            .map(|integration| integration.profile().clone())
            .collect()
    }

    /// The integration installed under `key`.
    pub(crate) fn find(&self, key: &IntegrationKey) -> Option<&dyn Integration> {
        self.integrations
            .iter()
            .find(|integration| integration.key() == key)
            .map(|integration| &**integration)
    }
}

/// Refuses an integration declaring an operation under another key.
fn ensure_declares_its_own(integration: &dyn Integration) -> Result<(), DomainError> {
    let foreign = integration
        .operations()
        .iter()
        .any(|spec| spec.integration() != integration.key());
    if foreign {
        return Err(DomainError::infra_msg(
            "an integration declares an operation under another key",
        ));
    }
    Ok(())
}

/// Refuses an integration whose events are not its own, are not explained
/// one guide each naming exactly their filters, or have nothing to
/// register them; or that can register events it does not offer.
fn ensure_events_fit(integration: &dyn Integration) -> Result<(), DomainError> {
    let events = integration.events();
    ensure_event_registration(integration, events)?;
    let guides = integration.event_guides();
    if guides.len() != events.len() {
        return Err(DomainError::infra_msg(
            "an integration explains its events other than one guide each",
        ));
    }
    for spec in events {
        let Some(guide) = guides.iter().find(|guide| guide.event() == spec.event()) else {
            return Err(DomainError::infra_msg(
                "an integration offers an event it does not explain",
            ));
        };
        guide
            .ensure_explains(spec)
            .map_err(|_| DomainError::infra_msg("an integration's guide does not fit its event"))?;
    }
    Ok(())
}

/// Refuses foreign event keys or a mismatch between events and their watcher.
fn ensure_event_registration(
    integration: &dyn Integration,
    events: &[ServiceEventSpec],
) -> Result<(), DomainError> {
    if events.is_empty() != integration.watcher().is_none() {
        return Err(DomainError::infra_msg(
            "an integration offers events without registering them, or the other way round",
        ));
    }
    if events
        .iter()
        .any(|spec| spec.integration() != integration.key())
    {
        return Err(DomainError::infra_msg(
            "an integration declares an event under another key",
        ));
    }
    Ok(())
}

/// Refuses an integration whose guides are not one per operation, each
/// explaining exactly the inputs its operation takes.
fn ensure_explains_each(integration: &dyn Integration) -> Result<(), DomainError> {
    let guides = integration.guides();
    if guides.len() != integration.operations().len() {
        return Err(DomainError::infra_msg(
            "an integration explains its operations other than one guide each",
        ));
    }
    for spec in integration.operations() {
        let Some(guide) = guides
            .iter()
            .find(|guide| guide.operation() == spec.operation())
        else {
            return Err(DomainError::infra_msg(
                "an integration offers an operation it does not explain",
            ));
        };
        guide.ensure_explains(spec).map_err(|_| {
            DomainError::infra_msg("an integration's guide does not fit its operation")
        })?;
        guide
            .ensure_pickers_read(integration.operations())
            .map_err(|_| DomainError::infra_msg("an integration's picker is filled by no read"))?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::execution::ActionCall;
    use ianua_domain::domains::workflows::execution::step::ActionOutcome;
    use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
    use ianua_domain::domains::workflows::integration::guide::OperationGuide;
    use ianua_domain::domains::workflows::integration::{
        AccountNeed, OperationKey, OperationSpec, OperationSpecParams,
    };
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::DeclaredAction;
    use ianua_integration::Called;
    use ianua_integration::describe::{BuiltInText, GuideText, built_in_profile, guide};

    use super::*;

    /// An operation `operation` of `integration`, reading, through `account`.
    pub(crate) fn spec(integration: &str, operation: &str, account: AccountNeed) -> OperationSpec {
        OperationSpec::new(OperationSpecParams {
            integration: IntegrationKey::new(integration).unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            inputs: Vec::new(),
            effect: DeclaredAction::Undeclared,
            account,
            ceiling: DataClassLevel::Internal,
        })
        .unwrap()
    }

    /// The profile of the integration `key`, titled by it.
    pub(crate) fn profile_of(key: &str) -> IntegrationProfile {
        let text = BuiltInText {
            title: key,
            description: "An integration for tests.",
            icon: key,
            brand: "24292f",
        };
        built_in_profile(&IntegrationKey::new(key).unwrap(), &text).unwrap()
    }

    /// A guide explaining `spec`, which takes no inputs.
    pub(crate) fn guide_of(spec: &OperationSpec) -> OperationGuide {
        guide(&GuideText {
            operation: spec.operation().as_str(),
            title: spec.operation().as_str(),
            description: "Does what its name says.",
            inputs: &[],
            outputs: &[("status", "The answer's status.")],
            preview: None,
        })
        .unwrap()
    }

    /// An integration declaring `operations`, explaining each, and doing
    /// nothing.
    pub(crate) struct Idle {
        pub(crate) profile: IntegrationProfile,
        pub(crate) operations: Vec<OperationSpec>,
        pub(crate) guides: Vec<OperationGuide>,
    }

    impl Idle {
        /// The integration `key`, offering `operations`.
        pub(crate) fn offering(key: &str, operations: Vec<OperationSpec>) -> Self {
            Self {
                profile: profile_of(key),
                guides: operations.iter().map(guide_of).collect(),
                operations,
            }
        }
    }

    #[async_trait]
    impl Integration for Idle {
        fn profile(&self) -> &IntegrationProfile {
            &self.profile
        }

        fn operations(&self) -> &[OperationSpec] {
            &self.operations
        }

        fn guides(&self) -> &[OperationGuide] {
            &self.guides
        }

        async fn check_account(&self, _credential: &Secret) -> AccountCheck {
            AccountCheck::NotCheckable
        }

        async fn call(&self, _call: &ActionCall, _credential: Option<&Secret>) -> Called {
            ActionOutcome::Failed(ianua_domain::types::UntrustedText::record("idle")).into()
        }
    }

    fn idle(key: &str, operations: Vec<OperationSpec>) -> Arc<dyn Integration> {
        Arc::new(Idle::offering(key, operations))
    }

    /// Installing two integrations under the same key fails.
    #[test]
    fn two_integrations_under_one_key_are_refused() {
        let integrations = vec![idle("sheets", Vec::new()), idle("sheets", Vec::new())];

        let set = Installed::new(integrations);

        assert!(matches!(set, Err(DomainError::Infrastructure(_))));
    }

    /// An integration cannot be installed with an operation declared under
    /// another integration's key.
    #[test]
    fn an_operation_under_another_key_is_refused() {
        let foreign = spec("chat", "send", AccountNeed::NoAccount);

        let set = Installed::new(vec![idle("sheets", vec![foreign])]);

        assert!(matches!(set, Err(DomainError::Infrastructure(_))));
    }

    /// Installation rejects an operation with no guide or with a guide naming a
    /// different operation.
    #[test]
    fn an_operation_without_its_guide_is_refused() {
        let send = spec("chat", "send", AccountNeed::NoAccount);
        let unexplained = Idle {
            guides: Vec::new(),
            ..Idle::offering("chat", vec![send.clone()])
        };
        let misexplained = Idle {
            guides: vec![guide_of(&spec("chat", "delete", AccountNeed::NoAccount))],
            ..Idle::offering("chat", vec![send])
        };

        for integration in [unexplained, misexplained] {
            let set = Installed::new(vec![Arc::new(integration)]);
            assert!(matches!(set, Err(DomainError::Infrastructure(_))));
        }
    }

    /// Each installed integration is found by its key, and only by it, and
    /// presents itself once.
    #[test]
    fn an_integration_is_found_by_its_key() {
        let set =
            Installed::new(vec![idle("sheets", Vec::new()), idle("chat", Vec::new())]).unwrap();

        let found = set.find(&IntegrationKey::new("chat").unwrap());
        let missing = set.find(&IntegrationKey::new("mail").unwrap());

        assert_eq!(
            found.map(|integration| integration.key().as_str()),
            Some("chat")
        );
        assert!(missing.is_none());
        assert_eq!(set.profiles().len(), 2);
    }
}
