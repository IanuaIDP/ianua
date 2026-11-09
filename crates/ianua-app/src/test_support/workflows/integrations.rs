//! Integrations as the workflows tests see them: the accounts a tenant
//! connected, its raised views of operations, the catalog and the adapter
//! that makes a call.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::workflows::account::{
    AccountSharing, ConnectAccountParams, IntegrationAccount, IntegrationAccountRow, OperationScope,
};
use ianua_domain::domains::workflows::data::{DataPath, FieldName};
use ianua_domain::domains::workflows::execution::ActionCall;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
use ianua_domain::domains::workflows::integration::events::{
    ServiceEventGuide, ServiceEventGuideParams, ServiceEventSpec,
};
use ianua_domain::domains::workflows::integration::form::{BrandColor, InputForm};
use ianua_domain::domains::workflows::integration::guide::{
    InputNote, OperationGuide, OperationGuideParams, OutputNote,
};
use ianua_domain::domains::workflows::integration::profile::{
    IntegrationIcon, IntegrationLook, IntegrationPicture, IntegrationProfile,
    IntegrationProfileParams,
};
use ianua_domain::domains::workflows::integration::risk_override::{
    OperationRiskOverride, OperationRiskOverrideRow,
};
use ianua_domain::domains::workflows::integration::{IntegrationKey, OperationSpec};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    Human, IntegrationAccountId, Issuer, Label, OperationRiskOverrideId, SealedSecret, TenantId,
    Text, UntrustedText,
};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::authentication::{SealOwner, SealedAt, SealedField, SealedFor};
use crate::ports::workflows::{
    AccountVerifier, ActionRun, ActionRunner, CallCredential, CredentialCheck,
    IntegrationAccountSortField, IntegrationAccountStore, IntegrationCatalog,
    OperationRiskOverrideStore, Renewal, RunPassGrant, RunPasses,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::authentication::FakeEncryptor;
use crate::test_support::listing::page;
use crate::test_support::workflows::graphs::{SHEETS, managing};
use crate::test_support::{Fake, test_ctx};

/// The credential every account [`sheets_account`] connects holds, before
/// it is sealed.
pub const SHEETS_CREDENTIAL: &str = "sheets-api-token";

/// A spreadsheet account `owner` connected, shared as `sharing`, for every
/// operation, its credential sealed as [`FakeEncryptor`] seals it.
#[must_use]
pub fn sheets_account(
    owner: &Human,
    sharing: AccountSharing,
) -> IntegrationAccount<ResolvedTenant> {
    let id = IntegrationAccountId::new();
    IntegrationAccount::connect(
        ConnectAccountParams {
            id,
            integration: IntegrationKey::new(SHEETS).expect("an integration key"),
            name: Label::new("name", "Finance sheets").expect("a name"),
            credential: FakeEncryptor::sealed_for(
                SHEETS_CREDENTIAL,
                &account_credential_place(&id),
            ),
            sharing,
            scope: OperationScope::All,
        },
        &managing(owner),
    )
    .expect("someone managing workflows connects an account")
}

/// Where the test tenant's account `id` keeps its credential.
#[must_use]
pub fn account_credential_place(id: &IntegrationAccountId) -> SealedFor {
    SealedFor::new(
        SealOwner::Tenant(test_ctx().tenant_id()),
        SealedField::IntegrationCredential,
        id,
    )
}

fn account_copy(
    account: &IntegrationAccount<ResolvedTenant>,
) -> IntegrationAccount<ResolvedTenant> {
    IntegrationAccount::reconstitute(IntegrationAccountRow {
        id: *account.id(),
        integration: account.integration().clone(),
        name: account.name().clone(),
        credential: account.credential().clone(),
        owner: account.owner().clone(),
        sharing: account.sharing(),
        scope: account.scope().clone(),
        status: account.status(),
        created_at: Aggregate::created_at(account),
        updated_at: Aggregate::updated_at(account),
    })
    .expect("a kept account reads back as itself")
}

/// In-memory account store: accounts kept under their tenant, saved in
/// place.
#[derive(Default)]
pub struct FakeIntegrationAccountStore {
    accounts: Mutex<Vec<(TenantId, IntegrationAccount<ResolvedTenant>)>>,
}

impl TenantScoped for FakeIntegrationAccountStore {}

impl FakeIntegrationAccountStore {
    /// A store holding no account.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `account` in the test tenant.
    #[must_use]
    pub fn holding(account: &IntegrationAccount<ResolvedTenant>) -> Self {
        Self {
            accounts: Mutex::new(vec![(test_ctx().tenant_id(), account_copy(account))]),
        }
    }

    /// The account `id`, as the test tenant keeps it now.
    #[must_use]
    pub fn stored(&self, id: &IntegrationAccountId) -> Option<IntegrationAccount<ResolvedTenant>> {
        let tenant = test_ctx().tenant_id();
        self.accounts
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, kept)| *owner == tenant && kept.id() == id)
            .map(|(_, kept)| account_copy(kept))
    }

    /// How many accounts are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.accounts.lock().unwrap().len()
    }
}

#[async_trait]
impl IntegrationAccountStore for FakeIntegrationAccountStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &IntegrationAccountId,
    ) -> Result<Option<IntegrationAccount<ResolvedTenant>>, DomainError> {
        Ok(self
            .accounts
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, kept)| owner == &**tenant_id && kept.id() == id)
            .map(|(_, kept)| account_copy(kept)))
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        request: &PageRequest,
    ) -> Result<Page<IntegrationAccount<ResolvedTenant>>, DomainError> {
        let kept: Vec<_> = self
            .accounts
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, _)| owner == &**tenant_id)
            .map(|(_, kept)| account_copy(kept))
            .collect();
        page(
            kept,
            &SortOrder::<IntegrationAccountSortField>::default(),
            request,
        )
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        account: &IntegrationAccount<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut accounts = self.accounts.lock().unwrap();
        let held = accounts
            .iter()
            .position(|(owner, kept)| owner == &**tenant_id && kept.id() == account.id());
        let entry = (**tenant_id, account_copy(account));
        match held {
            Some(index) => accounts[index] = entry,
            None => accounts.push(entry),
        }
        Ok(())
    }
}

impl Fake for Arc<dyn IntegrationAccountStore> {
    fn fake() -> Self {
        Arc::new(FakeIntegrationAccountStore::empty())
    }
}

fn risk_copy(
    risk: &OperationRiskOverride<ResolvedTenant>,
) -> OperationRiskOverride<ResolvedTenant> {
    OperationRiskOverride::reconstitute(OperationRiskOverrideRow {
        id: *risk.id(),
        integration: risk.integration().clone(),
        operation: risk.operation().clone(),
        effect: risk.effect(),
        raised_by: risk.raised_by().clone(),
        created_at: Aggregate::created_at(risk),
        updated_at: Aggregate::updated_at(risk),
    })
    .expect("a kept override reads back as itself")
}

/// In-memory override store: at most one override per operation in a
/// tenant, as storage keeps it.
#[derive(Default)]
pub struct FakeOperationRiskOverrideStore {
    risks: Mutex<Vec<(TenantId, OperationRiskOverride<ResolvedTenant>)>>,
}

impl TenantScoped for FakeOperationRiskOverrideStore {}

impl FakeOperationRiskOverrideStore {
    /// A store holding no override.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `risk` in the test tenant.
    #[must_use]
    pub fn holding(risk: &OperationRiskOverride<ResolvedTenant>) -> Self {
        Self {
            risks: Mutex::new(vec![(test_ctx().tenant_id(), risk_copy(risk))]),
        }
    }

    /// How many overrides are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.risks.lock().unwrap().len()
    }
}

#[async_trait]
impl OperationRiskOverrideStore for FakeOperationRiskOverrideStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &OperationRiskOverrideId,
    ) -> Result<Option<OperationRiskOverride<ResolvedTenant>>, DomainError> {
        Ok(self
            .risks
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, kept)| owner == &**tenant_id && kept.id() == id)
            .map(|(_, kept)| risk_copy(kept)))
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<OperationRiskOverride<ResolvedTenant>>, DomainError> {
        Ok(self
            .risks
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, _)| owner == &**tenant_id)
            .map(|(_, kept)| risk_copy(kept))
            .collect())
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        risk: &OperationRiskOverride<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut risks = self.risks.lock().unwrap();
        let same_operation = risks.iter().any(|(owner, kept)| {
            owner == &**tenant_id
                && kept.id() != risk.id()
                && kept.integration() == risk.integration()
                && kept.operation() == risk.operation()
        });
        if same_operation {
            return Err(DomainError::conflict(
                "the operation's risk is raised already",
            ));
        }
        let held = risks
            .iter()
            .position(|(owner, kept)| owner == &**tenant_id && kept.id() == risk.id());
        let entry = (**tenant_id, risk_copy(risk));
        match held {
            Some(index) => risks[index] = entry,
            None => risks.push(entry),
        }
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &OperationRiskOverrideId,
    ) -> Result<(), DomainError> {
        self.risks
            .lock()
            .unwrap()
            .retain(|(owner, kept)| !(owner == &**tenant_id && kept.id() == id));
        Ok(())
    }
}

impl Fake for Arc<dyn OperationRiskOverrideStore> {
    fn fake() -> Self {
        Arc::new(FakeOperationRiskOverrideStore::empty())
    }
}

/// A catalog offering a fixed list of operations, each with a guide unless
/// told otherwise, and of service events.
pub struct FakeIntegrationCatalog {
    offered: Vec<OperationSpec>,
    events: Vec<ServiceEventSpec>,
    guided: bool,
}

impl FakeIntegrationCatalog {
    /// A catalog offering `offered`.
    #[must_use]
    pub fn offering(offered: Vec<OperationSpec>) -> Self {
        Self {
            offered,
            events: Vec::new(),
            guided: true,
        }
    }

    /// The same catalog, also offering `events`.
    #[must_use]
    pub fn with_events(self, events: Vec<ServiceEventSpec>) -> Self {
        Self { events, ..self }
    }

    /// The same catalog, explaining none of its operations.
    #[must_use]
    pub fn without_guides(self) -> Self {
        Self {
            guided: false,
            ..self
        }
    }

    /// A catalog offering nothing.
    #[must_use]
    pub fn offering_nothing() -> Self {
        Self::offering(Vec::new())
    }
}

#[async_trait]
impl IntegrationCatalog for FakeIntegrationCatalog {
    async fn installed(&self) -> Result<Vec<IntegrationProfile>, DomainError> {
        let mut installed: Vec<IntegrationProfile> = Vec::new();
        for spec in &self.offered {
            if !installed
                .iter()
                .any(|profile| profile.key() == spec.integration())
            {
                installed.push(profile_of(spec.integration()));
            }
        }
        Ok(installed)
    }

    async fn guides(
        &self,
        integration: &IntegrationKey,
    ) -> Result<Vec<OperationGuide>, DomainError> {
        Ok(self
            .offered
            .iter()
            .filter(|spec| self.guided && spec.integration() == integration)
            .map(guide_of)
            .collect())
    }

    async fn offered(
        &self,
        integration: &IntegrationKey,
    ) -> Result<Vec<OperationSpec>, DomainError> {
        Ok(self
            .offered
            .iter()
            .filter(|spec| spec.integration() == integration)
            .cloned()
            .collect())
    }

    async fn events(
        &self,
        integration: &IntegrationKey,
    ) -> Result<Vec<ServiceEventSpec>, DomainError> {
        Ok(self
            .events
            .iter()
            .filter(|spec| spec.integration() == integration)
            .cloned()
            .collect())
    }

    async fn event_guides(
        &self,
        integration: &IntegrationKey,
    ) -> Result<Vec<ServiceEventGuide>, DomainError> {
        Ok(self
            .events
            .iter()
            .filter(|spec| self.guided && spec.integration() == integration)
            .map(event_guide_of)
            .collect())
    }
}

/// A guide explaining `spec`'s event and each of its filters.
#[must_use]
pub fn event_guide_of(spec: &ServiceEventSpec) -> ServiceEventGuide {
    ServiceEventGuide::new(ServiceEventGuideParams {
        event: spec.event().clone(),
        title: Label::new("title", spec.event().as_str()).expect("a key is a valid title"),
        description: Text::new("description", format!("When {} happens.", spec.event()))
            .expect("a valid description"),
        filters: spec
            .filters()
            .iter()
            .map(|filter| {
                InputNote::new(
                    filter.name().clone(),
                    Text::new("description", "A filter.").expect("a valid description"),
                    plain_form(filter.name()),
                )
            })
            .collect(),
        outputs: Vec::new(),
    })
}

impl Fake for Arc<dyn IntegrationCatalog> {
    fn fake() -> Self {
        Arc::new(FakeIntegrationCatalog::offering_nothing())
    }
}

/// How the integration `key` presents itself in tests: titled by its key.
#[must_use]
pub fn profile_of(key: &IntegrationKey) -> IntegrationProfile {
    IntegrationProfile::new(IntegrationProfileParams {
        key: key.clone(),
        title: Label::new("title", key.as_str()).expect("a key is a valid title"),
        description: Text::new("description", format!("Calls {key}."))
            .expect("a valid description"),
        icon: IntegrationIcon::new(key.as_str()).expect("a key is a valid icon name"),
        look: IntegrationLook::Picture(
            IntegrationPicture::new(r#"<svg viewBox="0 0 24 24"><path d="M0 0h24v24H0z"/></svg>"#)
                .expect("a small picture"),
        ),
        brand: BrandColor::new("24292f").expect("a dark colour"),
    })
}

/// A one-line text box labelled by the input `name`.
fn plain_form(name: &FieldName) -> InputForm {
    InputForm::plain(Label::new("label", name.as_str()).expect("a field name is a valid label"))
}

/// A guide explaining `spec`, every input and the step's status.
#[must_use]
pub fn guide_of(spec: &OperationSpec) -> OperationGuide {
    let note = |what: &str| Text::new("description", what).expect("a valid description");
    OperationGuide::new(OperationGuideParams {
        operation: spec.operation().clone(),
        title: Label::new("title", spec.operation().as_str()).expect("a key is a valid title"),
        description: note("Does what its name says."),
        inputs: spec
            .inputs()
            .iter()
            .map(|input| {
                InputNote::new(
                    input.name().clone(),
                    note("An input."),
                    plain_form(input.name()),
                )
            })
            .collect(),
        outputs: vec![OutputNote::new(
            DataPath::parse("status").expect("a valid path"),
            note("The service's answer status."),
        )],
        preview: None,
    })
}

/// A verifier answering every question with one check, keeping each
/// integration it was asked about.
pub struct FakeAccountVerifier {
    answer: AccountCheck,
    replaced_by: Option<Secret>,
    asked: Mutex<Vec<IntegrationKey>>,
}

impl FakeAccountVerifier {
    /// A verifier answering `answer`.
    #[must_use]
    pub fn answering(answer: AccountCheck) -> Self {
        Self {
            answer,
            replaced_by: None,
            asked: Mutex::new(Vec::new()),
        }
    }

    /// The same verifier, replacing every credential it is asked about with
    /// `replaced_by`, as a service whose grants rotate does.
    #[must_use]
    pub fn replacing_with(self, replaced_by: &str) -> Self {
        Self {
            replaced_by: Some(Secret::new(replaced_by.to_owned())),
            ..self
        }
    }

    /// Every integration it was asked about, in order.
    #[must_use]
    pub fn asked(&self) -> Vec<IntegrationKey> {
        self.asked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl AccountVerifier for FakeAccountVerifier {
    async fn check(&self, integration: &IntegrationKey, _credential: &Secret) -> CredentialCheck {
        self.asked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(integration.clone());
        CredentialCheck {
            verdict: self.answer.clone(),
            replaced_by: self.replaced_by.clone(),
        }
    }
}

impl Fake for Arc<dyn AccountVerifier> {
    fn fake() -> Self {
        Arc::new(FakeAccountVerifier::answering(AccountCheck::Accepted))
    }
}

/// An adapter answering every call with one outcome, keeping each call and
/// the credential it was handed.
pub struct FakeActionRunner {
    outcome: ActionOutcome,
    renewal: Renewal,
    calls: Mutex<Vec<(ActionCall, Option<SealedAt>)>>,
    passes: Mutex<Vec<Secret>>,
}

impl TenantScoped for FakeActionRunner {}

impl FakeActionRunner {
    /// An adapter whose every call comes to `outcome`.
    #[must_use]
    pub fn answering(outcome: ActionOutcome) -> Self {
        Self {
            outcome,
            renewal: Renewal::Unchanged,
            calls: Mutex::new(Vec::new()),
            passes: Mutex::new(Vec::new()),
        }
    }

    /// The same adapter, the service renewing the credential to `renewed`
    /// on every call.
    #[must_use]
    pub fn renewing(self, renewed: SealedSecret) -> Self {
        Self {
            renewal: Renewal::Renewed(renewed),
            ..self
        }
    }

    /// Every call made, with the account's credential or the stream route
    /// login's sealed password it was handed.
    #[must_use]
    pub fn calls(&self) -> Vec<(ActionCall, Option<SealedAt>)> {
        self.calls.lock().unwrap().clone()
    }

    /// Every pass a call was handed, in order.
    #[must_use]
    pub fn passes(&self) -> Vec<Secret> {
        self.passes.lock().unwrap().clone()
    }
}

#[async_trait]
impl ActionRunner for FakeActionRunner {
    async fn run(
        &self,
        _tenant_id: &ScopedTenant,
        call: &ActionCall,
        credential: CallCredential<'_>,
    ) -> ActionRun {
        let sealed = match credential {
            CallCredential::Nothing => None,
            CallCredential::Account(sealed) => Some(sealed.clone()),
            CallCredential::Pass(pass) => {
                self.passes.lock().unwrap().push(pass.clone());
                None
            }
            CallCredential::Data(data) => {
                self.passes.lock().unwrap().push(data.pass.clone());
                Some(data.password.clone())
            }
        };
        self.calls.lock().unwrap().push((call.clone(), sealed));
        ActionRun {
            outcome: self.outcome.clone(),
            renewal: self.renewal.clone(),
        }
    }
}

/// Makes passes that say what they were made for, or refuses every one, as
/// a tenant with no signing key would.
#[derive(Default)]
pub struct FakeRunPasses {
    keys: PassKeys,
    issued: Mutex<Vec<RunPassGrant>>,
}

/// Whether the tenant has a key that signs passes.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum PassKeys {
    #[default]
    Signing,
    Missing,
}

impl TenantScoped for FakeRunPasses {}

impl FakeRunPasses {
    /// Passes that cannot be signed, the tenant having no key.
    #[must_use]
    pub fn refusing() -> Self {
        Self {
            keys: PassKeys::Missing,
            issued: Mutex::new(Vec::new()),
        }
    }

    /// Every pass made, by what it was made for.
    #[must_use]
    pub fn issued(&self) -> Vec<RunPassGrant> {
        self.issued.lock().unwrap().clone()
    }
}

#[async_trait]
impl RunPasses for FakeRunPasses {
    async fn issue(
        &self,
        _tenant_id: &ScopedTenant,
        _issuer: &Issuer,
        grant: &RunPassGrant,
    ) -> Result<Secret, DomainError> {
        if self.keys == PassKeys::Missing {
            return Err(DomainError::infra_msg("the tenant has no signing key"));
        }
        self.issued.lock().unwrap().push(*grant);
        Ok(Secret::new(format!("pass for {}", grant.call_id)))
    }
}

impl Fake for Arc<dyn RunPasses> {
    fn fake() -> Self {
        Arc::new(FakeRunPasses::default())
    }
}

impl Fake for Arc<dyn ActionRunner> {
    fn fake() -> Self {
        Arc::new(FakeActionRunner::answering(ActionOutcome::Failed(
            UntrustedText::record("no integration is installed"),
        )))
    }
}
