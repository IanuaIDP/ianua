//! Fakes for where notifications reach people beyond their inbox: members'
//! and operators' choices, an organization's destinations, what posts to
//! them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::channel::NotificationChannel;
use ianua_domain::domains::notifications::destination::{
    DestinationEndpoint, DestinationEndpointRow, DestinationState, NotificationDestination,
    NotificationDestinationRow,
};
use ianua_domain::domains::notifications::notification::Notification;
use ianua_domain::domains::notifications::personal::{
    MemberNotificationPreferences, OperatorNotificationPreferences,
};
use ianua_domain::domains::notifications::severity::NotificationSeverity;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    Label, NotificationDestinationId, OperatorId, OrgUserId, OrganizationId, PublicHttpsUrl,
    SealedSecret,
};

use crate::ports::authentication::SealedFor;
use crate::ports::notifications::{
    AlertKey, AlertThrottle, AlertTurn, DestinationPoster, DestinationSecretGenerator,
    MemberPreferenceStore, NotificationDestinationStore, OperatorPreferenceStore,
};
use crate::test_support::Fake;

/// In-memory store of organization members' notification choices.
#[derive(Default)]
pub struct FakeMemberPreferenceStore {
    held: Mutex<Vec<MemberNotificationPreferences>>,
}

impl FakeMemberPreferenceStore {
    /// A store where no member chose anything.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `preferences`.
    #[must_use]
    pub fn holding(preferences: MemberNotificationPreferences) -> Self {
        Self {
            held: Mutex::new(vec![preferences]),
        }
    }

    /// The member's choices as last saved.
    #[must_use]
    pub fn stored(&self, member: &OrgUserId) -> Option<MemberNotificationPreferences> {
        self.held
            .lock()
            .unwrap()
            .iter()
            .find(|held| held.org_user_id() == member)
            .cloned()
    }
}

#[async_trait]
impl MemberPreferenceStore for FakeMemberPreferenceStore {
    async fn find(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<Option<MemberNotificationPreferences>, DomainError> {
        Ok(self
            .stored(org_user_id)
            .filter(|held| held.organization_id() == organization_id))
    }

    async fn save(&self, preferences: &MemberNotificationPreferences) -> Result<(), DomainError> {
        let mut held = self.held.lock().unwrap();
        held.retain(|kept| kept.org_user_id() != preferences.org_user_id());
        held.push(preferences.clone());
        Ok(())
    }

    async fn chosen_channels(
        &self,
        organization_id: &OrganizationId,
        category: NotificationCategory,
    ) -> Result<Vec<(OrgUserId, NotificationChannel)>, DomainError> {
        Ok(self
            .held
            .lock()
            .unwrap()
            .iter()
            .filter(|held| held.organization_id() == organization_id)
            .map(|held| (*held.org_user_id(), held.channel_for(category)))
            .collect())
    }
}

impl Fake for Arc<dyn MemberPreferenceStore> {
    fn fake() -> Self {
        Arc::new(FakeMemberPreferenceStore::empty())
    }
}

/// In-memory store of operators' notification choices.
#[derive(Default)]
pub struct FakeOperatorPreferenceStore {
    held: Mutex<Vec<OperatorNotificationPreferences>>,
}

impl FakeOperatorPreferenceStore {
    /// A store where no operator chose anything.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `preferences`.
    #[must_use]
    pub fn holding(preferences: OperatorNotificationPreferences) -> Self {
        Self {
            held: Mutex::new(vec![preferences]),
        }
    }

    /// The operator's choices as last saved.
    #[must_use]
    pub fn stored(&self, operator: &OperatorId) -> Option<OperatorNotificationPreferences> {
        self.held
            .lock()
            .unwrap()
            .iter()
            .find(|held| held.operator_id() == operator)
            .cloned()
    }
}

#[async_trait]
impl OperatorPreferenceStore for FakeOperatorPreferenceStore {
    async fn find(
        &self,
        operator_id: &OperatorId,
    ) -> Result<Option<OperatorNotificationPreferences>, DomainError> {
        Ok(self.stored(operator_id))
    }

    async fn save(&self, preferences: &OperatorNotificationPreferences) -> Result<(), DomainError> {
        let mut held = self.held.lock().unwrap();
        held.retain(|kept| kept.operator_id() != preferences.operator_id());
        held.push(preferences.clone());
        Ok(())
    }

    async fn chosen_channels(
        &self,
        category: NotificationCategory,
    ) -> Result<Vec<(OperatorId, NotificationChannel)>, DomainError> {
        Ok(self
            .held
            .lock()
            .unwrap()
            .iter()
            .map(|held| (*held.operator_id(), held.channel_for(category)))
            .collect())
    }
}

impl Fake for Arc<dyn OperatorPreferenceStore> {
    fn fake() -> Self {
        Arc::new(FakeOperatorPreferenceStore::empty())
    }
}

/// In-memory store of organizations' notification destinations.
#[derive(Default)]
pub struct FakeDestinationStore {
    held: Mutex<Vec<NotificationDestination>>,
}

impl FakeDestinationStore {
    /// A store holding no destination.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `destinations`.
    #[must_use]
    pub fn holding(destinations: impl IntoIterator<Item = NotificationDestination>) -> Self {
        Self {
            held: Mutex::new(destinations.into_iter().collect()),
        }
    }

    /// The destination `id` as last saved.
    #[must_use]
    pub fn stored(&self, id: &NotificationDestinationId) -> Option<NotificationDestination> {
        self.held
            .lock()
            .unwrap()
            .iter()
            .find(|held| held.id() == id)
            .cloned()
    }

    /// How many destinations are kept, across every organization.
    #[must_use]
    pub fn count(&self) -> usize {
        self.held.lock().unwrap().len()
    }
}

#[async_trait]
impl NotificationDestinationStore for FakeDestinationStore {
    async fn find(
        &self,
        organization_id: &OrganizationId,
        id: &NotificationDestinationId,
    ) -> Result<Option<NotificationDestination>, DomainError> {
        Ok(self
            .stored(id)
            .filter(|held| held.organization_id() == organization_id))
    }

    async fn list(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Vec<NotificationDestination>, DomainError> {
        Ok(self
            .held
            .lock()
            .unwrap()
            .iter()
            .filter(|held| held.organization_id() == organization_id)
            .cloned()
            .collect())
    }

    async fn save(&self, destination: &NotificationDestination) -> Result<(), DomainError> {
        let mut held = self.held.lock().unwrap();
        held.retain(|kept| kept.id() != destination.id());
        held.push(destination.clone());
        Ok(())
    }

    async fn delete(
        &self,
        organization_id: &OrganizationId,
        id: &NotificationDestinationId,
    ) -> Result<(), DomainError> {
        self.held
            .lock()
            .unwrap()
            .retain(|kept| !(kept.organization_id() == organization_id && kept.id() == id));
        Ok(())
    }
}

impl Fake for Arc<dyn NotificationDestinationStore> {
    fn fake() -> Self {
        Arc::new(FakeDestinationStore::empty())
    }
}

/// The signing secret every [`FakeDestinationSecretGenerator`] makes.
pub const TEST_DESTINATION_SECRET: &str = "destination-secret";

/// Makes the same signing secret every time.
pub struct FakeDestinationSecretGenerator;

#[async_trait]
impl DestinationSecretGenerator for FakeDestinationSecretGenerator {
    async fn generate(&self) -> Result<Secret, DomainError> {
        Ok(Secret::new(TEST_DESTINATION_SECRET))
    }
}

impl Fake for Arc<dyn DestinationSecretGenerator> {
    fn fake() -> Self {
        Arc::new(FakeDestinationSecretGenerator)
    }
}

/// Posts notifications by noting where they went, or refuses every one.
#[derive(Default)]
pub struct FakeDestinationPoster {
    posted: Mutex<Vec<DestinationEndpoint>>,
    refusing: bool,
}

impl FakeDestinationPoster {
    /// A poster whose every destination takes the post.
    #[must_use]
    pub fn posting() -> Self {
        Self::default()
    }

    /// A poster whose every destination refuses the post.
    #[must_use]
    pub fn refusing() -> Self {
        Self {
            posted: Mutex::new(Vec::new()),
            refusing: true,
        }
    }

    /// How many posts were taken.
    #[must_use]
    pub fn posted(&self) -> usize {
        self.posted.lock().unwrap().len()
    }
}

#[async_trait]
impl DestinationPoster for FakeDestinationPoster {
    async fn post(
        &self,
        endpoint: &DestinationEndpoint,
        _: &SealedFor,
        _: &Notification,
    ) -> Result<(), DomainError> {
        if self.refusing {
            return Err(DomainError::infra_msg("the channel refused the post"));
        }
        self.posted.lock().unwrap().push(endpoint.clone());
        Ok(())
    }
}

impl Fake for Arc<dyn DestinationPoster> {
    fn fake() -> Self {
        Arc::new(FakeDestinationPoster::posting())
    }
}

/// Where one kind of alert stands in [`FakeAlertThrottle`].
#[derive(Default, Clone, Copy)]
struct AlertState {
    within_window: bool,
    alerted_before: bool,
    held_back: u64,
}

/// In-memory throttle whose window passes only when a test says so.
#[derive(Default)]
pub struct FakeAlertThrottle {
    kinds: Mutex<HashMap<AlertKey, AlertState>>,
}

impl FakeAlertThrottle {
    /// Lets every window pass, as an hour going by would.
    pub fn pass_window(&self) {
        for state in self.kinds.lock().unwrap().values_mut() {
            state.within_window = false;
        }
    }
}

#[async_trait]
impl AlertThrottle for FakeAlertThrottle {
    async fn admit(&self, key: &AlertKey, _window: time::Duration) -> AlertTurn {
        let mut kinds = self.kinds.lock().unwrap();
        let state = kinds.entry(*key).or_default();
        if state.within_window {
            state.held_back = state.held_back.saturating_add(1);
            return AlertTurn::HeldBack;
        }
        let since_last = state
            .alerted_before
            .then(|| state.held_back.saturating_add(1));
        *state = AlertState {
            within_window: true,
            alerted_before: true,
            held_back: 0,
        };
        AlertTurn::Raise { since_last }
    }
}

impl Fake for Arc<dyn AlertThrottle> {
    fn fake() -> Self {
        Arc::new(FakeAlertThrottle::default())
    }
}

/// A webhook destination of `organization_id`, active, receiving every
/// category at or above `minimum`.
///
/// # Panics
///
/// Never: the name, address and sealed secret are fixed and valid.
#[must_use]
pub fn webhook_destination(
    organization_id: OrganizationId,
    minimum: NotificationSeverity,
) -> NotificationDestination {
    destination_in_state(organization_id, minimum, DestinationState::Active)
}

/// [`webhook_destination`], in `state`.
///
/// # Panics
///
/// Never: the name, address and sealed secret are fixed and valid.
#[must_use]
pub fn destination_in_state(
    organization_id: OrganizationId,
    minimum: NotificationSeverity,
    state: DestinationState,
) -> NotificationDestination {
    let now = clock::now();
    NotificationDestination::reconstitute(NotificationDestinationRow {
        id: NotificationDestinationId::new(),
        organization_id,
        name: Label::new("name", "On-call hook").expect("a valid name"),
        endpoint: DestinationEndpointRow::Webhook {
            url: PublicHttpsUrl::new("https://hooks.acme.com/alerts").expect("a public URL"),
            signing_secret: SealedSecret::new("enc_hook").expect("a sealed form is a token"),
        },
        categories: NotificationCategory::all().to_vec(),
        minimum_severity: minimum,
        state,
        created_at: now,
        updated_at: now,
    })
    .expect("a consistent destination")
}
