//! The device code flow, for TVs, CLIs and other devices without a browser.

use std::marker::PhantomData;
use std::num::NonZeroU16;

use time::OffsetDateTime;

use crate::domains::identity::account::control::{SignedInPerson, ensure_holder};
use crate::domains::oauth::clients::client::{GrantType, OAuthClient};
use crate::domains::oauth::events::grants::{
    DeviceAuthorizationApproved, DeviceAuthorizationCollected, DeviceAuthorizationDenied,
    DeviceAuthorizationRequested,
};
use crate::domains::oauth::grants::device_auth_status::{
    DeviceAuthStatus, InvalidDeviceAuthTransition,
};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::ValidationError;
use crate::types::{DeviceUserCode, EventLabel, OAuthClientId, Scope, TokenHash, UserId};

/// Where a device authorization stands, with who approved it once someone
/// did.
///
/// An approved request always names its approver. Otherwise the device
/// could get a token for no account, or for whichever account a caller
/// filled in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAuthState {
    /// Waiting for someone to approve or deny it.
    Pending,
    /// Approved by this user.
    Approved {
        /// Who approved it.
        by: UserId,
    },
    /// Refused.
    Denied,
    /// Ran out unanswered.
    Expired,
    /// Approved by this user and handed to the device.
    Redeemed {
        /// Who approved it.
        by: UserId,
    },
}

impl DeviceAuthState {
    /// The status of this state, without the approver.
    #[must_use]
    pub fn status(self) -> DeviceAuthStatus {
        match self {
            Self::Pending => DeviceAuthStatus::Pending,
            Self::Approved { .. } => DeviceAuthStatus::Approved,
            Self::Denied => DeviceAuthStatus::Denied,
            Self::Expired => DeviceAuthStatus::Expired,
            Self::Redeemed { .. } => DeviceAuthStatus::Redeemed,
        }
    }

    /// Reads a state back from its stored status and approver.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when an approved or redeemed request
    ///   has no approver.
    /// - [`DomainError::Infrastructure`] when a pending, denied or expired
    ///   request has one.
    pub fn from_stored(
        status: DeviceAuthStatus,
        approved_by: Option<UserId>,
    ) -> Result<Self, DomainError> {
        match (status, approved_by) {
            (DeviceAuthStatus::Approved, Some(by)) => Ok(Self::Approved { by }),
            (DeviceAuthStatus::Redeemed, Some(by)) => Ok(Self::Redeemed { by }),
            (DeviceAuthStatus::Pending, None) => Ok(Self::Pending),
            (DeviceAuthStatus::Denied, None) => Ok(Self::Denied),
            (DeviceAuthStatus::Expired, None) => Ok(Self::Expired),
            (status, _) => Err(DomainError::infra_msg(format!(
                "stored {status:?} device authorization has an approver that contradicts it"
            ))),
        }
    }

    /// Who approved it, once someone did.
    #[must_use]
    pub fn approved_by(&self) -> Option<&UserId> {
        match self {
            Self::Approved { by } | Self::Redeemed { by } => Some(by),
            Self::Pending | Self::Denied | Self::Expired => None,
        }
    }
}

/// The shortest wait, in whole seconds, a device leaves between two polls.
///
/// It is at least a second. A zero interval would tell the device to poll
/// the token endpoint as fast as it can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollInterval(NonZeroU16);

impl PollInterval {
    /// Five seconds, the interval RFC 8628 has a device use when it is told
    /// none.
    ///
    /// It is built at compile time, so the `unwrap` cannot fail at run time.
    pub const DEFAULT: Self = Self(NonZeroU16::new(5).unwrap());

    /// An interval of `seconds`.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when `seconds` is zero.
    pub fn seconds(seconds: u16) -> Result<Self, ValidationError> {
        NonZeroU16::new(seconds)
            .map(Self)
            .ok_or(ValidationError::OutOfRange {
                field: "interval",
                min: 1,
                max: u64::from(u16::MAX),
                actual: 0,
            })
    }

    /// The interval in whole seconds.
    #[must_use]
    pub fn as_secs(self) -> u16 {
        self.0.get()
    }

    /// This interval made five seconds longer, as a device that polls too
    /// fast is told to wait (RFC 8628 3.5).
    #[must_use]
    pub fn slowed(self) -> Self {
        Self(self.0.saturating_add(5))
    }
}

/// When a device last polled for its approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastPoll {
    /// It has not polled yet.
    Never,
    /// It last polled at this time.
    At(OffsetDateTime),
}

impl LastPoll {
    /// Reads the stored column back. No time means it has not polled.
    #[must_use]
    pub fn from_stored(at: Option<OffsetDateTime>) -> Self {
        at.map_or(Self::Never, Self::At)
    }

    /// The time, when it has polled. Storage keeps it this way.
    #[must_use]
    pub fn at(self) -> Option<OffsetDateTime> {
        match self {
            Self::Never => None,
            Self::At(at) => Some(at),
        }
    }
}

/// A device authorization request.
///
/// The device shows a user code and a URL. The user opens the URL on their
/// phone or laptop, types the code, and approves or denies. The device polls
/// until it is approved, denied or expired.
#[derive(Debug)]
pub struct DeviceAuthorization<T: TenantScope> {
    /// The hash of the device code. The device polls with the raw code.
    device_code_hash: TokenHash,
    /// The short code the user types, such as `"ABCD-1234"`.
    user_code: DeviceUserCode,
    /// The client that started the flow.
    client_id: OAuthClientId,
    /// The scopes asked for.
    scopes: Vec<Scope>,
    /// Where it stands, with who approved it once someone did.
    state: DeviceAuthState,
    /// The shortest wait between polls, in seconds.
    interval: PollInterval,
    /// When the device last polled.
    last_poll: LastPoll,
    /// When the request was created.
    created_at: OffsetDateTime,
    /// When the request expires.
    expires_at: OffsetDateTime,
    /// What it raised and was not taken yet.
    raised: Raised<T>,
    /// Which tenant scope this belongs to. See [`crate::isolation`].
    _scope: PhantomData<T>,
}

/// What a new device authorization is made from.
pub struct CreateDeviceAuthParams {
    /// The digest used to find the pending grant when the device polls.
    pub device_code_hash: TokenHash,
    /// The short code the user types.
    pub user_code: DeviceUserCode,
    /// The scopes asked for.
    pub scopes: Vec<Scope>,
    /// The shortest wait between polls, in seconds.
    pub interval: PollInterval,
    /// How long the person has to approve.
    pub lifetime: crate::types::Lifetime,
}

/// A device authorization as storage keeps it, checked again by
/// [`DeviceAuthorization::reconstitute`].
pub struct DeviceAuthRow {
    /// The stored lookup digest, separate from the code the person types.
    pub device_code_hash: TokenHash,
    /// The short code the user types.
    pub user_code: DeviceUserCode,
    /// The client that started the flow.
    pub client_id: OAuthClientId,
    /// The scopes asked for.
    pub scopes: Vec<Scope>,
    /// Where it stands. See [`DeviceAuthState::from_stored`].
    pub state: DeviceAuthState,
    /// The shortest wait between polls, in seconds.
    pub interval: PollInterval,
    /// When the device last polled.
    pub last_poll: LastPoll,
    /// When the request was created.
    pub created_at: OffsetDateTime,
    /// When the request expires.
    pub expires_at: OffsetDateTime,
}

impl<T: TenantScope> DeviceAuthorization<T> {
    /// Creates a pending device authorization for `client`.
    ///
    /// The flow ends in tokens for a person, so a machine-only client must
    /// not start it. Raises `oauth.device_authorization_requested`, naming
    /// `client` and never the user code.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the client is not active.
    /// - [`DomainError::Forbidden`] when the client was not given the device
    ///   flow.
    /// - [`DomainError::Forbidden`] when it asks for a scope the client was
    ///   not registered with.
    pub fn create(
        client: &OAuthClient<T>,
        params: CreateDeviceAuthParams,
    ) -> Result<Self, DomainError> {
        ensure_device_client(client, &params.scopes)?;
        let now = crate::shared::clock::now();
        let mut auth = Self {
            device_code_hash: params.device_code_hash,
            user_code: params.user_code,
            client_id: *client.id(),
            scopes: params.scopes,
            state: DeviceAuthState::Pending,
            interval: params.interval,
            last_poll: LastPoll::Never,
            created_at: now,
            expires_at: params.lifetime.ends_after(now),
            raised: Raised::default(),
            _scope: PhantomData,
        };
        auth.raised.raise(DeviceAuthorizationRequested {
            client_id: auth.client_id,
            client_label: EventLabel::of(client.name().as_str()),
            occurred_at: now,
        });
        Ok(auth)
    }

    /// Rebuilds a device authorization from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the authorization
    ///   expires before it was started.
    pub fn reconstitute(row: DeviceAuthRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            device_code_hash: row.device_code_hash,
            user_code: row.user_code,
            client_id: row.client_id,
            scopes: row.scopes,
            state: row.state,
            interval: row.interval,
            last_poll: row.last_poll,
            created_at: row.created_at,
            expires_at: row.expires_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &DeviceAuthRow) -> Result<(), DomainError> {
        RowCheck::of("device authorization")
            .holds(
                row.created_at < row.expires_at,
                "expires before it was started",
            )
            .in_order_if(
                row.created_at,
                row.last_poll.at(),
                "polled before it was started",
            )
            .finish()
    }

    /// The lookup digest used by the device's token poll.
    #[must_use]
    pub fn device_code_hash(&self) -> &TokenHash {
        &self.device_code_hash
    }

    /// The short code the user types.
    #[must_use]
    pub fn user_code(&self) -> &DeviceUserCode {
        &self.user_code
    }

    /// The client that started the flow.
    #[must_use]
    pub fn client_id(&self) -> &OAuthClientId {
        &self.client_id
    }

    /// The scopes asked for.
    #[must_use]
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// The current status.
    #[must_use]
    pub fn status(&self) -> DeviceAuthStatus {
        self.state.status()
    }

    /// Where it stands, with who approved it once someone did.
    #[must_use]
    pub fn state(&self) -> DeviceAuthState {
        self.state
    }

    /// The user who approved it, once someone did.
    #[must_use]
    pub fn approved_by(&self) -> Option<&UserId> {
        self.state.approved_by()
    }

    /// The shortest wait between polls, in seconds.
    #[must_use]
    pub fn interval(&self) -> PollInterval {
        self.interval
    }

    /// When the request was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When the request expires.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Whether the request still waits for the user.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.state == DeviceAuthState::Pending
    }

    /// Whether the request has run out at `now`.
    #[must_use]
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at
    }

    /// When the device last polled.
    #[must_use]
    pub fn last_poll(&self) -> LastPoll {
        self.last_poll
    }

    /// Who approved the request, once the device collected the approval.
    #[must_use]
    pub fn collected_by(&self) -> Option<&UserId> {
        match &self.state {
            DeviceAuthState::Redeemed { by } => Some(by),
            DeviceAuthState::Pending
            | DeviceAuthState::Approved { .. }
            | DeviceAuthState::Denied
            | DeviceAuthState::Expired => None,
        }
    }

    /// Records that the device polled at `now`.
    ///
    /// A device must wait its interval between polls. One that polls sooner
    /// is told to slow down, and its interval grows by five seconds, so a
    /// device that keeps hammering waits ever longer (RFC 8628 3.5).
    ///
    /// # Errors
    ///
    /// - [`DeviceAuthError::SlowDown`] when it polled sooner than its
    ///   interval allows.
    pub fn poll(&mut self, now: OffsetDateTime) -> Result<(), DeviceAuthError> {
        let too_soon = self.last_poll.at().is_some_and(|last| {
            now < last.saturating_add(time::Duration::seconds(i64::from(self.interval.as_secs())))
        });
        self.last_poll = LastPoll::At(now);
        if too_soon {
            self.interval = self.interval.slowed();
            return Err(DeviceAuthError::SlowDown);
        }
        Ok(())
    }

    /// Records that `user_id`, signed in as `by`, approves the request.
    ///
    /// The device gets tokens for whoever approved, so only that person's
    /// own sign-in approves. Without this check, Mallory types the code
    /// from her TV and names Ann as the approver, and her TV signs in as
    /// Ann. Raises `oauth.device_authorization_approved` at `now`, naming
    /// the client by `client_label`.
    ///
    /// # Errors
    ///
    /// - [`DeviceAuthError::NotTheSignedInPerson`] when someone other than
    ///   `user_id` is signed in.
    /// - [`DeviceAuthError::Expired`] when the request has run out.
    /// - [`DeviceAuthError::InvalidTransition`] when it is not pending.
    pub fn approve(
        &mut self,
        user_id: UserId,
        by: &impl SignedInPerson<T>,
        client_label: EventLabel,
        now: OffsetDateTime,
    ) -> Result<(), DeviceAuthError> {
        ensure_signed_in_as(by, &user_id)?;
        if self.is_expired(now) {
            return Err(DeviceAuthError::Expired);
        }
        self.move_to(DeviceAuthState::Approved { by: user_id })?;
        self.raised.raise(DeviceAuthorizationApproved {
            client_id: self.client_id,
            client_label,
            occurred_at: now,
        });
        Ok(())
    }

    /// Records that `user_id`, signed in as `by`, denies the request.
    /// Raises `oauth.device_authorization_denied`, naming the client by
    /// `client_label`.
    ///
    /// # Errors
    ///
    /// - [`DeviceAuthError::NotTheSignedInPerson`] when someone other than
    ///   `user_id` is signed in.
    /// - [`DeviceAuthError::InvalidTransition`] when it is not pending.
    pub fn deny(
        &mut self,
        user_id: UserId,
        by: &impl SignedInPerson<T>,
        client_label: EventLabel,
    ) -> Result<(), DeviceAuthError> {
        ensure_signed_in_as(by, &user_id)?;
        self.move_to(DeviceAuthState::Denied)?;
        self.raised.raise(DeviceAuthorizationDenied {
            client_id: self.client_id,
            client_label,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Hands the approval to the device, once.
    ///
    /// Only the client that started the flow may redeem it, and only while
    /// it may still use the flow. After this, polling with the device code
    /// gets nothing. Raises `oauth.device_authorization_collected` at
    /// `now`, naming `client`.
    ///
    /// # Errors
    ///
    /// - [`DeviceAuthError::ClientRefused`] when `client` did not start the
    ///   flow, is not active, or may not use the device flow.
    /// - [`DeviceAuthError::Expired`] when the request has run out.
    /// - [`DeviceAuthError::InvalidTransition`] when it is not approved.
    pub fn redeem(
        &mut self,
        client: &OAuthClient<T>,
        now: OffsetDateTime,
    ) -> Result<(), DeviceAuthError> {
        let may_redeem = *client.id() == self.client_id
            && client.is_active()
            && client.supports_grant_type(GrantType::DeviceCode);
        if !may_redeem {
            return Err(DeviceAuthError::ClientRefused);
        }
        if self.is_expired(now) {
            return Err(DeviceAuthError::Expired);
        }
        let DeviceAuthState::Approved { by } = self.state else {
            return Err(DeviceAuthError::InvalidTransition(
                InvalidDeviceAuthTransition {
                    from: self.status(),
                    to: DeviceAuthStatus::Redeemed,
                },
            ));
        };
        self.move_to(DeviceAuthState::Redeemed { by })?;
        self.raised.raise(DeviceAuthorizationCollected {
            client_id: self.client_id,
            client_label: EventLabel::of(client.name().as_str()),
            occurred_at: now,
        });
        Ok(())
    }

    /// Marks the request as expired.
    ///
    /// # Errors
    ///
    /// - [`DeviceAuthError::InvalidTransition`] when it is not pending.
    pub fn expire(&mut self) -> Result<(), DeviceAuthError> {
        self.move_to(DeviceAuthState::Expired)
    }

    fn move_to(&mut self, to: DeviceAuthState) -> Result<(), DeviceAuthError> {
        self.status()
            .try_transition(to.status())
            .map_err(DeviceAuthError::InvalidTransition)?;
        self.state = to;
        Ok(())
    }
}

impl<T: TenantScope> Raises for DeviceAuthorization<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Why a change to a device authorization was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeviceAuthError {
    /// The status change is not allowed.
    #[error(transparent)]
    InvalidTransition(#[from] InvalidDeviceAuthTransition),
    /// The request has run out.
    #[error("the device authorization has expired")]
    Expired,
    /// The client redeeming the code did not start the flow, or may no
    /// longer use it.
    #[error("this client may not redeem the device code")]
    ClientRefused,
    /// The person answering is not the one signed in.
    #[error("only the person signed in may answer a device sign-in")]
    NotTheSignedInPerson,
    /// The device polled sooner than its interval allows.
    #[error("the device polled too soon; slow down")]
    SlowDown,
}

impl From<DeviceAuthError> for DomainError {
    fn from(refusal: DeviceAuthError) -> Self {
        match refusal {
            DeviceAuthError::InvalidTransition(transition) => transition.into(),
            DeviceAuthError::Expired | DeviceAuthError::SlowDown => {
                Self::invalid_transition(refusal.to_string())
            }
            DeviceAuthError::ClientRefused | DeviceAuthError::NotTheSignedInPerson => {
                Self::forbidden(refusal.to_string())
            }
        }
    }
}

/// Refuses `by` unless they are the holder of `user_id`.
fn ensure_signed_in_as<T: TenantScope>(
    by: &impl SignedInPerson<T>,
    user_id: &UserId,
) -> Result<(), DeviceAuthError> {
    ensure_holder(by, user_id).map_err(|_| DeviceAuthError::NotTheSignedInPerson)
}

/// Refuses a client that may not start the device flow, or scopes it was
/// not given.
fn ensure_device_client<T: TenantScope>(
    client: &OAuthClient<T>,
    scopes: &[Scope],
) -> Result<(), DomainError> {
    if !client.is_active() || !client.supports_grant_type(GrantType::DeviceCode) {
        return Err(DomainError::forbidden(message!(
            "oauth-this-client-may-not-use-the-2",
            "this client may not use the device authorization flow"
        )));
    }
    if let Some(scope) = client.first_unallowed_scope(scopes) {
        return Err(DomainError::forbidden(message!(
            "oauth-this-client-was-not-given-the",
            format!("this client was not given the scope {}", scope.as_str())
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::identity::account::user::tests::signed_in_as;
    use crate::domains::oauth::clients::client::NewOAuthClient;
    use crate::domains::oauth::clients::credential::ClientCredential;
    use crate::domains::oauth::clients::settings::ClientSettings;
    use crate::domains::oauth::control::tests::key_admin;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::ClientId;

    /// An active client given the device flow and the `read` scope.
    fn client_granted(grant_types: Vec<GrantType>) -> OAuthClient<ResolvedTenant> {
        OAuthClient::create(
            NewOAuthClient {
                id: OAuthClientId::new(),
                client_id_value: ClientId::new("tv_app").unwrap(),
                credential: ClientCredential::secret(TokenHash::from_stored(
                    "hashed_secret".to_owned(),
                )),
                name: crate::test_support::builders::label("Living-room TV"),
                redirect_uris: Vec::new(),
                post_logout_redirect_uris: Vec::new(),
                grant_types,
                scopes: vec![Scope::new("read").unwrap()],
                settings: ClientSettings::platform_defaults(),
            },
            &key_admin(),
        )
        .unwrap()
    }

    /// `user`, signed in as themselves, approves `auth` at `now`.
    fn approve_as(
        auth: &mut DeviceAuthorization<ResolvedTenant>,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<(), DeviceAuthError> {
        auth.approve(user, &signed_in_as::<ResolvedTenant>(user), tv(), now)
    }

    /// Someone signed in as themselves denies `auth`.
    fn deny_as_someone(
        auth: &mut DeviceAuthorization<ResolvedTenant>,
    ) -> Result<(), DeviceAuthError> {
        let user = UserId::new();
        auth.deny(user, &signed_in_as::<ResolvedTenant>(user), tv())
    }

    /// The label the TV app is named by in the audit trail.
    fn tv() -> EventLabel {
        EventLabel::of("Living-room TV")
    }

    /// Mallory's sign-in cannot approve a device request in Ann's name. The
    /// identity mismatch is refused and the request stays pending.
    #[test]
    fn a_device_is_approved_only_by_the_person_signed_in() {
        let mut auth = test_auth();
        let ann = UserId::new();
        let mallory = signed_in_as::<ResolvedTenant>(UserId::new());

        let approved = auth.approve(ann, &mallory, tv(), crate::shared::clock::now());

        assert_eq!(approved, Err(DeviceAuthError::NotTheSignedInPerson));
        assert!(auth.is_pending());
    }

    /// Naming another person while denying a device request is refused.
    /// The request remains pending after the sign-in mismatch.
    #[test]
    fn a_device_is_denied_only_by_the_person_signed_in() {
        let mut auth = test_auth();
        let mallory = signed_in_as::<ResolvedTenant>(UserId::new());

        let denied = auth.deny(UserId::new(), &mallory, tv());

        assert_eq!(denied, Err(DeviceAuthError::NotTheSignedInPerson));
        assert!(auth.is_pending());
    }

    /// A wrong person answering reads as forbidden to the use case.
    #[test]
    fn answering_as_someone_else_is_forbidden() {
        let refused = DomainError::from(DeviceAuthError::NotTheSignedInPerson);

        assert!(matches!(refused, DomainError::Forbidden(_)));
    }

    fn device_client() -> OAuthClient<ResolvedTenant> {
        client_granted(vec![GrantType::DeviceCode])
    }

    fn params(scope: &str) -> CreateDeviceAuthParams {
        CreateDeviceAuthParams {
            device_code_hash: TokenHash::from_stored("hash_device".to_owned()),
            user_code: DeviceUserCode::new("ABCD-1234").unwrap(),
            scopes: vec![Scope::new(scope).unwrap()],
            interval: PollInterval::DEFAULT,
            lifetime: crate::types::Lifetime::seconds(600).unwrap(),
        }
    }

    /// A client registered only for client credentials cannot start a
    /// device-authorization flow. Creation is forbidden.
    #[test]
    fn a_client_not_given_the_device_flow_cannot_start_one() {
        let machine = client_granted(vec![GrantType::ClientCredentials]);

        let refused = DeviceAuthorization::create(&machine, params("read"));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// A device client registered for `read` cannot start an authorization
    /// asking for `admin`. Creation is forbidden.
    #[test]
    fn a_device_flow_asks_only_for_scopes_the_client_was_given() {
        let refused = DeviceAuthorization::create(&device_client(), params("admin"));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    fn test_auth() -> DeviceAuthorization<ResolvedTenant> {
        DeviceAuthorization::create(
            &device_client(),
            CreateDeviceAuthParams {
                device_code_hash: TokenHash::from_stored("hash_device".to_owned()),
                user_code: DeviceUserCode::new("ABCD-1234").unwrap(),
                scopes: vec![Scope::new("read").unwrap()],
                interval: PollInterval::DEFAULT,
                lifetime: crate::types::Lifetime::seconds(600).unwrap(),
            },
        )
        .unwrap()
    }

    /// A new device request is pending and nobody has approved it.
    #[test]
    fn create_is_pending() {
        let auth = test_auth();
        assert!(auth.is_pending());
        assert!(auth.approved_by().is_none());
    }

    /// A user approves the request. It is approved and names that user.
    #[test]
    fn approve_sets_user() {
        let mut auth = test_auth();
        let user = UserId::new();
        let now = crate::shared::clock::now();

        approve_as(&mut auth, user, now).unwrap();
        assert_eq!(auth.status(), DeviceAuthStatus::Approved);
        assert_eq!(auth.approved_by(), Some(&user));
    }

    fn approved_for(client: &OAuthClient<ResolvedTenant>) -> DeviceAuthorization<ResolvedTenant> {
        let mut auth = DeviceAuthorization::create(client, params("read")).unwrap();
        approve_as(&mut auth, UserId::new(), crate::shared::clock::now()).unwrap();
        auth
    }

    /// The TV collects its approval. A second poll with the same code is
    /// refused, so one approval gives one set of tokens.
    #[test]
    fn an_approval_is_redeemed_once() {
        let client = device_client();
        let mut auth = approved_for(&client);
        let now = crate::shared::clock::now();

        auth.redeem(&client, now).unwrap();

        assert_eq!(auth.status(), DeviceAuthStatus::Redeemed);
        assert!(matches!(
            auth.redeem(&client, now),
            Err(DeviceAuthError::InvalidTransition(_))
        ));
    }

    /// A request approved within its ten minutes is collected after 601
    /// seconds. It is refused as expired.
    #[test]
    fn an_expired_approval_cannot_be_redeemed() {
        let client = device_client();
        let mut auth = approved_for(&client);

        let later = crate::shared::clock::now() + time::Duration::seconds(601);

        assert_eq!(auth.redeem(&client, later), Err(DeviceAuthError::Expired));
    }

    /// A different client cannot redeem an approved device authorization.
    /// The client refusal leaves the authorization approved.
    #[test]
    fn another_client_cannot_redeem_the_device_code() {
        let client = device_client();
        let mut auth = approved_for(&client);

        let result = auth.redeem(&device_client(), crate::shared::clock::now());

        assert_eq!(result, Err(DeviceAuthError::ClientRefused));
        assert_eq!(auth.status(), DeviceAuthStatus::Approved);
    }

    /// A user says no to the request. It is denied.
    #[test]
    fn deny_sets_status() {
        let mut auth = test_auth();

        deny_as_someone(&mut auth).unwrap();
        assert_eq!(auth.status(), DeviceAuthStatus::Denied);
    }

    /// A denied request cannot be approved afterwards.
    #[test]
    fn cannot_approve_after_deny() {
        let mut auth = test_auth();
        let now = crate::shared::clock::now();
        deny_as_someone(&mut auth).unwrap();

        assert!(matches!(
            approve_as(&mut auth, UserId::new(), now),
            Err(DeviceAuthError::InvalidTransition(_))
        ));
    }

    /// An approved request cannot be denied afterwards.
    #[test]
    fn cannot_deny_after_approve() {
        let mut auth = test_auth();
        let now = crate::shared::clock::now();
        approve_as(&mut auth, UserId::new(), now).unwrap();

        assert!(matches!(
            deny_as_someone(&mut auth),
            Err(DeviceAuthError::InvalidTransition(_))
        ));
    }

    /// A pending request is marked expired.
    #[test]
    fn expire_sets_status() {
        let mut auth = test_auth();

        auth.expire().unwrap();
        assert_eq!(auth.status(), DeviceAuthStatus::Expired);
    }

    /// A user approves a one-second request two seconds later. It is
    /// refused as expired.
    #[test]
    fn approve_expired_request_fails() {
        let mut auth = DeviceAuthorization::<ResolvedTenant>::create(
            &device_client(),
            CreateDeviceAuthParams {
                device_code_hash: TokenHash::from_stored("h".to_owned()),
                user_code: DeviceUserCode::new("X").unwrap(),
                scopes: vec![],
                interval: PollInterval::DEFAULT,
                lifetime: crate::types::Lifetime::seconds(1).unwrap(),
            },
        )
        .unwrap();

        let future = crate::shared::clock::now() + time::Duration::seconds(2);
        assert_eq!(
            approve_as(&mut auth, UserId::new(), future),
            Err(DeviceAuthError::Expired)
        );
    }

    /// Two seconds after a one-second request was made, it reads as expired
    /// though nobody marked it.
    #[test]
    fn expired_by_time() {
        let auth = DeviceAuthorization::<ResolvedTenant>::create(
            &device_client(),
            CreateDeviceAuthParams {
                device_code_hash: TokenHash::from_stored("h".to_owned()),
                user_code: DeviceUserCode::new("X").unwrap(),
                scopes: vec![],
                interval: PollInterval::DEFAULT,
                lifetime: crate::types::Lifetime::seconds(1).unwrap(),
            },
        )
        .unwrap();

        let future = crate::shared::clock::now() + time::Duration::seconds(2);
        assert!(auth.is_expired(future));
    }

    /// A request keeps its device code hash, its user code "ABCD-1234", its
    /// client and scopes. The device polls with one code and the person types
    /// the other, so either read back wrong could hand over someone else's
    /// approval.
    #[test]
    fn an_authorization_carries_both_codes_and_the_client_they_belong_to() {
        let tv = device_client();
        let client = *tv.id();

        let auth = DeviceAuthorization::<ResolvedTenant>::create(
            &tv,
            CreateDeviceAuthParams {
                device_code_hash: TokenHash::from_stored("hash_device".to_owned()),
                user_code: DeviceUserCode::new("ABCD-1234").unwrap(),
                scopes: vec![Scope::new("read").unwrap()],
                interval: PollInterval::DEFAULT,
                lifetime: crate::types::Lifetime::seconds(600).unwrap(),
            },
        )
        .unwrap();

        assert_eq!(auth.device_code_hash().as_str(), "hash_device");
        assert_eq!(auth.user_code().as_str(), "ABCD-1234");
        assert_eq!(*auth.client_id(), client);
        assert_eq!(auth.scopes(), &[Scope::new("read").unwrap()]);
    }

    /// A request made with a 5-second interval reports 5. The device is told
    /// this wait, and a zero would make it poll without pause.
    #[test]
    fn the_polling_interval_is_the_one_configured() {
        assert_eq!(test_auth().interval().as_secs(), 5);
    }

    /// A zero polling interval is invalid, while a one-second interval is
    /// accepted and retains its duration.
    #[test]
    fn a_zero_polling_interval_is_refused() {
        assert!(PollInterval::seconds(0).is_err());
        assert_eq!(PollInterval::seconds(1).unwrap().as_secs(), 1);
    }

    /// A request is pending until answered. After approval or denial it is
    /// not pending, so the device stops being told to wait.
    #[test]
    fn only_an_unanswered_authorization_is_pending() {
        let mut approved = test_auth();
        assert!(approved.is_pending());
        approve_as(&mut approved, UserId::new(), crate::shared::clock::now()).unwrap();
        assert!(!approved.is_pending());

        let mut denied = test_auth();
        deny_as_someone(&mut denied).unwrap();
        assert!(!denied.is_pending());
    }

    /// The request, with what it raised so far taken out.
    fn fresh(mut auth: DeviceAuthorization<ResolvedTenant>) -> DeviceAuthorization<ResolvedTenant> {
        raised_names(&mut auth);
        auth
    }

    /// The TV starts a device sign-in. The request is raised, naming the TV
    /// app.
    #[test]
    fn starting_raises_oauth_device_authorization_requested() {
        let mut auth = test_auth();

        let events = raised(&mut auth);

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "oauth.device_authorization_requested"
        );
        assert_eq!(client_label_of(&events[0]), "Living-room TV");
    }

    /// Ann approves the TV. The approval is raised, naming the TV app.
    #[test]
    fn approving_raises_oauth_device_authorization_approved() {
        let mut auth = fresh(test_auth());

        approve_as(&mut auth, UserId::new(), crate::shared::clock::now()).unwrap();

        let events = raised(&mut auth);
        assert_eq!(
            events[0].event_type().to_string(),
            "oauth.device_authorization_approved"
        );
        assert_eq!(client_label_of(&events[0]), "Living-room TV");
    }

    /// Ann denies the TV. The denial is raised.
    #[test]
    fn denying_raises_oauth_device_authorization_denied() {
        let mut auth = fresh(test_auth());

        deny_as_someone(&mut auth).unwrap();

        assert_eq!(
            raised_names(&mut auth),
            ["oauth.device_authorization_denied"]
        );
    }

    /// The TV collects Ann's approval. The collection is raised, naming the
    /// TV app.
    #[test]
    fn collecting_raises_oauth_device_authorization_collected() {
        let client = device_client();
        let mut auth = fresh(approved_for(&client));

        auth.redeem(&client, crate::shared::clock::now()).unwrap();

        assert_eq!(
            raised_names(&mut auth),
            ["oauth.device_authorization_collected"]
        );
    }

    /// A pending request runs out. Expiring it raises nothing.
    #[test]
    fn expiring_raises_nothing() {
        let mut auth = fresh(test_auth());

        auth.expire().unwrap();

        assert!(raised_names(&mut auth).is_empty());
    }

    /// The TV polls, then polls again a second later where it must wait
    /// five. It is told to slow down, and must now wait ten.
    #[test]
    fn polling_too_soon_slows_the_device_down() {
        let mut auth = test_auth();
        let now = crate::shared::clock::now();

        auth.poll(now).unwrap();
        let again = auth.poll(now + time::Duration::SECOND);

        assert_eq!(again, Err(DeviceAuthError::SlowDown));
        assert_eq!(auth.interval().as_secs(), 10);
    }

    /// The TV waits its interval between polls. Each poll is taken.
    #[test]
    fn polling_on_time_is_taken() {
        let mut auth = test_auth();
        let now = crate::shared::clock::now();

        auth.poll(now).unwrap();

        assert!(auth.poll(now + time::Duration::seconds(5)).is_ok());
    }

    /// The TV's request is read back from storage. Loading it is no change,
    /// so it has raised nothing.
    #[test]
    fn a_request_read_back_from_storage_has_raised_nothing() {
        let auth = test_auth();
        let row = DeviceAuthRow {
            device_code_hash: auth.device_code_hash.clone(),
            user_code: auth.user_code.clone(),
            client_id: auth.client_id,
            scopes: auth.scopes.clone(),
            state: auth.state,
            interval: auth.interval,
            last_poll: auth.last_poll,
            created_at: auth.created_at,
            expires_at: auth.expires_at,
        };

        let mut read_back = DeviceAuthorization::<ResolvedTenant>::reconstitute(row).unwrap();

        assert!(raised_names(&mut read_back).is_empty());
    }

    /// Approval with a mismatched sign-in, redemption by another client and
    /// approval after denial each fail without raising events.
    #[test]
    fn a_refused_answer_raises_nothing() {
        let client = device_client();
        let mallory = signed_in_as::<ResolvedTenant>(UserId::new());
        let mut pending = fresh(test_auth());
        let mut approved = fresh(approved_for(&client));
        let mut denied = test_auth();
        deny_as_someone(&mut denied).unwrap();
        let mut denied = fresh(denied);
        let now = crate::shared::clock::now();

        let impersonated = pending.approve(UserId::new(), &mallory, tv(), now);
        let stolen = approved.redeem(&device_client(), now);
        let reopened = approve_as(&mut denied, UserId::new(), now);

        assert!(impersonated.is_err());
        assert!(stolen.is_err());
        assert!(reopened.is_err());
        assert!(raised_names(&mut pending).is_empty());
        assert!(raised_names(&mut approved).is_empty());
        assert!(raised_names(&mut denied).is_empty());
    }

    /// The label an event gives the client it names.
    fn client_label_of(event: &DomainEvent) -> String {
        let payload = event.payload();
        let Some(FieldValue::Reference(client)) = payload.value("client") else {
            panic!("the event does not name the client");
        };
        client.label().to_owned()
    }
}
