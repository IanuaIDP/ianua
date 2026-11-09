//! An organization's connection to one of its own cloud accounts.
//!
//! The *organization* owns the connection. Each *tenant* decides whether to
//! use it. A cloud account is a billing and trust relationship, and those
//! already sit with the organization: the contract, the plan, the invoice.
//! One company connects one AWS account. If the connection lived on the
//! tenant, the same account would be connected once per tenant. That gives
//! several credentials to rotate, to revoke and to go stale on their own.
//! Offboarding should drop one row and leave nothing of theirs reachable.
//!
//! Placement stays per tenant. `production` may sit on a dedicated instance
//! in the customer's cloud while `staging` shares our platform database. Same
//! company, same connected account, different answers.

use time::OffsetDateTime;

use crate::domains::organization::cloud::credential::{CloudCredential, ExternalId};
use crate::domains::organization::events::cloud::{
    CloudAccountDisconnected, CloudAccountVerified, CloudConnectionStarted, CloudCredentialAttached,
};
use crate::domains::organization::members::control::OrgControl;
use crate::domains::organization::members::permission::{OrgPermission, OrganizationAction};
use crate::domains::tenant::provisioning::infrastructure::CloudProvider;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{OrganizationId, Text};

/// The right that begins a connection and hands it a credential. A
/// connection decides where tenant data is built, so it is a change to the
/// organization.
const UPDATE: OrgPermission = OrgPermission::Organization(OrganizationAction::Update);

text_value! {
    /// Who a credential turned out to be, once we used it.
    ///
    /// Read back from the cloud, not taken on trust. The customer sees it and
    /// can confirm we reached the account they meant. A role ARN is easy to
    /// paste wrong. Finding out at verification is much cheaper than after a
    /// tenant's data is in the wrong account.
    pub struct CloudIdentity;
}

impl TextValue for CloudIdentity {
    const FIELD: &'static str = "cloud_identity";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(1..=256)
    }
}

/// Where a connection sits in its lifecycle.
///
/// An enum, not `verified: bool` next to `reason: Option<String>`, which
/// would allow "verified, and here is why it failed". Each state carries
/// exactly the data it has, the credential included. So a connection can
/// never read as verified, or failed, while holding no credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// We have generated an external id and are waiting for the customer to
    /// create the role and hand back its ARN.
    ///
    /// The external id has to exist before they run our template, because it
    /// goes into the role's trust policy.
    AwaitingCredential,

    /// We hold a credential but have not yet proved it works.
    AwaitingVerification {
        /// The credential to prove.
        credential: CloudCredential,
    },

    /// Proved, against the account named.
    Verified {
        /// The credential that was proved.
        credential: CloudCredential,
        /// When we last proved it.
        at: OffsetDateTime,
        /// Whose account it opened.
        identity: CloudIdentity,
    },

    /// Proved not to work, with the reason to show the customer.
    ///
    /// The credential is kept. The customer usually fixes the trust policy,
    /// not the ARN, so dropping it would make them paste it again.
    Failed {
        /// The credential that did not work.
        credential: CloudCredential,
        /// When the attempt failed.
        at: OffsetDateTime,
        /// Why, in terms the customer can act on.
        reason: Text,
    },
}

impl ConnectionState {
    /// A short, stable name for persistence and audit.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AwaitingCredential => "AwaitingCredential",
            Self::AwaitingVerification { .. } => "AwaitingVerification",
            Self::Verified { .. } => "Verified",
            Self::Failed { .. } => "Failed",
        }
    }

    /// The credential held, whatever has been proved about it.
    #[must_use]
    pub fn credential(&self) -> Option<&CloudCredential> {
        match self {
            Self::AwaitingCredential => None,
            Self::AwaitingVerification { credential }
            | Self::Verified { credential, .. }
            | Self::Failed { credential, .. } => Some(credential),
        }
    }
}

/// The cloud account a connection is tied to, once it is first verified.
///
/// Rotating a credential is allowed. Pointing the connection at another
/// account is not: tenant databases already sit in the first one, and new
/// ones would be built somewhere else. Mallory swaps Acme's role ARN for one
/// in her own AWS account. Without the tie, the next tenant's data lands
/// there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudBinding {
    /// Never verified, so tied to nothing yet.
    Unbound,
    /// Tied to the account it was first verified against.
    Bound(CloudIdentity),
}

/// Which cloud a connection is for, with what it is begun with there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudSetup {
    /// AWS, with the external id we generated for the customer's trust
    /// policy. Holding it here stops a credential that names another
    /// customer's role and their external id from being accepted. That is the
    /// confused-deputy attack the external id exists to prevent.
    Aws {
        /// The id the customer's trust policy must name.
        external_id: ExternalId,
    },
    /// Google Cloud.
    Gcp,
    /// Microsoft Azure.
    Azure,
    /// DigitalOcean.
    DigitalOcean,
    /// The customer's own Kubernetes cluster.
    Kubernetes,
}

impl CloudSetup {
    /// The cloud.
    #[must_use]
    pub fn provider(&self) -> CloudProvider {
        match self {
            Self::Aws { .. } => CloudProvider::Aws,
            Self::Gcp => CloudProvider::Gcp,
            Self::Azure => CloudProvider::Azure,
            Self::DigitalOcean => CloudProvider::DigitalOcean,
            Self::Kubernetes => CloudProvider::Kubernetes,
        }
    }
}

/// One organization's connection to one cloud.
///
/// Keyed by organization and provider, so an organization may connect AWS
/// and GCP and place different tenants in each.
#[derive(Debug, Clone)]
pub struct CloudAccount {
    organization_id: OrganizationId,
    setup: CloudSetup,
    state: ConnectionState,
    binding: CloudBinding,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: RaisedEvents,
}

/// One `organization_cloud_accounts` row, for reconstitution.
pub struct CloudAccountRow {
    /// Owning organization.
    pub organization_id: OrganizationId,
    /// Which cloud, with what the connection was begun with.
    pub setup: CloudSetup,
    /// Lifecycle state, with the credential once the customer hands one over.
    pub state: ConnectionState,
    /// The account it was first verified against, if it has been.
    pub binding: CloudBinding,
    /// When the connection was begun.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

impl CloudAccount {
    /// Begins a connection for `organization_id`, as `by` decides, before
    /// the customer has granted anything.
    ///
    /// Starts in [`ConnectionState::AwaitingCredential`]. For AWS, `setup`
    /// carries the external id the caller generated for the customer's trust
    /// policy, and only a role assumed under that very id is accepted later.
    /// Raises `organization.cloud_connection_started`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update the
    ///   organization. A connection decides where tenant data is built.
    pub fn begin(
        organization_id: OrganizationId,
        setup: CloudSetup,
        now: OffsetDateTime,
        by: &OrgControl<'_>,
    ) -> Result<Self, DomainError> {
        by.ensure_may(&organization_id, UPDATE)?;
        let mut account = Self {
            organization_id,
            setup,
            state: ConnectionState::AwaitingCredential,
            binding: CloudBinding::Unbound,
            created_at: now,
            updated_at: now,
            raised: RaisedEvents::default(),
        };
        account.raised.raise_organization(CloudConnectionStarted {
            organization_id,
            provider: account.provider(),
            occurred_at: now,
        });
        Ok(account)
    }

    /// Rebuilds a cloud connection from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row holds a credential for
    ///   another cloud or external id than it was begun with.
    /// - [`DomainError::Infrastructure`] when the row is verified against
    ///   another account than it is tied to.
    /// - [`DomainError::Infrastructure`] when the row says it changed, or was
    ///   checked, before it was begun.
    pub fn reconstitute(row: CloudAccountRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            organization_id: row.organization_id,
            setup: row.setup,
            state: row.state,
            binding: row.binding,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: RaisedEvents::default(),
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &CloudAccountRow) -> Result<(), DomainError> {
        RowCheck::of("cloud account")
            .holds(
                holds_a_fitting_credential(row),
                "a credential for another cloud or external id",
            )
            .holds(
                verified_where_bound(row),
                "verified against another account than it is tied to",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was begun",
            )
            .in_order_if(
                row.created_at,
                last_checked_at(&row.state),
                "checked before it was begun",
            )
            .finish()
    }

    /// Accepts the customer's credential and queues it for verification.
    ///
    /// Replacing the credential on a verified connection is allowed, because
    /// that is how rotation works. It returns the connection to
    /// [`ConnectionState::AwaitingVerification`], because a new secret has
    /// proved nothing yet. Raises `organization.cloud_credential_attached`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if the credential is for a different
    ///   cloud than this connection. An AWS connection holding an Azure
    ///   service principal would fail far from here, with an unclear message.
    /// - [`DomainError::Forbidden`] if `by` may not update the organization.
    /// - [`DomainError::Validation`] if an AWS role is assumed under another
    ///   external id than the connection was begun with.
    pub fn attach_credential(
        &mut self,
        credential: CloudCredential,
        now: OffsetDateTime,
        by: &OrgControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(&self.organization_id, UPDATE)?;
        ensure_credential_fits(&self.setup, &credential)?;
        self.state = ConnectionState::AwaitingVerification { credential };
        self.updated_at = now;
        self.raised.raise_organization(CloudCredentialAttached {
            organization_id: self.organization_id,
            provider: self.provider(),
            occurred_at: now,
        });
        Ok(())
    }

    /// Records that the platform's own probe of the credential opened the
    /// named account. The first verification ties the connection to it.
    /// Raises `organization.cloud_account_verified` with the result.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] if no credential is held. Otherwise a
    ///   connection that cannot open anything would be marked usable.
    /// - [`DomainError::Forbidden`] if the credential opens another account
    ///   than the connection is tied to. The connection is left as it was.
    pub fn mark_verified(
        &mut self,
        identity: CloudIdentity,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let Some(credential) = self.state.credential().cloned() else {
            return Err(DomainError::conflict(message!(
                "organization-cannot-verify-a-connection-that-holds",
                "cannot verify a connection that holds no credential"
            )));
        };
        if let CloudBinding::Bound(tied) = &self.binding
            && *tied != identity
        {
            return Err(DomainError::forbidden(message!(
                "organization-the-credential-opens-another-cloud-account",
                "the credential opens another cloud account than this connection is tied to"
            )));
        }

        self.binding = CloudBinding::Bound(identity.clone());
        self.state = ConnectionState::Verified {
            credential,
            at: now,
            identity,
        };
        self.updated_at = now;
        self.raise_verification();
        Ok(())
    }

    /// Records that the credential did not work. Raises
    /// `organization.cloud_account_verified` with the failure.
    ///
    /// The credential is kept. The customer usually fixes the trust policy,
    /// not the ARN, so dropping it would make them paste it again.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if the reason is empty or too long.
    /// - [`DomainError::Conflict`] if no credential is held. Nothing was
    ///   tried, so nothing failed.
    pub fn mark_failed(
        &mut self,
        reason: impl Into<String>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let reason = Text::new("reason", reason.into())?;
        let Some(credential) = self.state.credential().cloned() else {
            return Err(DomainError::conflict(message!(
                "organization-cannot-fail-a-connection-that-holds",
                "cannot fail a connection that holds no credential"
            )));
        };

        self.state = ConnectionState::Failed {
            credential,
            at: now,
            reason,
        };
        self.updated_at = now;
        self.raise_verification();
        Ok(())
    }

    /// Raises the check of the credential, with the state it left.
    fn raise_verification(&mut self) {
        self.raised.raise_organization(CloudAccountVerified {
            organization_id: self.organization_id,
            provider: self.provider(),
            result: self.state.clone(),
            occurred_at: self.updated_at,
        });
    }

    /// Whether this connection may be used to provision.
    ///
    /// The one question every caller should ask. Deny by default. Anything
    /// short of a proved credential is a no.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        matches!(self.state, ConnectionState::Verified { .. })
    }

    /// The credential, if this connection is usable.
    ///
    /// `None` for an unverified or failed connection, even when a credential
    /// is held. So an unproved secret cannot reach a cloud call by accident.
    #[must_use]
    pub fn usable_credential(&self) -> Option<&CloudCredential> {
        let ConnectionState::Verified { credential, .. } = &self.state else {
            return None;
        };
        Some(credential)
    }

    /// The stored credential regardless of state.
    ///
    /// For verification, which must read a credential precisely when it is not
    /// yet proved, and for persistence. Everywhere else wants
    /// [`Self::usable_credential`].
    #[must_use]
    pub fn credential(&self) -> Option<&CloudCredential> {
        self.state.credential()
    }

    /// Owning organization.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Which cloud this connection opens.
    #[must_use]
    pub fn provider(&self) -> CloudProvider {
        self.setup.provider()
    }

    /// What the connection was begun with.
    #[must_use]
    pub fn setup(&self) -> &CloudSetup {
        &self.setup
    }

    /// Lifecycle state.
    #[must_use]
    pub fn state(&self) -> &ConnectionState {
        &self.state
    }

    /// The account the connection is tied to, once first verified.
    #[must_use]
    pub fn binding(&self) -> &CloudBinding {
        &self.binding
    }

    /// When the connection was begun.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When it last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// `by` forgetting `organization_id`'s connection to `provider`, which
    /// `left` of its tenants still live in. The caller deletes the
    /// connection, then takes the record the [`CloudDisconnection`] holds.
    ///
    /// Forgetting a connection drops the grant we reach the customer's
    /// cloud with. A tenant whose database lives there would be stranded,
    /// its infrastructure still running and billing where we can no longer
    /// reach it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update the
    ///   organization.
    /// - [`DomainError::Conflict`] when any tenant still lives there, naming
    ///   how many.
    pub fn disconnect(
        organization_id: &OrganizationId,
        provider: CloudProvider,
        left: TenantsInCloud,
        by: &OrgControl<'_>,
    ) -> Result<CloudDisconnection, DomainError> {
        by.ensure_may(organization_id, UPDATE)?;
        if left.0 != 0 {
            return Err(DomainError::conflict(message!(
                "organization-tenant-s-still-have-a-database",
                format!(
                    "{} tenant(s) still have a database in this cloud account; \
                 move them before disconnecting it",
                    left.0
                )
            )));
        }
        Ok(CloudDisconnection {
            organization_id: *organization_id,
            provider,
        })
    }
}

impl RaisesComplete for CloudAccount {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// A connection to a cloud that may be forgotten, as
/// [`CloudAccount::disconnect`] allowed it.
///
/// The connection is deleted without being loaded, so this holds what its
/// record names until the delete is done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloudDisconnection {
    organization_id: OrganizationId,
    provider: CloudProvider,
}

impl CloudDisconnection {
    /// The cloud whose connection is forgotten.
    #[must_use]
    pub fn provider(&self) -> CloudProvider {
        self.provider
    }

    /// The record of the connection forgotten: one
    /// `organization.cloud_account_disconnected`. Taken once it is deleted.
    #[must_use]
    pub fn events(self) -> Vec<DomainEvent> {
        vec![DomainEvent::organization(Box::new(
            CloudAccountDisconnected {
                organization_id: self.organization_id,
                provider: self.provider,
                occurred_at: crate::shared::clock::now(),
            },
        ))]
    }
}

/// How many of an organization's tenants still live in one of its clouds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantsInCloud(u64);

impl TenantsInCloud {
    /// `count` tenants, as the organization's records count them.
    #[must_use]
    pub fn counted(count: u64) -> Self {
        Self(count)
    }
}

/// Refuses a credential for another cloud than `setup`, or an AWS role
/// assumed under another external id than the connection was begun with.
fn ensure_credential_fits(
    setup: &CloudSetup,
    credential: &CloudCredential,
) -> Result<(), DomainError> {
    if credential.provider() != setup.provider() {
        return Err(DomainError::invalid(message!(
            "organization-this-connection-is-for-but-the",
            format!(
                "this connection is for {:?}, but the credential is for {:?}",
                setup.provider(),
                credential.provider()
            )
        )));
    }
    if let (
        CloudSetup::Aws { external_id },
        CloudCredential::AwsAssumeRole {
            external_id: given, ..
        },
    ) = (setup, credential)
        && given != external_id
    {
        return Err(DomainError::invalid(message!(
            "organization-the-role-must-be-assumed-under",
            "the role must be assumed under the external id this connection was begun with"
        )));
    }
    Ok(())
}

/// Whether a stored state's credential, if it holds one, fits the setup.
fn holds_a_fitting_credential(row: &CloudAccountRow) -> bool {
    row.state
        .credential()
        .is_none_or(|credential| ensure_credential_fits(&row.setup, credential).is_ok())
}

/// Whether a stored verified state names the account the row is tied to.
fn verified_where_bound(row: &CloudAccountRow) -> bool {
    let ConnectionState::Verified { identity, .. } = &row.state else {
        return true;
    };
    row.binding == CloudBinding::Bound(identity.clone())
}

/// When a stored state was last proved or found failing, if it was.
fn last_checked_at(state: &ConnectionState) -> Option<OffsetDateTime> {
    match state {
        ConnectionState::Verified { at, .. } | ConnectionState::Failed { at, .. } => Some(*at),
        ConnectionState::AwaitingCredential | ConnectionState::AwaitingVerification { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::organization::cloud::credential::{CloudSecret, ExternalId, RoleArn};
    use crate::domains::organization::lifecycle::tests::founding_of;
    use crate::domains::organization::members::control::tests::{acting, session_of};
    use crate::domains::organization::members::membership::OrgRole;
    use crate::domains::organization::members::org_user::{
        AddedBy, CreateOrgUserParams, OrgPassword, OrgUser,
    };
    use crate::shared::config::DisplayNameLimits;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::types::{DisplayName, Email, OrgUserId};

    /// Acme, whose connections these are.
    fn acme() -> OrganizationId {
        OrganizationId::from_uuid(uuid::Uuid::from_u128(11))
    }

    /// Someone in Acme with `role`.
    fn person(role: OrgRole) -> OrgUser {
        let params = |role| CreateOrgUserParams {
            id: OrgUserId::new(),
            organization_id: acme(),
            email: Email::new("ann@acme.com").unwrap(),
            display_name: DisplayName::new("Ann", &DisplayNameLimits::default()).unwrap(),
            password_hash: OrgPassword::NotSet,
            role,
        };
        let founder = OrgUser::create(
            params(OrgRole::Owner),
            AddedBy::Founding(founding_of(acme())),
        )
        .unwrap();
        if role == OrgRole::Owner {
            return founder;
        }
        let session = session_of(&founder);
        OrgUser::create(params(role), AddedBy::Member(acting(&founder, &session))).unwrap()
    }

    /// `credential` handed to `account` at `at` by Acme's owner.
    fn attach(
        account: &mut CloudAccount,
        credential: CloudCredential,
        at: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let ann = person(OrgRole::Owner);
        let session = session_of(&ann);
        account.attach_credential(credential, at, &acting(&ann, &session))
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    fn later() -> OffsetDateTime {
        now() + time::Duration::minutes(5)
    }

    fn aws_credential() -> CloudCredential {
        CloudCredential::AwsAssumeRole {
            role_arn: RoleArn::new("arn:aws:iam::123456789012:role/Ianua").unwrap(),
            external_id: ExternalId::new("abcdefghijklmnopqrstuvwxyz012345").unwrap(),
        }
    }

    fn do_credential() -> CloudCredential {
        CloudCredential::DigitalOceanToken {
            token: CloudSecret::new("dop_v1_token").unwrap(),
        }
    }

    fn aws_setup() -> CloudSetup {
        CloudSetup::Aws {
            external_id: ExternalId::new("abcdefghijklmnopqrstuvwxyz012345").unwrap(),
        }
    }

    fn aws_account() -> CloudAccount {
        let ann = person(OrgRole::Owner);
        let session = session_of(&ann);
        CloudAccount::begin(acme(), aws_setup(), now(), &acting(&ann, &session)).unwrap()
    }

    /// A member cannot begin a cloud connection or attach a credential;
    /// the existing connection stays awaiting a credential.
    #[test]
    fn a_plain_member_changes_no_connection() {
        let sam = person(OrgRole::Member);
        let session = session_of(&sam);
        let by_sam = acting(&sam, &session);
        let mut account = aws_account();

        let begun = CloudAccount::begin(acme(), aws_setup(), now(), &by_sam);
        let attached = account.attach_credential(aws_credential(), later(), &by_sam);

        assert!(matches!(begun, Err(DomainError::Forbidden(_))));
        assert!(matches!(attached, Err(DomainError::Forbidden(_))));
        assert_eq!(account.state(), &ConnectionState::AwaitingCredential);
    }

    /// An owner cannot disconnect a cloud still used by a tenant, and a
    /// member cannot disconnect even an unused cloud. An owner can
    /// disconnect once its tenant count is zero.
    #[test]
    fn a_connection_is_forgotten_only_once_no_tenant_lives_there() {
        let (olivia, sam) = (person(OrgRole::Owner), person(OrgRole::Member));
        let (olivias, sams) = (session_of(&olivia), session_of(&sam));
        let by_olivia = acting(&olivia, &olivias);
        let none = TenantsInCloud::counted(0);

        let aws = CloudProvider::Aws;

        let still_used =
            CloudAccount::disconnect(&acme(), aws, TenantsInCloud::counted(1), &by_olivia);
        let by_sam = CloudAccount::disconnect(&acme(), aws, none, &acting(&sam, &sams));
        let emptied = CloudAccount::disconnect(&acme(), aws, none, &by_olivia);

        assert!(matches!(still_used, Err(DomainError::Conflict(_))));
        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(emptied.is_ok());
    }

    /// Olivia disconnects Acme's AWS account once nothing lives there. The
    /// record names the cloud forgotten.
    #[test]
    fn a_disconnection_records_the_cloud_forgotten() {
        let olivia = person(OrgRole::Owner);
        let session = session_of(&olivia);
        let none = TenantsInCloud::counted(0);

        let disconnection = CloudAccount::disconnect(
            &acme(),
            CloudProvider::Aws,
            none,
            &acting(&olivia, &session),
        )
        .unwrap();

        let events = disconnection.events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "organization.cloud_account_disconnected"
        );
        assert_eq!(events[0].payload().get("provider"), Some("aws"));
    }

    /// Acme's owner begins an AWS connection, hands it a role, and the
    /// probe first fails, then works. Each step is raised, in order, the
    /// checks with what they found.
    #[test]
    fn each_step_of_a_connection_raises_its_record() {
        let mut account = aws_account();
        attach(&mut account, aws_credential(), now()).unwrap();
        account.mark_failed("not yet trusted", later()).unwrap();
        account.mark_verified(identity(), later()).unwrap();

        let events = account.take_events();
        let names: Vec<String> = events.iter().map(|e| e.event_type().to_string()).collect();
        assert_eq!(
            names,
            [
                "organization.cloud_connection_started",
                "organization.cloud_credential_attached",
                "organization.cloud_account_verified",
                "organization.cloud_account_verified",
            ]
        );
        assert_eq!(events[2].payload().get("result"), Some("Failed"));
        assert_eq!(events[3].payload().get("result"), Some("Verified"));
    }

    /// A member's credential attachment and verification without a held
    /// credential are both refused, raising no events.
    #[test]
    fn a_refused_step_raises_nothing() {
        let mut account = aws_account();
        let _ = account.take_events();
        let sam = person(OrgRole::Member);
        let session = session_of(&sam);

        let attached = account.attach_credential(aws_credential(), now(), &acting(&sam, &session));
        let verified = account.mark_verified(identity(), later());

        assert!(attached.is_err());
        assert!(verified.is_err());
        assert!(account.take_events().is_empty());
    }

    /// A connection is read back from storage. Loading it is no change, so
    /// it has raised nothing.
    #[test]
    fn a_connection_read_back_from_storage_has_raised_nothing() {
        let mut account = CloudAccount::reconstitute(CloudAccountRow {
            organization_id: acme(),
            setup: aws_setup(),
            state: ConnectionState::AwaitingCredential,
            binding: CloudBinding::Unbound,
            created_at: now(),
            updated_at: now(),
        })
        .unwrap();

        assert!(account.take_events().is_empty());
    }

    /// After credential rotation, verification against a different account
    /// is refused. The connection stays unusable and bound to its original
    /// account.
    #[test]
    fn a_rotated_credential_cannot_move_the_connection_to_another_account() {
        let mut account = aws_account();
        attach(&mut account, aws_credential(), now()).unwrap();
        account.mark_verified(identity(), now()).unwrap();
        attach(&mut account, aws_credential(), later()).unwrap();

        let moved = account.mark_verified(CloudIdentity::new("210987654321").unwrap(), later());

        assert!(matches!(moved, Err(DomainError::Forbidden(_))));
        assert!(!account.is_usable());
        assert_eq!(account.binding(), &CloudBinding::Bound(identity()));
    }

    fn identity() -> CloudIdentity {
        CloudIdentity::new("123456789012").unwrap()
    }

    /// Acme starts connecting its AWS account. The connection waits for a
    /// credential, holds none, and cannot be used to provision.
    #[test]
    fn a_new_connection_awaits_a_credential_and_is_not_usable() {
        let account = aws_account();
        assert_eq!(account.state(), &ConnectionState::AwaitingCredential);
        assert!(!account.is_usable());
        assert!(account.credential().is_none());
    }

    /// A role using a different external ID is refused, leaving the
    /// connection awaiting a credential.
    #[test]
    fn a_role_under_another_external_id_is_refused() {
        let mut account = aws_account();
        let theirs = CloudCredential::AwsAssumeRole {
            role_arn: RoleArn::new("arn:aws:iam::210987654321:role/Victim").unwrap(),
            external_id: ExternalId::new("zyxwvutsrqponmlkjihgfedcba543210").unwrap(),
        };

        let result = attach(&mut account, theirs, later());

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert_eq!(account.state(), &ConnectionState::AwaitingCredential);
    }

    /// Acme hands over its role ARN five minutes in. The connection waits for
    /// verification, is not yet usable, and records the change time.
    #[test]
    fn attaching_a_credential_queues_it_for_verification() {
        let mut account = aws_account();
        attach(&mut account, aws_credential(), later()).unwrap();

        assert!(matches!(
            account.state(),
            ConnectionState::AwaitingVerification { .. }
        ));
        assert!(!account.is_usable());
        assert_eq!(account.updated_at(), later());
    }

    /// Acme's role is assumed and opens account `123456789012`. The
    /// connection becomes usable and hands out its credential.
    #[test]
    fn verifying_makes_the_connection_usable() {
        let mut account = aws_account();
        attach(&mut account, aws_credential(), now()).unwrap();
        account.mark_verified(identity(), later()).unwrap();

        assert!(account.is_usable());
        assert!(account.usable_credential().is_some());
    }

    /// Acme's role could not be assumed. The connection is not usable and
    /// hands out no credential.
    #[test]
    fn a_failed_connection_is_not_usable() {
        let mut account = aws_account();
        attach(&mut account, aws_credential(), now()).unwrap();
        account
            .mark_failed("the role could not be assumed", later())
            .unwrap();

        assert!(!account.is_usable());
        assert!(account.usable_credential().is_none());
    }

    /// Acme's trust policy lacks the external id, so verification fails. The
    /// role ARN is kept for the retry, but is still not handed out for use.
    #[test]
    fn a_failed_connection_keeps_the_credential_so_it_need_not_be_pasted_again() {
        let mut account = aws_account();
        attach(&mut account, aws_credential(), now()).unwrap();
        account
            .mark_failed("trust policy is missing the external id", later())
            .unwrap();

        assert!(account.credential().is_some());
        assert!(account.usable_credential().is_none());
    }

    /// Acme pastes a DigitalOcean token into its AWS connection. It is
    /// refused and the connection still waits for a credential.
    #[test]
    fn a_credential_for_another_cloud_is_refused() {
        let mut account = aws_account();
        let err = attach(&mut account, do_credential(), now());

        assert!(matches!(err, Err(DomainError::Validation(_))));
        assert_eq!(account.state(), &ConnectionState::AwaitingCredential);
    }

    /// A connection with no credential is marked verified. It is refused, so
    /// a connection that can open nothing never reads as usable.
    #[test]
    fn verifying_without_a_credential_is_refused() {
        let mut account = aws_account();
        let err = account.mark_verified(identity(), now());

        assert!(matches!(err, Err(DomainError::Conflict(_))));
        assert!(!account.is_usable());
    }

    /// Acme rotates the credential on a verified connection. The connection
    /// goes back to waiting for verification and stops being usable.
    #[test]
    fn rotating_a_credential_returns_a_verified_connection_to_unverified() {
        let mut account = aws_account();
        attach(&mut account, aws_credential(), now()).unwrap();
        account.mark_verified(identity(), now()).unwrap();
        assert!(account.is_usable());

        attach(&mut account, aws_credential(), later()).unwrap();

        assert!(
            !account.is_usable(),
            "a replacement secret has proved nothing yet"
        );
        assert!(matches!(
            account.state(),
            ConnectionState::AwaitingVerification { .. }
        ));
    }

    /// A failure is recorded with an empty reason. It is refused, since the
    /// customer would have nothing to act on.
    #[test]
    fn an_empty_failure_reason_is_refused() {
        let mut account = aws_account();
        attach(&mut account, aws_credential(), now()).unwrap();

        assert!(matches!(
            account.mark_failed("", later()),
            Err(DomainError::Validation(_))
        ));
    }

    /// A failure is recorded with a 501-character reason, one past the limit.
    /// It is refused.
    #[test]
    fn an_overlong_failure_reason_is_refused() {
        let mut account = aws_account();
        attach(&mut account, aws_credential(), now()).unwrap();

        assert!(matches!(
            account.mark_failed("x".repeat(501), later()),
            Err(DomainError::Validation(_))
        ));
    }

    /// A failure is recorded with a reason of exactly 500 characters. It is
    /// kept, so the customer still gets the full diagnosis.
    #[test]
    fn a_failure_reason_of_exactly_the_limit_is_kept() {
        let mut account = aws_account();
        attach(&mut account, aws_credential(), now()).unwrap();

        assert!(account.mark_failed("x".repeat(500), later()).is_ok());
        assert!(matches!(account.state(), ConnectionState::Failed { .. }));
    }

    /// The cloud reports account `123456789012`. The identity reads back as
    /// that number, so Acme can check it reached the account it meant.
    #[test]
    fn an_identity_reads_back_as_the_value_it_was_given() {
        assert_eq!(identity().as_str(), "123456789012");
    }

    /// A verified AWS connection is loaded from storage. It is usable and
    /// keeps its organization and cloud.
    #[test]
    fn reconstitute_restores_a_verified_connection() {
        let org = OrganizationId::new();
        let account = CloudAccount::reconstitute(CloudAccountRow {
            organization_id: org,
            setup: aws_setup(),
            state: ConnectionState::Verified {
                credential: aws_credential(),
                at: now(),
                identity: identity(),
            },
            binding: CloudBinding::Bound(identity()),
            created_at: now(),
            updated_at: later(),
        })
        .unwrap();

        assert!(account.is_usable());
        assert_eq!(account.organization_id(), &org);
        assert_eq!(account.provider(), CloudProvider::Aws);
    }

    /// A stored row says the connection is verified against one account but
    /// tied to another. Loading it is refused as corrupt.
    #[test]
    fn a_stored_connection_verified_off_its_tie_is_refused() {
        let row = CloudAccountRow {
            organization_id: acme(),
            setup: aws_setup(),
            state: ConnectionState::Verified {
                credential: aws_credential(),
                at: now(),
                identity: identity(),
            },
            binding: CloudBinding::Bound(CloudIdentity::new("210987654321").unwrap()),
            created_at: now(),
            updated_at: later(),
        };

        assert!(refused_as_corrupt(&CloudAccount::reconstitute(row)));
    }

    /// A connection with no credential is marked failed. It is refused and
    /// still waits for a credential, since nothing was tried.
    #[test]
    fn failing_a_connection_with_no_credential_is_refused() {
        let mut account = aws_account();

        let result = account.mark_failed("the role could not be assumed", later());

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert_eq!(account.state(), &ConnectionState::AwaitingCredential);
    }

    /// Each state is named `AwaitingCredential`, `AwaitingVerification`,
    /// `Verified` or `Failed`. A renamed state fails here instead of breaking
    /// stored rows.
    #[test]
    fn state_names_are_stable_for_persistence() {
        assert_eq!(
            ConnectionState::AwaitingCredential.as_str(),
            "AwaitingCredential"
        );
        assert_eq!(
            ConnectionState::AwaitingVerification {
                credential: aws_credential()
            }
            .as_str(),
            "AwaitingVerification"
        );
        assert_eq!(
            ConnectionState::Verified {
                credential: aws_credential(),
                at: now(),
                identity: identity()
            }
            .as_str(),
            "Verified"
        );
        assert_eq!(
            ConnectionState::Failed {
                credential: aws_credential(),
                at: now(),
                reason: Text::new("reason", "nope".to_owned()).unwrap()
            }
            .as_str(),
            "Failed"
        );
    }

    /// A connection holding Acme's role is printed with `{:?}`, as a log line
    /// would. The external id shows as redacted.
    #[test]
    fn debug_output_never_carries_the_credential() {
        let mut account = aws_account();
        attach(&mut account, aws_credential(), now()).unwrap();

        let rendered = format!("{account:?}");
        assert!(!rendered.contains("abcdefghijklmnopqrstuvwxyz012345"));
        assert!(rendered.contains("redacted"));
    }

    /// A stored AWS connection holds a DigitalOcean token. Loading it is
    /// refused as a corrupt row, instead of failing later with an unclear
    /// message.
    #[test]
    fn a_stored_connection_holding_another_clouds_credential_is_refused() {
        let account = aws_account();
        let row = CloudAccountRow {
            organization_id: account.organization_id,
            setup: account.setup.clone(),
            state: ConnectionState::AwaitingVerification {
                credential: do_credential(),
            },
            binding: CloudBinding::Unbound,
            created_at: account.created_at,
            updated_at: account.updated_at,
        };

        assert!(refused_as_corrupt(&CloudAccount::reconstitute(row)));
    }
}
