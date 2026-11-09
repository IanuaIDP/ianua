//! Rows the cloud store tests build from: an organization's connections to
//! its own cloud accounts, and the saved organization they belong to.

use std::sync::Arc;

use ianua_app::ports::organization::OrganizationStore;
use ianua_domain::domains::organization::cloud::account::{
    CloudAccountRow, CloudBinding, CloudIdentity, CloudSetup, ConnectionState,
};
use ianua_domain::domains::organization::cloud::credential::{
    CloudCredential, CloudSecret, ExternalId, RoleArn,
};
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::OrganizationId;

use crate::postgres::Databases;
use crate::postgres::organization::PgOrganizationStore;
use crate::test_support::rows::at;
use crate::test_support::rows::organization::organization_row;

/// An organization saved under `slug` in `databases`, as a connection
/// belongs to one the platform keeps.
///
/// # Panics
///
/// When the organization cannot be saved, which is a broken test database.
pub async fn saved_organization(databases: &Arc<Databases>, slug: &str) -> OrganizationId {
    let organization =
        Organization::reconstitute(organization_row(slug, slug)).expect("a valid organization");
    PgOrganizationStore::new(Arc::clone(databases), DomainLimits::default())
        .save(&organization)
        .await
        .expect("the organization is saved");
    *organization.id()
}

/// The external id every test connection to AWS was begun with.
///
/// # Panics
///
/// Never: the id is fixed and valid.
#[must_use]
pub fn external_id() -> ExternalId {
    ExternalId::new("abcdefghijklmnopqrstuvwxyz012345").expect("a valid external id")
}

/// An AWS role assumed under [`external_id`].
///
/// # Panics
///
/// Never: the role is fixed and valid.
#[must_use]
pub fn aws_role() -> CloudCredential {
    CloudCredential::AwsAssumeRole {
        role_arn: RoleArn::new("arn:aws:iam::123456789012:role/Ianua").expect("a valid role"),
        external_id: external_id(),
    }
}

/// A DigitalOcean token.
///
/// # Panics
///
/// Never: the token is fixed and valid.
#[must_use]
pub fn digital_ocean_token() -> CloudCredential {
    CloudCredential::DigitalOceanToken {
        token: CloudSecret::new("dop_v1_secret_token").expect("a valid token"),
    }
}

/// The cloud account a test credential opens.
///
/// # Panics
///
/// Never: the account id is fixed and valid.
#[must_use]
pub fn cloud_identity() -> CloudIdentity {
    CloudIdentity::new("123456789012").expect("a valid account id")
}

/// `credential`, proved ten seconds after the fixed moment to open
/// [`cloud_identity`].
#[must_use]
pub fn verified(credential: CloudCredential) -> ConnectionState {
    ConnectionState::Verified {
        credential,
        at: at(10),
        identity: cloud_identity(),
    }
}

/// `organization`'s connection to AWS, begun with [`external_id`] at the
/// fixed moment and standing in `state` since ten seconds later. A verified
/// one is tied to the account it names.
#[must_use]
pub fn aws_account_row(organization: OrganizationId, state: ConnectionState) -> CloudAccountRow {
    connection_row(
        organization,
        CloudSetup::Aws {
            external_id: external_id(),
        },
        state,
    )
}

/// `organization`'s connection to DigitalOcean, begun at the fixed moment
/// and standing in `state` since ten seconds later.
#[must_use]
pub fn digital_ocean_account_row(
    organization: OrganizationId,
    state: ConnectionState,
) -> CloudAccountRow {
    connection_row(organization, CloudSetup::DigitalOcean, state)
}

fn connection_row(
    organization: OrganizationId,
    setup: CloudSetup,
    state: ConnectionState,
) -> CloudAccountRow {
    let binding = match &state {
        ConnectionState::Verified { identity, .. } => CloudBinding::Bound(identity.clone()),
        ConnectionState::AwaitingCredential
        | ConnectionState::AwaitingVerification { .. }
        | ConnectionState::Failed { .. } => CloudBinding::Unbound,
    };
    CloudAccountRow {
        organization_id: organization,
        setup,
        state,
        binding,
        created_at: at(0),
        updated_at: at(10),
    }
}
