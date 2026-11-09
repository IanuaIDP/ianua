//! A cloud connection as its row holds it: read back into the aggregate,
//! once its sealed parts are opened, and written out from it, before they
//! are sealed.
//!
//! Each part is sealed for the organization, the field and the cloud it
//! belongs to, by the sealer itself, so a part copied into another
//! organization's row, or another cloud's, does not open there.

use ianua_domain::domains::organization::cloud::account::{
    CloudAccount, CloudAccountRow, CloudBinding, CloudIdentity, CloudSetup, ConnectionState,
};
use ianua_domain::domains::organization::cloud::credential::{CloudCredential, ExternalId};
use ianua_domain::domains::tenant::provisioning::infrastructure::CloudProvider;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrganizationId, SealedSecret, Text};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::cloud::accounts::credential::StoredCredential;
use crate::postgres::cloud::accounts::words::Standing;
use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const CLOUD_ACCOUNT: Stored = Stored("cloud account");

const CREDENTIAL: Kept = Kept {
    entity: CLOUD_ACCOUNT.0,
    column: "credential",
    shape: 3,
};

const EXTERNAL_ID: Kept = Kept {
    entity: CLOUD_ACCOUNT.0,
    column: "external id",
    shape: 2,
};

/// A connection as it is read, its external id and credential still
/// sealed. The store's checked queries fill it.
pub(super) struct CloudAccountRecord {
    pub(super) organization_id: Uuid,
    pub(super) provider: String,
    pub(super) external_id_sealed: String,
    pub(super) state: String,
    pub(super) credential_sealed: Option<String>,
    pub(super) checked_at: Option<OffsetDateTime>,
    pub(super) verified_identity: Option<String>,
    pub(super) failure_reason: Option<String>,
    pub(super) bound_identity: Option<String>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl CloudAccountRecord {
    /// The organization the connection is of.
    pub(super) fn organization(&self) -> OrganizationId {
        OrganizationId::from_uuid(self.organization_id)
    }

    /// The external id as the record keeps it, sealed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the column holds nothing
    /// a sealer could have written.
    pub(super) fn sealed_external_id(&self) -> Result<SealedSecret, DomainError> {
        CLOUD_ACCOUNT.value(
            "external id",
            SealedSecret::new(self.external_id_sealed.as_str()),
        )
    }

    /// The credential as the record keeps it, sealed, or none while the
    /// connection waits for one.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the column holds nothing
    /// a sealer could have written.
    pub(super) fn sealed_credential(&self) -> Result<Option<SealedSecret>, DomainError> {
        self.credential_sealed
            .as_deref()
            .map(|sealed| CLOUD_ACCOUNT.value("credential", SealedSecret::new(sealed)))
            .transpose()
    }

    /// The connection the record holds, with `external_id` and
    /// `credential` opened from their sealed forms, rebuilt through the
    /// domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, the columns contradict its state, or
    /// the row breaks a rule the connection keeps.
    pub(super) fn into_account(
        self,
        external_id: ExternalId,
        credential: Option<CloudCredential>,
    ) -> Result<CloudAccount, DomainError> {
        let provider: CloudProvider = CLOUD_ACCOUNT.choice(&self.provider)?;
        let standing: Standing = CLOUD_ACCOUNT.choice(&self.state)?;
        let binding = match self.bound_identity {
            None => CloudBinding::Unbound,
            Some(identity) => CloudBinding::Bound(identity_from(identity)?),
        };
        let state = state_from(
            standing,
            credential,
            self.checked_at,
            (self.verified_identity, self.failure_reason),
        )?;
        CloudAccount::reconstitute(CloudAccountRow {
            organization_id: OrganizationId::from_uuid(self.organization_id),
            setup: setup_for(provider, external_id),
            state,
            binding,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// The setup a connection to `provider` was begun with. Only AWS keeps the
/// external id in it; every cloud keeps it beside the connection.
fn setup_for(provider: CloudProvider, external_id: ExternalId) -> CloudSetup {
    match provider {
        CloudProvider::Aws => CloudSetup::Aws { external_id },
        CloudProvider::Gcp => CloudSetup::Gcp,
        CloudProvider::Azure => CloudSetup::Azure,
        CloudProvider::DigitalOcean => CloudSetup::DigitalOcean,
        CloudProvider::Kubernetes => CloudSetup::Kubernetes,
    }
}

/// The state `standing` names, from the columns its case fills: the
/// credential, when it was checked, and the identity or the reason the
/// cloud answered with.
fn state_from(
    standing: Standing,
    credential: Option<CloudCredential>,
    checked_at: Option<OffsetDateTime>,
    answer: (Option<String>, Option<String>),
) -> Result<ConnectionState, DomainError> {
    match (standing, credential, checked_at, answer) {
        (Standing::AwaitingCredential, None, None, (None, None)) => {
            Ok(ConnectionState::AwaitingCredential)
        }
        (Standing::AwaitingVerification, Some(credential), None, (None, None)) => {
            Ok(ConnectionState::AwaitingVerification { credential })
        }
        (Standing::Verified, Some(credential), Some(at), (Some(identity), None)) => {
            verified_state(credential, at, identity)
        }
        (Standing::Failed, Some(credential), Some(at), (None, Some(reason))) => {
            Ok(ConnectionState::Failed {
                credential,
                at,
                reason: CLOUD_ACCOUNT.value("failure reason", Text::new("reason", reason))?,
            })
        }
        (
            Standing::AwaitingCredential
            | Standing::AwaitingVerification
            | Standing::Verified
            | Standing::Failed,
            _,
            _,
            _,
        ) => Err(DomainError::corrupt_row(
            CLOUD_ACCOUNT.0,
            "a state its columns contradict",
        )),
    }
}

/// Rebuilds a verified connection only after its cloud identity passes validation.
fn verified_state(
    credential: CloudCredential,
    at: OffsetDateTime,
    identity: String,
) -> Result<ConnectionState, DomainError> {
    Ok(ConnectionState::Verified {
        credential,
        at,
        identity: identity_from(identity)?,
    })
}

/// A stored cloud account id, read back through its rules.
fn identity_from(stored: String) -> Result<CloudIdentity, DomainError> {
    CLOUD_ACCOUNT.value("identity", CloudIdentity::new(stored))
}

/// What `credential` is sealed as: its stored shape, in the column's
/// envelope, as JSON.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the credential cannot be
/// written out.
pub(super) fn credential_json(credential: &CloudCredential) -> Result<Vec<u8>, DomainError> {
    let kept = CREDENTIAL.seal(&StoredCredential::of(credential))?;
    serde_json::to_vec(&kept).map_err(DomainError::infra)
}

/// The credential `opened`, a sealed credential once opened, holds.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it is not the JSON of a
/// stored credential, its shape is unknown, or a part no longer passes its
/// rules.
pub(super) fn credential_from(opened: &[u8]) -> Result<CloudCredential, DomainError> {
    let stored: Value = serde_json::from_slice(opened).map_err(DomainError::infra)?;
    CREDENTIAL
        .open::<StoredCredential>(stored)?
        .into_credential()
}

/// What `external_id` is sealed as: its text, in the column's envelope, as
/// JSON.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it cannot be written out.
pub(super) fn external_id_json(external_id: &ExternalId) -> Result<Vec<u8>, DomainError> {
    let kept = EXTERNAL_ID.seal(external_id.as_str())?;
    serde_json::to_vec(&kept).map_err(DomainError::infra)
}

/// The external id `opened`, a sealed external id once opened, holds.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it is not the JSON of a
/// stored external id, its shape is unknown, or it no longer passes its
/// rules.
pub(super) fn external_id_from(opened: &[u8]) -> Result<ExternalId, DomainError> {
    let stored: Value = serde_json::from_slice(opened).map_err(DomainError::infra)?;
    let text: String = EXTERNAL_ID.open(stored)?;
    CLOUD_ACCOUNT.value("external id", ExternalId::new(text))
}

/// A connection's columns, as they are written, besides its sealed parts.
pub(super) struct CloudAccountColumns<'a> {
    pub(super) organization_id: &'a Uuid,
    pub(super) provider: &'static str,
    pub(super) state: &'static str,
    pub(super) checked_at: Option<OffsetDateTime>,
    pub(super) verified_identity: Option<&'a str>,
    pub(super) failure_reason: Option<&'a str>,
    pub(super) bound_identity: Option<&'a str>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> CloudAccountColumns<'a> {
    /// The columns `account` is written to.
    pub(super) fn of(account: &'a CloudAccount) -> Self {
        let (checked_at, verified_identity, failure_reason) = match account.state() {
            ConnectionState::AwaitingCredential | ConnectionState::AwaitingVerification { .. } => {
                (None, None, None)
            }
            ConnectionState::Verified { at, identity, .. } => {
                (Some(*at), Some(identity.as_str()), None)
            }
            ConnectionState::Failed { at, reason, .. } => (Some(*at), None, Some(reason.as_str())),
        };
        let bound_identity = match account.binding() {
            CloudBinding::Unbound => None,
            CloudBinding::Bound(identity) => Some(identity.as_str()),
        };
        Self {
            organization_id: account.organization_id().as_uuid(),
            provider: account.provider().word(),
            state: Standing::of(account.state()).word(),
            checked_at,
            verified_identity,
            failure_reason,
            bound_identity,
            created_at: account.created_at(),
            updated_at: account.updated_at(),
        }
    }
}

#[cfg(test)]
mod tests {
    //! The shape the sealed credential is written in today. A row written
    //! now is read for years, so when this fails, the domain changed what a
    //! credential holds: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::organization::cloud::credential::{CloudSecret, RoleArn};
    use serde_json::json;

    use super::*;

    const EXTERNAL: &str = "abcdefghijklmnopqrstuvwxyz012345";

    fn json_of(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    /// An AWS role is written in the shape pinned here, and a credential in
    /// that shape reads back.
    #[test]
    fn an_aws_role_is_stored_in_its_pinned_shape() {
        let role = CloudCredential::AwsAssumeRole {
            role_arn: RoleArn::new("arn:aws:iam::123456789012:role/Ianua").unwrap(),
            external_id: ExternalId::new(EXTERNAL).unwrap(),
        };
        let stored = json!({"v": 3, "value": {
            "kind": "aws_assume_role",
            "role_arn": "arn:aws:iam::123456789012:role/Ianua",
            "external_id": EXTERNAL
        }});

        let written = credential_json(&role).unwrap();

        assert_eq!(serde_json::from_slice::<Value>(&written).unwrap(), stored);
        let pinned = CREDENTIAL.seal(&StoredCredential::of(&role)).unwrap();
        assert_eq!(pinned, stored);
        let read = credential_from(&json_of(&stored)).unwrap();
        assert!(read == role);
    }

    /// A DigitalOcean token is written in the shape pinned here, and reads
    /// back.
    #[test]
    fn a_token_is_stored_in_its_pinned_shape() {
        let token = CloudCredential::DigitalOceanToken {
            token: CloudSecret::new("dop_v1_token").unwrap(),
        };
        let stored = json!({"v": 3, "value": {
            "kind": "digital_ocean_token",
            "token": "dop_v1_token"
        }});

        let written = credential_json(&token).unwrap();

        assert_eq!(serde_json::from_slice::<Value>(&written).unwrap(), stored);
        assert!(credential_from(&written).unwrap() == token);
    }

    /// An external id is written in the shape pinned here, and reads back.
    #[test]
    fn an_external_id_is_stored_in_its_pinned_shape() {
        let external_id = ExternalId::new(EXTERNAL).unwrap();
        let stored = json!({"v": 2, "value": EXTERNAL});

        let written = external_id_json(&external_id).unwrap();

        assert_eq!(serde_json::from_slice::<Value>(&written).unwrap(), stored);
        let pinned = EXTERNAL_ID.seal(EXTERNAL).unwrap();
        assert_eq!(pinned, stored);
        assert!(external_id_from(&written).unwrap() == external_id);
    }

    /// A version-two credential envelope containing owner and part
    /// objects is rejected as corrupt storage.
    #[test]
    fn a_credential_in_an_older_shape_is_refused() {
        let older = json!({"v": 2, "value": {
            "owner": {"organization": Uuid::nil(), "provider": "digitalocean"},
            "part": {"kind": "digital_ocean_token", "token": "dop_v1_token"}
        }});

        let read = credential_from(&json_of(&older));

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
