//! An organization's identity provider as its row holds it: read back into
//! the aggregate, and written out from it.
//!
//! Its settings are kept as a tenant's connections keep theirs, in the
//! federation context's one shape for them.

use ianua_domain::domains::organization::access::identity_provider::{
    OrgIdentityProvider, OrgIdentityProviderRow,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConnectionId, Label, OrganizationId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::federation::connections::config::ConfigColumns;
use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const PROVIDER: Stored = Stored("organization identity provider");

const SAML: Kept = Kept {
    entity: PROVIDER.0,
    column: "saml",
    shape: 1,
};

const OIDC: Kept = Kept {
    entity: PROVIDER.0,
    column: "oidc",
    shape: 1,
};

const SETTINGS: ConfigColumns = ConfigColumns {
    row: PROVIDER,
    saml: SAML,
    oidc: OIDC,
};

/// A provider as it is read. The store's checked queries fill it.
pub(super) struct ProviderRecord {
    pub(super) id: Uuid,
    pub(super) organization_id: Uuid,
    pub(super) name: String,
    pub(super) saml: Option<Value>,
    pub(super) oidc: Option<Value>,
    pub(super) email_trust: String,
    pub(super) assurance_trust: String,
    pub(super) status: String,
    pub(super) created_at: OffsetDateTime,
}

impl ProviderRecord {
    /// The provider the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, the row holds settings for both
    /// protocols or neither, or it breaks a rule the provider keeps.
    pub(super) fn into_provider(self) -> Result<OrgIdentityProvider, DomainError> {
        OrgIdentityProvider::reconstitute(OrgIdentityProviderRow {
            id: ConnectionId::from_uuid(self.id),
            organization_id: OrganizationId::from_uuid(self.organization_id),
            name: PROVIDER.value("name", Label::new("name", self.name))?,
            config: SETTINGS.read(self.saml, self.oidc)?,
            email_trust: PROVIDER.choice(&self.email_trust)?,
            assurance_trust: PROVIDER.choice(&self.assurance_trust)?,
            status: PROVIDER.choice(&self.status)?,
            created_at: self.created_at,
        })
    }
}

/// A provider's columns, as they are written.
pub(super) struct ProviderColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) organization_id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) saml: Option<Value>,
    pub(super) oidc: Option<Value>,
    pub(super) email_trust: &'static str,
    pub(super) assurance_trust: &'static str,
    pub(super) status: &'static str,
    pub(super) created_at: OffsetDateTime,
}

impl<'a> ProviderColumns<'a> {
    /// The columns `provider` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its settings cannot be
    /// written out as JSON.
    pub(super) fn of(provider: &'a OrgIdentityProvider) -> Result<Self, DomainError> {
        let (saml, oidc) = SETTINGS.of(provider.config())?;
        Ok(Self {
            id: provider.id().as_uuid(),
            organization_id: provider.organization_id().as_uuid(),
            name: provider.name().as_str(),
            saml,
            oidc,
            email_trust: provider.email_trust().word(),
            assurance_trust: provider.assurance_trust().word(),
            status: provider.status().word(),
            created_at: provider.created_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::federation::connection::{ConnectionConfig, OidcConfig, SamlConfig};
    use serde_json::json;

    use super::*;
    use crate::postgres::federation::connections::config::StoredSaml;
    use crate::test_support::rows::organization::{org_oidc_config, org_saml_config};

    fn saml() -> SamlConfig {
        let ConnectionConfig::Saml(saml) = org_saml_config() else {
            panic!("the test SAML settings are SAML");
        };
        *saml
    }

    /// The SAML settings are written in the shape pinned here, and a row in
    /// that shape reads back as the same settings.
    #[test]
    fn the_saml_settings_are_stored_in_their_pinned_shape() {
        let stored = json!({"v": 1, "value": {
            "entity_id": "https://acme.okta.com/saml",
            "sso_url": "https://acme.okta.com/saml/sso",
            "slo_url": null,
            "certificate": "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----",
            "next_certificate": null,
            "name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            "request_signing": "unsigned",
            "assertion_encryption": null,
            "metadata_url": null
        }});

        assert_eq!(SAML.seal(&StoredSaml::of(&saml())).unwrap(), stored);
        let read: StoredSaml = SAML.open(stored).unwrap();
        assert_eq!(read.into_config(PROVIDER).unwrap(), saml());
    }

    /// The OIDC settings are written in the shape pinned here, the client
    /// secret as sealed, and a row in that shape reads back.
    #[test]
    fn the_oidc_settings_are_stored_in_their_pinned_shape() {
        let ConnectionConfig::Oidc(oidc) = org_oidc_config() else {
            panic!("the test OIDC settings are OIDC");
        };
        let stored = json!({"v": 1, "value": {
            "issuer": "https://acme.okta.com",
            "client_id": "ianua-dashboard",
            "encrypted_client_secret": "v1.sealedclientsecret",
            "scopes": ["openid", "email"]
        }});

        assert_eq!(OIDC.seal(&oidc).unwrap(), stored);
        assert_eq!(OIDC.open::<OidcConfig>(stored).unwrap(), oidc);
    }

    /// Reading both SAML and OIDC settings for one provider returns an
    /// infrastructure error.
    #[test]
    fn settings_for_both_protocols_are_refused() {
        let saml = SAML.seal(&StoredSaml::of(&saml())).unwrap();
        let oidc = SETTINGS.of(&org_oidc_config()).unwrap().1;

        let read = SETTINGS.read(Some(saml), oidc);

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
