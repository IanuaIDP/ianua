//! A tenant's SAML app as its row holds it: read back into the aggregate,
//! and written out from it.
//!
//! How the app is answered is one value of many parts, kept whole in one
//! JSON column. Its addresses, certificates and names are built through
//! their own checks, which a derived reader would step around, so they are
//! kept in a shape of this store's own, every value as plain text, and
//! rebuilt through those checks.

use ianua_domain::domains::federation::saml::name_id::NameIdFormat;
use ianua_domain::domains::federation::service_provider::{
    AcsUrls, AssertionEncryption, AttributeStatement, AttributeStatements, RequestSigningRule,
    SamlAttributeName, SamlServiceProvider, SamlServiceProviderRow, SamlServiceProviderSettings,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    CertificatePem, HttpsUrl, Label, SamlEntityId, SamlServiceProviderId, Setting,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const APP: Stored = Stored("SAML app");

const SETTINGS: Kept = Kept {
    entity: APP.0,
    column: "settings",
    shape: 1,
};

/// An app as it is read. The store's checked queries fill it.
pub(super) struct AppRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) entity_id: String,
    pub(super) status: String,
    pub(super) settings: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl AppRecord {
    /// The app the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, the settings do not read, or the row
    /// breaks a rule the app keeps.
    pub(super) fn into_app(self) -> Result<SamlServiceProvider<ResolvedTenant>, DomainError> {
        let settings: StoredSettings = SETTINGS.open(self.settings)?;
        SamlServiceProvider::reconstitute(SamlServiceProviderRow {
            id: SamlServiceProviderId::from_uuid(self.id),
            name: APP.value("name", Label::new("name", self.name))?,
            entity_id: APP.value("entity id", SamlEntityId::new(self.entity_id))?,
            status: APP.choice(&self.status)?,
            settings: settings.into_settings()?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// The apps `records` hold.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` for the first record that does
/// not read back.
pub(super) fn apps_from(
    records: Vec<AppRecord>,
) -> Result<Vec<SamlServiceProvider<ResolvedTenant>>, DomainError> {
    records.into_iter().map(AppRecord::into_app).collect()
}

/// An app's columns, as they are written.
pub(super) struct AppColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) entity_id: &'a str,
    pub(super) status: &'static str,
    pub(super) settings: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> AppColumns<'a> {
    /// The columns `app` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its settings cannot be
    /// written out as JSON.
    pub(super) fn of(app: &'a SamlServiceProvider<ResolvedTenant>) -> Result<Self, DomainError> {
        Ok(Self {
            id: app.id().as_uuid(),
            name: app.name().as_str(),
            entity_id: app.entity_id().as_str(),
            status: app.status().word(),
            settings: SETTINGS.seal(&StoredSettings::of(app.settings()))?,
            created_at: app.created_at(),
            updated_at: app.updated_at(),
        })
    }
}

/// How an app is answered, as it is kept: its default address first.
#[derive(Serialize, Deserialize)]
struct StoredSettings {
    acs_urls: Vec<String>,
    logout_url: Option<String>,
    name_id_format: String,
    attributes: Vec<StoredStatement>,
    signing: String,
    encryption_certificate: Option<String>,
    request_signing_certificate: Option<String>,
}

/// One attribute the app is sent, as it is kept.
#[derive(Serialize, Deserialize)]
struct StoredStatement {
    source: String,
    name: String,
    name_format: String,
}

impl StoredSettings {
    /// `settings` as they are kept.
    fn of(settings: &SamlServiceProviderSettings) -> Self {
        let acs_urls = std::iter::once(settings.acs_urls.default_url())
            .chain(settings.acs_urls.others())
            .map(|url| url.as_str().to_owned())
            .collect();
        Self {
            acs_urls,
            logout_url: settings
                .logout_url
                .value()
                .map(|url| url.as_str().to_owned()),
            name_id_format: settings.name_id_format.as_str().to_owned(),
            attributes: settings
                .attributes
                .statements()
                .iter()
                .map(StoredStatement::of)
                .collect(),
            signing: settings.signing.word().to_owned(),
            encryption_certificate: match &settings.encryption {
                AssertionEncryption::Plain => None,
                AssertionEncryption::EncryptedFor(certificate) => {
                    Some(certificate.as_str().to_owned())
                }
            },
            request_signing_certificate: match &settings.request_signing {
                RequestSigningRule::NotRequired => None,
                RequestSigningRule::Required(certificate) => Some(certificate.as_str().to_owned()),
            },
        }
    }

    /// The settings it keeps, each value read through its own checks.
    fn into_settings(self) -> Result<SamlServiceProviderSettings, DomainError> {
        let statements = self
            .attributes
            .into_iter()
            .map(StoredStatement::into_statement)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SamlServiceProviderSettings {
            acs_urls: acs_urls_from(self.acs_urls)?,
            logout_url: Setting::from_stored(
                self.logout_url
                    .map(|url| APP.value("logout url", HttpsUrl::new(url)))
                    .transpose()?,
            ),
            name_id_format: NameIdFormat::from_stored(&self.name_id_format)?,
            attributes: AttributeStatements::new(statements).map_err(DomainError::infra)?,
            signing: APP.choice(&self.signing)?,
            encryption: match certificate_from(self.encryption_certificate)? {
                None => AssertionEncryption::Plain,
                Some(certificate) => AssertionEncryption::EncryptedFor(certificate),
            },
            request_signing: match certificate_from(self.request_signing_certificate)? {
                None => RequestSigningRule::NotRequired,
                Some(certificate) => RequestSigningRule::Required(certificate),
            },
        })
    }
}

impl StoredStatement {
    fn of(statement: &AttributeStatement) -> Self {
        Self {
            source: statement.source.word().to_owned(),
            name: statement.name.as_str().to_owned(),
            name_format: statement.name_format.word().to_owned(),
        }
    }

    fn into_statement(self) -> Result<AttributeStatement, DomainError> {
        Ok(AttributeStatement {
            source: APP.choice(&self.source)?,
            name: APP.value("attribute name", SamlAttributeName::new(self.name))?,
            name_format: APP.choice(&self.name_format)?,
        })
    }
}

/// The addresses kept, the default first.
fn acs_urls_from(stored: Vec<String>) -> Result<AcsUrls, DomainError> {
    let mut urls = stored
        .into_iter()
        .map(|url| APP.value("assertion address", HttpsUrl::new(url)))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter();
    let Some(default) = urls.next() else {
        return Err(DomainError::corrupt_row(APP.0, "no assertion address"));
    };
    AcsUrls::new(default, urls.collect()).map_err(DomainError::infra)
}

fn certificate_from(stored: Option<String>) -> Result<Option<CertificatePem>, DomainError> {
    stored
        .map(|pem| APP.value("certificate", CertificatePem::new(pem)))
        .transpose()
}

#[cfg(test)]
mod tests {
    //! The shape the settings column is stored in today. A row written now
    //! is read for years, so when this fails, the domain changed how it
    //! writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use serde_json::json;

    use super::*;
    use crate::test_support::rows::federation::service_provider_row;

    /// The settings are written in the shape pinned here, and a row in that
    /// shape reads back as the same settings.
    #[test]
    fn the_settings_are_stored_in_their_pinned_shape() {
        let settings = service_provider_row("Wiki", "https://wiki.acme.example").settings;
        let stored = json!({"v": 1, "value": {
            "acs_urls": ["https://app.acme.example/acs"],
            "logout_url": null,
            "name_id_format": "persistent",
            "attributes": [
                {"source": "email", "name": "email", "name_format": "basic"},
                {"source": "display_name", "name": "displayName", "name_format": "basic"}
            ],
            "signing": "assertion",
            "encryption_certificate": null,
            "request_signing_certificate": null
        }});

        assert_eq!(
            SETTINGS.seal(&StoredSettings::of(&settings)).unwrap(),
            stored
        );
        let read: StoredSettings = SETTINGS.open(stored).unwrap();
        assert_eq!(read.into_settings().unwrap(), settings);
    }

    /// An empty list of stored assertion addresses is rejected as corrupt
    /// storage.
    #[test]
    fn settings_without_an_address_are_refused() {
        let read = acs_urls_from(Vec::new());

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
