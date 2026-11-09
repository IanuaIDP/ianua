//! A connection as its row holds it, with the rules of its group mapping:
//! read back into the aggregate, and written out from it.

use std::collections::HashMap;

use ianua_domain::domains::federation::connection::{
    ConnectionRow, FederatedIdpConnection, GroupMapping, GroupRule, GroupRules, MappedGrant,
    ProfileField, ProviderGroupName,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConnectionId, DomainName, GroupId, Label, RoleId, Setting};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::federation::connections::config::ConfigColumns;
use crate::postgres::federation::connections::words::GrantKind;
use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const CONNECTION: Stored = Stored("federated connection");

const SAML: Kept = Kept {
    entity: CONNECTION.0,
    column: "saml",
    shape: 1,
};

const OIDC: Kept = Kept {
    entity: CONNECTION.0,
    column: "oidc",
    shape: 1,
};

const SETTINGS: ConfigColumns = ConfigColumns {
    row: CONNECTION,
    saml: SAML,
    oidc: OIDC,
};

/// A connection as it is read. The store's checked queries fill it.
pub(super) struct ConnectionRecord {
    pub(super) id: Uuid,
    pub(super) provider_name: String,
    pub(super) status: String,
    pub(super) saml: Option<Value>,
    pub(super) oidc: Option<Value>,
    pub(super) jit_provisioning: String,
    pub(super) jit_default_role_id: Option<Uuid>,
    pub(super) email_trust: String,
    pub(super) assurance_trust: String,
    pub(super) domain_hint: Option<String>,
    pub(super) allowed_domains: Vec<String>,
    pub(super) mapped_claims: Vec<String>,
    pub(super) mapped_fields: Vec<String>,
    pub(super) group_claim: Option<String>,
    pub(super) rule_groups: Vec<String>,
    pub(super) rule_kinds: Vec<String>,
    pub(super) rule_grants: Vec<Uuid>,
    pub(super) created_at: OffsetDateTime,
    pub(super) keyed_at: OffsetDateTime,
}

impl ConnectionRecord {
    /// The connection the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, the settings or the mapping do not
    /// read, or the row breaks a rule the connection keeps.
    pub(super) fn into_connection(
        self,
    ) -> Result<FederatedIdpConnection<ResolvedTenant>, DomainError> {
        let group_mapping = mapping_from(
            self.group_claim,
            self.rule_groups,
            self.rule_kinds,
            self.rule_grants,
        )?;
        FederatedIdpConnection::reconstitute(ConnectionRow {
            id: ConnectionId::from_uuid(self.id),
            provider_name: CONNECTION.value(
                "provider name",
                Label::new("provider_name", self.provider_name),
            )?,
            status: CONNECTION.choice(&self.status)?,
            config: SETTINGS.read(self.saml, self.oidc)?,
            jit_provisioning: CONNECTION.choice(&self.jit_provisioning)?,
            jit_default_role_id: Setting::from_stored(
                self.jit_default_role_id.map(RoleId::from_uuid),
            ),
            email_trust: CONNECTION.choice(&self.email_trust)?,
            assurance_trust: CONNECTION.choice(&self.assurance_trust)?,
            domain_hint: domain_hint_from(self.domain_hint)?,
            allowed_domains: domains_from(self.allowed_domains)?,
            attribute_mapping: attribute_mapping_from(self.mapped_claims, self.mapped_fields)?,
            group_mapping,
            created_at: self.created_at,
            keyed_at: self.keyed_at,
        })
    }
}

/// Validates an optional discovery hint without turning an absent hint into a domain.
fn domain_hint_from(hint: Option<String>) -> Result<Setting<DomainName>, DomainError> {
    hint.map(|hint| CONNECTION.value("domain hint", DomainName::new(hint)))
        .transpose()
        .map(Setting::from_stored)
}

/// The connections `records` hold.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` for the first record that does
/// not read back.
pub(super) fn connections_from(
    records: Vec<ConnectionRecord>,
) -> Result<Vec<FederatedIdpConnection<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(ConnectionRecord::into_connection)
        .collect()
}

fn domains_from(stored: Vec<String>) -> Result<Vec<DomainName>, DomainError> {
    stored
        .into_iter()
        .map(|domain| CONNECTION.value("allowed domain", DomainName::new(domain)))
        .collect()
}

/// The claims and the profile fields they fill, paired by position.
fn attribute_mapping_from(
    claims: Vec<String>,
    fields: Vec<String>,
) -> Result<HashMap<Label, ProfileField>, DomainError> {
    if claims.len() != fields.len() {
        return Err(DomainError::corrupt_row(
            CONNECTION.0,
            "claims and profile fields that do not pair up",
        ));
    }
    claims
        .into_iter()
        .zip(fields)
        .map(|(claim, field)| {
            let claim = CONNECTION.value("mapped claim", Label::new("claim", claim))?;
            let field = ProfileField::parse(&field).ok_or_else(|| {
                DomainError::corrupt_row(CONNECTION.0, "an unknown profile field")
            })?;
            Ok((claim, field))
        })
        .collect()
}

/// The group mapping the claim column and the rules hold: off with neither,
/// on with both.
fn mapping_from(
    claim: Option<String>,
    groups: Vec<String>,
    kinds: Vec<String>,
    grants: Vec<Uuid>,
) -> Result<GroupMapping, DomainError> {
    let Some(claim) = claim else {
        if groups.is_empty() {
            return Ok(GroupMapping::Off);
        }
        return Err(DomainError::corrupt_row(
            CONNECTION.0,
            "group mapping rules with no claim to read groups from",
        ));
    };
    let claim = CONNECTION.value("group claim", Label::new("group_claim", claim))?;
    let rules = rules_from(groups, kinds, grants)?;
    GroupRules::new(claim, rules)
        .map(GroupMapping::On)
        .map_err(DomainError::infra)
}

fn rules_from(
    groups: Vec<String>,
    kinds: Vec<String>,
    grants: Vec<Uuid>,
) -> Result<Vec<GroupRule>, DomainError> {
    groups
        .into_iter()
        .zip(kinds)
        .zip(grants)
        .map(|((group, kind), grant)| {
            let grant = match CONNECTION.choice::<GrantKind>(&kind)? {
                GrantKind::Role => MappedGrant::Role(RoleId::from_uuid(grant)),
                GrantKind::Group => MappedGrant::Group(GroupId::from_uuid(grant)),
            };
            Ok(GroupRule {
                provider_group: CONNECTION
                    .value("provider group", ProviderGroupName::new(group))?,
                grant,
            })
        })
        .collect()
}

/// A connection's columns, as they are written, with the rules of its
/// group mapping as three lists paired by position.
pub(super) struct ConnectionColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) provider_name: &'a str,
    pub(super) status: &'static str,
    pub(super) saml: Option<Value>,
    pub(super) oidc: Option<Value>,
    pub(super) jit_provisioning: &'static str,
    pub(super) jit_default_role_id: Option<Uuid>,
    pub(super) email_trust: &'static str,
    pub(super) assurance_trust: &'static str,
    pub(super) domain_hint: Option<&'a str>,
    pub(super) allowed_domains: Vec<String>,
    pub(super) mapped_claims: Vec<String>,
    pub(super) mapped_fields: Vec<String>,
    pub(super) group_claim: Option<&'a str>,
    pub(super) rules: RuleColumns,
    pub(super) created_at: OffsetDateTime,
    pub(super) keyed_at: OffsetDateTime,
}

/// The rules of a group mapping, as the lists they are written from.
#[derive(Default)]
pub(super) struct RuleColumns {
    pub(super) groups: Vec<String>,
    pub(super) kinds: Vec<String>,
    pub(super) grants: Vec<Uuid>,
}

impl<'a> ConnectionColumns<'a> {
    /// The columns `connection` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its settings cannot be
    /// written out as JSON.
    pub(super) fn of(
        connection: &'a FederatedIdpConnection<ResolvedTenant>,
    ) -> Result<Self, DomainError> {
        let (saml, oidc) = SETTINGS.of(connection.config())?;
        let (mapped_claims, mapped_fields): (Vec<String>, Vec<String>) = connection
            .attribute_mapping()
            .iter()
            .map(|(claim, field)| (claim.as_str().to_owned(), field.as_str().to_owned()))
            .unzip();
        let (group_claim, rules) = match connection.group_mapping() {
            GroupMapping::Off => (None, RuleColumns::default()),
            GroupMapping::On(rules) => (Some(rules.claim().as_str()), RuleColumns::of(rules)),
        };
        Ok(Self {
            id: connection.id().as_uuid(),
            provider_name: connection.provider_name().as_str(),
            status: connection.status().word(),
            saml,
            oidc,
            jit_provisioning: connection.jit_provisioning().word(),
            jit_default_role_id: connection.jit_default_role_id().map(|role| *role.as_uuid()),
            email_trust: connection.email_trust().word(),
            assurance_trust: connection.assurance_trust().word(),
            domain_hint: connection.domain_hint().map(DomainName::as_str),
            allowed_domains: domain_columns(connection.allowed_domains()),
            mapped_claims,
            mapped_fields,
            group_claim,
            rules,
            created_at: connection.created_at(),
            keyed_at: connection.keyed_at(),
        })
    }
}

/// Writes each permitted email domain as its validated hostname.
fn domain_columns(domains: &[DomainName]) -> Vec<String> {
    domains
        .iter()
        .map(|domain| domain.as_str().to_owned())
        .collect()
}

impl RuleColumns {
    /// The lists `rules` are written from.
    fn of(rules: &GroupRules) -> Self {
        let mut columns = Self::default();
        for rule in rules.rules() {
            let (kind, grant) = match rule.grant {
                MappedGrant::Role(role) => (GrantKind::Role, *role.as_uuid()),
                MappedGrant::Group(group) => (GrantKind::Group, *group.as_uuid()),
            };
            columns.groups.push(rule.provider_group.as_str().to_owned());
            columns.kinds.push(kind.word().to_owned());
            columns.grants.push(grant);
        }
        columns
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::federation::connection::{ConnectionConfig, OidcConfig};
    use serde_json::json;

    use super::*;
    use crate::postgres::federation::connections::config::StoredSaml;
    use crate::test_support::rows::federation::{oidc_config, saml_config_following};

    /// The SAML settings are written in the shape pinned here, the metadata
    /// address among them, and a row in that shape reads back.
    #[test]
    fn the_saml_settings_are_stored_in_their_pinned_shape() {
        let ConnectionConfig::Saml(saml) = saml_config_following("https://acme.okta.com/metadata")
        else {
            panic!("the test SAML settings are SAML");
        };
        let stored = json!({"v": 1, "value": {
            "entity_id": "https://acme.okta.com/saml",
            "sso_url": "https://acme.okta.com/saml/sso",
            "slo_url": null,
            "certificate": "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----",
            "next_certificate": null,
            "name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            "request_signing": "unsigned",
            "assertion_encryption": null,
            "metadata_url": "https://acme.okta.com/metadata"
        }});

        assert_eq!(SAML.seal(&StoredSaml::of(&saml)).unwrap(), stored);
        let read: StoredSaml = SAML.open(stored).unwrap();
        assert_eq!(read.into_config(CONNECTION).unwrap(), *saml);
    }

    /// The OIDC settings are written in the shape pinned here, the client
    /// secret as sealed, and a row in that shape reads back.
    #[test]
    fn the_oidc_settings_are_stored_in_their_pinned_shape() {
        let ConnectionConfig::Oidc(oidc) = oidc_config() else {
            panic!("the test OIDC settings are OIDC");
        };
        let stored = json!({"v": 1, "value": {
            "issuer": "https://acme.okta.com",
            "client_id": "ianua-app",
            "encrypted_client_secret": "v1.sealedclientsecret",
            "scopes": ["openid", "email"]
        }});

        assert_eq!(OIDC.seal(&oidc).unwrap(), stored);
        assert_eq!(OIDC.open::<OidcConfig>(stored).unwrap(), oidc);
    }

    /// Stored group mapping rules without a source claim are rejected as
    /// corrupt storage.
    #[test]
    fn rules_without_a_claim_are_refused() {
        let read = mapping_from(
            None,
            vec!["engineering".to_owned()],
            vec!["role".to_owned()],
            vec![Uuid::nil()],
        );

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// A stored group mapping claim without any rules is rejected as
    /// corrupt storage.
    #[test]
    fn a_claim_without_rules_is_refused() {
        let read = mapping_from(
            Some("groups".to_owned()),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
