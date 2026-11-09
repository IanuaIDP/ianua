//! A change to a connection, made ready to apply: a new client secret
//! sealed or the provider's metadata read, the role new accounts get loaded,
//! and the domains proved. The connection then takes each part, and decides
//! who may make it.

use std::collections::HashMap;

use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::federation::connection::{
    AssuranceTrust, ConnectionDomains, DomainHolders, EmailTrust, FederatedIdpConnection,
    ProfileField,
};
use ianua_domain::domains::federation::control::FederationControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, Setting};

use crate::error::AppError;
use crate::ports::authentication::SealedFor;
use crate::ports::authorization::RoleStore;
use crate::services::lookup::existing_role;
use crate::tenancy::ScopedTenant;
use crate::use_cases::authentication::federation::lookup::client_secret_place;
use crate::use_cases::federation::connections::settings::allowed_domains::DomainProofs;
use crate::use_cases::federation::connections::settings::stored_config::{
    ConfigSources, StoredConfig, decryption_of,
};
use crate::use_cases::federation::connections::{
    AccountProvisioning, ProviderConfig, UpdateRequest,
};

/// Where the parts of a change are read and sealed.
pub(in crate::use_cases::federation::connections) struct ChangeSources<'a> {
    /// Seals a new client secret and reads a provider's metadata.
    pub(in crate::use_cases::federation::connections) config: ConfigSources<'a>,
    /// Loads the role new accounts get.
    pub(in crate::use_cases::federation::connections) role_store: &'a dyn RoleStore,
    /// Reads the proofs of the tenant's domains.
    pub(in crate::use_cases::federation::connections) proofs: DomainProofs<'a>,
}

/// A change ready for the connection to take.
pub(in crate::use_cases::federation::connections) struct PreparedChange {
    provider_name: Option<Label>,
    config: Option<StoredConfig>,
    provisioning: Option<Provisioning>,
    domains: Option<ConnectionDomains>,
    attribute_mapping: Option<HashMap<Label, ProfileField>>,
    email_trust: Option<EmailTrust>,
    assurance_trust: Option<AssuranceTrust>,
}

/// Whether the connection makes accounts, with the role it gives them
/// loaded.
enum Provisioning {
    Enabled(Setting<Role<ResolvedTenant>>),
    Disabled,
}

impl ChangeSources<'_> {
    /// `request`, ready to apply to `conn`.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the role for new accounts is not the
    ///   tenant's.
    /// - `AppError::Domain` or `AppError::Conflict` if a domain is not one
    ///   the tenant proved it owns.
    /// - `AppError::Domain` if the provider's metadata cannot be fetched or
    ///   read.
    /// - `AppError::Internal` on encryption or storage failure.
    pub(in crate::use_cases::federation::connections) async fn prepare(
        &self,
        tenant: &ScopedTenant,
        request: UpdateRequest,
        conn: &FederatedIdpConnection<ResolvedTenant>,
    ) -> Result<PreparedChange, AppError> {
        let domains = self.domains(tenant, &request, conn).await?;
        let provisioning = self.provisioning(tenant, request.provisioning).await?;
        let place = client_secret_place(tenant, conn.id());
        let config = self.config(request.config, conn, &place).await?;
        Ok(PreparedChange {
            provider_name: request.provider_name,
            config,
            provisioning,
            domains,
            attribute_mapping: request.attribute_mapping,
            email_trust: request.email_trust,
            assurance_trust: request.assurance_trust,
        })
    }

    /// The new configuration as the connection keeps it, its secret sealed
    /// for `place` or its metadata read, keeping the key `conn` takes
    /// sealed assertions with.
    async fn config(
        &self,
        config: Option<ProviderConfig>,
        conn: &FederatedIdpConnection<ResolvedTenant>,
        place: &SealedFor,
    ) -> Result<Option<StoredConfig>, AppError> {
        let Some(config) = config else {
            return Ok(None);
        };
        self.config
            .stored(config, decryption_of(conn.config()), place)
            .await
            .map(Some)
    }

    /// The new provisioning, with the role it gives loaded.
    async fn provisioning(
        &self,
        tenant: &ScopedTenant,
        provisioning: Option<AccountProvisioning>,
    ) -> Result<Option<Provisioning>, AppError> {
        let role_id = match provisioning {
            None => return Ok(None),
            Some(AccountProvisioning::Disabled) => return Ok(Some(Provisioning::Disabled)),
            Some(AccountProvisioning::Enabled(role_id)) => role_id,
        };
        let role = match role_id {
            Setting::Set(id) => Setting::Set(existing_role(self.role_store, tenant, &id).await?),
            Setting::Unset => Setting::Unset,
        };
        Ok(Some(Provisioning::Enabled(role)))
    }

    /// The domains `request` leaves `conn` vouching for, each proved, and the
    /// hint among them. The part `request` does not name stays as it was,
    /// and is proved again.
    async fn domains(
        &self,
        tenant: &ScopedTenant,
        request: &UpdateRequest,
        conn: &FederatedIdpConnection<ResolvedTenant>,
    ) -> Result<Option<ConnectionDomains>, AppError> {
        if request.allowed_domains.is_none() && request.domain_hint.is_none() {
            return Ok(None);
        }
        let names = request
            .allowed_domains
            .as_deref()
            .unwrap_or(conn.allowed_domains());
        let hint = request
            .domain_hint
            .clone()
            .unwrap_or_else(|| Setting::from_stored(conn.domain_hint().cloned()));
        let allowed = self.proofs.owned(tenant, names).await?;
        Ok(Some(ConnectionDomains { allowed, hint }))
    }
}

impl PreparedChange {
    /// Applies every named part to `conn`, as `control` allows, binding only
    /// domains proved by `holders`.
    ///
    /// # Errors
    ///
    /// The first refusal of the connection: a right the person lacks, a role
    /// they may not hand out, another provider, or a hint outside the
    /// allowed domains.
    pub(in crate::use_cases::federation::connections) fn apply_to(
        self,
        conn: &mut FederatedIdpConnection<ResolvedTenant>,
        control: &FederationControl<'_>,
        holders: DomainHolders<'_>,
    ) -> Result<(), DomainError> {
        if let Some(name) = self.provider_name {
            conn.rename(name, control)?;
        }
        match self.config {
            Some(StoredConfig::Config(config)) => conn.update_config(config, control)?,
            Some(StoredConfig::Metadata(metadata)) => conn.import_metadata(*metadata, control)?,
            None => {}
        }
        if let Some(provisioning) = self.provisioning {
            provisioning.apply_to(conn, control)?;
        }
        if let Some(domains) = self.domains {
            conn.change_domains(domains, control, holders)?;
        }
        if let Some(mapping) = self.attribute_mapping {
            conn.replace_attribute_mapping(mapping, control)?;
        }
        if let Some(trust) = self.email_trust {
            conn.change_email_trust(trust, control)?;
        }
        if let Some(trust) = self.assurance_trust {
            conn.change_assurance_trust(trust, control)?;
        }
        Ok(())
    }
}

impl Provisioning {
    /// Sets whether `conn` makes accounts, as `control` allows.
    fn apply_to(
        self,
        conn: &mut FederatedIdpConnection<ResolvedTenant>,
        control: &FederationControl<'_>,
    ) -> Result<(), DomainError> {
        match self {
            Self::Disabled => conn.stop_provisioning(control),
            Self::Enabled(Setting::Set(role)) => {
                conn.provision_new_accounts(Setting::Set(&role), control)
            }
            Self::Enabled(Setting::Unset) => conn.provision_new_accounts(Setting::Unset, control),
        }
    }
}
