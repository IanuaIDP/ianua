//! A model provider as its row holds it: read back into the aggregate, and
//! written out from it.

use ianua_domain::domains::agents::execution::model_provider::{
    LastTest, ModelEndpoint, ModelName, ModelProvider, ModelProviderRow, ModelProviderTestStatus,
    ProviderEmbeddings, ProviderKey,
};
use ianua_domain::domains::agents::execution::usage::{ModelPricing, Spend};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{Label, ModelProviderId, SealedSecret};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const PROVIDER: Stored = Stored("model provider");

/// A provider as it is read. The store's checked queries fill it.
pub(super) struct ProviderRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) kind: String,
    pub(super) endpoint: String,
    pub(super) model: String,
    pub(super) embedding_model: Option<String>,
    pub(super) input_price_micros: Option<i64>,
    pub(super) output_price_micros: Option<i64>,
    pub(super) api_key_sealed: Option<String>,
    pub(super) clearance: String,
    pub(super) status: String,
    pub(super) last_test_status: Option<String>,
    pub(super) last_tested_at: Option<OffsetDateTime>,
    pub(super) last_test_reason: Option<String>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl ProviderRecord {
    /// The provider the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the provider
    /// keeps.
    pub(super) fn into_provider(self) -> Result<ModelProvider<ResolvedTenant>, DomainError> {
        let last_test = self.last_test()?;
        let pricing = pricing_from(self.input_price_micros, self.output_price_micros)?;
        ModelProvider::reconstitute(ModelProviderRow {
            id: ModelProviderId::from_uuid(self.id),
            name: PROVIDER.value("name", Label::new("name", self.name))?,
            kind: PROVIDER.choice(&self.kind)?,
            endpoint: PROVIDER.value("endpoint", ModelEndpoint::new(self.endpoint))?,
            model: PROVIDER.value("model", ModelName::new(self.model))?,
            pricing,
            credential_ref: key_from(self.api_key_sealed)?,
            clearance: DataClassLevel::from_stored(&self.clearance)?,
            embeddings: embeddings_from(self.embedding_model)?,
            status: PROVIDER.choice(&self.status)?,
            last_test,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }

    /// The last test the record holds, or that none ran.
    fn last_test(&self) -> Result<LastTest, DomainError> {
        let status = self
            .last_test_status
            .as_deref()
            .map(|word| PROVIDER.choice(word))
            .transpose()?;
        LastTest::from_stored(status, self.last_tested_at, self.last_test_reason.clone())
    }
}

/// The price two stored columns hold: both set, or neither for a provider
/// nobody priced.
fn pricing_from(input: Option<i64>, output: Option<i64>) -> Result<ModelPricing, DomainError> {
    match (input, output) {
        (None, None) => Ok(ModelPricing::Unpriced),
        (Some(input), Some(output)) => Ok(ModelPricing::PerMillionTokens {
            input: spend_from(input)?,
            output: spend_from(output)?,
        }),
        (Some(_), None) | (None, Some(_)) => {
            Err(DomainError::corrupt_row(PROVIDER.0, "half of a price"))
        }
    }
}

/// An amount a stored column holds, in millionths.
fn spend_from(micros: i64) -> Result<Spend, DomainError> {
    u64::try_from(micros)
        .map(Spend::from_micros)
        .map_err(|_| DomainError::corrupt_row(PROVIDER.0, "a price below nothing"))
}

/// The embedding model a stored column holds, or that it offers none.
fn embeddings_from(model: Option<String>) -> Result<ProviderEmbeddings, DomainError> {
    let Some(model) = model else {
        return Ok(ProviderEmbeddings::Off);
    };
    PROVIDER
        .value("embedding model", ModelName::new(model))
        .map(ProviderEmbeddings::Model)
}

/// The key a stored column holds, sealed, or that the endpoint takes none.
fn key_from(sealed: Option<String>) -> Result<ProviderKey, DomainError> {
    let key = sealed
        .map(|text| PROVIDER.value("API key", SealedSecret::new(text)))
        .transpose()?;
    Ok(ProviderKey::from_stored(key))
}

/// A provider's columns, as they are written.
pub(super) struct ProviderColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) kind: &'static str,
    pub(super) endpoint: &'a str,
    pub(super) model: &'a str,
    pub(super) embedding_model: Option<&'a str>,
    pub(super) input_price_micros: Option<i64>,
    pub(super) output_price_micros: Option<i64>,
    pub(super) api_key_sealed: Option<&'a str>,
    pub(super) clearance: &'static str,
    pub(super) status: &'static str,
    pub(super) last_test_status: Option<&'static str>,
    pub(super) last_tested_at: Option<OffsetDateTime>,
    pub(super) last_test_reason: Option<&'a str>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> ProviderColumns<'a> {
    /// The columns `provider` is written to. Its key is written in the
    /// sealed form it already holds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a price is past what a
    /// column holds.
    pub(super) fn of(provider: &'a ModelProvider<ResolvedTenant>) -> Result<Self, DomainError> {
        let (input_price_micros, output_price_micros) = price_columns(provider.pricing())?;
        Ok(Self {
            id: provider.id().as_uuid(),
            name: provider.name().as_str(),
            kind: provider.kind().word(),
            endpoint: provider.endpoint().as_str(),
            embedding_model: provider.embeddings().model().map(ModelName::as_str),
            model: provider.model().as_str(),
            input_price_micros,
            output_price_micros,
            api_key_sealed: provider.credential_ref().sealed().map(SealedSecret::as_str),
            clearance: provider.clearance().as_str(),
            status: provider.status().word(),
            last_test_status: provider
                .last_test_status()
                .map(ModelProviderTestStatus::word),
            last_tested_at: provider.last_tested_at(),
            last_test_reason: provider.last_test_message(),
            created_at: provider.created_at(),
            updated_at: provider.updated_at(),
        })
    }
}

/// The two columns `pricing` is written to.
fn price_columns(pricing: ModelPricing) -> Result<(Option<i64>, Option<i64>), DomainError> {
    let ModelPricing::PerMillionTokens { input, output } = pricing else {
        return Ok((None, None));
    };
    let input = i64::try_from(input.micros()).map_err(DomainError::infra)?;
    let output = i64::try_from(output.micros()).map_err(DomainError::infra)?;
    Ok((Some(input), Some(output)))
}
