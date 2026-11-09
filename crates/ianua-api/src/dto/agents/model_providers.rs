//! Model provider bodies: the LLM backends runs reason with.

use ianua_app::use_cases::agents::model_providers::{
    ChangeClearanceRequest, ChangeModelRequest, ConnectRequest, OfferEmbeddingsRequest,
    RotateKeyRequest, UpdateStatusRequest,
};
use ianua_domain::domains::agents::execution::model_provider::{
    ModelEndpoint, ModelName, ModelProvider, ModelProviderKind, ModelProviderStatus,
    ProviderEmbeddings,
};
use ianua_domain::domains::agents::execution::usage::{ModelPricing, Spend};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Label, ModelProviderId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;

/// The most characters of a probe's answer shown back.
const SAMPLE_LENGTH: usize = 200;

/// The provider kind a wire name names.
fn kind_named(value: &str) -> Result<ModelProviderKind, ApiError> {
    match value {
        "self_hosted" => Ok(ModelProviderKind::SelfHosted),
        "openai" => Ok(ModelProviderKind::OpenAi),
        "anthropic" => Ok(ModelProviderKind::Anthropic),
        _ => Err(ApiError::validation(message!(
            "api-unknown-provider-kind",
            format!("unknown provider kind: {value}")
        ))),
    }
}

/// What a model provider charges, in millionths of the tenant's billing
/// currency per million tokens.
#[derive(Clone, Copy, Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct ModelPricingDto {
    /// The price of a million tokens sent to the model.
    pub input_micros_per_million: u64,
    /// The price of a million tokens the model wrote.
    pub output_micros_per_million: u64,
}

impl ModelPricingDto {
    /// The price named, or that it is unknown when none is given.
    #[must_use]
    pub(crate) fn pricing_of(pricing: Option<Self>) -> ModelPricing {
        pricing.map_or(ModelPricing::Unpriced, |price| {
            ModelPricing::PerMillionTokens {
                input: Spend::from_micros(price.input_micros_per_million),
                output: Spend::from_micros(price.output_micros_per_million),
            }
        })
    }

    /// `pricing` on the wire, or `None` when nobody set a price.
    #[must_use]
    pub(crate) fn of(pricing: ModelPricing) -> Option<Self> {
        match pricing {
            ModelPricing::Unpriced => None,
            ModelPricing::PerMillionTokens { input, output } => Some(Self {
                input_micros_per_million: input.micros(),
                output_micros_per_million: output.micros(),
            }),
        }
    }
}

/// Request body for connecting a model provider.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ConnectModelProviderBody {
    /// A name people know it by, such as `prod-deepseek`.
    pub name: String,
    /// Backend kind: `self_hosted`, `openai`, or `anthropic`.
    pub kind: String,
    /// Base endpoint URL, such as `http://deepseek.models.svc:8000/v1`.
    pub endpoint: String,
    /// Model to request, such as `deepseek-chat`.
    pub model: String,
    /// Optional API key: paste one to bring your own OpenAI or Anthropic;
    /// leave it out for a keyless self-hosted endpoint. Encrypted at rest;
    /// never returned.
    #[serde(default)]
    pub api_key: Option<String>,
    /// The most sensitive data runs may send it: `Public`, `Internal`,
    /// `Confidential` or `Restricted`. `Public` when left out, so a
    /// provider nobody cleared receives nothing a tenant keeps to itself.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub clearance: Option<DataClassLevel>,
    /// What the provider charges, so runs can be held to a spend limit.
    /// Left out when unknown: a run under a spend limit then stops as
    /// `over_budget` after its first model call, since its spend cannot be
    /// counted.
    #[serde(default)]
    pub pricing: Option<ModelPricingDto>,
}

impl TryFrom<ConnectModelProviderBody> for ConnectRequest {
    type Error = ApiError;

    fn try_from(body: ConnectModelProviderBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            kind: kind_named(&body.kind)?,
            endpoint: ModelEndpoint::new(body.endpoint).map_err(ApiError::validation)?,
            model: ModelName::new(body.model).map_err(ApiError::validation)?,
            pricing: ModelPricingDto::pricing_of(body.pricing),
            api_key: body.api_key.map(Secret::new),
            clearance: body.clearance.unwrap_or(DataClassLevel::Public),
        })
    }
}

/// Request body for replacing a model provider's API key.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RotateModelProviderKeyBody {
    /// The new API key, encrypted at rest and never returned. Left out to
    /// remove the key, for a keyless self-hosted endpoint.
    #[serde(default)]
    pub api_key: Option<String>,
}

impl RotateModelProviderKeyBody {
    /// The key change of `provider_id` this body asks for.
    #[must_use]
    pub(crate) fn into_request(self, provider_id: ModelProviderId) -> RotateKeyRequest {
        RotateKeyRequest {
            provider_id,
            api_key: self.api_key.map(Secret::new),
        }
    }
}

/// Request body for changing the model a provider is asked for, and its
/// price.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeModelProviderModelBody {
    /// The model to request, such as `deepseek-chat`.
    pub model: String,
    /// What the new model charges. Left out when unknown.
    #[serde(default)]
    pub pricing: Option<ModelPricingDto>,
}

impl ChangeModelProviderModelBody {
    /// The model change of `provider_id` this body asks for.
    ///
    /// # Errors
    ///
    /// - A validation error when `model` is not a valid model name.
    pub(crate) fn into_request(
        self,
        provider_id: ModelProviderId,
    ) -> Result<ChangeModelRequest, ApiError> {
        Ok(ChangeModelRequest {
            provider_id,
            model: ModelName::new(self.model).map_err(ApiError::validation)?,
            pricing: ModelPricingDto::pricing_of(self.pricing),
        })
    }
}

/// Request body for changing the most sensitive data runs may send a
/// provider.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeModelProviderClearanceBody {
    /// `Public`, `Internal`, `Confidential` or `Restricted`.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub clearance: DataClassLevel,
}

impl ChangeModelProviderClearanceBody {
    /// The clearance change of `provider_id` this body asks for.
    #[must_use]
    pub(crate) fn into_request(self, provider_id: ModelProviderId) -> ChangeClearanceRequest {
        ChangeClearanceRequest {
            provider_id,
            clearance: self.clearance,
        }
    }
}

/// Request body for setting the embedding model a provider offers beside
/// its chat model.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OfferEmbeddingsBody {
    /// The embedding model, such as `text-embedding-3-small`; `null` to
    /// offer none.
    pub embedding_model: Option<String>,
}

impl OfferEmbeddingsBody {
    /// The change of `provider_id` this body asks for.
    ///
    /// # Errors
    ///
    /// - A validation error when the model name is not one.
    pub(crate) fn into_request(
        self,
        provider_id: ModelProviderId,
    ) -> Result<OfferEmbeddingsRequest, ApiError> {
        let embeddings = match self.embedding_model {
            Some(model) => {
                ProviderEmbeddings::Model(ModelName::new(model).map_err(ApiError::validation)?)
            }
            None => ProviderEmbeddings::Off,
        };
        Ok(OfferEmbeddingsRequest {
            provider_id,
            embeddings,
        })
    }
}

/// Request body for enabling or disabling a model provider.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateModelProviderStatusBody {
    /// The status wanted: `active` or `disabled`.
    pub status: String,
}

impl UpdateModelProviderStatusBody {
    /// The change of `provider_id` to the status named.
    ///
    /// # Errors
    ///
    /// - A validation error when `status` names no status.
    pub(crate) fn into_request(
        self,
        provider_id: ModelProviderId,
    ) -> Result<UpdateStatusRequest, ApiError> {
        Ok(UpdateStatusRequest {
            provider_id,
            status: ModelProviderStatus::parse(&self.status).map_err(ApiError::validation)?,
        })
    }
}

/// Identifies a newly connected provider.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ConnectModelProviderResponse {
    /// The provider's unique identifier.
    pub id: Uuid,
}

/// A model provider; never its key.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ModelProviderResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// The name people know it by.
    pub name: String,
    /// Backend kind.
    pub kind: String,
    /// Base endpoint URL.
    pub endpoint: String,
    /// Model name.
    pub model: String,
    /// The embedding model it offers beside its chat model, or `null` for
    /// none.
    pub embedding_model: Option<String>,
    /// Whether an API key is stored (never the key itself).
    pub has_credential: bool,
    /// The most sensitive data runs may send it.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub clearance: DataClassLevel,
    /// Lifecycle status (`active` or `disabled`).
    pub status: String,
    /// Outcome of the most recent connectivity test (`passed` or
    /// `failed`), or `null` if it was never tested.
    pub last_test_status: Option<String>,
    /// When the most recent connectivity test ran, or `null` if never
    /// tested.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_tested_at: Option<OffsetDateTime>,
    /// Why the most recent test failed; set only when `last_test_status`
    /// is `failed`.
    pub last_test_message: Option<String>,
    /// What the provider charges, or `null` when nobody set a price.
    pub pricing: Option<ModelPricingDto>,
}

impl From<ModelProvider<ResolvedTenant>> for ModelProviderResponse {
    fn from(provider: ModelProvider<ResolvedTenant>) -> Self {
        Self {
            id: *provider.id().as_uuid(),
            name: provider.name().as_str().to_owned(),
            kind: provider.kind().as_str().to_owned(),
            endpoint: provider.endpoint().as_str().to_owned(),
            model: provider.model().as_str().to_owned(),
            embedding_model: provider
                .embeddings()
                .model()
                .map(|model| model.as_str().to_owned()),
            has_credential: provider.credential_ref().sealed().is_some(),
            clearance: provider.clearance(),
            status: provider.status().as_str().to_owned(),
            last_test_status: provider
                .last_test_status()
                .map(|status| status.as_str().to_owned()),
            last_tested_at: provider.last_tested_at(),
            last_test_message: provider.last_test_message().map(str::to_owned),
            pricing: ModelPricingDto::of(provider.pricing()),
        }
    }
}

/// Result of a connectivity probe against a provider.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TestModelProviderResponse {
    /// Whether the model answered.
    pub ok: bool,
    /// The start of the model's reply.
    pub sample: String,
}

impl From<String> for TestModelProviderResponse {
    fn from(answer: String) -> Self {
        Self {
            ok: true,
            sample: answer.chars().take(SAMPLE_LENGTH).collect(),
        }
    }
}

impl From<ModelProviderId> for ConnectModelProviderResponse {
    fn from(id: ModelProviderId) -> Self {
        Self { id: *id.as_uuid() }
    }
}
