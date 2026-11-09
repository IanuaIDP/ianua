//! The model providers runs reason with: connecting one and testing it.

use crate::api::{Request, TenantPath};
use crate::net::Call;
use crate::wire::agents::Created;
use crate::wire::agents::models::{ConnectProvider, EmbeddingModel, Provider, ProviderTest};

/// `POST …/model-providers`.
#[must_use]
pub fn connect(tenant: &TenantPath, provider: &ConnectProvider) -> Request<Created> {
    Request::of(Call::post(tenant.at("/model-providers")).json(provider))
}

/// `GET …/model-providers`.
#[must_use]
pub fn list(tenant: &TenantPath) -> Request<Vec<Provider>> {
    Request::of(Call::get(tenant.at("/model-providers")))
}

/// `POST …/model-providers/{id}/test`: asks the model one short question.
#[must_use]
pub fn test(tenant: &TenantPath, provider_id: &str) -> Request<ProviderTest> {
    Request::of(Call::post(
        tenant.at(&format!("/model-providers/{provider_id}/test")),
    ))
}

/// `PUT …/model-providers/{id}/embeddings`: the embedding model the
/// provider offers beside its chat model, or none.
#[must_use]
pub fn offer_embeddings(
    tenant: &TenantPath,
    provider_id: &str,
    model: &EmbeddingModel,
) -> Request<()> {
    Request::of(
        Call::put(tenant.at(&format!("/model-providers/{provider_id}/embeddings"))).json(model),
    )
}
