//! Running a memory step: keeping its text in the memory it names, or
//! finding the memory's texts most like it, through the memory's own
//! embedding model.
//!
//! Everything is asked again at each call: the memory must still be the
//! tenant's and active, a text kept must be no more sensitive than the
//! memory is cleared for, the tenant's memories must have room under its
//! plan, and the embedding model must be the one the memory was filled
//! with. A memory that is gone, set to be deleted, full or refusing the
//! data fails the step, since trying again finds the same; an embedding
//! endpoint or store that does not answer turns it away to be tried again,
//! since nothing was kept.

use std::sync::Arc;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::{FieldName, FlowData, FlowValue};
use ianua_domain::domains::workflows::execution::ActionCall;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::memory::entry::{
    FoundCount, FoundEntry, MAX_FOUND, MemoryEntry, MemoryEntryParams, MemoryText,
};
use ianua_domain::domains::workflows::memory::{
    COUNT_INPUT, FIND_SIMILAR, Memory, REMEMBER, TEXT_INPUT,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::UntrustedText;

use crate::error::AppError;
use crate::ports::agents::ModelProviderStore;
use crate::ports::authentication::SecretEncryptor;
use crate::ports::workflows::{Embedder, MemoryEntries, MemoryStore};
use crate::services::embeddings::Embeddings;
use crate::use_cases::workflows::executions::answers::{data, failed, moment_text};
use crate::use_cases::workflows::executions::driving::Driving;

/// The ports a memory step goes through.
#[derive(ianua_macros::Fakes)]
pub struct MemoryPorts {
    /// Keeps the tenant's memories.
    pub memories: Arc<dyn MemoryStore>,
    /// The vector store keeping their texts.
    pub entries: Arc<dyn MemoryEntries>,
    /// Turns texts into vectors.
    pub embedder: Arc<dyn Embedder>,
    /// The tenant's model providers, which may fill a memory.
    pub providers: Arc<dyn ModelProviderStore>,
    /// Opens a provider's key.
    pub encryptor: Arc<dyn SecretEncryptor>,
}

impl Driving<'_> {
    /// How the memory step `call` went.
    pub(super) async fn memory_call(&self, call: &ActionCall) -> ActionOutcome {
        match self.memory_outcome(call).await {
            Ok(outcome) | Err(outcome) => outcome,
        }
    }

    /// The step's outcome, or the reason it went no further.
    async fn memory_outcome(&self, call: &ActionCall) -> Result<ActionOutcome, ActionOutcome> {
        let memory = self.reached_memory(call).await?;
        memory.ensure_active().map_err(|error| refused(&error))?;
        let text = text_of(call)?;
        match call.operation.as_str() {
            REMEMBER => self.remembered(call, &memory, text).await,
            FIND_SIMILAR => self.found(call, &memory, &text).await,
            _ => Err(failed("the memory offers no such operation")),
        }
    }

    /// The memory `call` names, while the tenant keeps it.
    async fn reached_memory(
        &self,
        call: &ActionCall,
    ) -> Result<Memory<ResolvedTenant>, ActionOutcome> {
        let Some(id) = call.reached_memory() else {
            return Err(failed("the step names no memory by its id"));
        };
        self.ports
            .memory
            .memories
            .find_by_id(self.tenant, &id)
            .await
            .map_err(|error| unanswered(&error))?
            .ok_or_else(|| failed("the memory is gone"))
    }

    /// Keeps `text` in `memory`, as exposed as `call` is.
    async fn remembered(
        &self,
        call: &ActionCall,
        memory: &Memory<ResolvedTenant>,
        text: MemoryText,
    ) -> Result<ActionOutcome, ActionOutcome> {
        memory
            .ensure_clears(call.exposure)
            .map_err(|error| refused(&error))?;
        self.ensure_room().await?;
        let embedding = self
            .embeddings()
            .vector(memory.source(), memory.vector_size(), &text)
            .await
            .map_err(|error| unembedded(&error))?;
        let entry = MemoryEntry::new(MemoryEntryParams {
            text,
            embedding,
            exposure: call.exposure,
        });
        self.ports
            .memory
            .entries
            .keep(self.tenant, memory.id(), &entry)
            .await
            .map_err(|error| unanswered(&error))?;
        let output = data(vec![("entry_id", FlowData::text(entry.id().to_string()))])?;
        Ok(ActionOutcome::Succeeded {
            output,
            exposure: call.exposure,
        })
    }

    /// The texts of `memory` most like `text`, as many as `call` asks.
    async fn found(
        &self,
        call: &ActionCall,
        memory: &Memory<ResolvedTenant>,
        text: &MemoryText,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let count = count_of(call)?;
        let near = self
            .embeddings()
            .vector(memory.source(), memory.vector_size(), text)
            .await
            .map_err(|error| unembedded(&error))?;
        let found = self
            .ports
            .memory
            .entries
            .find_similar(self.tenant, memory.id(), &near, count)
            .await
            .map_err(|error| unanswered(&error))?;
        let exposure = found
            .iter()
            .map(|entry| entry.exposure)
            .max()
            .unwrap_or(DataClassLevel::Public);
        let output = found_data(&found)?;
        Ok(ActionOutcome::Succeeded { output, exposure })
    }

    /// Refuses another text once the tenant's memories hold as many as its
    /// plan allows. Nothing kept is ever removed for it.
    async fn ensure_room(&self) -> Result<(), ActionOutcome> {
        let limits = self
            .ports
            .plan_limits
            .for_tenant(self.tenant)
            .await
            .map_err(|error| unanswered(&error))?;
        let kept = self
            .ports
            .memory
            .entries
            .count(self.tenant)
            .await
            .map_err(|error| unanswered(&error))?;
        if kept < u64::from(limits.max_memory_entries) {
            return Ok(());
        }
        Err(failed(
            "the tenant's memories hold as many texts as its plan allows",
        ))
    }

    /// What turns this tenant's texts into vectors.
    fn embeddings(&self) -> Embeddings<'_> {
        Embeddings {
            embedder: self.ports.memory.embedder.as_ref(),
            providers: self.ports.memory.providers.as_ref(),
            encryptor: self.ports.memory.encryptor.as_ref(),
            tenant: self.tenant,
        }
    }
}

/// The text `call` keeps or searches with.
fn text_of(call: &ActionCall) -> Result<MemoryText, ActionOutcome> {
    let name = FieldName::new(TEXT_INPUT).map_err(|_| failed("the step names no text"))?;
    let Some(FlowValue::Text(text)) = call.arguments.field(&name).map(FlowData::value) else {
        return Err(failed("the step's text is not text"));
    };
    MemoryText::new(text).map_err(|_| failed("the text is empty or longer than a memory keeps"))
}

/// How many texts `call` asks to find, three when it names none.
fn count_of(call: &ActionCall) -> Result<FoundCount, ActionOutcome> {
    let name = FieldName::new(COUNT_INPUT).map_err(|_| failed("the step names no count"))?;
    let Some(given) = call.arguments.field(&name).map(FlowData::value) else {
        return Ok(FoundCount::DEFAULT);
    };
    let FlowValue::Number(number) = given else {
        return Err(failed("the count is not a number"));
    };
    (1..=MAX_FOUND)
        .find(|count| (f64::from(*count) - number).abs() < f64::EPSILON)
        .and_then(|count| FoundCount::new(count).ok())
        .ok_or_else(|| failed("the count is not a whole number from 1 to 20"))
}

/// What a search found, as workflow data: each text with how alike it is.
fn found_data(found: &[FoundEntry]) -> Result<FlowData, ActionOutcome> {
    let items = found
        .iter()
        .map(|entry| {
            data(vec![
                ("entry_id", FlowData::text(entry.id.to_string())),
                ("text", FlowData::text(entry.text.as_str())),
                ("similarity", FlowData::number(f64::from(entry.similarity))),
                ("kept_at", moment_text(entry.kept_at)),
            ])
        })
        .collect::<Result<Vec<_>, _>>()?;
    let count = FlowData::number(f64::from(u32::try_from(items.len()).unwrap_or(u32::MAX)));
    let list =
        FlowData::list(items).map_err(|_| failed("what was found does not fit workflow data"))?;
    data(vec![("found", Ok(list)), ("found_count", count)])
}

/// The failure of a rule the memory keeps, in its own words.
fn refused(error: &DomainError) -> ActionOutcome {
    error.refusal().map_or_else(
        || failed("the memory refused the step"),
        |refusal| failed(refusal.as_str()),
    )
}

/// A store that did not answer: nothing was kept, so the call is tried
/// again.
fn unanswered(error: &DomainError) -> ActionOutcome {
    tracing::warn!(%error, "a memory store did not answer");
    ActionOutcome::TurnedAway(UntrustedText::record("the memory store did not answer"))
}

/// The text could not be turned into a vector: tried again when the
/// endpoint did not answer, failed when the memory's model is no longer
/// offered or the provider is gone.
fn unembedded(error: &AppError) -> ActionOutcome {
    match error {
        AppError::Internal(_) | AppError::Upstream(_) => {
            tracing::warn!(%error, "an embedding endpoint did not answer");
            ActionOutcome::TurnedAway(UntrustedText::record("the embedding model did not answer"))
        }
        AppError::Domain(error) => refused(error),
        AppError::NotFound(refusal)
        | AppError::Forbidden(refusal)
        | AppError::Conflict(refusal) => failed(refusal.as_str()),
        _ => failed("the memory's embedding model could not be used"),
    }
}
