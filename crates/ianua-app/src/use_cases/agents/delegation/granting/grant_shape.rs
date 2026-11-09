//! The shape a new delegation takes before the domain grants it: what it
//! gives and under which limits, narrowed by a bound intent and capped by a
//! task template.

use ianua_domain::domains::agents::authority::capability::{CapabilitySet, DelegationConstraints};
use ianua_domain::domains::agents::authority::intent::{CompiledIntent, IntentBinding};
use ianua_domain::domains::agents::authority::task_template::{TaskTemplate, TemplatedGrant};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::TaskTemplateId;

use crate::error::{AppError, OrInternal};
use crate::ports::agents::{IntentCompiler, TaskTemplateStore};
use crate::tenancy::ScopedTenant;
use crate::use_cases::agents::delegation::IntentGrant;
use crate::use_cases::agents::lookup::existing_task_template;

/// What a person asks a delegation to be, before anything narrows it.
pub(in crate::use_cases::agents) struct AskedGrant<'a> {
    /// The capabilities asked for.
    pub(in crate::use_cases::agents) granted: &'a CapabilitySet,
    /// The limits asked for.
    pub(in crate::use_cases::agents) constraints: &'a DelegationConstraints,
    /// The intent to bind, if any.
    pub(in crate::use_cases::agents) intent: Option<&'a IntentGrant>,
    /// The approved template to fit inside, if any.
    pub(in crate::use_cases::agents) template: Option<&'a TaskTemplateId>,
}

/// Where a grant's intent and template are read from.
#[derive(Clone, Copy)]
pub(in crate::use_cases::agents) struct ShapeSources<'a> {
    /// Compiles a bound intent into its scope and digest.
    pub(in crate::use_cases::agents) compiler: &'a dyn IntentCompiler,
    /// The tenant's task templates.
    pub(in crate::use_cases::agents) templates: &'a dyn TaskTemplateStore,
}

/// A grant as it will be issued.
pub(in crate::use_cases::agents) struct Shaped {
    /// What it gives.
    pub(in crate::use_cases::agents) granted: CapabilitySet,
    /// Its limits.
    pub(in crate::use_cases::agents) constraints: DelegationConstraints,
}

/// What `asked` becomes once its intent narrows it and its template caps
/// it.
///
/// # Errors
///
/// - `AppError::NotFound` when the template does not exist.
/// - `AppError::Forbidden` when the template is not approved, the grant
///   asks past it, or the intent compiles to more than was asked.
/// - `AppError::Internal` when the intent cannot be compiled or a store
///   fails.
pub(in crate::use_cases::agents) async fn shaped_grant(
    sources: ShapeSources<'_>,
    tenant: &ScopedTenant,
    asked: AskedGrant<'_>,
) -> Result<Shaped, AppError> {
    let template = template_of(sources.templates, tenant, asked.template).await?;
    let shaped = intent_shaped(sources.compiler, &asked, template.as_ref()).await?;
    let Some(template) = template else {
        return Ok(shaped);
    };
    let TemplatedGrant {
        granted,
        constraints,
    } = template
        .apply(&shaped.granted, shaped.constraints)
        .map_err(AppError::from_domain)?;
    Ok(Shaped {
        granted,
        constraints,
    })
}

/// The asked grant, narrowed by its bound intent when it has one: the grant
/// shrinks to what the purpose can use, and the intent's envelope is capped
/// by the template's action classes.
async fn intent_shaped(
    compiler: &dyn IntentCompiler,
    asked: &AskedGrant<'_>,
    template: Option<&TaskTemplate<ResolvedTenant>>,
) -> Result<Shaped, AppError> {
    let Some(intent) = asked.intent else {
        return Ok(Shaped {
            granted: asked.granted.clone(),
            constraints: asked.constraints.clone(),
        });
    };
    let compiled = compiler
        .compile(&intent.statement, asked.granted)
        .await
        .or_internal()?;
    ensure_narrowed(&compiled, asked.granted)?;
    let envelope = template.map_or_else(
        || compiled.envelope().clone(),
        |template| compiled.envelope().intersect(template.classes()),
    );
    let binding = IntentBinding::new(
        intent.statement.clone(),
        *compiled.digest(),
        intent.drift_policy,
        envelope,
    );
    Ok(Shaped {
        granted: compiled.scope().clone(),
        constraints: asked.constraints.clone().with_intent(binding),
    })
}

/// Refuses a compiled intent that reaches past what was asked. An intent
/// only ever narrows a grant: a compiler that answers wider, broken or
/// tricked by the statement, would otherwise grant what nobody asked for.
fn ensure_narrowed(compiled: &CompiledIntent, asked: &CapabilitySet) -> Result<(), AppError> {
    if compiled.scope().subset_of(asked) {
        return Ok(());
    }
    Err(AppError::Forbidden(message!(
        "agents-the-compiled-intent-reaches-past-the",
        "the compiled intent reaches past the grant asked for"
    )))
}

/// The template `id` names, when one is named.
async fn template_of(
    store: &dyn TaskTemplateStore,
    tenant: &ScopedTenant,
    id: Option<&TaskTemplateId>,
) -> Result<Option<TaskTemplate<ResolvedTenant>>, AppError> {
    let Some(id) = id else {
        return Ok(None);
    };
    existing_task_template(store, tenant, id).await.map(Some)
}
