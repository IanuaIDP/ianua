//! Writing the pipelines a document declares, stage by stage through the
//! pipeline itself, so a document cannot build one the pipeline would
//! refuse.

use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
use ianua_domain::domains::proxy::stages::stage::StageConfig;
use ianua_domain::domains::routing::control::RoutingControl;
use ianua_domain::domains::routing::route::Route;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{Label, StageId};

use crate::error::AppError;
use crate::use_cases::gateway::apply::state::{Apply, declared, invalid, pipeline_refused};
use crate::use_cases::gateway::document::{PipelineDeclaration, StageSwitch};
use crate::use_cases::gateway::normalize::{as_built, chosen_stages};
use crate::use_cases::routing::lookup::routes_on;

/// Writes the pipeline the document declares under `name`.
///
/// A new pipeline starts with Identity and Policy and gains the declared
/// stages behind them. An existing one whose stages differ is turned off,
/// emptied of the stages the tenant chose and given the declared ones, then
/// turned back on if the document says so, held to the routes that run it.
///
/// # Errors
///
/// - `AppError::Forbidden` when the caller may not change pipelines.
/// - `AppError::Domain` when a stage is set up so it could not do its job,
///   a route that needs sign-in runs a cache shared between callers, or the
///   document moves a pipeline that has run back to draft.
/// - `AppError::Conflict` when the store refuses the name.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn write_pipeline(apply: &mut Apply<'_>, name: &Label) -> Result<(), AppError> {
    let desired = apply.desired;
    let want = declared(&desired.pipelines, name, |p| &p.name)?;
    let tenant = apply.tenant();
    let by = apply.applier.by;
    let pipeline = match apply.pipelines.get(name).cloned() {
        None => created_pipeline(want, &by)?,
        Some(existing) => {
            let store = apply.applier.ports.records.route_store.as_ref();
            let routes = routes_on(store, &tenant, existing.id()).await?;
            updated_pipeline(existing, want, &routes, &by)?
        }
    };
    apply
        .applier
        .ports
        .records
        .pipeline_store
        .save(&tenant, &pipeline)
        .await
        .map_err(AppError::from_domain)?;
    apply.pipelines.insert(name.clone(), pipeline);
    Ok(())
}

/// A new pipeline as `want` declares it. No route runs it yet.
fn created_pipeline(
    want: &PipelineDeclaration,
    by: &RoutingControl<'_>,
) -> Result<Pipeline<ResolvedTenant>, AppError> {
    let mut pipeline = Pipeline::with_defaults(want.name.clone(), by).map_err(pipeline_refused)?;
    add_declared_stages(&mut pipeline, want, by)?;
    settle_status(&mut pipeline, want.status, &[], by)?;
    Ok(pipeline)
}

/// `pipeline` changed to what `want` declares, held to the `routes` that run
/// it.
fn updated_pipeline(
    mut pipeline: Pipeline<ResolvedTenant>,
    want: &PipelineDeclaration,
    routes: &[Route<ResolvedTenant>],
    by: &RoutingControl<'_>,
) -> Result<Pipeline<ResolvedTenant>, AppError> {
    let held = as_built(&PipelineDeclaration::of(&pipeline));
    if held.stages != as_built(want).stages {
        restage(&mut pipeline, want, by)?;
    }
    settle_status(&mut pipeline, want.status, routes, by)?;
    Ok(pipeline)
}

/// Replaces the stages the tenant chose with the ones `want` declares,
/// turning the pipeline off first if it runs.
fn restage(
    pipeline: &mut Pipeline<ResolvedTenant>,
    want: &PipelineDeclaration,
    by: &RoutingControl<'_>,
) -> Result<(), AppError> {
    if pipeline.status().is_active() {
        pipeline.disable(by).map_err(pipeline_refused)?;
    }
    let chosen: Vec<StageId> = pipeline
        .stages()
        .iter()
        .filter(|stage| !stage.mandatory())
        .map(|stage| *stage.id())
        .collect();
    for stage_id in &chosen {
        pipeline
            .remove_stage(stage_id, by)
            .map_err(pipeline_refused)?;
    }
    add_declared_stages(pipeline, want, by)
}

/// Adds the stages `want` declares, in their order, switched as declared.
fn add_declared_stages(
    pipeline: &mut Pipeline<ResolvedTenant>,
    want: &PipelineDeclaration,
    by: &RoutingControl<'_>,
) -> Result<(), AppError> {
    for stage in chosen_stages(want) {
        let config = StageConfig::new(stage.kind.clone(), stage.position, stage.removal)
            .map_err(AppError::from_domain)?;
        let stage_id = *config.id();
        pipeline.add_stage(config, by).map_err(pipeline_refused)?;
        if stage.switch == StageSwitch::Off {
            pipeline
                .disable_stage(&stage_id, by)
                .map_err(pipeline_refused)?;
        }
    }
    Ok(())
}

/// Moves `pipeline` to `status`, held to the `routes` that run it.
///
/// A new pipeline is a draft. A document that wants it disabled has it
/// turned on and off again, which nothing sees, since no route runs it yet.
/// A pipeline that has run never goes back to draft.
fn settle_status(
    pipeline: &mut Pipeline<ResolvedTenant>,
    status: PipelineStatus,
    routes: &[Route<ResolvedTenant>],
    by: &RoutingControl<'_>,
) -> Result<(), AppError> {
    match (pipeline.status(), status) {
        (PipelineStatus::Draft, PipelineStatus::Draft)
        | (PipelineStatus::Active, PipelineStatus::Active)
        | (PipelineStatus::Disabled, PipelineStatus::Disabled) => Ok(()),
        (_, PipelineStatus::Active) => pipeline.activate(routes, by).map_err(pipeline_refused),
        (PipelineStatus::Active, PipelineStatus::Disabled) => {
            pipeline.disable(by).map_err(pipeline_refused)
        }
        (PipelineStatus::Draft, PipelineStatus::Disabled) => pipeline
            .activate(routes, by)
            .and_then(|()| pipeline.disable(by))
            .map_err(pipeline_refused),
        (PipelineStatus::Active | PipelineStatus::Disabled, PipelineStatus::Draft) => {
            Err(invalid(format!(
                "pipeline '{}' has run, so it does not go back to draft; declare it disabled",
                pipeline.name()
            )))
        }
    }
}
