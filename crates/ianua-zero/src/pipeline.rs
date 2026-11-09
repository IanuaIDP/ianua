//! The pipeline a route's requests run through: each stage a thin call into
//! the application or a domain rule, its answer enforced here.
//!
//! The application's `EvaluatePipelineUseCase` decides which stages run
//! and in what order; the gateway fills its `StageExecutor` and
//! `ResponseStageExecutor` ports through [`executor::StageDispatch`], which
//! hands each stage to its group with the request's [`facts::RequestFacts`].

pub mod executor;
pub mod facts;
pub mod stages;
