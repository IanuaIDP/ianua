//! What a route needs to know about the pipeline it runs.
//!
//! Routing sits below the proxy, so a route never names the proxy's
//! pipeline type. It asks this trait instead, and the pipeline answers it.

use crate::domains::routing::sealed::Sealed;
use crate::types::PipelineId;

/// Whether a pipeline may serve one caller's cached response to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseSharing {
    /// Every cached response is kept for the caller who asked, or nothing
    /// is cached.
    PerCaller,
    /// Some stage, on or off, keeps one cached response for every caller.
    Shared,
}

/// The pipeline a route runs, as the route sees it.
///
/// Only the proxy's pipeline answers it. Otherwise a caller outside the
/// crate could write a type that gives the id of a pipeline with a shared
/// cache and says it caches nothing. A signed-in route made with it would
/// then run on that cache, and Sam would be served Ann's payslip.
pub trait RoutePipeline: Sealed {
    /// The pipeline's id, which the route stores.
    fn pipeline_id(&self) -> PipelineId;

    /// Whether the pipeline shares cached responses between callers.
    fn response_sharing(&self) -> ResponseSharing;
}
