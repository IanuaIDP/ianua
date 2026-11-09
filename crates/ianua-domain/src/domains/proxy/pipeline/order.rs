//! Reordering a pipeline's stages in one step.
//!
//! A reorder is one intent, so it takes the whole order at once: the proxy
//! never sees an order in between, and Identity and Policy stay first.

use std::collections::HashSet;

use crate::domains::proxy::events::PipelineReordered;
use crate::domains::proxy::pipeline::{Pipeline, PipelineError};
use crate::domains::proxy::stages::stage::StageConfig;
use crate::domains::routing::control::RoutingControl;
use crate::isolation::scope::TenantScope;
use crate::types::StageId;

impl<T: TenantScope> Pipeline<T> {
    /// Reorders the whole pipeline in one step, `order` naming every stage
    /// exactly once in the sequence they should run. Raises
    /// `proxy.pipeline_reordered` with the order it runs now.
    ///
    /// It takes the whole order, not one stage's position, because a reorder
    /// is one intent. Moved one at a time, the proxy would see every order in
    /// between. A failure part-way would leave an order nobody asked for, and
    /// two stages could land on one position.
    ///
    /// Positions are given from the sequence, so callers order stages
    /// instead of choosing numbers. Only relative order means anything.
    /// [`active_stages`](Self::active_stages) sorts by position.
    ///
    /// Identity runs first and Policy second, whatever the sequence says. If
    /// a sequence puts another stage ahead of them, or Policy ahead of
    /// Identity, those two move to the top. The rest keep their relative
    /// order. A check that reads who is calling before Identity has run
    /// would decide on nothing.
    ///
    /// # Errors
    ///
    /// - [`PipelineError::NotAllowed`] when `by` may not change pipelines.
    /// - [`PipelineError::ActivePipelineImmutable`] if the pipeline is active.
    /// - [`PipelineError::IncompleteOrder`] if `order` does not name every
    ///   stage exactly once. A partial list would leave the stages it omits
    ///   at the front of the pipeline without anyone seeing.
    pub fn reorder_stages(
        &mut self,
        order: &[StageId],
        by: &RoutingControl<'_>,
    ) -> Result<(), PipelineError> {
        self.require_mutable(by)?;

        let named: HashSet<&StageId> = order.iter().collect();
        let names_each_stage_once = named.len() == order.len() && named.len() == self.stages.len();
        if !names_each_stage_once || !self.stages.iter().all(|s| named.contains(s.id())) {
            return Err(PipelineError::IncompleteOrder);
        }

        let rank = |id: &StageId| {
            self.stages
                .iter()
                .find(|s| s.id() == id)
                .map_or(u8::MAX, StageConfig::run_rank)
        };
        let mut ranked: Vec<&StageId> = order.iter().collect();
        ranked.sort_by_key(|id| rank(id));

        self.move_into(&ranked)?;
        self.touch();
        self.raised.raise(PipelineReordered {
            pipeline_id: self.id,
            order: self
                .stages_in_order()
                .iter()
                .map(|stage| *stage.id())
                .collect(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Gives each stage its place, in the order `ranked` names them.
    fn move_into(&mut self, ranked: &[&StageId]) -> Result<(), PipelineError> {
        let mut position: u16 = 0;
        for id in ranked {
            let stage = self
                .stages
                .iter_mut()
                .find(|s| s.id() == *id)
                .ok_or(PipelineError::StageNotFound)?;
            stage.move_to(position);
            position = position.saturating_add(1);
        }
        Ok(())
    }
}
