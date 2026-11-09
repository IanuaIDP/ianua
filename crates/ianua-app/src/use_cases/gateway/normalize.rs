//! A configuration as the gateway holds it once applied, rather than as it
//! was written.
//!
//! Every pipeline runs Identity, then Policy, whether a document names them
//! or not, and a pipeline places the stages it is given one after another
//! behind them. Only their order means anything. Comparing a document as
//! written with the live gateway would report an update on every import,
//! because the apply keeps making something the document does not say. So
//! both sides are put in this one form before they are compared.

use ianua_domain::domains::proxy::stages::stage::{MandatoryStage, StageConfig, StageRemoval};

use crate::use_cases::gateway::document::{GatewayConfig, PipelineDeclaration, StageDeclaration};

/// `config` with every pipeline as the gateway would hold it.
#[must_use]
pub(crate) fn normalized(config: &GatewayConfig) -> GatewayConfig {
    GatewayConfig {
        pipelines: config.pipelines.iter().map(as_built).collect(),
        ..config.clone()
    }
}

/// The pipeline `want` declares, with Identity and Policy in their fixed
/// places and the stages the tenant chose behind them, in the order given.
pub(crate) fn as_built(want: &PipelineDeclaration) -> PipelineDeclaration {
    let mandatory: Vec<StageDeclaration> = [MandatoryStage::Identity, MandatoryStage::Policy]
        .into_iter()
        .map(|stage| StageDeclaration::of(&StageConfig::locked(stage)))
        .collect();
    let first_free = mandatory
        .iter()
        .map(|stage| stage.position)
        .max()
        .map_or(0, |last| last.saturating_add(1));
    let chosen = chosen_stages(want)
        .into_iter()
        .zip(first_free..)
        .map(|(stage, position)| StageDeclaration {
            position,
            ..stage.clone()
        });
    PipelineDeclaration {
        name: want.name.clone(),
        stages: mandatory.into_iter().chain(chosen).collect(),
        status: want.status,
    }
}

/// The stages of `want` the tenant chose, in the order they run.
pub(crate) fn chosen_stages(want: &PipelineDeclaration) -> Vec<&StageDeclaration> {
    let mut chosen: Vec<&StageDeclaration> = want
        .stages
        .iter()
        .filter(|stage| StageRemoval::of(&stage.kind) == StageRemoval::Allowed)
        .collect();
    chosen.sort_by_key(|stage| stage.position);
    chosen
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
    use ianua_domain::domains::proxy::stages::stage::StageKind;

    use super::*;
    use crate::test_support::routing::routing_label;
    use crate::use_cases::gateway::document::StageSwitch;

    fn stage(kind: StageKind, position: u16) -> StageDeclaration {
        StageDeclaration {
            removal: StageRemoval::of(&kind),
            kind,
            position,
            switch: StageSwitch::On,
        }
    }

    fn pipeline(stages: Vec<StageDeclaration>) -> PipelineDeclaration {
        PipelineDeclaration {
            name: routing_label("edge"),
            stages,
            status: PipelineStatus::Draft,
        }
    }

    /// Ann's document names no stage at all. The pipeline still runs
    /// Identity and then Policy.
    #[test]
    fn a_pipeline_without_stages_gains_identity_and_policy() {
        let built = as_built(&pipeline(Vec::new()));

        let kinds: Vec<_> = built.stages.iter().map(|s| s.kind.clone()).collect();
        assert_eq!(kinds, [StageKind::Identity, StageKind::Policy]);
    }

    /// Two documents put Policy at 900 and Identity at 5, or the other way
    /// round. Both come out the same, with Identity first.
    #[test]
    fn where_a_document_puts_the_mandatory_stages_does_not_matter() {
        let one = pipeline(vec![
            stage(StageKind::Policy, 900),
            stage(StageKind::Identity, 5),
        ]);
        let other = pipeline(vec![
            stage(StageKind::Identity, 900),
            stage(StageKind::Policy, 5),
        ]);

        assert_eq!(as_built(&one), as_built(&other));
        assert_eq!(as_built(&one).stages[0].kind, StageKind::Identity);
    }
}
