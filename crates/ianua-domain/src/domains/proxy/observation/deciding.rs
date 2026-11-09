//! Which check refused a request, and under which rule.
//!
//! A denied request records more than its status and reason. An admin
//! searching the request log for why Ann was refused needs to see that it
//! was the geofence stage, or the tenant policy rule "contractors off
//! hours", without reading the gateway's code.

use crate::domains::proxy::stages::stage::{StageConfig, StageKindName};
use crate::types::{Label, StageId};

/// A check the gateway makes before any pipeline stage runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GatewayCheck {
    /// The request named no tenant the gateway serves, or a closed one.
    Tenant,
    /// No active route matched the request.
    Route,
    /// The request was for an app sign-in address and was refused there.
    AppSignIn,
    /// The request's body was larger than the gateway accepts.
    BodyLimit,
    /// The route's pipeline is not running, so its traffic is refused.
    PipelineOff,
    /// The route is in attack mode, and the client's address was flagged
    /// or sent more than attack mode lets one address send.
    AttackMode,
    /// The upstream could not be reached or did not answer in time.
    Upstream,
}

impl GatewayCheck {
    /// Every check, in the order the gateway makes them.
    pub const ALL: [Self; 7] = [
        Self::Tenant,
        Self::Route,
        Self::AppSignIn,
        Self::BodyLimit,
        Self::PipelineOff,
        Self::AttackMode,
        Self::Upstream,
    ];

    /// The check whose stable name is `name`, or `None` when no check has
    /// it.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|check| check.as_str() == name)
    }

    /// The stable name a record keeps, such as `pipeline_off`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Route => "route",
            Self::AppSignIn => "app_sign_in",
            Self::BodyLimit => "body_limit",
            Self::PipelineOff => "pipeline_off",
            Self::AttackMode => "attack_mode",
            Self::Upstream => "upstream",
        }
    }
}

/// Where in the gateway a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecidingStage {
    /// By one of the gateway's own checks, before any stage ran.
    Gateway(GatewayCheck),
    /// By this stage of the route's pipeline.
    Stage {
        /// The pipeline instance that produced the refusal.
        stage_id: StageId,
        /// Its kind, without its settings.
        kind: StageKindName,
    },
}

impl DecidingStage {
    /// The pipeline stage `stage`, as the one that decided.
    #[must_use]
    pub fn stage(stage: &StageConfig) -> Self {
        Self::Stage {
            stage_id: *stage.id(),
            kind: stage.kind().kind_name(),
        }
    }

    /// The stable name of what decided: a gateway check's or a stage kind's.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Gateway(check) => check.as_str(),
            Self::Stage { kind, .. } => kind.as_str(),
        }
    }
}

/// The rule a refusal was made under, when one has a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecidingRule {
    /// No named rule: a stage's own setting or a gateway check.
    Unnamed,
    /// The tenant policy rule of this name.
    Named(Label),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::proxy::stages::stage::{GeoFenceConfig, StageKind, StageRemoval};
    use crate::types::CountryCode;

    /// The geofence stage refuses Sam. The record names that stage by its id
    /// and as `geo_fence`.
    #[test]
    fn a_stage_that_decides_is_named_by_id_and_kind() {
        let stage = StageConfig::new(
            StageKind::GeoFence(GeoFenceConfig {
                allowed_countries: vec![CountryCode::new("DE").unwrap()],
                blocked_countries: Vec::new(),
            }),
            300,
            StageRemoval::Allowed,
        )
        .unwrap();

        let decided = DecidingStage::stage(&stage);

        assert_eq!(
            decided,
            DecidingStage::Stage {
                stage_id: *stage.id(),
                kind: StageKindName::GeoFence
            }
        );
        assert_eq!(decided.name(), "geo_fence");
    }

    /// Every check reads back from its own name, so a search naming one
    /// finds the refusals it made, and a name no check has reads as none.
    #[test]
    fn every_gateway_check_reads_back_from_its_own_name() {
        for check in GatewayCheck::ALL {
            assert_eq!(GatewayCheck::parse(check.as_str()), Some(check));
        }
        assert_eq!(GatewayCheck::parse("firewall"), None);
    }

    /// A request refused because its pipeline is off records `pipeline_off`,
    /// so a search for it finds every such refusal.
    #[test]
    fn a_gateway_check_has_a_stable_name() {
        assert_eq!(
            DecidingStage::Gateway(GatewayCheck::PipelineOff).name(),
            "pipeline_off"
        );
    }
}
