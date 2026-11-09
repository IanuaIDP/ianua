//! Code steps: one run of a sandbox version's code on what the step is
//! handed.
//!
//! The step names a version, never a sandbox, so what runs is exactly what
//! was reviewed when the workflow was published. The code is given only
//! the fields its mapping sets, and what it gives back is the step's
//! output.
//!
//! A version may hold an agent instead: the step then runs that agent
//! under the rules saved with the version, given the same fields, and the
//! version's code checks each answer before the step hands it on.

use crate::domains::workflows::design::node::Mapping;
use crate::types::SandboxVersionId;

/// A step that runs one sandbox version's code.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CodeStep {
    version: SandboxVersionId,
    inputs: Mapping,
}

impl CodeStep {
    /// Runs `version`'s code on the fields `inputs` sets.
    #[must_use]
    pub fn new(version: SandboxVersionId, inputs: Mapping) -> Self {
        Self { version, inputs }
    }

    /// The sandbox version whose code runs.
    #[must_use]
    pub fn version(&self) -> SandboxVersionId {
        self.version
    }

    /// What of the step's input the code is given.
    #[must_use]
    pub fn inputs(&self) -> &Mapping {
        &self.inputs
    }
}
