//! The records of a sandbox: made, a version saved, its bundle built or
//! its image cleared, or failed, a version tried or pushed to a repository,
//! and archived; and the image registries a tenant allows.
//!
//! Saving a version, its bundle coming ready and trying it happen as a
//! person works, so they stay out of colleagues' feeds. A sandbox made or
//! archived, a bundle that could not be built or an image refused, a
//! version pushed to a company's repository, and a registry allowed or
//! removed are worth a look.

use time::OffsetDateTime;

use crate::domains::workflows::sandbox::SandboxKind;
use crate::domains::workflows::sandbox::build::BuildFailure;
use crate::domains::workflows::sandbox::image::{PinnedImage, RegistryHost};
use crate::domains::workflows::sandbox::network::NetworkAccess;
use crate::domains::workflows::sandbox::recipe::Program;
use crate::domains::workflows::sandbox::runtime::Runtime;
use crate::domains::workflows::sandbox::source::{CodeSource, CommitSha, PushTarget};
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::event_type::WorkflowsEvent;
use crate::types::{
    AgentId, EventLabel, ImageRegistryId, SandboxId, SandboxTrialId, SandboxVersionId,
};

/// The reference kind for a sandbox.
const SANDBOX: RefKind = RefKind::new("sandbox");

/// The reference kind for one version of a sandbox.
const SANDBOX_VERSION: RefKind = RefKind::new("sandbox_version");

/// The reference kind for an image registry a tenant allowed.
const IMAGE_REGISTRY: RefKind = RefKind::new("image_registry");

/// Which sandbox an event is about.
#[derive(Debug, Clone)]
pub(crate) struct SandboxRef {
    /// The code project whose lifecycle change is recorded.
    pub(crate) sandbox_id: SandboxId,
    /// Its name when the event fired.
    pub(crate) label: EventLabel,
}

impl SandboxRef {
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "sandbox",
            Reference::new(SANDBOX, self.sandbox_id.to_string(), self.label.as_str()),
        )
    }
}

/// Which version of a sandbox an event is about.
#[derive(Debug, Clone)]
pub(crate) struct SandboxVersionRef {
    /// The code project containing the affected immutable artifact.
    pub(crate) sandbox_id: SandboxId,
    /// The immutable artifact whose build or repository activity is recorded.
    pub(crate) version_id: SandboxVersionId,
    /// The revision sequence used to label the artifact in the audit trail.
    pub(crate) number: u32,
}

impl SandboxVersionRef {
    fn payload(&self) -> EventData {
        let named = format!("version {}", self.number);
        EventData::new()
            .reference(
                "sandbox_version",
                Reference::new(SANDBOX_VERSION, self.version_id.to_string(), &named),
            )
            .field("sandbox_id", self.sandbox_id.to_string())
            .field("version", self.number.to_string())
    }
}

/// A sandbox was made.
#[derive(Debug)]
pub struct SandboxCreated {
    /// The newly created code project and its captured display label.
    pub(crate) sandbox: SandboxRef,
    /// What its versions run: code of a language, or the company's image.
    pub(crate) kind: SandboxKind,
    /// When it was made.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SandboxCreated => WorkflowsEvent::SandboxCreated,
    fn payload(&self) -> EventData {
        self.sandbox
            .payload()
            .field("kind", self.kind.as_str())
            .optional("language", self.kind.language().map(|language| language.as_str().to_owned()))
    }
}

/// What a saved version runs, as its record names it.
#[derive(Debug, Clone)]
pub(crate) enum SavedProgram {
    /// Code under this runtime, pinning this many packages.
    Code {
        /// The runtime it runs under.
        runtime: Runtime,
        /// How many packages it pins.
        packages: usize,
    },
    /// The company's image, by its digest.
    Image(PinnedImage),
}

impl SavedProgram {
    /// What `program` runs, as a record names it.
    pub(crate) fn of(program: &Program) -> Self {
        match program {
            Program::Code(code) => Self::Code {
                runtime: code.runtime(),
                packages: code.packages().as_slice().len(),
            },
            Program::Image(own) => Self::Image(own.image().clone()),
        }
    }

    fn payload(&self, data: EventData) -> EventData {
        match self {
            Self::Code { runtime, packages } => data
                .field("runtime", runtime.as_str())
                .field("count", packages.to_string()),
            Self::Image(image) => data.field("image", image.as_str()),
        }
    }
}

/// A version of a sandbox was saved, and its bundle is being built.
#[derive(Debug)]
pub struct SandboxVersionSaved {
    /// The immutable source revision queued for dependency bundling.
    pub(crate) version: SandboxVersionRef,
    /// What it runs.
    pub(crate) program: SavedProgram,
    /// The hosts its code may reach; none for most versions.
    pub(crate) network: NetworkAccess,
    /// Where its code came from.
    pub(crate) source: CodeSource,
    /// The agent it holds, whose answers its code checks; `None` when its
    /// code is the step's work.
    pub(crate) agent: Option<AgentId>,
    /// When it was saved.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SandboxVersionSaved => WorkflowsEvent::SandboxVersionSaved,
    fn payload(&self) -> EventData {
        let imported_from = match &self.source {
            CodeSource::Written => None,
            CodeSource::Imported(file) => Some(format!(
                "{} {}/{} at {}",
                file.integration,
                file.repository.as_str(),
                file.path.as_str(),
                file.commit.as_str()
            )),
        };
        self.program
            .payload(self.version.payload())
            .optional("hosts", self.network.listed())
            .optional("imported_from", imported_from)
            .optional("agent", self.agent.map(|agent| agent.to_string()))
    }
}

/// A copy of a version was pushed to a company's repository.
#[derive(Debug)]
pub struct SandboxVersionPushed {
    /// The immutable source revision copied to the external repository.
    pub(crate) version: SandboxVersionRef,
    /// Where it went.
    pub(crate) target: PushTarget,
    /// The commit it became.
    pub(crate) commit: CommitSha,
    /// When it was pushed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SandboxVersionPushed => WorkflowsEvent::SandboxVersionPushed,
    fn payload(&self) -> EventData {
        self.version
            .payload()
            .field("integration", self.target.integration.as_str())
            .field("repository", self.target.repository.as_str())
            .field("branch", self.target.branch.as_str())
            .field("path", self.target.folder.as_str())
            .field("commit", self.commit.as_str())
    }
}

/// A version's bundle was built and stored.
#[derive(Debug)]
pub struct SandboxVersionBuilt {
    /// The immutable source revision whose runnable bundle is now stored.
    pub(crate) version: SandboxVersionRef,
    /// How large the bundle is, in bytes.
    pub(crate) bytes: u64,
    /// When it was ready.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SandboxVersionBuilt => WorkflowsEvent::SandboxVersionBuilt,
    fn payload(&self) -> EventData {
        self.version.payload().field("byte_len", self.bytes.to_string())
    }
}

/// A version's bundle could not be built.
#[derive(Debug)]
pub struct SandboxVersionFailed {
    /// The immutable source revision whose dependency bundling failed.
    pub(crate) version: SandboxVersionRef,
    /// Why.
    pub(crate) failure: BuildFailure,
    /// When it failed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SandboxVersionFailed => WorkflowsEvent::SandboxVersionFailed,
    fn payload(&self) -> EventData {
        self.version
            .payload()
            .field("failure", self.failure.code())
            .field("detail", self.failure.detail())
    }
}

/// A sandbox was archived: no version of it is saved or picked again.
#[derive(Debug)]
pub struct SandboxArchived {
    /// The code project no longer available for saving or selecting revisions.
    pub(crate) sandbox: SandboxRef,
    /// When it was archived.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SandboxArchived => WorkflowsEvent::SandboxArchived,
    fn payload(&self) -> EventData {
        self.sandbox.payload()
    }
}

/// A person started a trial of a sandbox version on sample input.
#[derive(Debug)]
pub struct SandboxTrialStarted {
    /// The version it tries.
    pub(crate) version: SandboxVersionRef,
    /// The sample-input execution started for the referenced artifact.
    pub(crate) trial_id: SandboxTrialId,
    /// The hosts its code may reach; none for most versions.
    pub(crate) network: NetworkAccess,
    /// When it was started.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SandboxTrialStarted => WorkflowsEvent::SandboxTrialStarted,
    fn payload(&self) -> EventData {
        self.version
            .payload()
            .field("trial_id", self.trial_id.to_string())
            .optional("hosts", self.network.listed())
    }
}

/// Which image registry an event is about.
#[derive(Debug, Clone)]
pub(crate) struct ImageRegistryRef {
    /// The registry's row on the tenant's list.
    pub(crate) registry_id: ImageRegistryId,
    /// Its host, which also names it in the record.
    pub(crate) host: RegistryHost,
}

impl ImageRegistryRef {
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "image_registry",
            Reference::new(
                IMAGE_REGISTRY,
                self.registry_id.to_string(),
                self.host.as_str(),
            ),
        )
    }
}

/// An administrator allowed an image registry, which sandbox versions may
/// pull the company's own images from.
#[derive(Debug)]
pub struct ImageRegistryAllowed {
    /// The registry allowed.
    pub(crate) registry: ImageRegistryRef,
    /// How images are pulled from it: `password`, with a login the
    /// platform keeps sealed, or `anonymous`.
    pub(crate) login: &'static str,
    /// When it was allowed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ImageRegistryAllowed => WorkflowsEvent::ImageRegistryAllowed,
    fn payload(&self) -> EventData {
        self.registry.payload().field("login", self.login)
    }
}

/// An image registry was taken off the tenant's list: versions whose image
/// it keeps no longer run.
#[derive(Debug)]
pub struct ImageRegistryRemoved {
    /// The registry removed.
    pub(crate) registry: ImageRegistryRef,
    /// When it was removed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ImageRegistryRemoved => WorkflowsEvent::ImageRegistryRemoved,
    fn payload(&self) -> EventData {
        self.registry.payload()
    }
}
