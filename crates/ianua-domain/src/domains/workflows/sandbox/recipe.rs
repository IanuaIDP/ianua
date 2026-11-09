//! What one version of a sandbox is made of: its runtime and the exact
//! image of it, its code and the packages it pins, or a company's own
//! image; and the limits each run keeps to.

use crate::domains::workflows::sandbox::image::OwnImage;
use crate::domains::workflows::sandbox::network::NetworkAccess;
use crate::domains::workflows::sandbox::package::Packages;
use crate::domains::workflows::sandbox::runtime::{Runtime, RuntimeImage};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;
use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};

/// The most bytes of code one version holds.
pub(crate) const MAX_CODE_BYTES: usize = 256 * 1024;

/// The longest one run may take, in seconds.
pub const MAX_RUN_SECONDS: u32 = 300;

/// The least memory one run is given, in MiB.
pub(crate) const MIN_MEMORY_MIB: u32 = 64;

/// The most memory one run may be given, in MiB.
pub(crate) const MAX_MEMORY_MIB: u32 = 2048;

text_value! {
    /// A version's code, as written: text with lines and tabs, nothing
/// else that controls a terminal, at most `MAX_CODE_BYTES`.
    pub struct SandboxCode;
}

impl TextValue for SandboxCode {
    const FIELD: &'static str = "code";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_blank()
            .max_bytes(MAX_CODE_BYTES)
            .rule(&OnlyLinesAndTabs)
    }
}

/// What one run of a version may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunBudget {
    seconds: u32,
    memory_mib: u32,
}

impl RunBudget {
    /// At most `seconds` and `memory_mib` per run.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the time is outside
    ///   1..=[`MAX_RUN_SECONDS`].
    /// - [`DomainError::Validation`] when the memory is outside
    ///   `MIN_MEMORY_MIB..=MAX_MEMORY_MIB`.
    pub fn new(seconds: u32, memory_mib: u32) -> Result<Self, DomainError> {
        validate_range("run_seconds", seconds, 1..=MAX_RUN_SECONDS)?;
        validate_range("memory_mib", memory_mib, MIN_MEMORY_MIB..=MAX_MEMORY_MIB)?;
        Ok(Self {
            seconds,
            memory_mib,
        })
    }

    /// The longest one run may take, in seconds.
    #[must_use]
    pub fn seconds(self) -> u32 {
        self.seconds
    }

    /// The memory one run is given, in MiB.
    #[must_use]
    pub fn memory_mib(self) -> u32 {
        self.memory_mib
    }
}

/// What a version runs: code under one of the offered runtimes, or a
/// company's own image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Program {
    /// Code, with its packages, under an offered runtime.
    Code(CodeProgram),
    /// The company's own image, pinned to its digest, which reads the
    /// step's input on its standard input and writes its answer on its
    /// standard output.
    Image(OwnImage),
}

impl Program {
    /// The image it runs in: the runtime's, or the company's own.
    #[must_use]
    pub fn image(&self) -> &str {
        match self {
            Self::Code(code) => code.image().as_str(),
            Self::Image(own) => own.image().as_str(),
        }
    }

    /// Its code and packages; `None` for a company's image, which holds no
    /// code the platform keeps.
    #[must_use]
    pub fn code(&self) -> Option<&CodeProgram> {
        match self {
            Self::Code(code) => Some(code),
            Self::Image(_) => None,
        }
    }

    /// The pinned packages a built bundle must not leave out; none for a
    /// company's image.
    pub(super) fn packages(&self) -> Option<&Packages> {
        self.code().map(CodeProgram::packages)
    }
}

/// Code under one of the offered runtimes: the runtime and the exact image
/// of it, the code and the packages it pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeProgram {
    runtime: Runtime,
    image: RuntimeImage,
    code: SandboxCode,
    packages: Packages,
}

/// What code under an offered runtime is made of, before it is checked.
pub struct CodeParams {
    /// The runtime it runs under.
    pub runtime: Runtime,
    /// The exact image of that runtime it runs in.
    pub image: RuntimeImage,
    /// The source text bundled and executed under the selected runtime.
    pub code: SandboxCode,
    /// The packages it pins.
    pub packages: Packages,
}

impl CodeProgram {
    /// `params.code` in `params.image` of its runtime, with its packages.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when a package comes from another
    ///   language's registry than the runtime's.
    pub fn new(params: CodeParams) -> Result<Self, DomainError> {
        let language = params.runtime.language();
        if !params.packages.all_of(language) {
            return Err(DomainError::invalid(message!(
                "workflows-a-package-is-not-for-this-language",
                format!(
                    "every package must come from the {} registry",
                    language.as_str()
                )
            )));
        }
        Ok(Self {
            runtime: params.runtime,
            image: params.image,
            code: params.code,
            packages: params.packages,
        })
    }

    /// The runtime it runs under.
    #[must_use]
    pub fn runtime(&self) -> Runtime {
        self.runtime
    }

    /// The exact image of its runtime it runs in, every time.
    #[must_use]
    pub fn image(&self) -> &RuntimeImage {
        &self.image
    }

    /// The immutable source text it executes.
    #[must_use]
    pub fn code(&self) -> &SandboxCode {
        &self.code
    }

    /// The packages it pins.
    #[must_use]
    pub fn packages(&self) -> &Packages {
        &self.packages
    }
}

/// What a version runs, the limits each run keeps to, and the hosts it may
/// reach: none unless it names them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipe {
    program: Program,
    budget: RunBudget,
    network: NetworkAccess,
}

impl Recipe {
    /// A recipe running `program`, each run kept to `budget` and reaching
    /// only `network`.
    #[must_use]
    pub fn new(program: Program, budget: RunBudget, network: NetworkAccess) -> Self {
        Self {
            program,
            budget,
            network,
        }
    }

    /// What it runs.
    #[must_use]
    pub fn program(&self) -> &Program {
        &self.program
    }

    /// What one run may use.
    #[must_use]
    pub fn budget(&self) -> RunBudget {
        self.budget
    }

    /// The hosts it may reach; none for most versions.
    #[must_use]
    pub fn network(&self) -> &NetworkAccess {
        &self.network
    }
}

/// Code holds line breaks and tabs, and no other control character.
struct OnlyLinesAndTabs;

impl Rule for OnlyLinesAndTabs {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let controlled = value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'));
        controlled.then(|| ValidationError::Custom {
            field,
            code: "control_characters".to_owned(),
            message: message!(
                "workflows-code-may-hold-only-line-breaks-and-tabs",
                "code may hold no control character other than line breaks and tabs"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::sandbox::package::{PackageName, PackageVersion, PinnedPackage};
    use crate::domains::workflows::sandbox::runtime::Language;

    /// Python code indented with tabs is taken. Code holding an escape
    /// character, or nothing but spaces, is refused.
    #[test]
    fn code_holds_lines_and_tabs_and_nothing_else_that_controls() {
        assert!(SandboxCode::new("def main(item):\n\treturn item\n").is_ok());
        assert!(SandboxCode::new("print('\u{1b}[2J')").is_err());
        assert!(SandboxCode::new("   ").is_err());
    }

    /// A run of 300 seconds and 2 GiB is allowed. One second more, or 32
    /// MiB of memory, is refused.
    #[test]
    fn a_run_keeps_to_its_limits() {
        assert!(RunBudget::new(MAX_RUN_SECONDS, MAX_MEMORY_MIB).is_ok());
        assert!(RunBudget::new(MAX_RUN_SECONDS + 1, 256).is_err());
        assert!(RunBudget::new(30, 32).is_err());
    }

    /// A Python recipe rejects a pinned JavaScript package.
    #[test]
    fn a_package_of_another_language_is_refused() {
        let lodash = PinnedPackage::new(
            PackageName::new(Language::JavaScript, "lodash").unwrap(),
            PackageVersion::new(Language::JavaScript, "4.17.21").unwrap(),
        );

        let program = CodeProgram::new(CodeParams {
            runtime: Runtime::Python312,
            image: RuntimeImage::new(format!("python:3.12-slim@sha256:{}", "ab".repeat(32)))
                .unwrap(),
            code: SandboxCode::new("print(1)").unwrap(),
            packages: Packages::new(vec![lodash]).unwrap(),
        });

        assert!(matches!(program, Err(DomainError::Validation(_))));
    }
}
