//! A tool call with the path it really goes to.

use crate::domains::agents::execution::run::call::ToolCall;
use crate::domains::agents::execution::run::gate::CallRefusal;
use crate::domains::agents::execution::tool::{AgentTool, PathValues};
use crate::isolation::scope::TenantScope;
use crate::types::{ActionClass, CanonicalPath};

/// A tool call, the tool it names, and the path it goes to once the values
/// the model gave are filled in.
///
/// The run decides on this, not on the tool's template. `/orders/{id}` reads
/// as a read. Filled with `id` set to `admin`, a call on a route that
/// declares nothing goes to `/orders/admin`, and the run classes that path.
#[derive(Debug)]
pub struct ResolvedCall<'a, T: TenantScope> {
    call: ToolCall,
    tool: &'a AgentTool<T>,
    target: CanonicalPath,
}

impl<'a, T: TenantScope> ResolvedCall<'a, T> {
    /// `call` to `tool`, going to the tool's path filled from `values`.
    ///
    /// The adapter reads `values` out of the call's arguments, one
    /// [`PathValue`](crate::domains::agents::execution::tool::PathValue) per
    /// part the path names.
    ///
    /// # Errors
    ///
    /// - [`CallRefusal::UnknownTool`] when `tool` is not the one the call
    ///   names, or is disabled.
    /// - [`CallRefusal::UnfilledPath`] when `values` do not fill the tool's
    ///   path exactly.
    pub fn resolve(
        call: ToolCall,
        tool: &'a AgentTool<T>,
        values: &PathValues,
    ) -> Result<Self, CallRefusal> {
        if tool.name().as_str() != call.tool() || !tool.is_active() {
            return Err(CallRefusal::UnknownTool);
        }
        let target = tool
            .path()
            .resolve(values)
            .map_err(|_| CallRefusal::UnfilledPath)?;
        Ok(Self { call, tool, target })
    }

    /// The call as the model made it.
    #[must_use]
    pub fn call(&self) -> &ToolCall {
        &self.call
    }

    /// The tool it calls.
    #[must_use]
    pub fn tool(&self) -> &'a AgentTool<T> {
        self.tool
    }

    /// The path the call goes to.
    #[must_use]
    pub fn target(&self) -> &CanonicalPath {
        &self.target
    }

    /// The two classes the call must fit: the tool's own, read from its
    /// template, and the one of the path it goes to.
    ///
    /// A run's purpose must allow both. A call needs approval when either
    /// does. A `/config/{name}` tool filled with `messages` goes to a path
    /// that reads as messaging. It still changes settings.
    #[must_use]
    pub fn classes(&self) -> [ActionClass; 2] {
        [
            self.tool.action_class(),
            self.tool.action_class_at(&self.target),
        ]
    }

    /// The riskier of [`Self::classes`]: a high-risk one when either is, and
    /// the class of the path it goes to otherwise. A paused call is shown
    /// and approved under this class.
    #[must_use]
    pub fn class(&self) -> ActionClass {
        let [template, target] = self.classes();
        if template.is_high_risk() && !target.is_high_risk() {
            return template;
        }
        target
    }

    pub(super) fn into_call(self) -> ToolCall {
        self.call
    }
}
