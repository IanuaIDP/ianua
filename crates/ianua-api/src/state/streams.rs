//! Context use cases and the stream gates their WebSocket handlers share.

use axum::extract::FromRef;
use ianua_assembly::messaging::MessagingState;
use ianua_assembly::realtime::RealtimeState;
use ianua_assembly::workflows::WorkflowState;

use crate::state::{ApiState, StreamGates};

/// Realtime use cases and the limits applied when their streams open.
#[derive(Clone)]
pub(crate) struct RealtimeStreamState {
    /// Readers and subscriber for provisioning updates.
    pub(crate) realtime: RealtimeState,
    /// Per-caller capacity and periodic recheck timing.
    pub(crate) gates: StreamGates,
}

impl FromRef<ApiState> for RealtimeStreamState {
    fn from_ref(state: &ApiState) -> Self {
        Self {
            realtime: state.realtime.clone(),
            gates: state.stream_gates.clone(),
        }
    }
}

/// Messaging use cases and the limits applied to a topic stream.
#[derive(Clone)]
pub(crate) struct MessagingStreamState {
    /// Topic admission and its live subscriber.
    pub(crate) messaging: MessagingState,
    /// Per-caller capacity and periodic recheck timing.
    pub(crate) gates: StreamGates,
}

impl FromRef<ApiState> for MessagingStreamState {
    fn from_ref(state: &ApiState) -> Self {
        Self {
            messaging: state.messaging.clone(),
            gates: state.stream_gates.clone(),
        }
    }
}

/// Workflow readers, their realtime subscriber, and stream admission limits.
#[derive(Clone)]
pub(crate) struct WorkflowStreamState {
    /// Readers used to admit and recheck workflow streams.
    pub(crate) workflows: WorkflowState,
    /// Subscriber supplying workflow updates.
    pub(crate) realtime: RealtimeState,
    /// Per-caller capacity and periodic recheck timing.
    pub(crate) gates: StreamGates,
}

impl FromRef<ApiState> for WorkflowStreamState {
    fn from_ref(state: &ApiState) -> Self {
        Self {
            workflows: state.workflows.clone(),
            realtime: state.realtime.clone(),
            gates: state.stream_gates.clone(),
        }
    }
}
