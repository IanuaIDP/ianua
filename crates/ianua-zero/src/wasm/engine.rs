//! The one wasmtime engine, and the clock that ends a guest's time.

use std::error::Error;
use std::time::Duration;

use ianua_boot::shutdown::Shutdown;

/// How often the engine's epoch advances. A stage's time limit counts in
/// these ticks, so a guest overruns it by one tick at most.
pub(super) const TICK: Duration = Duration::from_millis(1);

/// The process-wide engine every module is compiled and run on.
///
/// Building an engine is costly and sharing one is cheap, so the process
/// holds one. Isolation comes from a fresh store per call. Fuel bounds how
/// much a call computes and the epoch bounds how long it takes; a store
/// past either traps.
#[derive(Clone)]
pub(crate) struct WasmEngine {
    engine: wasmtime::Engine,
}

/// The engine could not be built on this platform.
#[derive(Debug, thiserror::Error)]
#[error("the WASM engine could not be built")]
pub(crate) struct EngineError(#[source] Box<dyn Error + Send + Sync>);

impl EngineError {
    /// The error wasmtime gave.
    pub(super) fn from_wasmtime(error: wasmtime::Error) -> Self {
        Self(error.into())
    }
}

impl WasmEngine {
    /// An engine counting fuel and epochs, with no threads.
    ///
    /// # Errors
    ///
    /// - [`EngineError`] when wasmtime cannot build it here.
    pub(crate) fn new() -> Result<Self, EngineError> {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        config.wasm_threads(false);
        let engine = wasmtime::Engine::new(&config).map_err(EngineError::from_wasmtime)?;
        Ok(Self { engine })
    }

    /// Starts the clock that ends a guest's time, until `shutdown` stops.
    ///
    /// Without it only fuel bounds a call, so the process starts it once,
    /// beside the runtime.
    pub(crate) fn keep_time(&self, shutdown: &Shutdown) {
        shutdown.spawn_until_stopped(tick(self.engine.clone()));
    }

    /// The engine itself.
    pub(super) fn inner(&self) -> &wasmtime::Engine {
        &self.engine
    }
}

/// Advances `engine`'s epoch every [`TICK`].
///
/// Missed ticks are not made up in a burst: a busy runtime that fired
/// them back to back would spend a guest's whole time limit in an instant.
async fn tick(engine: wasmtime::Engine) {
    let mut interval = tokio::time::interval(TICK);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        engine.increment_epoch();
    }
}
