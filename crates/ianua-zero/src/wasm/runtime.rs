//! Running one call of a tenant's module, inside its limits.

use std::sync::Arc;
use std::time::Duration;

use ianua_app::ports::proxy::WasmModuleStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::proxy::stages::stage::WasmStageRef;
use tokio::sync::Semaphore;
use wasmtime::{
    Caller, Extern, Linker, Memory, Module, ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder,
};

use super::abi::{self, GuestInput, MAX_ANSWER_BYTES, MalformedAnswer, Verdict};
use super::cache::ModuleCache;
use super::engine::{EngineError, TICK, WasmEngine};
use super::failure::Failure;

/// How much fuel a call burns between giving its thread back to the
/// runtime, so a long call does not starve other requests.
const YIELD_EVERY: u64 = 100_000;

/// The most table elements a module may hold.
const TABLE_ELEMENTS: usize = 10_000;

/// How much a [`WasmRuntime`] holds and runs at once.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WasmBounds {
    /// The most compiled modules kept.
    pub modules: usize,
    /// The most calls running at once. Each may use up to its stage's
    /// memory limit, so this bounds the memory guests use together.
    pub concurrent_calls: usize,
    /// The fuel each call starts with, a ceiling on how much it computes
    /// whatever its time limit.
    pub fuel_per_call: u64,
}

impl Default for WasmBounds {
    /// 256 modules, 16 calls at once, a billion units of fuel per call.
    fn default() -> Self {
        Self {
            modules: 256,
            concurrent_calls: 16,
            fuel_per_call: 1_000_000_000,
        }
    }
}

/// What a call's store holds: the input, and the limits it grows under.
struct Guest {
    input: Arc<[u8]>,
    limits: StoreLimits,
}

/// Runs tenants' modules for `Custom` stages.
pub(crate) struct WasmRuntime {
    engine: WasmEngine,
    cache: ModuleCache,
    linker: Linker<Guest>,
    calls: Semaphore,
    fuel_per_call: u64,
}

impl WasmRuntime {
    /// A runtime on `engine`, reading modules from `store`, held to
    /// `bounds`. Start the engine's clock with
    /// [`WasmEngine::keep_time`], or only fuel bounds a call.
    ///
    /// # Errors
    ///
    /// - [`EngineError`] when the host import cannot be linked.
    pub(crate) fn new(
        engine: &WasmEngine,
        store: Arc<dyn WasmModuleStore>,
        bounds: WasmBounds,
    ) -> Result<Self, EngineError> {
        let mut linker = Linker::new(engine.inner());
        linker
            .func_wrap("env", "get_request", get_request)
            .map_err(EngineError::from_wasmtime)?;
        Ok(Self {
            engine: engine.clone(),
            cache: ModuleCache::new(engine.inner().clone(), store, bounds.modules),
            linker,
            calls: Semaphore::new(bounds.concurrent_calls.max(1)),
            fuel_per_call: bounds.fuel_per_call,
        })
    }

    /// Runs the module `stage` names for `tenant` on `input`.
    ///
    /// Never fails: anything that keeps the module from answering, or an
    /// answer that does not fit the ABI, is [`Verdict::Refused`], logged
    /// with its cause for the operator.
    pub(crate) async fn run(
        &self,
        tenant: &ScopedTenant,
        stage: &WasmStageRef,
        input: &GuestInput,
    ) -> Verdict {
        match self.evaluate(tenant, stage, input).await {
            Ok(verdict) => verdict,
            Err(failure) => {
                tracing::warn!(
                    tenant_id = %**tenant,
                    module_ref = %stage.module_ref,
                    failure = failure.as_str(),
                    error = %failure,
                    "custom stage module refused"
                );
                Verdict::Refused(failure)
            }
        }
    }

    /// The module's verdict, or why there is none.
    async fn evaluate(
        &self,
        tenant: &ScopedTenant,
        stage: &WasmStageRef,
        input: &GuestInput,
    ) -> Result<Verdict, Failure> {
        let limit = Duration::from_millis(u64::from(stage.timeout_ms.max(1)));
        let _call = tokio::time::timeout(limit, self.calls.acquire())
            .await
            .map_err(|_| Failure::Busy)?
            .map_err(|_| Failure::Busy)?;
        let module = self.cache.module(tenant, &stage.module_ref).await?;
        let mut store = self.store_for(stage, input)?;
        let answer = self.call(&mut store, &module).await?;
        abi::verdict_from(&answer).map_err(Failure::Malformed)
    }

    /// A fresh store for one call, with its fuel, its time and its memory
    /// limit.
    fn store_for(&self, stage: &WasmStageRef, input: &GuestInput) -> Result<Store<Guest>, Failure> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(usize::try_from(stage.max_memory_bytes).unwrap_or(usize::MAX))
            .memories(1)
            .instances(1)
            .tables(4)
            .table_elements(TABLE_ELEMENTS)
            .trap_on_grow_failure(true)
            .build();
        let guest = Guest {
            input: input.shared(),
            limits,
        };
        let mut store = Store::new(self.engine.inner(), guest);
        store.limiter(|guest| &mut guest.limits as &mut dyn ResourceLimiter);
        store
            .set_fuel(self.fuel_per_call)
            .map_err(|error| Failure::Setup(error.into()))?;
        store
            .fuel_async_yield_interval(Some(YIELD_EVERY))
            .map_err(|error| Failure::Setup(error.into()))?;
        store.set_epoch_deadline(ticks_in(stage.timeout_ms));
        Ok(store)
    }

    /// Instantiates `module`, calls its `evaluate`, and reads its answer.
    async fn call(&self, store: &mut Store<Guest>, module: &Module) -> Result<Vec<u8>, Failure> {
        let instance = self
            .linker
            .instantiate_async(&mut *store, module)
            .await
            .map_err(Failure::instantiating)?;
        let evaluate = instance
            .get_typed_func::<(), i64>(&mut *store, "evaluate")
            .map_err(|_| Failure::MissingExport("evaluate"))?;
        let memory = instance
            .get_memory(&mut *store, "memory")
            .ok_or(Failure::MissingExport("memory"))?;
        let packed = evaluate
            .call_async(&mut *store, ())
            .await
            .map_err(Failure::trapped)?;
        read_answer(store, memory, packed).map_err(Failure::Malformed)
    }
}

/// The epoch ticks in `timeout_ms`, at least one.
fn ticks_in(timeout_ms: u32) -> u64 {
    let tick = u64::try_from(TICK.as_millis()).unwrap_or(1).max(1);
    (u64::from(timeout_ms) / tick).max(1)
}

/// The answer `packed` points at in `memory`.
fn read_answer(
    store: &Store<Guest>,
    memory: Memory,
    packed: i64,
) -> Result<Vec<u8>, MalformedAnswer> {
    let (offset, len) = abi::unpack(packed);
    if len > MAX_ANSWER_BYTES {
        return Err(MalformedAnswer::TooLong { len });
    }
    let mut answer = vec![0u8; len];
    memory
        .read(store, offset, &mut answer)
        .map_err(|_| MalformedAnswer::OutOfBounds)?;
    Ok(answer)
}

/// `env.get_request(ptr, max_len) -> i32`: writes up to `max_len` bytes of
/// the call's input into the guest's memory at `ptr`, and says how many,
/// or `-1` when it cannot.
fn get_request(mut caller: Caller<'_, Guest>, ptr: i32, max_len: i32) -> i32 {
    let (Ok(offset), Ok(max_len)) = (usize::try_from(ptr), usize::try_from(max_len)) else {
        return -1;
    };
    let input = Arc::clone(&caller.data().input);
    let Some(memory) = caller.get_export("memory").and_then(Extern::into_memory) else {
        return -1;
    };
    let Some(bytes) = input.get(..input.len().min(max_len)) else {
        return -1;
    };
    if memory.write(&mut caller, offset, bytes).is_err() {
        return -1;
    }
    i32::try_from(bytes.len()).unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use async_trait::async_trait;
    use ianua_app::ports::TenantScoped;
    use ianua_domain::domains::proxy::stages::stage::ModuleRef;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::TenantId;

    use super::*;

    /// A store holding one tenant's modules, written as text.
    struct Modules(HashMap<ModuleRef, Vec<u8>>);

    impl TenantScoped for Modules {}

    #[async_trait]
    impl WasmModuleStore for Modules {
        async fn save(&self, _: &ScopedTenant, _: &[u8]) -> Result<ModuleRef, DomainError> {
            Err(DomainError::infra_msg("this store is read-only"))
        }

        async fn find(
            &self,
            _: &ScopedTenant,
            module_ref: &ModuleRef,
        ) -> Result<Option<Vec<u8>>, DomainError> {
            Ok(self.0.get(module_ref).cloned())
        }
    }

    /// Answers `{"decision":"pass"}`, written at 16.
    const PASSES: &str = r#"(module
        (memory (export "memory") 1)
        (data (i32.const 16) "{\"decision\":\"pass\"}")
        (func (export "evaluate") (result i64) i64.const 68719476755))"#;

    /// Reads its input and answers it back as its decision.
    const ECHOES: &str = r#"(module
        (import "env" "get_request" (func $get (param i32 i32) (result i32)))
        (memory (export "memory") 1)
        (func (export "evaluate") (result i64)
            (i64.or
                (i64.const 4294967296)
                (i64.extend_i32_u (call $get (i32.const 1) (i32.const 1024))))))"#;

    /// Never stops.
    const SPINS: &str = r#"(module
        (memory (export "memory") 1)
        (func (export "evaluate") (result i64) (loop $again (br $again)) i64.const 0))"#;

    /// Traps at once.
    const TRAPS: &str = r#"(module
        (memory (export "memory") 1)
        (func (export "evaluate") (result i64) unreachable))"#;

    /// Asks for 100 pages, 6.4 MB, of memory up front.
    const HOARDS: &str = r#"(module
        (memory (export "memory") 100)
        (func (export "evaluate") (result i64) i64.const 0))"#;

    /// Exports no `evaluate`.
    const SILENT: &str = r#"(module (memory (export "memory") 1))"#;

    /// Answers with a decision the ABI does not have.
    const FORKS: &str = r#"(module
        (memory (export "memory") 1)
        (data (i32.const 0) "{\"decision\":\"fork\"}")
        (func (export "evaluate") (result i64) i64.const 19))"#;

    fn runtime(fuel_per_call: u64) -> WasmRuntime {
        let modules = [
            ("passes", PASSES),
            ("echoes", ECHOES),
            ("spins", SPINS),
            ("traps", TRAPS),
            ("hoards", HOARDS),
            ("silent", SILENT),
            ("forks", FORKS),
        ]
        .into_iter()
        .map(|(name, text)| (reference(name), text.as_bytes().to_vec()))
        .collect();
        let engine = WasmEngine::new().expect("an engine");
        let bounds = WasmBounds {
            fuel_per_call,
            ..WasmBounds::default()
        };
        WasmRuntime::new(&engine, Arc::new(Modules(modules)), bounds).expect("a runtime")
    }

    fn reference(name: &str) -> ModuleRef {
        ModuleRef::new(name).expect("a valid reference")
    }

    fn stage(name: &str) -> WasmStageRef {
        WasmStageRef {
            module_ref: reference(name),
            timeout_ms: 1_000,
            max_memory_bytes: 64 * 1024,
        }
    }

    async fn run(runtime: &WasmRuntime, name: &str, input: &[u8]) -> Verdict {
        let tenant = ScopedTenant::for_test(TenantId::new());
        let input = GuestInput::new(input.to_vec()).expect("a small input");
        runtime.run(&tenant, &stage(name), &input).await
    }

    #[tokio::test]
    async fn a_module_that_passes_is_a_pass() {
        let verdict = run(&runtime(1_000_000), "passes", b"{}").await;

        assert!(matches!(verdict, Verdict::Pass { .. }));
    }

    #[tokio::test]
    async fn the_module_reads_the_input_it_is_given() {
        let input = br#"{"decision":"deny","status":429,"reason":"too many"}"#;

        let verdict = run(&runtime(1_000_000), "echoes", input).await;

        assert!(matches!(verdict, Verdict::Deny { status, .. } if status.code() == 429));
    }

    #[tokio::test]
    async fn a_module_out_of_fuel_is_refused() {
        let verdict = run(&runtime(10_000), "spins", b"{}").await;

        assert!(matches!(verdict, Verdict::Refused(Failure::OutOfFuel)));
    }

    #[tokio::test]
    async fn a_module_that_traps_is_refused() {
        let verdict = run(&runtime(1_000_000), "traps", b"{}").await;

        assert!(matches!(verdict, Verdict::Refused(Failure::Trap(_))));
    }

    #[tokio::test]
    async fn a_module_asking_for_more_memory_than_allowed_is_refused() {
        let verdict = run(&runtime(1_000_000), "hoards", b"{}").await;

        assert!(matches!(
            verdict,
            Verdict::Refused(Failure::Instantiate(_) | Failure::Trap(_))
        ));
    }

    #[tokio::test]
    async fn a_module_without_evaluate_is_refused() {
        let verdict = run(&runtime(1_000_000), "silent", b"{}").await;

        assert!(matches!(
            verdict,
            Verdict::Refused(Failure::MissingExport("evaluate"))
        ));
    }

    #[tokio::test]
    async fn a_module_answering_fork_is_refused() {
        let verdict = run(&runtime(1_000_000), "forks", b"{}").await;

        assert!(matches!(verdict, Verdict::Refused(Failure::Malformed(_))));
    }

    #[tokio::test]
    async fn a_module_that_is_not_stored_is_refused() {
        let verdict = run(&runtime(1_000_000), "missing", b"{}").await;

        assert!(matches!(verdict, Verdict::Refused(Failure::NotFound)));
    }

    #[test]
    fn a_time_limit_is_at_least_one_tick() {
        assert_eq!(ticks_in(0), 1);
        assert_eq!(ticks_in(250), 250);
    }
}
