//! Compiled modules, kept by tenant and reference, so each version is
//! compiled once.
//!
//! A reference is a digest of the module's bytes, so a cached module never
//! goes stale and needs no invalidation. The cache is bounded: past its
//! bound the module used least recently is dropped, and compiled again if
//! it is asked for again. Concurrent first calls for one module wait on a
//! single compile rather than each compiling it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ianua_app::ports::proxy::WasmModuleStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::proxy::stages::stage::ModuleRef;
use ianua_domain::types::TenantId;
use tokio::sync::{OnceCell, Semaphore};
use wasmtime::Module;

use super::failure::Failure;

/// The longest a module's bytes are waited for.
const STORE_TIMEOUT: Duration = Duration::from_secs(2);

/// The longest a compile is waited for, a wait for a compile slot included.
const COMPILE_TIMEOUT: Duration = Duration::from_secs(10);

/// How many modules compile at once. Compiling is CPU-bound work off the
/// async threads, and a burst of new modules must not take every core.
const CONCURRENT_COMPILES: usize = 2;

/// A module cached under a tenant and a reference.
type Key = (TenantId, ModuleRef);

/// Compiled modules, bounded, read through the module store.
pub(super) struct ModuleCache {
    engine: wasmtime::Engine,
    store: Arc<dyn WasmModuleStore>,
    slots: Mutex<Slots>,
    compiles: Semaphore,
}

/// The cached modules and when each was last asked for.
struct Slots {
    entries: HashMap<Key, Slot>,
    clock: u64,
    bound: usize,
}

/// One module, compiled or about to be.
struct Slot {
    module: Arc<OnceCell<Module>>,
    used: u64,
}

impl ModuleCache {
    /// A cache of at most `bound` modules compiled on `engine`, read from
    /// `store`.
    pub(super) fn new(
        engine: wasmtime::Engine,
        store: Arc<dyn WasmModuleStore>,
        bound: usize,
    ) -> Self {
        Self {
            engine,
            store,
            slots: Mutex::new(Slots::new(bound.max(1))),
            compiles: Semaphore::new(CONCURRENT_COMPILES),
        }
    }

    /// The compiled module `tenant` stores under `module_ref`, compiled now
    /// when it is not cached. A failed load is not cached: the next call
    /// tries again.
    ///
    /// # Errors
    ///
    /// - [`Failure::NotFound`], [`Failure::Store`] or
    ///   [`Failure::StoreTimedOut`] when the bytes cannot be read.
    /// - [`Failure::Compile`] or [`Failure::CompileTimedOut`] when they do
    ///   not compile in time.
    pub(super) async fn module(
        &self,
        tenant: &ScopedTenant,
        module_ref: &ModuleRef,
    ) -> Result<Module, Failure> {
        let cell = self
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take((**tenant, module_ref.clone()));
        let module = cell
            .get_or_try_init(|| self.load(tenant, module_ref))
            .await?;
        Ok(module.clone())
    }

    /// Reads and compiles a module.
    async fn load(&self, tenant: &ScopedTenant, module_ref: &ModuleRef) -> Result<Module, Failure> {
        let bytes = self.fetch(tenant, module_ref).await?;
        tokio::time::timeout(COMPILE_TIMEOUT, self.compile(bytes))
            .await
            .map_err(|_| Failure::CompileTimedOut)?
    }

    /// A module's bytes, within [`STORE_TIMEOUT`].
    async fn fetch(
        &self,
        tenant: &ScopedTenant,
        module_ref: &ModuleRef,
    ) -> Result<Vec<u8>, Failure> {
        tokio::time::timeout(STORE_TIMEOUT, self.store.find(tenant, module_ref))
            .await
            .map_err(|_| Failure::StoreTimedOut)?
            .map_err(Failure::Store)?
            .ok_or(Failure::NotFound)
    }

    /// `bytes` compiled off the async threads, once a compile slot is free.
    async fn compile(&self, bytes: Vec<u8>) -> Result<Module, Failure> {
        let _slot = self.compiles.acquire().await.map_err(|_| Failure::Busy)?;
        let engine = self.engine.clone();
        tokio::task::spawn_blocking(move || Module::new(&engine, &bytes))
            .await
            .map_err(|joined| Failure::Compile(Box::new(joined)))?
            .map_err(|compiled| Failure::Compile(compiled.into()))
    }

    /// How many modules are cached.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .len()
    }
}

impl Slots {
    fn new(bound: usize) -> Self {
        Self {
            entries: HashMap::new(),
            clock: 0,
            bound,
        }
    }

    /// The slot for `key`, noted as used now; a new one when there is
    /// none, making room by dropping the slot used least recently.
    fn take(&mut self, key: Key) -> Arc<OnceCell<Module>> {
        self.clock += 1;
        let now = self.clock;
        if let Some(slot) = self.entries.get_mut(&key) {
            slot.used = now;
            return Arc::clone(&slot.module);
        }
        if self.entries.len() >= self.bound {
            self.drop_least_used();
        }
        let module = Arc::new(OnceCell::new());
        let slot = Slot {
            module: Arc::clone(&module),
            used: now,
        };
        self.entries.insert(key, slot);
        module
    }

    /// Drops the slot used least recently.
    fn drop_least_used(&mut self) {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, slot)| slot.used)
            .map(|(key, _)| key.clone());
        let Some(oldest) = oldest else {
            return;
        };
        self.entries.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use ianua_app::ports::TenantScoped;
    use ianua_domain::shared::errors::DomainError;

    use super::*;
    use crate::wasm::engine::WasmEngine;

    /// A store of fixed modules that counts how often it is read.
    struct CountingStore {
        modules: HashMap<ModuleRef, Vec<u8>>,
        reads: AtomicUsize,
    }

    impl CountingStore {
        fn of(modules: &[(&str, &[u8])]) -> Arc<Self> {
            let modules = modules
                .iter()
                .map(|(name, bytes)| (reference(name), bytes.to_vec()))
                .collect();
            Arc::new(Self {
                modules,
                reads: AtomicUsize::new(0),
            })
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl TenantScoped for CountingStore {}

    #[async_trait]
    impl WasmModuleStore for CountingStore {
        async fn save(&self, _: &ScopedTenant, _: &[u8]) -> Result<ModuleRef, DomainError> {
            Err(DomainError::infra_msg("this store is read-only"))
        }

        async fn find(
            &self,
            _: &ScopedTenant,
            module_ref: &ModuleRef,
        ) -> Result<Option<Vec<u8>>, DomainError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(self.modules.get(module_ref).cloned())
        }
    }

    const EMPTY_MODULE: &[u8] = b"(module)";
    const OTHER_MODULE: &[u8] = b"(module (memory 1))";

    fn reference(name: &str) -> ModuleRef {
        ModuleRef::new(name).expect("a valid reference")
    }

    fn cache(store: Arc<CountingStore>, bound: usize) -> ModuleCache {
        let engine = WasmEngine::new().expect("an engine");
        ModuleCache::new(engine.inner().clone(), store, bound)
    }

    fn tenant() -> ScopedTenant {
        ScopedTenant::for_test(TenantId::new())
    }

    #[tokio::test]
    async fn a_module_is_read_and_compiled_once() {
        let store = CountingStore::of(&[("sha256:a", EMPTY_MODULE)]);
        let cache = cache(Arc::clone(&store), 4);
        let acme = tenant();

        cache
            .module(&acme, &reference("sha256:a"))
            .await
            .expect("compiled");
        cache
            .module(&acme, &reference("sha256:a"))
            .await
            .expect("cached");

        assert_eq!(store.reads(), 1);
    }

    #[tokio::test]
    async fn past_its_bound_the_cache_drops_the_module_used_least_recently() {
        let store = CountingStore::of(&[("sha256:a", EMPTY_MODULE), ("sha256:b", OTHER_MODULE)]);
        let cache = cache(Arc::clone(&store), 1);
        let acme = tenant();

        cache
            .module(&acme, &reference("sha256:a"))
            .await
            .expect("compiled");
        cache
            .module(&acme, &reference("sha256:b"))
            .await
            .expect("compiled");
        cache
            .module(&acme, &reference("sha256:a"))
            .await
            .expect("compiled again");

        assert_eq!(cache.len(), 1);
        assert_eq!(store.reads(), 3);
    }

    #[tokio::test]
    async fn one_tenants_module_is_not_another_tenants() {
        let store = CountingStore::of(&[("sha256:a", EMPTY_MODULE)]);
        let cache = cache(Arc::clone(&store), 4);

        cache
            .module(&tenant(), &reference("sha256:a"))
            .await
            .expect("compiled");
        cache
            .module(&tenant(), &reference("sha256:a"))
            .await
            .expect("compiled");

        assert_eq!(store.reads(), 2);
    }

    #[tokio::test]
    async fn an_unknown_reference_is_not_found() {
        let cache = cache(CountingStore::of(&[]), 4);

        let loaded = cache.module(&tenant(), &reference("sha256:missing")).await;

        assert!(matches!(loaded, Err(Failure::NotFound)));
    }

    #[tokio::test]
    async fn bytes_that_are_not_a_module_do_not_compile() {
        let store = CountingStore::of(&[("sha256:bad", &b"not a module"[..])]);
        let cache = cache(store, 4);

        let loaded = cache.module(&tenant(), &reference("sha256:bad")).await;

        assert!(matches!(loaded, Err(Failure::Compile(_))));
    }
}
