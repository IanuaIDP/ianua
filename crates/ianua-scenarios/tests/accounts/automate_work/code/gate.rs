//! The sandbox gate as a self-hosted server runs it: the one holder of the
//! local container engine's socket, which the stack's worker asks for runs
//! over the gate's own socket. A forged ask reaching that socket starts
//! nothing.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ianua_infra::sandbox::{DEFAULT_IMAGES, GateServing, SandboxGate};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// The local container engine's socket.
const ENGINE_SOCKET: &str = "/var/run/docker.sock";

/// A gate serving in this process until stopped.
pub(crate) struct RunningGate {
    folder: TempDir,
    stop: oneshot::Sender<()>,
    served: JoinHandle<std::io::Result<()>>,
}

impl RunningGate {
    /// A gate serving the pinned runtimes' repositories through the local
    /// engine, on a socket in a folder of its own, putting runs that reach
    /// the network filter on `proxy_network`, or giving code no network.
    pub(crate) async fn start(proxy_network: Option<&str>) -> Self {
        let folder = TempDir::new().expect("a folder for the gate's socket");
        let serving = GateServing {
            listen: folder.path().join("gate.sock"),
            engine: PathBuf::from(ENGINE_SOCKET),
            runtime: None,
            repositories: DEFAULT_IMAGES
                .iter()
                .map(|(_, image)| (*image).to_owned())
                .collect(),
            tenant_registries: Vec::new(),
            proxy_network: proxy_network.map(str::to_owned),
            start_grace: Duration::from_secs(120),
            most_at_once: 4,
        };
        let socket = serving.listen.clone();
        let gate = Arc::new(SandboxGate::new(serving));
        let (stop, stopped) = oneshot::channel::<()>();
        let served = tokio::spawn(gate.serve(async move {
            let _ = stopped.await;
        }));
        listening(&socket).await;
        Self {
            folder,
            stop,
            served,
        }
    }

    /// The gate's socket.
    pub(crate) fn socket(&self) -> PathBuf {
        self.folder.path().join("gate.sock")
    }

    /// Stops the gate once its runs have ended.
    pub(crate) async fn stop(self) {
        let _ = self.stop.send(());
        self.served
            .await
            .expect("the gate's task ends")
            .expect("the gate served cleanly");
    }
}

/// Waits until the gate's socket takes connections.
async fn listening(socket: &Path) {
    for _ in 0..100 {
        if UnixStream::connect(socket).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the gate did not listen");
}

/// Mallory requests a run using her own registry's image, then one with
/// excessive resource limits. The gate answers both requests with the
/// response that means no container was started.
#[tokio::test]
async fn the_gate_starts_nothing_a_version_could_not_hold() {
    let gate = RunningGate::start(None).await;
    let digest = "ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1";
    let foreign =
        format!("ask python-3.13 evil.example.com/python@sha256:{digest} 20 128 closed\n");
    let unbounded =
        format!("ask python-3.13 python:3.13-slim@sha256:{digest} 86400 65536 closed\n");

    let foreign = answer_to(&gate.socket(), &foreign).await;
    let unbounded = answer_to(&gate.socket(), &unbounded).await;

    assert_eq!(foreign, b'N');
    assert_eq!(unbounded, b'N');
    gate.stop().await;
}

/// The first byte of what the gate answers to `ask`, sent alone: `N` when
/// it started no container.
async fn answer_to(socket: &Path, ask: &str) -> u8 {
    let mut stream = UnixStream::connect(socket)
        .await
        .expect("the gate is reached");
    stream
        .write_all(ask.as_bytes())
        .await
        .expect("the ask is sent");
    stream.read_u8().await.expect("the gate answers")
}
