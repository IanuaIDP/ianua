//! A relay in front of one part the platform depends on, the database, the
//! cache or the bus, that a scenario can cut and mend while the platform
//! runs.
//!
//! The shared servers are shared by every stack in the run, so stopping
//! one would fail other scenarios. A relay stands in for the part to this
//! stack alone: cut, it drops every connection it carries and refuses new
//! ones, as a part that crashed or a network that split looks to the
//! platform; mended, it carries connections again. Held, it takes new
//! connections and answers nothing on them, as a part that hangs looks.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ianua_boot::shutdown::Shutdown;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};

/// A part the platform depends on that a scenario can cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Part {
    /// The database: every role's connections.
    Database,
    /// The cache server.
    Cache,
    /// The message bus.
    Bus,
    /// The platform's SMTP receiver.
    Mail,
}

/// Whether a relay carries connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Line {
    /// It carries them.
    Up,
    /// It drops those it carried, and takes new ones without carrying
    /// them anywhere, so nothing is ever answered on them.
    Held,
    /// It drops and refuses them.
    Cut,
}

/// A relay from a local address to one part.
#[derive(Debug, Clone)]
pub(crate) struct Relay {
    address: SocketAddr,
    line: Arc<watch::Sender<Line>>,
    held: Arc<AtomicUsize>,
}

impl Relay {
    /// A relay listening on loopback and carrying each connection to
    /// `target`, until `shutdown` stops.
    ///
    /// # Errors
    ///
    /// When no loopback port can be taken.
    pub(crate) async fn open(target: SocketAddr, shutdown: &Shutdown) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (line, _) = watch::channel(Line::Up);
        let line = Arc::new(line);
        let held = Arc::new(AtomicUsize::new(0));
        let switch = Switch {
            line: Arc::clone(&line),
            held: Arc::clone(&held),
        };
        shutdown.spawn_until_stopped(accepting(listener, target, switch, shutdown.clone()));
        Ok(Self {
            address,
            line,
            held,
        })
    }

    /// Where the platform connects instead of to the part.
    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    /// Drops every connection the relay carries and refuses new ones.
    pub(crate) fn cut(&self) {
        self.line.send_replace(Line::Cut);
    }

    /// Carries connections again.
    pub(crate) fn mend(&self) {
        self.line.send_replace(Line::Up);
    }

    /// Drops the connections the relay carries, and from now on takes new
    /// ones and answers nothing on them, until it is cut or mended.
    pub(crate) fn hold(&self) {
        self.line.send_replace(Line::Held);
    }

    /// How many connections the relay holds unanswered now.
    pub(crate) fn held(&self) -> usize {
        self.held.load(Ordering::SeqCst)
    }
}

/// The line a relay's connections follow, and its count of the ones it
/// holds unanswered.
struct Switch {
    line: Arc<watch::Sender<Line>>,
    held: Arc<AtomicUsize>,
}

/// Takes connections for as long as the stack runs, carrying each while
/// the line is up, keeping it open unanswered while it is held, and
/// closing it at once while it is cut.
async fn accepting(listener: TcpListener, target: SocketAddr, switch: Switch, tasks: Shutdown) {
    let permits = Arc::new(Semaphore::new(256));
    loop {
        let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
            return;
        };
        let Ok((client, _)) = listener.accept().await else {
            continue;
        };
        let now = *switch.line.borrow();
        let receiver = switch.line.subscribe();
        match now {
            Line::Cut => drop(client),
            Line::Held => {
                let held = Arc::clone(&switch.held);
                tasks.spawn_until_stopped(async move {
                    hold_unanswered(client, receiver, held).await;
                    drop(permit);
                });
            }
            Line::Up => {
                tasks.spawn_until_stopped(async move {
                    relay(client, target, receiver).await;
                    drop(permit);
                });
            }
        }
    }
}

/// Keeps `client` open and answers nothing on it until the line is no
/// longer held, counting it in `held` meanwhile, then closes it.
async fn hold_unanswered(
    client: TcpStream,
    mut line: watch::Receiver<Line>,
    held: Arc<AtomicUsize>,
) {
    held.fetch_add(1, Ordering::SeqCst);
    while *line.borrow_and_update() == Line::Held {
        if line.changed().await.is_err() {
            break;
        }
    }
    held.fetch_sub(1, Ordering::SeqCst);
    drop(client);
}

/// Carries `client` to `target` until either end closes or the line is
/// cut or held.
async fn relay(mut client: TcpStream, target: SocketAddr, mut line: watch::Receiver<Line>) {
    let Ok(mut part) = TcpStream::connect(target).await else {
        return;
    };
    tokio::select! {
        _ = copy_bidirectional(&mut client, &mut part) => {}
        () = cut_off(&mut line) => {}
    }
}

/// Returns once the line is cut or held.
async fn cut_off(line: &mut watch::Receiver<Line>) {
    while *line.borrow_and_update() == Line::Up {
        if line.changed().await.is_err() {
            return;
        }
    }
}
