//! Stack-local network failures, control-plane restarts and crashes, and
//! gateway restarts, with durable state kept.

use std::net::SocketAddr;
use std::time::Duration;

use ianua_boot::shutdown::Shutdown;
use ianua_infra::bus::ServerBus;
use ianua_infra::namespace::Namespace;
use ianua_infra::test_support::{APP_ROLE, GATEWAY_ROLE, GATEWAY_ROLE_PASSWORD, TestDb};
use url::Url;

use super::relay::{Part, Relay};
use super::settings::Settings;
use super::{STOP_GRACE, Stack, StackError, gateway, serving};

/// How long a scenario's redelivery waits on the bus for each step.
const DELIVERY_DEADLINE: Duration = Duration::from_secs(5);

/// The parts a crashed control plane loses every connection to at once.
const LOST_IN_A_CRASH: [Part; 4] = [Part::Database, Part::Cache, Part::Bus, Part::Mail];

/// Whether this scenario database permits the real audit adapter to append.
pub enum AuditWrites {
    /// Restore the app role's normal insert privilege.
    Allow,
    /// Refuse audit inserts while leaving resource mutations available.
    Refuse,
}

/// Stops a serving generation even if startup fails before a Stack owns it.
pub(super) struct Services(pub(super) Shutdown);

impl Drop for Services {
    /// Cancels listeners and workers when their owning generation is discarded.
    fn drop(&mut self) {
        self.0.stop();
    }
}

impl Stack {
    /// Changes this stack's shared database audit privileges, covering both
    /// platform and tenant records while leaving resource writes available.
    /// Dedicated tenant databases are outside this shared-database fault.
    ///
    /// # Panics
    ///
    /// When the test database owner cannot change the privilege.
    pub async fn audit_writes(&self, writes: AuditWrites) {
        let statement = match writes {
            AuditWrites::Allow => {
                format!("GRANT INSERT ON platform_audit_records, audit_records TO {APP_ROLE}")
            }
            AuditWrites::Refuse => {
                format!("REVOKE INSERT ON platform_audit_records, audit_records FROM {APP_ROLE}")
            }
        };
        self.database.tamper(&statement).await;
    }

    /// Changes whether the gateway may add to its inbox in the shared
    /// database: the only way its records of agents' actions reach the
    /// audit trail. Its request records and every other write stay open.
    ///
    /// # Panics
    ///
    /// When the test database owner cannot change the privilege.
    pub async fn gateway_event_writes(&self, writes: AuditWrites) {
        let statement = match writes {
            AuditWrites::Allow => format!("GRANT INSERT ON gateway_events TO {GATEWAY_ROLE}"),
            AuditWrites::Refuse => format!("REVOKE INSERT ON gateway_events FROM {GATEWAY_ROLE}"),
        };
        self.database.tamper(&statement).await;
    }

    /// Disconnects this stack's clients from one dependency without affecting
    /// other scenarios or stopping the shared infrastructure server.
    pub fn cut(&self, part: Part) {
        for (_, relay) in self.relays.iter().filter(|(kind, _)| *kind == part) {
            relay.cut();
        }
    }

    /// Restores new connections to a dependency cut by this stack.
    pub fn mend(&self, part: Part) {
        for (_, relay) in self.relays.iter().filter(|(kind, _)| *kind == part) {
            relay.mend();
        }
    }

    /// Drops this stack's connections to one dependency and from then on
    /// takes new ones and answers nothing on them, as a part that hangs
    /// looks, such as a mail server that never greets; [`mend`](Self::mend)
    /// or [`cut`](Self::cut) ends the hold.
    pub fn hold(&self, part: Part) {
        for (_, relay) in self.relays.iter().filter(|(kind, _)| *kind == part) {
            relay.hold();
        }
    }

    /// How many connections to `part` are held unanswered now: once one
    /// is, the platform is waiting on the part in the middle of its work.
    #[must_use]
    pub fn held(&self, part: Part) -> usize {
        self.relays
            .iter()
            .filter(|(kind, _)| *kind == part)
            .map(|(_, relay)| relay.held())
            .sum()
    }

    /// Hands every event of type `event_type` on this stack's bus out once
    /// more, its seal unchanged, as the bus does after a delivery it never
    /// heard acknowledged or past its duplicate window. Says how many.
    ///
    /// # Panics
    ///
    /// When the stack's bus cannot be reached: the scenario's step did not
    /// happen, and nothing it says afterwards would mean anything.
    #[allow(clippy::expect_used)]
    pub async fn deliver_again(&self, event_type: &str) -> usize {
        let url = self.settings.get("BUS_URL").expect("every stack has a bus");
        let namespace = self
            .settings
            .get("NAMESPACE")
            .expect("every stack has a namespace");
        let namespace = Namespace::new(namespace).expect("the stack's namespace reads");
        let bus = ServerBus::connect(url, &namespace, DELIVERY_DEADLINE)
            .await
            .expect("the stack's bus takes a connection");
        bus.deliver_again(event_type)
            .await
            .expect("the events go out again")
    }

    /// Ends the API and the worker as a killed process ends, then starts
    /// them again on their previous ports. Every connection they hold to
    /// the database, the cache, the bus and the mail receiver drops at
    /// once, so the database rolls back whatever was under way and nothing
    /// they were still doing reaches anything; only once all their tasks
    /// have ended are the parts mended. Jobs they had claimed stay held
    /// until their leases run out, as after a real crash.
    ///
    /// # Errors
    ///
    /// Returns the shutdown error when a task outlived the grace period,
    /// or the startup error when the services cannot start again.
    ///
    /// # Panics
    ///
    /// When the profile has no cuttable parts: without them a crash would
    /// be a clean stop, and the scenario would test something else.
    pub async fn crash(&self) -> Result<(), StackError> {
        assert!(
            self.profile.cuttable(),
            "a crash needs a profile with cuttable parts"
        );
        for part in LOST_IN_A_CRASH {
            self.cut(part);
        }
        let previous = self.service_shutdown.borrow().0.clone();
        previous.stop();
        let ended = previous.join().await;
        for part in LOST_IN_A_CRASH {
            self.mend(part);
        }
        ended?;
        let next = Services(Shutdown::new(STOP_GRACE));
        serving(&self.settings, &next.0).await?;
        *self.service_shutdown.borrow_mut() = next;
        Ok(())
    }

    /// Stops the gateway alone, as an operator stopping its process does:
    /// it stops taking connections, ends the requests in flight and lets go
    /// of its ports, while the control plane keeps running.
    ///
    /// # Errors
    ///
    /// Returns the shutdown error when its tasks outlived the grace period.
    pub async fn stop_gateway(&self) -> Result<(), StackError> {
        let running = self.gateway_shutdown.borrow().0.clone();
        running.stop();
        running.join().await?;
        Ok(())
    }

    /// Starts the gateway again after [`stop_gateway`](Self::stop_gateway),
    /// from the same settings, keys and certificate, on every port it
    /// first took, so clients reach it where they did.
    ///
    /// # Errors
    ///
    /// Returns the startup error when it cannot start, such as while the
    /// gateway before it still holds its ports.
    pub async fn start_gateway(&self) -> Result<(), StackError> {
        let next = Services(Shutdown::new(STOP_GRACE));
        gateway::serving(&self.gateway_settings, &next.0).await?;
        *self.gateway_shutdown.borrow_mut() = next;
        Ok(())
    }

    /// Restarts the API and worker on their previous ports, retaining the
    /// database, keys, gateway, receivers and ingress. Existing clients keep
    /// their addresses and credentials, as during a control-plane deployment.
    ///
    /// # Errors
    ///
    /// Returns the shutdown or startup error if either service cannot restart.
    pub async fn restart(&self) -> Result<(), StackError> {
        let previous = self.service_shutdown.borrow().0.clone();
        previous.stop();
        previous.join().await?;
        let next = Services(Shutdown::new(STOP_GRACE));
        serving(&self.settings, &next.0).await?;
        *self.service_shutdown.borrow_mut() = next;
        Ok(())
    }
}

/// Routes each database role and shared service through an independently
/// switchable local connection. URL credentials remain private in settings.
pub(super) async fn relays(
    settings: &mut Settings,
    database: &TestDb,
    shutdown: &Shutdown,
) -> Result<Vec<(Part, Relay)>, StackError> {
    settings.set(
        "GATEWAY_DATABASE_URL",
        &database.address(GATEWAY_ROLE, GATEWAY_ROLE_PASSWORD),
    );
    let mut relays = Vec::new();
    for (name, part) in [
        ("DATABASE_URL", Part::Database),
        ("MIGRATION_DATABASE_URL", Part::Database),
        ("AUDIT_PURGE_DATABASE_URL", Part::Database),
        ("GATEWAY_DATABASE_URL", Part::Database),
        ("CACHE_URL", Part::Cache),
        ("BUS_URL", Part::Bus),
    ] {
        if let Some(relay) = relay_url(settings, name, shutdown).await? {
            relays.push((part, relay));
        }
    }
    if let (Some(host), Some(port)) = (settings.get("SMTP_HOST"), settings.get("SMTP_PORT")) {
        let target = format!("{host}:{port}")
            .parse()
            .map_err(|_| invalid_address())?;
        let relay = open(target, shutdown).await?;
        settings.set("SMTP_HOST", "127.0.0.1");
        settings.set("SMTP_PORT", &relay.address().port().to_string());
        relays.push((Part::Mail, relay));
    }
    Ok(relays)
}

/// Rewrites one configured service URL to its relay while retaining URL credentials.
async fn relay_url(
    settings: &mut Settings,
    name: &str,
    shutdown: &Shutdown,
) -> Result<Option<Relay>, StackError> {
    let Some(value) = settings.get(name) else {
        return Ok(None);
    };
    let mut url = Url::parse(value).map_err(|_| invalid_address())?;
    let target = url
        .socket_addrs(|| None)
        .map_err(|_| invalid_address())?
        .into_iter()
        .next()
        .ok_or_else(invalid_address)?;
    let relay = open(target, shutdown).await?;
    url.set_host(Some("127.0.0.1"))
        .map_err(|_| invalid_address())?;
    url.set_port(Some(relay.address().port()))
        .map_err(|_| invalid_address())?;
    settings.set(name, url.as_str());
    Ok(Some(relay))
}

/// Opens a relay while preserving the operating system's failure cause.
async fn open(target: SocketAddr, shutdown: &Shutdown) -> Result<Relay, StackError> {
    Relay::open(target, shutdown)
        .await
        .map_err(|cause| StackError::Io {
            what: "dependency relay",
            cause,
        })
}

/// Reports malformed harness addresses without disclosing URL credentials.
fn invalid_address() -> StackError {
    StackError::Io {
        what: "dependency address",
        cause: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "a numeric loopback dependency address was required",
        ),
    }
}
