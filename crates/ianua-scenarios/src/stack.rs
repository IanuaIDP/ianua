//! The platform started for one test: the API and the worker through the
//! server's own composition root, over a database of the test's own, the
//! shared cache and bus servers, and a TLS ingress in front.
//!
//! Nextest runs each test in a process of its own, so each test starts its
//! own [`Stack`]. Everything about a stack is its own: its database, its
//! ports, its domain under `.test`, its namespace on the shared bus and
//! cache servers, its certificate authority, its keys, its mail and text
//! receivers, its stand-in of the password breach service and its first
//! operator. It stops when dropped, or with [`Stack::stop`] to wait until
//! every task has ended.

mod acme;
pub(crate) mod authority;
pub mod breaches;
pub mod cities;
mod directory;
pub mod dns;
pub(crate) mod gateway;
pub(crate) mod ingress;
mod installation;
pub(crate) mod process;
pub mod profile;
mod relay;
mod resilience;
pub(crate) mod secrets;
pub(crate) mod settings;

use std::cell::RefCell;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use authority::Authority;
pub use authority::Issued;
pub use breaches::BREACHED_PASSWORDS;
use breaches::Breaches;
use dns::NameServer;
use ianua_boot::shutdown::{Shutdown, ShutdownError};
use ianua_infra::test_support::TestDb;
use ianua_infra::test_support::clock::stepping::SteppedClock;
use ianua_server::command::{Command, CommandError};
use ianua_server::error::ServerError;
use ianua_server::serve;
use ianua_zero::serve::Serving as GatewayServing;
pub use installation::{Install, Installed};
pub use profile::{MailSetup, Profile};
pub use relay::Part;
use relay::Relay;
pub use resilience::AuditWrites;
use resilience::Services;
use settings::{Settings, Surroundings, apps_domain};
use tempfile::TempDir;
use tokio::runtime::{Handle, RuntimeFlavor};
use url::Url;

use crate::mail::Mailbox;
use crate::memory::{self, MemoryReading, MemoryReport};
use crate::sms::Texts;

/// How long a stop waits for the platform's tasks.
const STOP_GRACE: Duration = Duration::from_secs(10);

/// The most a stack may hold at once above what was held when it started,
/// in bytes. Set generously at first and lowered once the reports in
/// `target/scenario-memory/` show what the scenarios really take, so a
/// change that suddenly takes far more fails the run.
const MEMORY_BUDGET: usize = 1024 * 1024 * 1024;

/// The setting holding the first operator's password, which only the
/// operator command reads.
const OPERATOR_PASSWORD: &str = "OPERATOR_PASSWORD";

/// Why a stack could not start or stop cleanly.
#[derive(Debug, thiserror::Error)]
pub enum StackError {
    /// A setup script did not name a shared server's port: the test was
    /// not run by `cargo nextest` with the scenarios' setup scripts.
    #[error(
        "{variable} is not set; run the scenarios with cargo nextest, whose setup scripts start the shared servers"
    )]
    NoSharedServer {
        /// The variable that should name the port.
        variable: &'static str,
    },
    /// A receiver, the ingress or the files directory could not be set up.
    #[error("the stack's {what} could not be set up")]
    Io {
        /// What could not.
        what: &'static str,
        /// Why.
        #[source]
        cause: std::io::Error,
    },
    /// A certificate could not be made.
    #[error("the stack's certificates could not be made")]
    Certificate(#[from] rcgen::Error),
    /// TLS would not take the certificate.
    #[error("the ingress's TLS could not be set up")]
    Tls(#[from] tokio_rustls::rustls::Error),
    /// The first operator's command line was refused.
    #[error("the operator command was refused")]
    Command(#[from] CommandError),
    /// The platform refused its settings or could not start.
    #[error("the platform could not {what}")]
    Platform {
        /// What it could not do.
        what: &'static str,
        /// Why.
        #[source]
        cause: ServerError,
    },
    /// The platform started without its API, which `MODE=all` always runs.
    #[error("the platform started without its API")]
    NoApi,
    /// The gateway refused its settings or could not start.
    #[error("the gateway could not start")]
    Gateway(#[source] ianua_zero::error::GatewayError),
    /// The bundled nameserver could not serve the platform's DNS-01 proofs.
    #[error("the bundled nameserver could not start")]
    Nameserver(#[source] ianua_dns::error::NameserverError),
    /// The platform's tasks did not end within the grace period.
    #[error("the platform did not stop cleanly")]
    Stop(#[from] ShutdownError),
    /// The stack held more at once than its budget while it ran.
    #[error("the stack held {peak} bytes at once, over its budget of {budget}")]
    OverMemoryBudget {
        /// The most it held at once, above what was held when it started.
        peak: usize,
        /// Maximum additional live allocation permitted for one scenario stack.
        budget: usize,
    },
}

/// The platform's first operator, as the stack made them. `Debug` shows no
/// password.
#[derive(Clone)]
pub struct FirstOperator {
    email: String,
    password: String,
}

impl fmt::Debug for FirstOperator {
    /// Identifies the operator by email without exposing the setup password
    /// in scenario failures or diagnostic output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FirstOperator")
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

impl FirstOperator {
    /// The address they sign in with.
    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }

    /// Setup secret used to obtain the first operator's API credential.
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }
}

/// What a client of an internal listener presents in its handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presenting {
    /// No certificate, as a stranger on the network.
    Nothing,
    /// The worker's own certificate, issued by the stack's internal
    /// authority.
    WorkersCertificate,
    /// The gateway's own certificate, issued by the stack's internal
    /// authority.
    GatewaysCertificate,
}

impl Presenting {
    /// The settings naming the certificate and key presented, if any.
    fn files(self) -> Option<[&'static str; 2]> {
        match self {
            Self::Nothing => None,
            Self::WorkersCertificate => Some([
                "GATEWAY_WORKFLOW_CLIENT_CERT_FILE",
                "GATEWAY_WORKFLOW_CLIENT_KEY_FILE",
            ]),
            Self::GatewaysCertificate => Some([
                "API_INTERNAL_CLIENT_CERT_FILE",
                "API_INTERNAL_CLIENT_KEY_FILE",
            ]),
        }
    }
}

/// Where a company's own database is reached, as a stream route's backend.
#[derive(Debug, Clone)]
pub struct CompanyDatabase {
    /// The host its server listens on.
    pub host: String,
    /// Socket number reached through a stream route's database backend.
    pub port: u16,
    /// The database's name.
    pub name: String,
}

/// One running platform and everything around it.
pub struct Stack {
    shutdown: Shutdown,
    service_shutdown: RefCell<Services>,
    relays: Vec<(Part, Relay)>,
    profile: Profile,
    settings: Settings,
    base_domain: String,
    ingress: SocketAddr,
    internal: SocketAddr,
    relay: SocketAddr,
    directory: Option<SocketAddr>,
    gateway: GatewayServing,
    gateway_shutdown: RefCell<Services>,
    gateway_settings: Settings,
    root_pem: String,
    authority: Arc<Authority>,
    operator: FirstOperator,
    mailbox: Mailbox,
    texts: Texts,
    name_server: NameServer,
    memory_start: MemoryReading,
    _files: TempDir,
    database: TestDb,
    _clock: Option<SteppedClock>,
}

impl fmt::Debug for Stack {
    /// Identifies the running profile and ingress without formatting the
    /// stack's settings, credentials or signing material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stack")
            .field("profile", &self.profile.name())
            .field("base_domain", &self.base_domain)
            .field("ingress", &self.ingress)
            .finish_non_exhaustive()
    }
}

impl Stack {
    /// Starts the platform as `profile` says: a database cloned from the
    /// migrated template, the receivers, the first operator, the API and
    /// the worker on ports the system picks, and the ingress in front.
    ///
    /// The future holds the platform's settings, which are not shared
    /// between threads, so it is awaited where it is made, as a test's
    /// body does, and never spawned.
    ///
    /// # Errors
    ///
    /// [`StackError`] for the first part that could not start; whatever
    /// had started is stopped again.
    ///
    /// # Panics
    ///
    /// When the shared Postgres is not running, as the test database's
    /// own setup does.
    pub async fn start(profile: Profile) -> Result<Self, StackError> {
        process::set_up();
        memory::reset_peak();
        let memory_start = memory::reading();
        let clock = scenario_clock();
        let shutdown = Shutdown::new(STOP_GRACE);
        let started = Self::started(profile, &shutdown, memory_start, clock).await;
        if started.is_err() {
            shutdown.stop();
        }
        started
    }

    /// Starts every part under `shutdown`, counting its memory from
    /// `memory_start` and holding `clock` until the stack is dropped.
    async fn started(
        profile: Profile,
        shutdown: &Shutdown,
        memory_start: MemoryReading,
        clock: Option<SteppedClock>,
    ) -> Result<Self, StackError> {
        let prepared = StackSetup::new(shutdown).await?;
        let mut settings = prepared.settings(&profile, shutdown).await?;
        let relays = match profile.cuttable() {
            true => resilience::relays(&mut settings, &prepared.database, shutdown).await?,
            false => Vec::new(),
        };
        let running = prepared.serve(&mut settings, shutdown).await?;
        tracing::info!(
            profile = profile.name(),
            base_domain = %prepared.base_domain,
            ingress = %running.ingress,
            gateway = %running.gateway.serving.public,
            "the stack is up"
        );
        let runtime = StackRuntime {
            shutdown: shutdown.clone(),
            relays,
            profile,
            settings,
            memory_start,
            clock,
        };
        Ok(Self::assembled(prepared, running, runtime))
    }

    /// Transfers the prepared resources and started services into their final owner.
    fn assembled(prepared: StackSetup, running: RunningStack, runtime: StackRuntime) -> Self {
        Self {
            shutdown: runtime.shutdown,
            service_shutdown: RefCell::new(running.service_shutdown),
            relays: runtime.relays,
            profile: runtime.profile,
            settings: runtime.settings,
            base_domain: prepared.base_domain,
            ingress: running.ingress,
            internal: running.api.internal,
            relay: running.relay,
            directory: running.directory,
            gateway: running.gateway.serving,
            gateway_shutdown: RefCell::new(running.gateway_shutdown),
            gateway_settings: running.gateway.settings,
            root_pem: prepared.authority.root_pem(),
            authority: prepared.authority,
            operator: running.operator,
            mailbox: prepared.receivers.mailbox,
            texts: prepared.receivers.texts,
            name_server: prepared.receivers.name_server,
            memory_start: runtime.memory_start,
            _files: prepared.files,
            database: prepared.database,
            _clock: runtime.clock,
        }
    }

    /// Stops the platform and everything around it, waits for every task
    /// to end, and writes the test's [`MemoryReport`].
    ///
    /// # Errors
    ///
    /// - [`StackError::Stop`] when tasks were still running when the grace
    ///   period ended.
    /// - [`StackError::OverMemoryBudget`] when the stack held more at once
    ///   than [`MEMORY_BUDGET`] while it ran.
    pub async fn stop(self) -> Result<(), StackError> {
        let services = self.service_shutdown.borrow().0.clone();
        services.stop();
        let services_stopped = services.join().await;
        let gateway = self.gateway_shutdown.borrow().0.clone();
        gateway.stop();
        let gateway_stopped = gateway.join().await;
        self.shutdown.stop();
        let surroundings_stopped = self.shutdown.join().await;
        services_stopped?;
        gateway_stopped?;
        surroundings_stopped?;
        let report = MemoryReport::between(self.memory_start, memory::reading());
        tracing::info!(
            test = %report.test,
            peak_above_start = report.peak_above_start,
            held_after_stop = report.held_after_stop,
            allocations = report.allocations,
            "the stack's memory"
        );
        report.write();
        if report.peak_above_start > MEMORY_BUDGET {
            return Err(StackError::OverMemoryBudget {
                peak: report.peak_above_start,
                budget: MEMORY_BUDGET,
            });
        }
        Ok(())
    }

    /// The profile it runs.
    #[must_use]
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// The domain every name of the stack sits under, such as
    /// `s1a2b3c4d.test`.
    #[must_use]
    pub fn base_domain(&self) -> &str {
        &self.base_domain
    }

    /// `label` under the stack's domain, such as `app.s1a2b3c4d.test`.
    #[must_use]
    pub fn host(&self, label: &str) -> String {
        format!("{label}.{}", self.base_domain)
    }

    /// The dashboard's address, `APP_BASE_URL`, which the ingress sends to
    /// the API and which every mailed link starts with.
    ///
    /// # Panics
    ///
    /// Never: the domain is made here and reads as a URL.
    /// The fixed scheme and generated hexadecimal `.test` hostname form a valid URL.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn app_url(&self) -> Url {
        let address = format!("https://{}/", self.host("app"));
        Url::parse(&address).expect("the stack's own address reads as a URL")
    }

    /// Where the ingress listens; every name under the stack's domain
    /// resolves here.
    #[must_use]
    pub fn ingress(&self) -> SocketAddr {
        self.ingress
    }

    /// Runs `sql` as the test database's owner: for a scenario that sets up
    /// a company's own data, which the platform reaches only through a
    /// stream route, such as a table and a login for workflows.
    ///
    /// # Panics
    ///
    /// When the statement fails, which is a mistake in the scenario.
    pub async fn as_database_owner(&self, sql: &str) {
        self.database.tamper(sql).await;
    }

    /// Where the test database listens and its name, as a company's own
    /// database behind a stream route is reached.
    ///
    /// # Panics
    ///
    /// Never: the address is the test database's own, and reads.
    /// The test database constructs this address from its valid connection settings.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn company_database(&self) -> CompanyDatabase {
        let address = url::Url::parse(&self.database.address("postgres", "postgres"))
            .expect("the test database's address reads");
        CompanyDatabase {
            host: address.host_str().unwrap_or("127.0.0.1").to_owned(),
            port: address.port().unwrap_or(5432),
            name: address.path().trim_start_matches('/').to_owned(),
        }
    }

    /// The API's internal listener: the probes and the metrics. No ingress
    /// routes to it.
    #[must_use]
    pub fn internal_api(&self) -> SocketAddr {
        self.internal
    }

    /// The API's relay listener, which the gateway asks about app sign-ins
    /// and agents' approvals over mutual TLS. No ingress routes to it.
    #[must_use]
    pub fn api_relay(&self) -> SocketAddr {
        self.relay
    }

    /// Changes the audit records `filter` picks as `change` says, as
    /// whoever holds the database itself could, past every store, guard
    /// and row-level security, in every schema holding tenants' records:
    /// the insider a tamper-evident chain must give away, never a step a
    /// person through the API could take.
    ///
    /// # Panics
    ///
    /// When a statement fails, which is a mistake in the scenario.
    pub async fn tamper_with_audit_records(&self, change: &str, filter: &str) {
        let schemas: Vec<(String,)> = self
            .database
            .read_back(
                "SELECT table_schema::text FROM information_schema.tables \
                 WHERE table_name = 'audit_records'",
            )
            .await;
        for (schema,) in schemas {
            self.database
                .tamper(&format!(
                    "SET session_replication_role = replica; \
                     UPDATE {schema}.audit_records SET {change} WHERE {filter}; \
                     SET session_replication_role = origin;"
                ))
                .await;
        }
    }

    /// The name the LDAP directory's certificate is issued for, which a
    /// client checks it against.
    #[must_use]
    pub fn ldap_name(&self) -> String {
        directory::server_name(&self.base_domain)
    }

    /// Where the LDAP directory listens on loopback, over TLS, when the
    /// profile asked for it with [`Profile::with_directory`].
    ///
    /// # Panics
    ///
    /// When the profile did not ask for the directory.
    /// Requiring a directory here asserts the calling scenario's setup contract.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn ldap(&self) -> SocketAddr {
        self.directory
            .expect("the profile asks for the LDAP directory")
    }

    /// The domain tenants' apps sit under, such as `apps.s1a2b3c4d.test`:
    /// a tenant's platform host is one label under it.
    #[must_use]
    pub fn apps_domain(&self) -> String {
        apps_domain(&self.base_domain)
    }

    /// The domain the stack's customers' own domains sit under, such as
    /// `s1a2b3c4d.example`: a tenant registers names under it as its own,
    /// proves them through the stack's name server, and uploads the
    /// certificate the stack's authority issues for them.
    #[must_use]
    pub fn customer_domain(&self) -> String {
        customer_domain(&self.base_domain)
    }

    /// Where the gateway's public listener is: every tenant's app host, on
    /// the apps domain or the customer domain, resolves here.
    #[must_use]
    pub fn gateway(&self) -> SocketAddr {
        self.gateway.public
    }

    /// Where the gateway's workflow listener is, which the worker's
    /// Protected apps steps call: only inside the deployment, never behind
    /// the ingress.
    ///
    /// # Panics
    ///
    /// When the stack started without one, which its settings always set.
    /// This accessor asserts that the scenario's required workflow listener started.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn gateway_workflows(&self) -> SocketAddr {
        self.gateway
            .workflows
            .expect("every stack opens the gateway's workflow listener")
    }

    /// A client of an internal listener, the gateway's workflow listener at
    /// [`gateway_workflows`](Self::gateway_workflows) or the API's relay at
    /// [`api_relay`](Self::api_relay), trusting the stack's internal
    /// authority and presenting what `presenting` says.
    ///
    /// # Panics
    ///
    /// When the stack's internal certificates cannot be read or the client
    /// cannot be built.
    /// These failures invalidate the scenario's internal TLS setup before its requests run.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn internal_client(&self, presenting: Presenting) -> reqwest::Client {
        let read = |name: &str| {
            let path = self
                .settings
                .get(name)
                .expect("every stack issues internal certificates");
            std::fs::read(path).expect("the stack's internal certificates read")
        };
        let authority = reqwest::Certificate::from_pem(&read("GATEWAY_WORKFLOW_CA_FILE"))
            .expect("the internal authority reads");
        let builder = reqwest::Client::builder()
            .tls_built_in_root_certs(false)
            .add_root_certificate(authority);
        let Some([certificate, key]) = presenting.files() else {
            return builder.build().expect("the client builds");
        };
        let mut pem = read(certificate);
        pem.push(b'\n');
        pem.extend(read(key));
        builder
            .identity(reqwest::Identity::from_pem(&pem).expect("the presented identity"))
            .build()
            .expect("the client builds")
    }

    /// Where the gateway's status listener is: `/health/live`,
    /// `/health/ready` and `/metrics`. No client is routed to it.
    #[must_use]
    pub fn gateway_status(&self) -> SocketAddr {
        self.gateway.status
    }

    /// A certificate the stack's authority issued for exactly `names`, as a
    /// certificate authority issues a customer one for their own domain.
    ///
    /// # Panics
    ///
    /// When it cannot be made.
    /// Certificate issuance is a prerequisite of the calling scenario's TLS fixture.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn certificate_for(&self, names: &[String]) -> Issued {
        self.authority
            .issue(names)
            .expect("the stack's authority issues a certificate")
    }

    /// The certificate of the stack's authority, the only one its clients
    /// trust.
    #[must_use]
    pub fn root_certificate_pem(&self) -> &str {
        &self.root_pem
    }

    /// The platform's first operator.
    #[must_use]
    pub fn operator(&self) -> &FirstOperator {
        &self.operator
    }

    /// The receiver of the platform's mail.
    #[must_use]
    pub fn mailbox(&self) -> &Mailbox {
        &self.mailbox
    }

    /// The receiver of the platform's texts.
    #[must_use]
    pub fn texts(&self) -> &Texts {
        &self.texts
    }

    /// The public DNS as the platform reads it, where a customer writes
    /// the records that prove a domain is theirs.
    #[must_use]
    pub fn name_server(&self) -> &NameServer {
        &self.name_server
    }
}

impl Drop for Stack {
    /// Asks every task to stop. Nothing is waited for here: a test that
    /// wants the stop finished calls [`Stack::stop`].
    fn drop(&mut self) {
        self.service_shutdown.borrow().0.stop();
        self.gateway_shutdown.borrow().0.stop();
        self.shutdown.stop();
    }
}

/// The clock a scenario's platform runs on: a stepped one, so an
/// authenticator app reaches its next code at once instead of waiting up
/// to a whole time step, unless the scenario installed a clock of its own
/// first. A runtime whose tasks move between threads keeps the wall clock,
/// since a stepped clock holds only on the thread that installed it.
fn scenario_clock() -> Option<SteppedClock> {
    let flavor = Handle::try_current().ok()?.runtime_flavor();
    match flavor {
        RuntimeFlavor::CurrentThread => SteppedClock::unless_installed(),
        _ => None,
    }
}

/// The domain a stack on `base_domain` lets customers bring names under:
/// its own label under `.example`, which no real name can ever be.
fn customer_domain(base_domain: &str) -> String {
    let label = base_domain.split('.').next().unwrap_or(base_domain);
    format!("{label}.example")
}

/// Makes the platform's first operator through the operator command, as
/// `ianua operator create --email <address>` does, the password in
/// `OPERATOR_PASSWORD`.
async fn first_operator(
    settings: &Settings,
    base_domain: &str,
) -> Result<FirstOperator, StackError> {
    let operator = FirstOperator {
        email: format!("operator@{base_domain}"),
        password: secrets::password(),
    };
    let words = ["operator", "create", "--email", operator.email.as_str()];
    let command = Command::parse(words.map(str::to_owned))?;
    let vars = settings.env_with(OPERATOR_PASSWORD, &operator.password);
    serve::perform(&command, &vars)
        .await
        .map_err(|cause| StackError::Platform {
            what: "make its first operator",
            cause,
        })?;
    Ok(operator)
}

/// Starts the API and the worker under `shutdown`, answering the API's
/// addresses.
async fn serving(settings: &Settings, shutdown: &Shutdown) -> Result<Started, StackError> {
    let vars = settings.env();
    let serving = serve::serving(&vars, shutdown)
        .await
        .map_err(|cause| StackError::Platform {
            what: "start serving",
            cause,
        })?;
    Ok(Started {
        api: serving.api.ok_or(StackError::NoApi)?,
        directory: serving.directory,
    })
}

/// Where the started API and, when its profile asks, its LDAP directory
/// listen.
struct Started {
    api: ianua_server::api::ApiAddresses,
    directory: Option<SocketAddr>,
}

/// Surrounding services needed before platform configuration is assembled.
struct Receivers {
    mailbox: Mailbox,
    texts: Texts,
    breaches: Breaches,
    name_server: NameServer,
}

impl Receivers {
    /// Opens receivers in the same order their failures are reported during stack setup.
    async fn open(shutdown: &Shutdown) -> Result<Self, StackError> {
        let mailbox = Mailbox::open(shutdown)
            .await
            .map_err(setup_error("mailbox"))?;
        let texts = Texts::open(shutdown)
            .await
            .map_err(setup_error("Twilio stand-in"))?;
        let breaches = Breaches::open(shutdown)
            .await
            .map_err(setup_error("breach service stand-in"))?;
        let name_server = NameServer::open(shutdown)
            .await
            .map_err(setup_error("name server"))?;
        Ok(Self {
            mailbox,
            texts,
            breaches,
            name_server,
        })
    }
}

/// Reports a setup operation without losing its underlying I/O failure.
fn setup_error(what: &'static str) -> impl FnOnce(std::io::Error) -> StackError {
    move |cause| StackError::Io { what, cause }
}

/// Resources prepared before starting the API, worker and gateway.
struct StackSetup {
    database: TestDb,
    files: TempDir,
    receivers: Receivers,
    namespace: String,
    base_domain: String,
    authority: Arc<Authority>,
}

impl StackSetup {
    /// Creates the isolated database and files, opens receivers, then issues the stack authority.
    async fn new(shutdown: &Shutdown) -> Result<Self, StackError> {
        let database = TestDb::fresh().await;
        let files = TempDir::new().map_err(setup_error("files directory"))?;
        let receivers = Receivers::open(shutdown).await?;
        let namespace = format!("s{}", secrets::hex(4));
        let base_domain = format!("{namespace}.test");
        let authority = Arc::new(Authority::for_domain(&base_domain)?);
        Ok(Self {
            database,
            files,
            receivers,
            namespace,
            base_domain,
            authority,
        })
    }

    /// Configures the prepared services and any directory or nested-address certificate authority.
    async fn settings(
        &self,
        profile: &Profile,
        shutdown: &Shutdown,
    ) -> Result<Settings, StackError> {
        let surroundings = Surroundings {
            database: &self.database,
            files: self.files.path(),
            mailbox: self.receivers.mailbox.address(),
            texts: &self.receivers.texts,
            breaches: &self.receivers.breaches,
            name_server: self.receivers.name_server.address(),
            base_domain: &self.base_domain,
            namespace: &self.namespace,
        };
        let mut settings = Settings::of(&surroundings, profile)?;
        if settings.get("LDAP_BIND_ADDR").is_some() {
            directory::configure_tls(
                &mut settings,
                &self.authority,
                self.files.path(),
                &self.base_domain,
            )?;
        }
        if profile.places_callers() {
            cities::configure(&mut settings, self.files.path())?;
        }
        if settings.nested_addresses() {
            let issuer = acme::open(&self.database, self.authority.clone(), shutdown).await?;
            settings.use_issuer(&issuer);
        }
        Ok(settings)
    }

    /// Creates the operator, starts the API and worker, then opens the ingress and gateway.
    async fn serve(
        &self,
        settings: &mut Settings,
        shutdown: &Shutdown,
    ) -> Result<RunningStack, StackError> {
        let operator = first_operator(settings, &self.base_domain).await?;
        let service_shutdown = Services(Shutdown::new(STOP_GRACE));
        let Started { api, directory } = serving(settings, &service_shutdown.0).await?;
        let relay = record_listeners(settings, &api, directory)?;
        let ingress = ingress::open(self.authority.server(), api.public, shutdown)
            .await
            .map_err(setup_error("ingress"))?;
        let gateway_shutdown = Services(Shutdown::new(STOP_GRACE));
        settings.release_workflow_port();
        let gateway = self.gateway(settings, relay, &gateway_shutdown.0).await?;
        Ok(RunningStack {
            operator,
            service_shutdown,
            api,
            directory,
            relay,
            ingress,
            gateway,
            gateway_shutdown,
        })
    }

    /// Starts the gateway beside the already serving control plane and its
    /// relay listener, under a shutdown of its own so it can be restarted
    /// alone.
    async fn gateway(
        &self,
        settings: &Settings,
        relay: SocketAddr,
        shutdown: &Shutdown,
    ) -> Result<gateway::Started, StackError> {
        gateway::started(
            settings,
            &gateway::Beside {
                database: &self.database,
                files: self.files.path(),
                authority: &self.authority,
                apps_domain: &apps_domain(&self.base_domain),
                api_relay: relay,
            },
            shutdown,
        )
        .await
    }
}

/// Saves the chosen ports for control-plane restarts and returns the required relay address.
fn record_listeners(
    settings: &mut Settings,
    api: &ianua_server::api::ApiAddresses,
    directory: Option<SocketAddr>,
) -> Result<SocketAddr, StackError> {
    settings.set("PORT", &api.public.port().to_string());
    settings.set("INTERNAL_PORT", &api.internal.port().to_string());
    let relay = api.relay.ok_or(StackError::NoApi)?;
    settings.set("RELAY_PORT", &relay.port().to_string());
    if let Some(directory) = directory {
        settings.set("LDAP_BIND_ADDR", &directory.to_string());
    }
    Ok(relay)
}

/// Started service generation and the addresses retained by the running stack.
struct RunningStack {
    operator: FirstOperator,
    service_shutdown: Services,
    api: ianua_server::api::ApiAddresses,
    directory: Option<SocketAddr>,
    relay: SocketAddr,
    ingress: SocketAddr,
    gateway: gateway::Started,
    gateway_shutdown: Services,
}

/// Configuration and shutdown ownership transferred after every listener has started.
struct StackRuntime {
    shutdown: Shutdown,
    relays: Vec<(Part, Relay)>,
    profile: Profile,
    settings: Settings,
    memory_start: MemoryReading,
    clock: Option<SteppedClock>,
}
