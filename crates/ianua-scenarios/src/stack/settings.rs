//! The settings a stack starts the platform with: its own database,
//! listeners, secrets and receivers, then the profile's.

use std::net::SocketAddr;
use std::path::Path;

use ianua_boot::env::Env;
use ianua_infra::crypto::{InternalListener, InternalPki, LinkValidity, issue_internal_pki};
use ianua_infra::test_support::{
    APP_ROLE, APP_ROLE_PASSWORD, AUDIT_PURGE_ROLE, AUDIT_PURGE_ROLE_PASSWORD, GATEWAY_ROLE,
    GATEWAY_ROLE_PASSWORD, TestDb,
};

use super::acme::Issuer;
use super::breaches::Breaches;
use super::profile::{MailSetup, Profile};
use super::{StackError, secrets};
use crate::sms::Texts;

/// The variable the cache setup script names the shared cache server's
/// port in.
const CACHE_PORT: &str = "IANUA_TEST_CACHE_PORT";

/// The variable the bus setup script names the shared bus server's port
/// in.
const BUS_PORT: &str = "IANUA_TEST_BUS_PORT";

/// The first of the ports a workflow listener is picked from. They lie below
/// the range the system hands out for port 0, so the port stays free between
/// this pick and the gateway's bind while other stacks open ports.
const FIRST_WORKFLOW_PORT: u16 = 20_000;

/// How many ports a workflow listener is picked from.
const WORKFLOW_PORTS: u16 = 10_000;

/// A free loopback port for the gateway's workflow listener, held open
/// until the gateway is about to bind it, each test process starting its
/// search at a place of its own.
fn workflow_listener() -> std::io::Result<std::net::TcpListener> {
    let start = std::process::id();
    (0..u32::from(WORKFLOW_PORTS))
        .map(|offset| start.wrapping_add(offset) % u32::from(WORKFLOW_PORTS))
        .filter_map(|port| u16::try_from(port).ok())
        .map(|port| FIRST_WORKFLOW_PORT.saturating_add(port))
        .find_map(|port| std::net::TcpListener::bind(("127.0.0.1", port)).ok())
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::AddrInUse))
}

/// The networks tenants' upstreams may be on: loopback, where the
/// scenarios' apps listen.
const LOOPBACK: &str = "127.0.0.0/8";

/// The gateway's own certificate for the API's relay listener and the
/// authority it trusts there, issued with the stack's internal links.
const RELAY_CALLER: [&str; 3] = [
    "API_INTERNAL_CA_FILE",
    "API_INTERNAL_CLIENT_CERT_FILE",
    "API_INTERNAL_CLIENT_KEY_FILE",
];

/// The settings the gateway reads with the same value as the control
/// plane, or the two disagree: on its tokens' issuer, its keys, the bus and
/// cache its changes travel on, and the names it serves.
const SHARED_WITH_THE_GATEWAY: [&str; 20] = [
    "PLATFORM_ADDRESSING",
    "PLATFORM_WILDCARD_TLS",
    "ACME_DIRECTORY_URL",
    "DNS_NAMESERVERS",
    "PROXY_PUBLIC_ADDRESS",
    "DEPLOYMENT",
    "APP_ENV",
    "APP_BASE_URL",
    "PROXY_BASE_DOMAIN",
    "UPSTREAM_NETWORKS",
    "HMAC_SECRET",
    "ENCRYPTION_KEY",
    "CACHE_URL",
    "BUS_URL",
    "NAMESPACE",
    "SHUTDOWN_GRACE_SECONDS",
    "WEBAUTHN_RP_ID",
    "WEBAUTHN_RP_ORIGIN",
    "JWKS_ROTATION_GRACE_SECONDS",
    "GEOIP_DB_PATH",
];

/// The domain tenants' apps sit under on a stack's `base_domain`.
pub(crate) fn apps_domain(base_domain: &str) -> String {
    format!("apps.{base_domain}")
}

/// Where the gateway beside a stack's platform finds what it needs.
pub(crate) struct GatewayPlace<'a> {
    /// The test database, reached as the gateway's role.
    pub(crate) database: &'a TestDb,
    /// The platform's certificate for the apps domain, as a PEM file.
    pub(crate) certificate: &'a Path,
    /// Its key, as a PEM file.
    pub(crate) key: &'a Path,
    /// The directory tenants' file references are read from.
    pub(crate) secrets: &'a Path,
    /// The API's relay listener.
    pub(crate) api_relay: SocketAddr,
}

/// What a stack runs beside the platform, for the settings that point the
/// platform at it.
pub(crate) struct Surroundings<'a> {
    /// The test database.
    pub(crate) database: &'a TestDb,
    /// Where the platform keeps files.
    pub(crate) files: &'a Path,
    /// The SMTP receiver.
    pub(crate) mailbox: SocketAddr,
    /// The Twilio stand-in.
    pub(crate) texts: &'a Texts,
    /// The password breach service's stand-in.
    pub(crate) breaches: &'a Breaches,
    /// The name server domain proofs ask.
    pub(crate) name_server: SocketAddr,
    /// The domain every name of the stack sits under.
    pub(crate) base_domain: &'a str,
    /// What the stack's names on the shared bus and cache servers sit
    /// under, so no other stack hears its events or counts its keys.
    pub(crate) namespace: &'a str,
}

/// The settings, in order: a later one of the same name wins.
pub(crate) struct Settings {
    pairs: Vec<(String, String)>,
    workflow_port: Option<std::net::TcpListener>,
}

impl Settings {
    /// Lets go of the workflow listener's port, held since it was picked so
    /// no other stack starting meanwhile can take it, just before the
    /// gateway binds it.
    pub(crate) fn release_workflow_port(&mut self) {
        self.workflow_port = None;
    }

    /// Whether this profile needs the real nested certificate and DNS path.
    pub(crate) fn nested_addresses(&self) -> bool {
        self.pairs
            .iter()
            .any(|(name, value)| name == "PLATFORM_ADDRESSING" && value == "nested")
    }

    /// Points the production worker at the local authority and bundled DNS,
    /// preserving the same certificate validation and lease rules as production.
    pub(crate) fn use_issuer(&mut self, issuer: &Issuer) {
        self.pairs
            .retain(|(name, _)| name != "TLS_TERMINATED_UPSTREAM");
        self.set("ACME_DIRECTORY_URL", &issuer.directory);
        self.set("DNS_RESOLVERS", &issuer.resolver.to_string());
        self.set("DNS_NAMESERVERS", "ns1.example.com");
        self.set("PROXY_PUBLIC_ADDRESS", "127.0.0.1");
        self.set("ACME_DNS_POLL_INTERVAL_SECONDS", "1");
        self.set("WORKER_SWEEP_TICK_SECONDS", "1");
        self.set("GATEWAY_RELOAD_SECONDS", "10");
    }

    /// The settings of a stack in `surroundings`, run as `profile` says.
    ///
    /// # Errors
    ///
    /// [`StackError::NoSharedServer`] when a setup script did not name a
    /// shared server's port.
    pub(crate) fn of(
        surroundings: &Surroundings<'_>,
        profile: &Profile,
    ) -> Result<Self, StackError> {
        let mut settings = Self {
            pairs: Vec::new(),
            workflow_port: None,
        };
        settings.deployment(surroundings.base_domain);
        settings.listeners();
        settings.jobs();
        settings.foundation(surroundings)?;
        settings.secrets();
        settings.mail(surroundings, profile.mail());
        settings.texts(surroundings.texts);
        settings.breaches(surroundings.breaches);
        settings.internal_links(surroundings.files)?;
        settings.set("DNS_RESOLVERS", &surroundings.name_server.to_string());
        for (name, value) in profile.settings() {
            settings.set(name, value);
        }
        for name in profile.dropped() {
            settings.pairs.retain(|(set, _)| set != name);
        }
        Ok(settings)
    }

    /// The environment these settings make.
    pub(crate) fn env(&self) -> Env {
        Env::of(
            self.pairs
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        )
    }

    /// The environment these settings make with `name` set to `value`
    /// too, for a one-off command that reads a setting serving refuses.
    pub(crate) fn env_with(&self, name: &str, value: &str) -> Env {
        self.env_including([(name, value)])
    }

    /// The environment with the command's additional settings, kept out
    /// of the environment used for serving.
    pub(crate) fn env_including<'a>(
        &'a self,
        additional: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Env {
        Env::of(
            self.pairs
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .chain(additional),
        )
    }

    /// Sets `name` to `value`, over any earlier value.
    pub(super) fn set(&mut self, name: &str, value: &str) {
        self.pairs.retain(|(set, _)| set != name);
        self.pairs.push((name.to_owned(), value.to_owned()));
    }

    /// The configured value, borrowed so relay setup can preserve credentials.
    pub(super) fn get(&self, name: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Who the deployment serves and where: the hosted service, in
    /// development so mail may go out unencrypted to the receiver, every
    /// name under the stack's own domain, tenants' apps under its `apps`
    /// label, and their upstreams on loopback, where the scenarios' apps
    /// listen.
    fn deployment(&mut self, base_domain: &str) {
        let app = format!("https://app.{base_domain}");
        self.set("APP_ENV", "development");
        self.set("MODE", "all");
        self.set("DEPLOYMENT", "cloud");
        self.set("APP_BASE_URL", &app);
        self.set("PROXY_BASE_DOMAIN", &apps_domain(base_domain));
        self.set("PLATFORM_ADDRESSING", "flat");
        self.set("PLATFORM_WILDCARD_TLS", "true");
        self.set("WEBAUTHN_RP_ID", base_domain);
        self.set("WEBAUTHN_RP_ORIGIN", &app);
        self.set("UPSTREAM_NETWORKS", LOOPBACK);
    }

    /// The gateway's settings beside these: the ones both roots read, with
    /// the same values, then its own login, listeners, certificate and the
    /// API's internal listener, and every `GATEWAY_*` setting the profile
    /// set. Nothing only the control plane holds is passed on.
    pub(crate) fn gateway(&self, place: &GatewayPlace<'_>) -> Self {
        let mut gateway = Self {
            pairs: Vec::new(),
            workflow_port: None,
        };
        for (name, value) in &self.pairs {
            if SHARED_WITH_THE_GATEWAY.contains(&name.as_str()) || name.starts_with("GATEWAY_") {
                gateway.set(name, value);
            }
        }
        gateway.set(
            "GATEWAY_DATABASE_URL",
            &place.database.address(GATEWAY_ROLE, GATEWAY_ROLE_PASSWORD),
        );
        if let Some(address) = self.get("GATEWAY_DATABASE_URL") {
            gateway.set("GATEWAY_DATABASE_URL", address);
        }
        gateway.set("GATEWAY_LISTEN", "127.0.0.1:0");
        gateway.set("GATEWAY_STATUS_LISTEN", "127.0.0.1:0");
        gateway.set("GATEWAY_TLS_CERT", &place.certificate.display().to_string());
        gateway.set("GATEWAY_TLS_KEY", &place.key.display().to_string());
        gateway.set("GATEWAY_SECRETS_DIR", &place.secrets.display().to_string());
        gateway.set("API_INTERNAL_URL", &format!("https://{}", place.api_relay));
        for name in RELAY_CALLER {
            if let Some(file) = self.get(name) {
                gateway.set(name, file);
            }
        }
        gateway
    }

    /// The internal links over mutual TLS, with certificates issued for
    /// this stack into `files`: the gateway's workflow listener on a
    /// loopback port picked and held now, with the worker's Protected apps steps
    /// pointed at it under the worker's certificate (the worker starts
    /// before the gateway, so the port cannot be the gateway's own pick),
    /// and the API's relay listener, which the gateway calls under its own.
    ///
    /// # Errors
    ///
    /// [`StackError::Io`] when no port can be picked or a file written.
    fn internal_links(&mut self, files: &Path) -> Result<(), StackError> {
        let io = |what: &'static str| move |cause| StackError::Io { what, cause };
        let held = workflow_listener().map_err(io("workflow listener port"))?;
        let picked = held.local_addr().map_err(io("workflow listener port"))?;
        self.workflow_port = Some(held);
        let pki = internal_pki()?;
        let folder = files.join("internal-pki");
        write_internal_pki(&pki, &folder).map_err(io("internal certificates"))?;
        self.link_files(&folder, picked);
        Ok(())
    }

    /// Points both internal listeners and their callers at the generated certificate files.
    fn link_files(&mut self, folder: &Path, picked: SocketAddr) {
        let at = |name: &str| folder.join(name).display().to_string();
        self.set("GATEWAY_WORKFLOW_LISTEN", &picked.to_string());
        self.set("GATEWAY_WORKFLOW_CA_FILE", &at("ca-cert.pem"));
        self.set(
            "GATEWAY_WORKFLOW_TLS_CERT_FILE",
            &at("workflow-listener-cert.pem"),
        );
        self.set(
            "GATEWAY_WORKFLOW_TLS_KEY_FILE",
            &at("workflow-listener-key.pem"),
        );
        self.set("GATEWAY_WORKFLOW_URL", &format!("https://{picked}"));
        self.set("GATEWAY_WORKFLOW_CLIENT_CERT_FILE", &at("worker-cert.pem"));
        self.set("GATEWAY_WORKFLOW_CLIENT_KEY_FILE", &at("worker-key.pem"));
        self.set("RELAY_CA_FILE", &at("ca-cert.pem"));
        self.set("RELAY_TLS_CERT_FILE", &at("relay-listener-cert.pem"));
        self.set("RELAY_TLS_KEY_FILE", &at("relay-listener-key.pem"));
        self.set("API_INTERNAL_CA_FILE", &at("ca-cert.pem"));
        self.set("API_INTERNAL_CLIENT_CERT_FILE", &at("gateway-cert.pem"));
        self.set("API_INTERNAL_CLIENT_KEY_FILE", &at("gateway-key.pem"));
    }

    /// The three listeners on loopback at ports the system picks, behind the
    /// stack's ingress, which ends TLS and is the one proxy believed.
    fn listeners(&mut self) {
        self.set("HOST", "127.0.0.1");
        self.set("PORT", "0");
        self.set("INTERNAL_PORT", "0");
        self.set("RELAY_PORT", "0");
        self.set("TRUSTED_PROXIES", "127.0.0.1/32");
        self.set("TLS_TERMINATED_UPSTREAM", "true");
        self.set("SHUTDOWN_GRACE_SECONDS", "5");
    }

    /// Wakes idle job lanes once a second, the shortest supported poll,
    /// so mailed links and tenant setup do not each wait the production
    /// default of two seconds. Jobs still use the real worker and store;
    /// a scenario profile may override this setting when testing polling.
    fn jobs(&mut self) {
        self.set("JOB_POLL_INTERVAL_SECONDS", "1");
    }

    /// The test database as the app's, the owner's and the audit purge's
    /// roles, the shared cache and bus servers under the stack's own
    /// namespace, and the files directory.
    fn foundation(&mut self, surroundings: &Surroundings<'_>) -> Result<(), StackError> {
        let database = surroundings.database;
        self.set(
            "DATABASE_URL",
            &database.address(APP_ROLE, APP_ROLE_PASSWORD),
        );
        self.set(
            "MIGRATION_DATABASE_URL",
            &database.address("postgres", "postgres"),
        );
        self.set(
            "AUDIT_PURGE_DATABASE_URL",
            &database.address(AUDIT_PURGE_ROLE, AUDIT_PURGE_ROLE_PASSWORD),
        );
        self.set(
            "CACHE_URL",
            &format!("redis://127.0.0.1:{}", port_of(CACHE_PORT)?),
        );
        self.set(
            "BUS_URL",
            &format!("nats://127.0.0.1:{}", port_of(BUS_PORT)?),
        );
        self.set("NAMESPACE", surroundings.namespace);
        self.set("FILES_DIR", &surroundings.files.display().to_string());
        Ok(())
    }

    /// The keys, made at random for this stack alone, and password hashing
    /// light enough for a test.
    fn secrets(&mut self) {
        self.set("HMAC_SECRET", &secrets::key());
        self.set("EVENT_SIGNING_SECRET", &secrets::key());
        self.set("ENCRYPTION_KEY", &secrets::key());
        self.set("ARGON2_MEMORY_KIB", "8192");
        self.set("ARGON2_ITERATIONS", "1");
        self.set("ARGON2_LANES", "1");
    }

    /// The platform's mail: over SMTP without TLS or a login into the
    /// receiver, or no mail server at all.
    fn mail(&mut self, surroundings: &Surroundings<'_>, setup: MailSetup) {
        self.set(
            "EMAIL_FROM",
            &format!("noreply@{}", surroundings.base_domain),
        );
        match setup {
            MailSetup::Receiver => {
                self.set("EMAIL_PROVIDER", "smtp");
                self.set("SMTP_HOST", &surroundings.mailbox.ip().to_string());
                self.set("SMTP_PORT", &surroundings.mailbox.port().to_string());
                self.set("SMTP_TLS", "none");
            }
            MailSetup::NotSetUp => self.set("EMAIL_PROVIDER", "none"),
        }
    }

    /// The Twilio account of the stand-in, texted through at its address.
    fn texts(&mut self, texts: &Texts) {
        let account = texts.account();
        self.set("TWILIO_ACCOUNT_SID", account.sid());
        self.set("TWILIO_AUTH_TOKEN", account.auth_token());
        self.set("TWILIO_FROM", account.sender());
        self.set("TWILIO_API_URL", &texts.api_url());
    }

    /// The password breach check, asked of the stand-in rather than the
    /// public service, so no scenario needs the internet.
    fn breaches(&mut self, breaches: &Breaches) {
        self.set("PASSWORD_BREACH_URL", &breaches.url());
    }
}

/// Issues the server and client identities used only by this stack's internal links.
fn internal_pki() -> Result<InternalPki, StackError> {
    let listeners = [
        InternalListener {
            name: "workflow-listener",
            host: "127.0.0.1",
        },
        InternalListener {
            name: "relay-listener",
            host: "127.0.0.1",
        },
    ];
    let clients = ["worker", "gateway"];
    issue_internal_pki(&listeners, &clients, LinkValidity::default()).map_err(|cause| {
        StackError::Io {
            what: "internal certificates",
            cause: std::io::Error::other(cause),
        }
    })
}

/// Writes the authority followed by each listener and caller's matching certificate and key.
fn write_internal_pki(pki: &InternalPki, folder: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(folder)?;
    std::fs::write(folder.join("ca-cert.pem"), &pki.authority.certificate_pem)?;
    for leaf in pki.servers.iter().chain(&pki.clients) {
        let keyed = &leaf.keyed;
        std::fs::write(
            folder.join(format!("{}-cert.pem", leaf.name)),
            &keyed.certificate_pem,
        )?;
        std::fs::write(
            folder.join(format!("{}-key.pem", leaf.name)),
            keyed.private_key_pem.expose(),
        )?;
    }
    Ok(())
}

/// The port a setup script wrote into `variable`.
fn port_of(variable: &'static str) -> Result<u16, StackError> {
    std::env::var(variable)
        .ok()
        .and_then(|port| port.parse().ok())
        .ok_or(StackError::NoSharedServer { variable })
}
