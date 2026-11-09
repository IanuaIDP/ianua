//! The four kinds of company database, each started with Acme's orders and
//! a login made for workflows, serving TLS or not.

use crate::systems::{
    CompanySystem, Container, ContainerSpec, LOGIN_PASSWORD, Serving, SystemCertificate,
};

/// The workflow login's user name in every system.
const LOGIN_USER: &str = "workflows";

/// The database owner's password inside each container: words, not a key.
const OWNER_PASSWORD: &str = "acme-owner";

/// A Postgres holding table `orders` in database `postgres`, its login
/// allowed to read and delete there.
///
/// # Panics
///
/// When the container does not start, which needs docker on the path.
pub async fn postgres(serving: Serving) -> CompanySystem {
    let certificate = certificate_for(serving);
    let tls_start = "install -o postgres -m 600 /certs/server.key /tmp/server.key \
        && install -o postgres -m 644 /certs/server.crt /tmp/server.crt \
        && exec docker-entrypoint.sh postgres -c ssl=on \
        -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key";
    let (entrypoint, args): (Option<&str>, &[&str]) = match serving {
        Serving::Plain => (None, &[]),
        Serving::Tls(_) => (Some("sh"), &["-c", tls_start]),
    };
    let container = Container::run(&ContainerSpec {
        image: "postgres:16-alpine",
        port: 5432,
        env: &[("POSTGRES_PASSWORD", OWNER_PASSWORD)],
        entrypoint,
        args,
        certificates: certificate.as_ref().map(SystemCertificate::folder),
        volumes: &[],
        platform: None,
    });
    seed_postgres(&container).await;
    running(container, certificate)
}

/// Creates the workflow login and orders in the started PostgreSQL server.
async fn seed_postgres(container: &Container) {
    let seed = format!(
        "CREATE ROLE {LOGIN_USER} LOGIN PASSWORD '{LOGIN_PASSWORD}';
         CREATE TABLE orders (id integer PRIMARY KEY, total integer NOT NULL);
         INSERT INTO orders VALUES (1, 40), (2, 120), (3, 300);
         GRANT SELECT, DELETE ON orders TO {LOGIN_USER};"
    );
    container
        .exec_until_done(&[
            "psql",
            "-U",
            "postgres",
            "-1",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            &seed,
        ])
        .await;
}

/// A MySQL holding table `orders` in database `acme`, its login allowed to
/// read and delete there, refusing connections without TLS when serving
/// it.
///
/// # Panics
///
/// When the container does not start, which needs docker on the path.
pub async fn mysql(serving: Serving) -> CompanySystem {
    let certificate = certificate_for(serving);
    let args: &[&str] = match serving {
        Serving::Plain => &[],
        Serving::Tls(_) => &[
            "--ssl-ca=/certs/ca.pem",
            "--ssl-cert=/certs/server.crt",
            "--ssl-key=/certs/server.key",
            "--require-secure-transport=ON",
        ],
    };
    let container = Container::run(&ContainerSpec {
        image: "mysql:8.4",
        port: 3306,
        env: &[
            ("MYSQL_ROOT_PASSWORD", OWNER_PASSWORD),
            ("MYSQL_DATABASE", "acme"),
        ],
        entrypoint: None,
        args,
        certificates: certificate.as_ref().map(SystemCertificate::folder),
        volumes: &[],
        platform: None,
    });
    seed_mysql(&container).await;
    running(container, certificate)
}

/// Creates the workflow login and orders in the started MySQL server.
async fn seed_mysql(container: &Container) {
    let seed = format!(
        "CREATE USER '{LOGIN_USER}'@'%' IDENTIFIED BY '{LOGIN_PASSWORD}';
         CREATE TABLE acme.orders (id INT PRIMARY KEY, total INT NOT NULL);
         INSERT INTO acme.orders VALUES (1, 40), (2, 120), (3, 300);
         GRANT SELECT, DELETE ON acme.* TO '{LOGIN_USER}'@'%';"
    );
    let owner = format!("-p{OWNER_PASSWORD}");
    container
        .exec_until_done(&["mysql", "-uroot", &owner, "--protocol=TCP", "-e", &seed])
        .await;
}

/// A Redis (Valkey) holding keys `order:1` to `order:3`, each its total,
/// its login allowed every command, speaking only TLS when serving it.
///
/// # Panics
///
/// When the container does not start, which needs docker on the path.
pub async fn redis(serving: Serving) -> CompanySystem {
    let certificate = certificate_for(serving);
    let container = Container::run(&ContainerSpec {
        image: "valkey/valkey:8-alpine",
        port: 6379,
        env: &[],
        entrypoint: None,
        args: redis_arguments(serving),
        certificates: certificate.as_ref().map(SystemCertificate::folder),
        volumes: &[],
        platform: None,
    });
    seed_redis(&container, serving).await;
    running(container, certificate)
}

/// Selects a plain listener or a TLS-only listener using the mounted certificate files.
fn redis_arguments(serving: Serving) -> &'static [&'static str] {
    match serving {
        Serving::Plain => &["valkey-server"],
        Serving::Tls(_) => &[
            "valkey-server",
            "--port",
            "0",
            "--tls-port",
            "6379",
            "--tls-cert-file",
            "/certs/server.crt",
            "--tls-key-file",
            "/certs/server.key",
            "--tls-ca-cert-file",
            "/certs/ca.pem",
            "--tls-auth-clients",
            "no",
        ],
    }
}

/// Creates the workflow login and order keys through the server's chosen transport.
async fn seed_redis(container: &Container, serving: Serving) {
    let cli: &[&str] = match serving {
        Serving::Plain => &["valkey-cli"],
        Serving::Tls(_) => &["valkey-cli", "--tls", "--insecure"],
    };
    let password = format!(">{LOGIN_PASSWORD}");
    let commands: [&[&str]; 4] = [
        &["ACL", "SETUSER", LOGIN_USER, "on", &password, "~*", "+@all"],
        &["SET", "order:1", "40"],
        &["SET", "order:2", "120"],
        &["SET", "order:3", "300"],
    ];
    for command in commands {
        let full: Vec<&str> = cli.iter().chain(command).copied().collect();
        container.exec_until_done(&full).await;
    }
}

/// A MongoDB holding collection `orders` in database `acme`, its login kept
/// in `admin` and allowed to read and write `acme`, offering TLS when
/// serving it.
///
/// # Panics
///
/// When the container does not start, which needs docker on the path.
pub async fn mongodb(serving: Serving) -> CompanySystem {
    let certificate = certificate_for(serving);
    let args: &[&str] = match serving {
        Serving::Plain => &[],
        Serving::Tls(_) => &[
            "--tlsMode",
            "preferTLS",
            "--tlsCertificateKeyFile",
            "/certs/combined.pem",
            "--tlsCAFile",
            "/certs/ca.pem",
            "--tlsAllowConnectionsWithoutCertificates",
        ],
    };
    let container = Container::run(&ContainerSpec {
        image: "mongo:7",
        port: 27017,
        env: &[
            ("MONGO_INITDB_ROOT_USERNAME", "owner"),
            ("MONGO_INITDB_ROOT_PASSWORD", OWNER_PASSWORD),
        ],
        entrypoint: None,
        args,
        certificates: certificate.as_ref().map(SystemCertificate::folder),
        volumes: &[],
        platform: None,
    });
    seed_mongodb(&container).await;
    running(container, certificate)
}

/// Creates the workflow login and orders in the started MongoDB server.
async fn seed_mongodb(container: &Container) {
    let seed = format!(
        "db.getSiblingDB('admin').createUser({{user: '{LOGIN_USER}', pwd: '{LOGIN_PASSWORD}', \
         roles: [{{role: 'readWrite', db: 'acme'}}]}}); \
         db.getSiblingDB('acme').orders.insertMany([{{_id: 1, total: 40}}, \
         {{_id: 2, total: 120}}, {{_id: 3, total: 300}}]);"
    );
    container
        .exec_until_done(&[
            "mongosh",
            "--quiet",
            "-u",
            "owner",
            "-p",
            OWNER_PASSWORD,
            "--authenticationDatabase",
            "admin",
            "--eval",
            &seed,
        ])
        .await;
}

/// The certificate `serving` asks for, if any.
fn certificate_for(serving: Serving) -> Option<SystemCertificate> {
    match serving {
        Serving::Plain => None,
        Serving::Tls(name) => Some(SystemCertificate::for_name(name)),
    }
}

/// The system `container` runs, serving `certificate`.
fn running(container: Container, certificate: Option<SystemCertificate>) -> CompanySystem {
    CompanySystem {
        container,
        certificate,
        user: LOGIN_USER.to_owned(),
    }
}

/// A vector server speaking Qdrant's REST API, empty, answering once it is
/// ready.
///
/// # Panics
///
/// When the container does not start or never becomes ready.
pub async fn vector_server() -> Container {
    let container = Container::run(&ContainerSpec {
        image: "qdrant/qdrant:v1.13.6",
        port: 6333,
        env: &[],
        entrypoint: None,
        args: &[],
        certificates: None,
        volumes: &[],
        platform: None,
    });
    container.answer_until_ready("/readyz").await;
    container
}

/// Hugging Face's text-embeddings-inference serving `model` on CPU through
/// OpenAI's embeddings API, answering once the model is downloaded and
/// loaded. Its CPU image is built for `linux/amd64` alone, so it runs as
/// that, emulated on another machine.
///
/// # Panics
///
/// When the container does not start or never becomes ready.
pub async fn embedding_server(model: &str) -> Container {
    let container = Container::run(&ContainerSpec {
        image: "ghcr.io/huggingface/text-embeddings-inference:cpu-1.7",
        port: 80,
        env: &[("HF_HOME", "/data")],
        entrypoint: None,
        args: &["--model-id", model, "--port", "80"],
        certificates: None,
        volumes: &[("ianua-test-embedding-models", "/data")],
        platform: Some("linux/amd64"),
    });
    container.answer_until_ready("/health").await;
    container
}
