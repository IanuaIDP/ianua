//! Protected data's integrations, each a crate of its own under
//! `integrations/` behind a feature of the same name, reaching companies'
//! own databases over connections the worker opens at the gateway's
//! workflow listener.

use std::sync::Arc;

use ianua_integration::Integration;

use crate::config::Config;
use crate::error::PlatformError;

/// The Protected data integrations this build includes, or none while
/// `GATEWAY_WORKFLOW_URL` is unset.
///
/// # Errors
///
/// [`PlatformError`] when an integration cannot be built.
pub(super) fn protected_data(config: &Config) -> Result<Vec<Arc<dyn Integration>>, PlatformError> {
    if config.gateway_link.is_none() {
        return Ok(Vec::new());
    }
    Ok(vec![
        #[cfg(feature = "postgres")]
        postgres(config)?,
        #[cfg(feature = "mysql")]
        mysql(config)?,
        #[cfg(feature = "redis")]
        redis(config)?,
        #[cfg(feature = "mongodb")]
        mongodb(config)?,
    ])
}

/// The Postgres steps, each statement held to the workflow request timeout
/// inside the database, reading at most
/// [`ianua_integration_postgres::MOST_ROWS`] rows.
///
/// # Errors
///
/// [`PlatformError`] when the integration cannot be built.
#[cfg(feature = "postgres")]
fn postgres(config: &Config) -> Result<Arc<dyn Integration>, PlatformError> {
    use ianua_integration_postgres::{MOST_ROWS, Postgres, PostgresSettings};

    let requests = &config.http.workflow_requests;
    let postgres = Postgres::new(PostgresSettings {
        statement_timeout: requests.timeout,
        most_rows: MOST_ROWS,
        ceiling: requests.ceiling,
    })
    .map_err(PlatformError::of("the Postgres step"))?;
    Ok(Arc::new(postgres))
}

/// The MySQL steps, each read held to the workflow request timeout inside
/// the database, reading at most [`ianua_integration_mysql::MOST_ROWS`]
/// rows.
///
/// # Errors
///
/// [`PlatformError`] when the integration cannot be built.
#[cfg(feature = "mysql")]
fn mysql(config: &Config) -> Result<Arc<dyn Integration>, PlatformError> {
    use ianua_integration_mysql::{MOST_ROWS, MySql, MySqlSettings};

    let requests = &config.http.workflow_requests;
    let mysql = MySql::new(MySqlSettings {
        statement_timeout: requests.timeout,
        most_rows: MOST_ROWS,
        ceiling: requests.ceiling,
    })
    .map_err(PlatformError::of("the MySQL step"))?;
    Ok(Arc::new(mysql))
}

/// The Redis steps, each command's answer awaited at most the workflow
/// request timeout.
///
/// # Errors
///
/// [`PlatformError`] when the integration cannot be built.
#[cfg(feature = "redis")]
fn redis(config: &Config) -> Result<Arc<dyn Integration>, PlatformError> {
    use ianua_integration_redis::{Redis, RedisSettings};

    let requests = &config.http.workflow_requests;
    let redis = Redis::new(RedisSettings {
        command_timeout: requests.timeout,
        ceiling: requests.ceiling,
    })
    .map_err(PlatformError::of("the Redis step"))?;
    Ok(Arc::new(redis))
}

/// The MongoDB steps, each read held to the workflow request timeout
/// inside the database, returning at most
/// [`ianua_integration_mongodb::MOST_DOCUMENTS`] documents.
///
/// # Errors
///
/// [`PlatformError`] when the integration cannot be built.
#[cfg(feature = "mongodb")]
fn mongodb(config: &Config) -> Result<Arc<dyn Integration>, PlatformError> {
    use ianua_integration_mongodb::{MOST_DOCUMENTS, MongoDb, MongoDbSettings};

    let requests = &config.http.workflow_requests;
    let mongodb = MongoDb::new(MongoDbSettings {
        operation_timeout: requests.timeout,
        most_documents: MOST_DOCUMENTS,
        ceiling: requests.ceiling,
    })
    .map_err(PlatformError::of("the MongoDB step"))?;
    Ok(Arc::new(mongodb))
}
