//! One MongoDB call over connections the platform opens: a client signed in
//! through the door with the stream route's login, the one operation, and
//! the client shut down with the call.

use std::sync::Arc;
use std::time::Duration;

use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::InputNeed;
use ianua_integration::answer::{failed, flow_of};
use ianua_integration::arguments::{argument, optional_flag, required_count, required_text};
use ianua_integration::data::{DoorKind, Through};
use mongodb::bson::Document;
use mongodb::options::{ClientOptions, Credential, ServerAddress, ServerMonitoringMode};
use mongodb::{Client, Collection, Cursor};
use serde_json::{Value, json};

use crate::MongoDbSettings;
use crate::documents::{document_list, documents_of, optional_document, required_document};

/// The database the login's user is kept in.
const AUTH_DATABASE: &str = "admin";

/// The name each connection tells the database, so its owner can tell a
/// workflow's sessions apart.
const APPLICATION_NAME: &str = "ianua-workflow";

/// The longest the client waits to reach the database and sign in.
const REACH_TIMEOUT: Duration = Duration::from_secs(10);

/// What a call does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Finds documents.
    Find,
    /// Runs a pipeline that only reads.
    Aggregate,
    /// Inserts documents.
    Insert,
    /// Updates the documents a filter matches.
    Update,
    /// Deletes the documents a filter matches.
    Delete,
}

impl Kind {
    /// Every operation, in the order the catalog lists them.
    pub(crate) const ALL: [Self; 5] = [
        Self::Find,
        Self::Aggregate,
        Self::Insert,
        Self::Update,
        Self::Delete,
    ];

    /// The operation `name` names, if any.
    pub(crate) fn of(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.name() == name)
    }

    /// The operation's name.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Find => "find",
            Self::Aggregate => "aggregate",
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }

    /// The inputs the operation takes beside the route, database and
    /// collection.
    pub(crate) fn own_inputs(self) -> &'static [(&'static str, InputNeed)] {
        match self {
            Self::Find => &[
                ("filter", InputNeed::Optional),
                ("projection", InputNeed::Optional),
                ("sort", InputNeed::Optional),
                ("limit", InputNeed::Optional),
            ],
            Self::Aggregate => &[
                ("pipeline", InputNeed::Required),
                ("limit", InputNeed::Optional),
            ],
            Self::Insert => &[("documents", InputNeed::Required)],
            Self::Update => &[
                ("filter", InputNeed::Required),
                ("update", InputNeed::Required),
                ("many", InputNeed::Optional),
            ],
            Self::Delete => &[
                ("filter", InputNeed::Required),
                ("many", InputNeed::Optional),
            ],
        }
    }
}

/// The stages an aggregate refuses: each writes what it reads elsewhere.
const WRITING_STAGES: &[&str] = &["$merge", "$out"];

/// How `kind`, with `arguments`, went over `through`, held to `settings`.
pub(crate) async fn run(
    kind: Kind,
    arguments: &FlowData,
    through: Through,
    settings: MongoDbSettings,
) -> ActionOutcome {
    let target = match Target::asked(arguments) {
        Ok(target) => target,
        Err(refused) => return refused,
    };
    let through = Arc::new(through);
    let Ok(door) = through.door(DoorKind::Protected).await else {
        return failed("the worker could not open its door to the database");
    };
    let Ok(client) = Client::with_options(options(&through, door.address().port())) else {
        return failed("the database's client could not be set up");
    };
    let collection = client
        .database(&target.database)
        .collection::<Document>(&target.collection);
    let outcome = Asked {
        arguments,
        collection: &collection,
        settings,
    }
    .run(kind)
    .await;
    client.shutdown().await;
    drop(door);
    outcome.map_or_else(|refused| refused, |output| succeeded(&output, settings))
}

/// The client's settings: the one server behind the door on `port`, the
/// route's login, few connections, and no monitoring connection of its own
/// past the one it needs.
fn options(through: &Through, port: u16) -> ClientOptions {
    let credential = Credential::builder()
        .username(through.login.user.clone())
        .password(through.login.password.expose().to_owned())
        .source(AUTH_DATABASE.to_owned())
        .build();
    ClientOptions::builder()
        .hosts(vec![ServerAddress::Tcp {
            host: "127.0.0.1".to_owned(),
            port: Some(port),
        }])
        .direct_connection(true)
        .credential(credential)
        .app_name(APPLICATION_NAME.to_owned())
        .max_pool_size(2)
        .min_pool_size(0)
        .server_monitoring_mode(ServerMonitoringMode::Poll)
        .connect_timeout(REACH_TIMEOUT)
        .server_selection_timeout(REACH_TIMEOUT)
        .build()
}

/// The database and collection a step names.
struct Target {
    database: String,
    collection: String,
}

impl Target {
    /// The target `arguments` name.
    fn asked(arguments: &FlowData) -> Result<Self, ActionOutcome> {
        Ok(Self {
            database: required_text(arguments, "database")?.to_owned(),
            collection: required_text(arguments, "collection")?.to_owned(),
        })
    }
}

/// One operation's arguments, its collection and limits.
struct Asked<'a> {
    arguments: &'a FlowData,
    collection: &'a Collection<Document>,
    settings: MongoDbSettings,
}

impl Asked<'_> {
    /// What `kind` gave, or why it was refused.
    async fn run(&self, kind: Kind) -> Result<Value, ActionOutcome> {
        match kind {
            Kind::Find => self.find().await,
            Kind::Aggregate => self.aggregate().await,
            Kind::Insert => self.insert().await,
            Kind::Update => self.update().await,
            Kind::Delete => self.delete().await,
        }
    }

    /// The documents a filter matches, at most the limit.
    async fn find(&self) -> Result<Value, ActionOutcome> {
        let limit = self.limit()?;
        let mut find = self
            .collection
            .find(optional_document(self.arguments, "filter")?.unwrap_or_default())
            .limit(i64::from(limit) + 1)
            .max_time(self.settings.operation_timeout);
        if let Some(projection) = optional_document(self.arguments, "projection")? {
            find = find.projection(projection);
        }
        if let Some(sort) = optional_document(self.arguments, "sort")? {
            find = find.sort(sort);
        }
        let cursor = find.await.map_err(|error| refused_by_database(&error))?;
        read(cursor, limit).await
    }

    /// What a pipeline that only reads gives, at most the limit.
    async fn aggregate(&self) -> Result<Value, ActionOutcome> {
        let limit = self.limit()?;
        let pipeline = document_list(self.arguments, "pipeline")?;
        ensure_reads_only(&pipeline)?;
        let cursor = self
            .collection
            .aggregate(pipeline)
            .max_time(self.settings.operation_timeout)
            .await
            .map_err(|error| refused_by_database(&error))?;
        read(cursor, limit).await
    }

    /// How many documents were inserted.
    async fn insert(&self) -> Result<Value, ActionOutcome> {
        let documents = document_list(self.arguments, "documents")?;
        let inserted = self
            .collection
            .insert_many(documents)
            .await
            .map_err(|error| refused_by_database(&error))?;
        Ok(json!({ "inserted_count": inserted.inserted_ids.len() }))
    }

    /// How many documents a filter matched and the update changed.
    async fn update(&self) -> Result<Value, ActionOutcome> {
        let filter = required_document(self.arguments, "filter")?;
        let update = required_document(self.arguments, "update")?;
        let updated = match self.many()? {
            Many::All => self.collection.update_many(filter, update).await,
            Many::One => self.collection.update_one(filter, update).await,
        }
        .map_err(|error| refused_by_database(&error))?;
        Ok(json!({
            "matched_count": updated.matched_count,
            "modified_count": updated.modified_count,
        }))
    }

    /// How many documents a filter matched and were deleted.
    async fn delete(&self) -> Result<Value, ActionOutcome> {
        let filter = required_document(self.arguments, "filter")?;
        let deleted = match self.many()? {
            Many::All => self.collection.delete_many(filter).await,
            Many::One => self.collection.delete_one(filter).await,
        }
        .map_err(|error| refused_by_database(&error))?;
        Ok(json!({ "deleted_count": deleted.deleted_count }))
    }

    /// The most documents a read hands back: the step's limit, held to the
    /// deployment's most, or that most when the step gives none.
    fn limit(&self) -> Result<u32, ActionOutcome> {
        let most = self.settings.most_documents;
        if argument(self.arguments, "limit").is_none() {
            return Ok(most);
        }
        let asked = required_count(self.arguments, "limit")?;
        Ok(u32::try_from(asked).unwrap_or(most).clamp(1, most))
    }

    /// Whether a change reaches every matching document or the first.
    fn many(&self) -> Result<Many, ActionOutcome> {
        match optional_flag(self.arguments, "many")? {
            Some(true) => Ok(Many::All),
            Some(false) | None => Ok(Many::One),
        }
    }
}

/// How many matching documents a change reaches.
#[derive(Debug, Clone, Copy)]
enum Many {
    /// Every one.
    All,
    /// The first.
    One,
}

/// The documents `cursor` gives, at most `limit`, read one at a time so no
/// more than one past it is ever taken.
async fn read(mut cursor: Cursor<Document>, limit: u32) -> Result<Value, ActionOutcome> {
    let most = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut read = Vec::new();
    let mut truncated = false;
    while cursor
        .advance()
        .await
        .map_err(|error| refused_by_database(&error))?
    {
        if read.len() == most {
            truncated = true;
            break;
        }
        let document = cursor
            .deserialize_current()
            .map_err(|_| failed("the database sent a document that does not read"))?;
        read.push(document);
    }
    Ok(json!({
        "document_count": read.len(),
        "truncated": truncated,
        "documents": documents_of(read),
    }))
}

/// Refuses a pipeline with a stage that writes.
fn ensure_reads_only(pipeline: &[Document]) -> Result<(), ActionOutcome> {
    let writing = pipeline
        .iter()
        .flat_map(Document::keys)
        .find(|stage| WRITING_STAGES.contains(&stage.as_str()));
    let Some(stage) = writing else {
        return Ok(());
    };
    Err(failed(&format!(
        "{stage} writes what the pipeline reads, so an aggregate does not run it"
    )))
}

/// The call's success, with `output` held as workflow data.
fn succeeded(output: &Value, settings: MongoDbSettings) -> ActionOutcome {
    match flow_of(output) {
        Ok(output) => ActionOutcome::Succeeded {
            output,
            exposure: settings.ceiling,
        },
        Err(_) => failed(
            "the documents are larger than workflow data may be, or hold a field name a workflow cannot",
        ),
    }
}

/// The failure of an operation the database refused, in its own words,
/// which name the operation's problem and never the login.
fn refused_by_database(error: &mongodb::error::Error) -> ActionOutcome {
    let words = match error.kind.as_ref() {
        mongodb::error::ErrorKind::Command(command) => command.message.clone(),
        mongodb::error::ErrorKind::Write(_) | mongodb::error::ErrorKind::InsertMany(_) => {
            "a document was refused".to_owned()
        }
        mongodb::error::ErrorKind::Authentication { .. } => {
            "the sign-in was refused".to_owned()
        }
        mongodb::error::ErrorKind::ServerSelection { .. } => {
            "the database could not be reached through the gateway, or its certificate is not the one its login asks for".to_owned()
        }
        _ => "the database could not run the operation".to_owned(),
    };
    failed(&format!("the database refused the operation: {words}"))
}

#[cfg(test)]
mod tests {
    use mongodb::bson::doc;

    use super::*;

    /// A pipeline that groups and sorts reads only.
    #[test]
    fn a_reading_pipeline_runs() {
        let pipeline = [
            doc! { "$match": { "status": "open" } },
            doc! { "$sort": { "at": -1 } },
        ];

        assert!(ensure_reads_only(&pipeline).is_ok());
    }

    /// An aggregate pipeline containing an `$out` stage fails the read-only check.
    #[test]
    fn a_writing_stage_is_refused() {
        let pipeline = [doc! { "$match": {} }, doc! { "$out": "stolen" }];

        assert!(ensure_reads_only(&pipeline).is_err());
    }

    /// Every operation reads back from its own name.
    #[test]
    fn every_operation_reads_back_from_its_name() {
        assert!(
            Kind::ALL
                .into_iter()
                .all(|kind| Kind::of(kind.name()) == Some(kind))
        );
    }
}
