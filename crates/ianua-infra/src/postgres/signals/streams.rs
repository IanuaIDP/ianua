//! A tenant's signal streams, with the subjects each lists and every
//! signal sent to it, each table under row-level security.
//!
//! A stream's endpoint challenge is kept in its row until the endpoint
//! echoes it, and never handed back by a read: the stream says only that
//! it waits. The receiver's `Authorization` header is kept as the sealer
//! handed it over. A save writes the stream and puts exactly its subjects
//! on it in one call. A read of streams reads their subjects in one more
//! query, and a list first reads the ids of its page, then those rows by
//! id.

mod deliveries;
mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::signals::{
    SignalStreamStore, StreamChallenge, StreamDeliverySortField, StreamSortField,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::signals::delivery::SignalDeliveryAttempt;
use ianua_domain::domains::signals::stream::{SignalStream, StreamStatus};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{SignalStreamId, TenantId};
use sqlx::PgConnection;
use uuid::Uuid;

use self::deliveries::{DeliveryColumns, DeliveryRecord};
use self::record::{Listed, StreamColumns, StreamRecord, SubjectColumns, SubjectRecord};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;

/// Whether a save wrote the stream, or found it waiting on its endpoint
/// with no challenge to wait on and wrote nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Saved {
    /// The stream and its subjects are written.
    Written,
    /// Nothing is written: the stream waits on a challenge nobody sent.
    WithoutChallenge,
}

/// The Postgres signal stream store.
pub struct PgSignalStreamStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgSignalStreamStore {}

impl PgSignalStreamStore {
    /// A store keeping signal streams in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Writes `columns` for `tenant` and puts exactly `subjects` on the
    /// stream, or writes nothing when the stream waits on no challenge.
    async fn write(
        &self,
        tenant: &ScopedTenant,
        columns: &StreamColumns<'_>,
        subjects: &SubjectColumns,
    ) -> Result<Saved, DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                if write_stream(&mut *connection, tenant, columns).await? == 0 {
                    return Ok(Saved::WithoutChallenge);
                }
                list_subjects(connection, tenant, columns.id, subjects).await?;
                Ok(Saved::Written)
            },
        )
        .await
    }

    /// The streams of `tenant` with the ids `ids`, in no order.
    async fn streams_of(
        &self,
        tenant: &ScopedTenant,
        ids: &[Uuid],
    ) -> Result<Vec<SignalStream<ResolvedTenant>>, DomainError> {
        let (records, subjects) = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| records_of(connection, tenant, ids).await,
        )
        .await?;
        assembled(records, subjects)
    }
}

/// Writes the stream `columns` describe, answering how many rows it wrote.
async fn write_stream(
    connection: &mut PgConnection,
    tenant: &TenantId,
    columns: &StreamColumns<'_>,
) -> Result<u64, sqlx::Error> {
    let written = sqlx::query_file!(
        "queries/signal_streams/save.sql",
        columns.id,
        tenant.as_uuid(),
        columns.endpoint,
        columns.verification,
        columns.issued_challenge,
        columns.delivery_method,
        columns.authorization_sealed,
        columns.receiver_key_hash,
        &columns.signal_types,
        columns.default_subjects,
        columns.status,
        columns.consecutive_failures,
        columns.created_at,
        columns.updated_at,
    )
    .execute(connection)
    .await?;
    Ok(written.rows_affected())
}

/// Puts exactly `subjects` on the stream `stream_id`, in order.
async fn list_subjects(
    connection: &mut PgConnection,
    tenant: &TenantId,
    stream_id: &Uuid,
    subjects: &SubjectColumns,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/signal_stream_subjects/withdraw.sql",
        tenant.as_uuid(),
        stream_id
    )
    .execute(&mut *connection)
    .await?;
    sqlx::query_file!(
        "queries/signal_stream_subjects/list.sql",
        tenant.as_uuid(),
        stream_id,
        &subjects.users as &[Option<Uuid>],
        &subjects.agents as &[Option<Uuid>],
    )
    .execute(connection)
    .await?;
    Ok(())
}

/// The records of the streams of `tenant` that `ids` names, in no order,
/// and the subjects they list.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &TenantId,
    ids: &[Uuid],
) -> Result<(Vec<StreamRecord>, Vec<SubjectRecord>), sqlx::Error> {
    let records = sqlx::query_file_as!(
        StreamRecord,
        "queries/signal_streams/by_ids.sql",
        tenant.as_uuid(),
        ids
    )
    .fetch_all(&mut *connection)
    .await?;
    let subjects = subjects_of(connection, tenant, ids).await?;
    Ok((records, subjects))
}

/// The subjects the streams of `tenant` that `ids` names list.
async fn subjects_of(
    connection: &mut PgConnection,
    tenant: &TenantId,
    ids: &[Uuid],
) -> Result<Vec<SubjectRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        SubjectRecord,
        "queries/signal_stream_subjects/of_streams.sql",
        tenant.as_uuid(),
        ids
    )
    .fetch_all(connection)
    .await
}

/// The streams `records` hold, each listing its own of `subjects`, in the
/// order of `records`.
fn assembled(
    records: Vec<StreamRecord>,
    subjects: Vec<SubjectRecord>,
) -> Result<Vec<SignalStream<ResolvedTenant>>, DomainError> {
    let mut listed = Listed::of(subjects);
    records
        .into_iter()
        .map(|record| {
            let own = listed.take(&record.id);
            record.into_stream(own)
        })
        .collect()
}

/// The challenge `challenge` says to write for `stream`: the one just
/// issued, or none, which keeps the stored one.
///
/// # Errors
///
/// Returns `DomainError::Validation` when the challenge was issued for
/// another endpoint than the stream's.
fn issued_for<'a>(
    stream: &SignalStream<ResolvedTenant>,
    challenge: StreamChallenge<'a>,
) -> Result<Option<&'a str>, DomainError> {
    let StreamChallenge::Issued(issued) = challenge else {
        return Ok(None);
    };
    if issued.endpoint() != stream.endpoint() {
        return Err(DomainError::invalid(message!(
            "infra-the-challenge-was-issued-for-another",
            "the challenge was issued for another endpoint"
        )));
    }
    Ok(Some(issued.challenge().as_str()))
}

impl SortColumns for StreamSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::Status => "status",
            Self::Endpoint => "endpoint",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

impl SortColumns for StreamDeliverySortField {
    fn column(self) -> &'static str {
        match self {
            Self::AttemptedAt => "attempted_at",
            Self::Status => "status",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl SignalStreamStore for PgSignalStreamStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SignalStreamId,
    ) -> Result<Option<SignalStream<ResolvedTenant>>, DomainError> {
        let streams = self.streams_of(tenant_id, &[*id.as_uuid()]).await?;
        Ok(streams.into_iter().next())
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<StreamStatus>,
        sort: &SortOrder<StreamSortField>,
        page: &PageRequest,
    ) -> Result<Page<SignalStream<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(sort)?;
        let of_tenant =
            PageQuery::ids("id", "signal_streams").filter("tenant_id = ?", *tenant_id.as_uuid());
        let listed = match status {
            Some(status) => of_tenant.filter("status = ?", status.word()),
            None => of_tenant,
        };
        let (records, subjects) = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let (records, subjects) = records_of(connection, tenant_id, &ids).await?;
                Ok((in_page_order(&ids, records, |record| record.id), subjects))
            },
        )
        .await?;
        Ok(keyset.seal(assembled(records, subjects)?))
    }

    async fn list_active(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<SignalStream<ResolvedTenant>>, DomainError> {
        let (records, subjects) = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let records = sqlx::query_file_as!(
                    StreamRecord,
                    "queries/signal_streams/active.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(&mut *connection)
                .await?;
                let ids: Vec<Uuid> = records.iter().map(|record| record.id).collect();
                let subjects = subjects_of(connection, tenant_id, &ids).await?;
                Ok((records, subjects))
            },
        )
        .await?;
        assembled(records, subjects)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        stream: &SignalStream<ResolvedTenant>,
        challenge: StreamChallenge<'_>,
    ) -> Result<(), DomainError> {
        let issued = issued_for(stream, challenge)?;
        let columns = StreamColumns::of(stream, issued);
        let subjects = SubjectColumns::of(stream);
        match self.write(tenant_id, &columns, &subjects).await? {
            Saved::Written => Ok(()),
            Saved::WithoutChallenge => Err(DomainError::invalid(message!(
                "infra-a-stream-waiting-on-its-endpoint",
                "a stream waiting on its endpoint is saved with no challenge issued or kept for it"
            ))),
        }
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &SignalStreamId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/signal_streams/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn list_deliveries(
        &self,
        tenant_id: &ScopedTenant,
        stream_id: &SignalStreamId,
        sort: &SortOrder<StreamDeliverySortField>,
        page: &PageRequest,
    ) -> Result<Page<SignalDeliveryAttempt>, DomainError> {
        let keyset = page.keyset(sort)?;
        let listed = PageQuery::ids("id", "signal_deliveries")
            .filter("tenant_id = ?", *tenant_id.as_uuid())
            .filter("stream_id = ?", *stream_id.as_uuid());
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = sqlx::query_file_as!(
                    DeliveryRecord,
                    "queries/signal_deliveries/by_ids.sql",
                    tenant_id.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        let attempts = records
            .into_iter()
            .map(DeliveryRecord::into_attempt)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(keyset.seal(attempts))
    }

    async fn record_delivery(
        &self,
        tenant_id: &ScopedTenant,
        attempt: &SignalDeliveryAttempt,
    ) -> Result<(), DomainError> {
        let columns = DeliveryColumns::of(attempt);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/signal_deliveries/record.sql",
                    tenant_id.as_uuid(),
                    columns.stream_id,
                    columns.id,
                    columns.signal_id,
                    columns.signal_type,
                    columns.status,
                    columns.response_code,
                    columns.duration_ms,
                    columns.attempt_number,
                    columns.attempted_at,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_domain::domains::authorization::permission::{SignalsAction, SystemPermission};
    use ianua_domain::domains::signals::delivery::{ReceiverAuthorization, SignalDelivery};
    use ianua_domain::domains::signals::signal::{SecuritySignalType, SignalSubject};
    use ianua_domain::domains::signals::stream::{
        ChallengeToSend, DeliveryMethod, EndpointVerification, RegisterStreamParams,
        SignalStreamRow, StreamVerificationStatus,
    };
    use ianua_domain::domains::signals::subjects::{DefaultSubjects, StreamSubjects};
    use ianua_domain::test_support::authority::anyone_holding;
    use ianua_domain::types::{PublicHttpsUrl, TokenHash, UserId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::branding::sealed;
    use crate::test_support::rows::messaging::an_agent;
    use crate::test_support::rows::oauth::a_person;
    use crate::test_support::rows::signals::{challenge, delivery_row, stream_row, taken};

    struct Fixture {
        db: TestDb,
        store: PgSignalStreamStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it, and one tenant to keep streams
    /// for.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgSignalStreamStore::new(Arc::clone(&db.databases)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            db,
        }
    }

    fn stream(row: SignalStreamRow) -> SignalStream<ResolvedTenant> {
        SignalStream::reconstitute(row).unwrap()
    }

    fn at_endpoint(endpoint: &str) -> SignalStream<ResolvedTenant> {
        stream(stream_row(endpoint))
    }

    /// A poll stream registered at `endpoint` by someone who may change
    /// streams, with the challenge handed out for its endpoint.
    fn registered(endpoint: &str) -> (SignalStream<ResolvedTenant>, ChallengeToSend) {
        let fay = anyone_holding(&[SystemPermission::Signals(SignalsAction::Update)]);
        SignalStream::register(
            RegisterStreamParams {
                id: SignalStreamId::new(),
                endpoint: PublicHttpsUrl::new(endpoint).unwrap(),
                challenge: challenge("sent"),
                delivery_method: DeliveryMethod::Poll,
                authorization: ReceiverAuthorization::Header(sealed("bearer-token")),
                receiver_key: TokenHash::from_stored("hash:key".to_owned()),
                signal_types: vec![
                    SecuritySignalType::SessionRevoked,
                    SecuritySignalType::AccountLocked,
                ],
                default_subjects: DefaultSubjects::None,
            },
            fay,
        )
        .unwrap()
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn endpoints(page: &Page<SignalStream<ResolvedTenant>>) -> Vec<&str> {
        page.items
            .iter()
            .map(|stream| stream.endpoint().as_str())
            .collect()
    }

    impl Fixture {
        async fn save_all(&self, streams: &[&SignalStream<ResolvedTenant>]) {
            for stream in streams {
                self.store
                    .save(&self.tenant, stream, StreamChallenge::Kept)
                    .await
                    .unwrap();
            }
        }

        async fn found(&self, id: &SignalStreamId) -> Option<SignalStream<ResolvedTenant>> {
            self.store.find_by_id(&self.tenant, id).await.unwrap()
        }

        /// Reads this tenant's stream page with the requested status filter.
        async fn page(
            &self,
            status: Option<StreamStatus>,
            order: &SortOrder<StreamSortField>,
            page: &PageRequest,
        ) -> Page<SignalStream<ResolvedTenant>> {
            self.store
                .list_all(&self.tenant, status, order, page)
                .await
                .unwrap()
        }

        /// Reads one stream's delivery history under its owning fixture tenant.
        async fn deliveries(
            &self,
            stream: &SignalStreamId,
            order: &SortOrder<StreamDeliverySortField>,
            page: &PageRequest,
        ) -> Page<SignalDeliveryAttempt> {
            self.store
                .list_deliveries(&self.tenant, stream, order, page)
                .await
                .unwrap()
        }
    }

    /// A newly registered poll stream, with a header for its pushes, two
    /// signal types and the one user and one agent it hears about, is
    /// found by its id as it was saved, still waiting on its endpoint.
    #[tokio::test]
    async fn a_registered_stream_is_found_waiting_on_its_endpoint() {
        let fx = fixture().await;
        let ann = a_person(&fx.db, &fx.tenant, "ann@acme.example").await;
        let agent = an_agent(&fx.db, &fx.tenant).await;
        let (registered, sent) = registered("https://app.acme.com/sse");
        let listing = stream(SignalStreamRow {
            id: *registered.id(),
            endpoint: registered.endpoint().clone(),
            verification: EndpointVerification::Pending(sent.challenge().clone()),
            delivery_method: registered.delivery_method(),
            authorization: registered.authorization().clone(),
            receiver_key: registered.receiver_key().clone(),
            signal_types: registered.signal_types().to_vec(),
            subjects: StreamSubjects::Only(vec![
                SignalSubject::Agent(agent),
                SignalSubject::User(ann),
            ]),
            ..stream_row("https://app.acme.com/sse")
        });

        fx.store
            .save(&fx.tenant, &listing, StreamChallenge::Issued(&sent))
            .await
            .unwrap();

        let found = fx.found(listing.id()).await.unwrap();
        assert_eq!(found.verification(), StreamVerificationStatus::Pending);
        assert_eq!(found.delivery_method(), DeliveryMethod::Poll);
        assert_eq!(found.authorization(), listing.authorization());
        assert_eq!(found.receiver_key(), listing.receiver_key());
        assert_eq!(found.signal_types(), listing.signal_types());
        assert_eq!(found.subjects(), listing.subjects());
        assert_eq!(found.created_at(), listing.created_at());
    }

    /// The stream waits on the challenge it was sent across saves that
    /// issue none, and once its endpoint echoes it, the stream reads back
    /// verified.
    #[tokio::test]
    async fn the_challenge_is_kept_until_the_endpoint_echoes_it() {
        let fx = fixture().await;
        let (registered, sent) = registered("https://app.acme.com/sse");
        fx.store
            .save(&fx.tenant, &registered, StreamChallenge::Issued(&sent))
            .await
            .unwrap();
        let read = fx.found(registered.id()).await.unwrap();
        fx.save_all(&[&read]).await;

        let mut waiting = fx.found(registered.id()).await.unwrap();
        waiting.confirm_endpoint(sent.challenge()).unwrap();
        fx.save_all(&[&waiting]).await;

        let found = fx.found(registered.id()).await.unwrap();
        assert_eq!(found.verification(), StreamVerificationStatus::Verified);
    }

    /// Saving a pending stream without an issued or stored challenge
    /// returns a validation error and leaves no stream to read.
    #[tokio::test]
    async fn a_waiting_stream_with_no_challenge_is_refused() {
        let fx = fixture().await;
        let waiting = stream(SignalStreamRow {
            verification: EndpointVerification::Pending(challenge("never-sent")),
            ..stream_row("https://app.acme.com/sse")
        });

        let saved = fx
            .store
            .save(&fx.tenant, &waiting, StreamChallenge::Kept)
            .await;

        assert!(matches!(saved, Err(DomainError::Validation(_))));
        assert!(fx.found(waiting.id()).await.is_none());
    }

    /// Moving a pending stream while retaining its old challenge returns
    /// a validation error and preserves the original endpoint.
    #[tokio::test]
    async fn a_challenge_kept_for_another_endpoint_is_refused() {
        let fx = fixture().await;
        let (registered, sent) = registered("https://app.acme.com/sse");
        fx.store
            .save(&fx.tenant, &registered, StreamChallenge::Issued(&sent))
            .await
            .unwrap();
        let moved = stream(SignalStreamRow {
            id: *registered.id(),
            endpoint: PublicHttpsUrl::new("https://evil.example.com/sse").unwrap(),
            verification: EndpointVerification::Pending(sent.challenge().clone()),
            ..stream_row("https://app.acme.com/sse")
        });

        let saved = fx
            .store
            .save(&fx.tenant, &moved, StreamChallenge::Kept)
            .await;

        assert!(matches!(saved, Err(DomainError::Validation(_))));
        assert_eq!(
            fx.found(registered.id()).await.unwrap().endpoint(),
            registered.endpoint()
        );
    }

    /// Saving a stream with a challenge issued for another endpoint
    /// returns a validation error and leaves no stream to read.
    #[tokio::test]
    async fn a_challenge_issued_for_another_endpoint_is_refused() {
        let fx = fixture().await;
        let (_, sent) = registered("https://app.acme.com/sse");
        let elsewhere = at_endpoint("https://other.acme.com/sse");

        let saved = fx
            .store
            .save(&fx.tenant, &elsewhere, StreamChallenge::Issued(&sent))
            .await;

        assert!(matches!(saved, Err(DomainError::Validation(_))));
        assert!(fx.found(elsewhere.id()).await.is_none());
    }

    /// An id nobody has finds nothing, and another tenant does not find
    /// this tenant's stream.
    #[tokio::test]
    async fn a_stream_is_found_only_by_its_tenant() {
        let fx = fixture().await;
        let verified = at_endpoint("https://app.acme.com/sse");
        fx.save_all(&[&verified]).await;
        let other = ScopedTenant::for_background(TenantId::new());

        assert!(fx.found(&SignalStreamId::new()).await.is_none());
        assert!(
            fx.store
                .find_by_id(&other, verified.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The tenant's streams list by endpoint page by page, each page after
    /// the last, and the paused ones alone when asked for.
    #[tokio::test]
    async fn streams_are_listed_page_by_page_and_by_status() {
        let fx = fixture().await;
        let paused = stream(SignalStreamRow {
            status: StreamStatus::Paused,
            ..stream_row("https://b.acme.com/sse")
        });
        fx.save_all(&[
            &at_endpoint("https://c.acme.com/sse"),
            &paused,
            &at_endpoint("https://a.acme.com/sse"),
        ])
        .await;
        let by_endpoint = SortOrder::single(Sort::ascending(StreamSortField::Endpoint));
        let by_status = SortOrder::single(Sort::ascending(StreamSortField::Status));

        let page_one = fx.page(None, &by_endpoint, &first(2)).await;
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = fx.page(None, &by_endpoint, &after).await;
        let only_paused = fx
            .page(Some(StreamStatus::Paused), &by_status, &first(10))
            .await;

        assert_eq!(
            endpoints(&page_one),
            ["https://a.acme.com/sse", "https://b.acme.com/sse"]
        );
        assert_eq!(endpoints(&page_two), ["https://c.acme.com/sse"]);
        assert!(!page_two.has_next());
        assert_eq!(endpoints(&only_paused), ["https://b.acme.com/sse"]);
    }

    /// A signal fans out to every active stream of the tenant, and to no
    /// paused or disabled one.
    #[tokio::test]
    async fn only_the_active_streams_are_listed_for_a_signal() {
        let fx = fixture().await;
        let active = at_endpoint("https://a.acme.com/sse");
        let disabled = stream(SignalStreamRow {
            status: StreamStatus::Disabled,
            ..stream_row("https://b.acme.com/sse")
        });
        fx.save_all(&[&active, &disabled]).await;

        let listed = fx.store.list_active(&fx.tenant).await.unwrap();

        let ids: Vec<_> = listed.iter().map(|stream| *stream.id()).collect();
        assert_eq!(ids, [*active.id()]);
    }

    /// The signals sent to a stream list newest first, page by page, a
    /// held one among them reading back as held.
    #[tokio::test]
    async fn a_streams_deliveries_are_listed_page_by_page() {
        let fx = fixture().await;
        let verified = at_endpoint("https://app.acme.com/sse");
        fx.save_all(&[&verified]).await;
        let (old, held, new) = (
            delivery_row(*verified.id(), 1, taken()),
            delivery_row(*verified.id(), 2, SignalDelivery::Queued),
            delivery_row(*verified.id(), 3, taken()),
        );
        for attempt in [&old, &held, &new] {
            fx.store.record_delivery(&fx.tenant, attempt).await.unwrap();
        }
        let order = SortOrder::single(Sort::descending(StreamDeliverySortField::AttemptedAt));

        let page_one = fx.deliveries(verified.id(), &order, &first(2)).await;
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = fx.deliveries(verified.id(), &order, &after).await;

        let ids: Vec<_> = page_one.items.iter().map(|attempt| attempt.id).collect();
        assert_eq!(ids, [new.id, held.id]);
        assert_eq!(
            page_one.items.get(1).map(|attempt| attempt.delivery),
            Some(SignalDelivery::Queued)
        );
        assert_eq!(page_two.items.len(), 1);
        assert!(!page_two.has_next());
    }

    /// Recording a delivery from another tenant leaves the owning stream's
    /// delivery history empty.
    #[tokio::test]
    async fn a_delivery_for_another_tenants_stream_writes_nothing() {
        let fx = fixture().await;
        let theirs = ScopedTenant::for_background(TenantId::new());
        let verified = at_endpoint("https://app.acme.com/sse");
        fx.store
            .save(&theirs, &verified, StreamChallenge::Kept)
            .await
            .unwrap();
        let order = SortOrder::single(Sort::descending(StreamDeliverySortField::Status));

        fx.store
            .record_delivery(&fx.tenant, &delivery_row(*verified.id(), 1, taken()))
            .await
            .unwrap();

        let history = fx
            .store
            .list_deliveries(&theirs, verified.id(), &order, &first(10))
            .await
            .unwrap();
        assert!(history.items.is_empty());
    }

    /// Removing an endpoint after recording a delivery leaves both the endpoint
    /// lookup and delivery history empty.
    #[tokio::test]
    async fn a_deleted_stream_is_gone_with_its_history() {
        let fx = fixture().await;
        let verified = at_endpoint("https://app.acme.com/sse");
        fx.save_all(&[&verified]).await;
        fx.store
            .record_delivery(&fx.tenant, &delivery_row(*verified.id(), 1, taken()))
            .await
            .unwrap();
        let order = SortOrder::single(Sort::ascending(StreamDeliverySortField::AttemptedAt));

        fx.store.delete(&fx.tenant, verified.id()).await.unwrap();

        assert!(fx.found(verified.id()).await.is_none());
        let history = fx
            .store
            .list_deliveries(&fx.tenant, verified.id(), &order, &first(10))
            .await
            .unwrap();
        assert!(history.items.is_empty());
    }

    /// Saving a stream naming an unknown user returns an infrastructure
    /// error and leaves no stream to read.
    #[tokio::test]
    async fn a_subject_the_tenant_does_not_have_is_refused() {
        let fx = fixture().await;
        let ghost = stream(SignalStreamRow {
            subjects: StreamSubjects::Only(vec![SignalSubject::User(UserId::new())]),
            ..stream_row("https://app.acme.com/sse")
        });

        let saved = fx
            .store
            .save(&fx.tenant, &ghost, StreamChallenge::Kept)
            .await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
        assert!(fx.found(ghost.id()).await.is_none());
    }

    /// A tenant with a database of its own keeps its streams there.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_keeps_its_streams_there() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        let verified = at_endpoint("https://app.acme.com/sse");

        fx.store
            .save(&apart, &verified, StreamChallenge::Kept)
            .await
            .unwrap();

        let there = PgSignalStreamStore::new(Arc::clone(&own.databases));
        assert!(
            there
                .find_by_id(&apart, verified.id())
                .await
                .unwrap()
                .is_some()
        );
    }

    /// A stream with a stored HTTP endpoint fails to load as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_stream_is_refused() {
        let fx = fixture().await;
        let verified = at_endpoint("https://app.acme.com/sse");
        fx.save_all(&[&verified]).await;
        fx.db
            .tamper("UPDATE signal_streams SET endpoint = 'http://app.acme.com/sse'")
            .await;

        let read = fx.store.find_by_id(&fx.tenant, verified.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
