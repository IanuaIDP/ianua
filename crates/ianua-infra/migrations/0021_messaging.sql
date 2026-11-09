-- Messaging, signals and webhooks: a tenant's topics, the subscriptions
-- to them, its event schemas and the channels between its agents; the
-- signal streams its relying parties receive security signals through,
-- with their delivery history and the tokens held for a receiver that
-- polls; and its webhook subscriptions, with the messages they send and
-- every try at sending one.
--
-- Every table is a tenant table, under row-level security, and lives in a
-- tenant's own database too. That database has no tenants table, so no
-- table here points at one; foreign keys carry the tenant, so a row never
-- points into another tenant.
--
-- The checks repeat the rules the domain keeps between columns, so a row
-- written past the domain is refused here too. Every signing secret and
-- every receiver's credential is written sealed, as the platform's sealer
-- hands it over; none is ever kept in clear.

-- The named channels a tenant's services publish to.
CREATE TABLE topics (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    topic_name text NOT NULL,
    description text,
    -- The JSON schema messages are held to, or NULL for none.
    schema_definition text,
    -- How long messages are kept: for a number of seconds, for a number of
    -- messages, or until purged, with NULL for the amount.
    retention_kind text NOT NULL,
    retention_amount bigint,
    status text NOT NULL,
    -- Who made it: a person through one of their accounts, with the person
    -- behind it, or a consumer, with no person.
    created_by_kind text NOT NULL,
    -- no foreign key: the maker is a user, an organization member or a consumer, named by its kind, and the topic outlives them.
    created_by_id uuid NOT NULL,
    created_by_person text,
    data_class text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT topics_tenant_id_key UNIQUE (tenant_id, id),
    -- A service publishes to a topic by its name, so one name is one topic
    -- of the tenant.
    CONSTRAINT topics_name_key UNIQUE (tenant_id, topic_name),
    CONSTRAINT topics_retention_known
        CHECK (retention_kind IN ('duration', 'message_count', 'unlimited')),
    CONSTRAINT topics_retention_fits_kind
        CHECK ((retention_kind = 'unlimited') = (retention_amount IS NULL)),
    CONSTRAINT topics_retention_positive
        CHECK (retention_amount > 0),
    CONSTRAINT topics_status_known
        CHECK (status IN ('active', 'paused', 'archived')),
    CONSTRAINT topics_maker_kind_known
        CHECK (created_by_kind IN ('user', 'org_user', 'consumer')),
    CONSTRAINT topics_maker_whole
        CHECK ((created_by_kind = 'consumer') = (created_by_person IS NULL)),
    CONSTRAINT topics_data_class_known
        CHECK (data_class IN ('public', 'internal', 'confidential', 'restricted')),
    CONSTRAINT topics_changed_after_created
        CHECK (updated_at >= created_at)
);

ALTER TABLE topics ENABLE ROW LEVEL SECURITY;
ALTER TABLE topics FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON topics
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One index per order a topic list can ask for, the id last.
CREATE INDEX topics_by_created ON topics (tenant_id, created_at, id);
CREATE INDEX topics_by_updated ON topics (tenant_id, updated_at, id);
CREATE INDEX topics_by_name ON topics (tenant_id, name, id);
CREATE INDEX topics_by_topic_name ON topics (tenant_id, topic_name, id);
CREATE INDEX topics_by_status ON topics (tenant_id, status, id);

-- How each service of the tenant receives a topic's messages. How far it
-- has read is kept by the message bus, not here.
CREATE TABLE topic_subscriptions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    topic_name text NOT NULL,
    consumer_id uuid NOT NULL,
    consumer_group text,
    delivery_mode text NOT NULL,
    -- Where a push goes and the secret it is signed with, sealed, both
    -- NULL for a pulled subscription.
    push_url text,
    push_secret_sealed text,
    -- The secret before the last rotation, sealed, and when it stops
    -- signing, or NULL in both when none signs.
    previous_secret_sealed text,
    previous_secret_until timestamptz,
    ack_deadline_seconds bigint NOT NULL,
    max_deliveries bigint NOT NULL,
    filter text,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- Deleting a topic deletes every subscription to it, so the
    -- subscriptions go with the topic.
    CONSTRAINT topic_subscriptions_topic_fkey FOREIGN KEY (tenant_id, topic_name)
        REFERENCES topics (tenant_id, topic_name) ON DELETE CASCADE,
    -- A subscription is how one service hears a topic; without the service
    -- it delivers to nobody, so it goes with the service.
    CONSTRAINT topic_subscriptions_consumer_fkey FOREIGN KEY (tenant_id, consumer_id)
        REFERENCES consumers (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT topic_subscriptions_delivery_known
        CHECK (delivery_mode IN ('pull', 'push')),
    CONSTRAINT topic_subscriptions_push_fits_mode
        CHECK ((delivery_mode = 'push') = (push_url IS NOT NULL)
            AND (delivery_mode = 'push') = (push_secret_sealed IS NOT NULL)),
    CONSTRAINT topic_subscriptions_previous_only_pushed
        CHECK (delivery_mode = 'push' OR previous_secret_sealed IS NULL),
    CONSTRAINT topic_subscriptions_previous_whole
        CHECK (num_nulls(previous_secret_sealed, previous_secret_until) IN (0, 2)),
    CONSTRAINT topic_subscriptions_deadline_in_range
        CHECK (ack_deadline_seconds BETWEEN 5 AND 600),
    CONSTRAINT topic_subscriptions_deliveries_in_range
        CHECK (max_deliveries BETWEEN 1 AND 100),
    CONSTRAINT topic_subscriptions_status_known
        CHECK (status IN ('active', 'paused')),
    CONSTRAINT topic_subscriptions_changed_after_created
        CHECK (updated_at >= created_at)
);

ALTER TABLE topic_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE topic_subscriptions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON topic_subscriptions
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A topic's subscriptions and a service's, in each order a list can ask
-- for, the id last. They lead with the topic and the service, for their
-- foreign keys too.
CREATE INDEX topic_subscriptions_of_topic_by_created
    ON topic_subscriptions (tenant_id, topic_name, created_at, id);
CREATE INDEX topic_subscriptions_of_topic_by_status
    ON topic_subscriptions (tenant_id, topic_name, status, id);
CREATE INDEX topic_subscriptions_of_topic
    ON topic_subscriptions (tenant_id, topic_name, id);
CREATE INDEX topic_subscriptions_of_consumer_by_created
    ON topic_subscriptions (tenant_id, consumer_id, created_at, id);
CREATE INDEX topic_subscriptions_of_consumer_by_topic
    ON topic_subscriptions (tenant_id, consumer_id, topic_name, id);
CREATE INDEX topic_subscriptions_of_consumer_by_status
    ON topic_subscriptions (tenant_id, consumer_id, status, id);
-- The subscriptions of one consumer group on a topic, which read through
-- one bus consumer together.
CREATE INDEX topic_subscriptions_of_group
    ON topic_subscriptions (tenant_id, topic_name, consumer_group, id)
    WHERE consumer_group IS NOT NULL;

-- The versioned schemas a tenant's services generate their message types
-- from. Topics do not point at them.
CREATE TABLE event_schemas (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    schema_name text NOT NULL,
    description text,
    format text NOT NULL,
    compatibility text NOT NULL,
    -- Who registered it, as a topic keeps its maker.
    created_by_kind text NOT NULL,
    -- no foreign key: the maker is a user, an organization member or a consumer, named by its kind, and the schema outlives them.
    created_by_id uuid NOT NULL,
    created_by_person text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT event_schemas_tenant_id_key UNIQUE (tenant_id, id),
    -- A service names a schema by its machine name, so one name is one
    -- schema of the tenant.
    CONSTRAINT event_schemas_name_key UNIQUE (tenant_id, schema_name),
    CONSTRAINT event_schemas_format_known
        CHECK (format IN ('json_schema', 'avro', 'protobuf')),
    CONSTRAINT event_schemas_compatibility_known
        CHECK (compatibility IN ('none', 'backward', 'forward', 'full')),
    CONSTRAINT event_schemas_maker_kind_known
        CHECK (created_by_kind IN ('user', 'org_user', 'consumer')),
    CONSTRAINT event_schemas_maker_whole
        CHECK ((created_by_kind = 'consumer') = (created_by_person IS NULL)),
    CONSTRAINT event_schemas_changed_after_created
        CHECK (updated_at >= created_at)
);

ALTER TABLE event_schemas ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_schemas FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON event_schemas
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One index per order a schema list can ask for, the id last.
CREATE INDEX event_schemas_by_created ON event_schemas (tenant_id, created_at, id);
CREATE INDEX event_schemas_by_updated ON event_schemas (tenant_id, updated_at, id);
CREATE INDEX event_schemas_by_name ON event_schemas (tenant_id, name, id);
CREATE INDEX event_schemas_by_schema_name ON event_schemas (tenant_id, schema_name, id);

-- Every version of a schema. Versions are only ever added, and a
-- published one never changes.
CREATE TABLE event_schema_versions (
    tenant_id uuid NOT NULL,
    schema_id uuid NOT NULL,
    version bigint NOT NULL,
    definition text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, schema_id, version),
    -- A version is part of its schema, so it goes with it.
    CONSTRAINT event_schema_versions_schema_fkey FOREIGN KEY (tenant_id, schema_id)
        REFERENCES event_schemas (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT event_schema_versions_counted
        CHECK (version BETWEEN 1 AND 1000),
    CONSTRAINT event_schema_versions_definition_bounded
        CHECK (octet_length(definition) BETWEEN 1 AND 65536)
);

ALTER TABLE event_schema_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_schema_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON event_schema_versions
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The channels people open for two agents to exchange messages or share
-- an object.
CREATE TABLE agent_channels (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    sender_id uuid NOT NULL,
    receiver_id uuid NOT NULL,
    -- What may travel: topics in the sender's area, or one object.
    scope_kind text NOT NULL,
    scope_value text NOT NULL,
    max_class text NOT NULL,
    -- The person who opened it, through which account.
    opened_by_kind text NOT NULL,
    -- no foreign key: the account is a user or an organization member, kept in another context's table, and the channel outlives it.
    opened_by_id uuid NOT NULL,
    opened_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    -- When a person closed it, or NULL while it is not closed.
    closed_at timestamptz,
    -- A channel carries data between its two agents; without either it
    -- carries nothing, so it goes with them.
    CONSTRAINT agent_channels_sender_fkey FOREIGN KEY (tenant_id, sender_id)
        REFERENCES agents (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_channels_receiver_fkey FOREIGN KEY (tenant_id, receiver_id)
        REFERENCES agents (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_channels_between_two
        CHECK (sender_id <> receiver_id),
    CONSTRAINT agent_channels_scope_known
        CHECK (scope_kind IN ('topics', 'resource')),
    CONSTRAINT agent_channels_class_known
        CHECK (max_class IN ('public', 'internal', 'confidential', 'restricted')),
    CONSTRAINT agent_channels_opened_by_a_person
        CHECK (opened_by_kind IN ('user', 'org_user')),
    CONSTRAINT agent_channels_lifetime_in_range
        CHECK (expires_at BETWEEN opened_at + interval '60 seconds'
                              AND opened_at + interval '30 days'),
    CONSTRAINT agent_channels_closed_after_opened
        CHECK (closed_at IS NULL OR closed_at >= opened_at)
);

ALTER TABLE agent_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_channels FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON agent_channels
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The tenant's channels in the order they are listed.
CREATE INDEX agent_channels_by_opened ON agent_channels (tenant_id, opened_at, id);
-- The channels from one agent to another, and those into one agent, each
-- leading with its foreign key.
CREATE INDEX agent_channels_between
    ON agent_channels (tenant_id, sender_id, receiver_id, opened_at, id);
CREATE INDEX agent_channels_into
    ON agent_channels (tenant_id, receiver_id, opened_at, id);

-- The relying parties of a tenant that receive its security signals.
CREATE TABLE signal_streams (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    endpoint text NOT NULL,
    -- The challenge the endpoint must echo before it is sent anything, or
    -- NULL once it has.
    endpoint_challenge text,
    delivery_method text NOT NULL,
    -- What a push sends in the Authorization header, sealed, or NULL for
    -- none.
    authorization_sealed text,
    -- The digest of the key the receiver manages its stream with.
    receiver_key_hash text NOT NULL,
    signal_types text[] NOT NULL,
    -- Which subjects it hears about: every subject but those listed in
    -- signal_stream_subjects, or only those.
    default_subjects text NOT NULL,
    status text NOT NULL,
    consecutive_failures bigint NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT signal_streams_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT signal_streams_delivery_known
        CHECK (delivery_method IN ('push', 'poll')),
    CONSTRAINT signal_streams_names_a_type
        CHECK (cardinality(signal_types) >= 1),
    CONSTRAINT signal_streams_subjects_known
        CHECK (default_subjects IN ('all', 'none')),
    CONSTRAINT signal_streams_status_known
        CHECK (status IN ('active', 'paused', 'disabled')),
    CONSTRAINT signal_streams_failures_counted
        CHECK (consecutive_failures >= 0),
    CONSTRAINT signal_streams_changed_after_created
        CHECK (updated_at >= created_at)
);

ALTER TABLE signal_streams ENABLE ROW LEVEL SECURITY;
ALTER TABLE signal_streams FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON signal_streams
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One index per order a stream list can ask for, the id last, and the
-- streams of one status, the active ones every signal fans out to.
CREATE INDEX signal_streams_by_created ON signal_streams (tenant_id, created_at, id);
CREATE INDEX signal_streams_by_status ON signal_streams (tenant_id, status, id);
CREATE INDEX signal_streams_by_endpoint ON signal_streams (tenant_id, endpoint, id);
CREATE INDEX signal_streams_of_status_by_created
    ON signal_streams (tenant_id, status, created_at, id);

-- The users and agents a stream lists, removed from every subject or the
-- only ones it hears about, in the order they were listed.
CREATE TABLE signal_stream_subjects (
    tenant_id uuid NOT NULL,
    stream_id uuid NOT NULL,
    position bigint NOT NULL,
    user_id uuid,
    agent_id uuid,
    PRIMARY KEY (tenant_id, stream_id, position),
    -- The list is part of its stream, so it goes with it.
    CONSTRAINT signal_stream_subjects_stream_fkey FOREIGN KEY (tenant_id, stream_id)
        REFERENCES signal_streams (tenant_id, id) ON DELETE CASCADE,
    -- A subject that is gone is heard about by no stream, so it leaves
    -- every list with it.
    CONSTRAINT signal_stream_subjects_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT signal_stream_subjects_agent_fkey FOREIGN KEY (tenant_id, agent_id)
        REFERENCES agents (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT signal_stream_subjects_one_subject
        CHECK (num_nonnulls(user_id, agent_id) = 1)
);

ALTER TABLE signal_stream_subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE signal_stream_subjects FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON signal_stream_subjects
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The lists naming one user or one agent, for their foreign keys.
CREATE INDEX signal_stream_subjects_naming_user ON signal_stream_subjects (tenant_id, user_id);
CREATE INDEX signal_stream_subjects_naming_agent ON signal_stream_subjects (tenant_id, agent_id);

-- Every signal sent to a stream, once each: pushed with how the push
-- ended, or held for a receiver that polls.
CREATE TABLE signal_deliveries (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    stream_id uuid NOT NULL,
    -- no foreign key: a signal is an event that went out, kept as no row of its own.
    signal_id uuid NOT NULL,
    signal_type text NOT NULL,
    status text NOT NULL,
    -- The code the receiver answered with, or NULL when it did not answer
    -- or the signal was held for polling.
    response_code integer,
    duration_ms bigint NOT NULL,
    attempt_number smallint NOT NULL,
    attempted_at timestamptz NOT NULL,
    -- A stream's history is part of the stream, so it goes with it.
    CONSTRAINT signal_deliveries_stream_fkey FOREIGN KEY (tenant_id, stream_id)
        REFERENCES signal_streams (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT signal_deliveries_status_known
        CHECK (status IN ('success', 'failed', 'timeout', 'unreachable', 'queued')),
    CONSTRAINT signal_deliveries_code_fits_status
        CHECK ((status IN ('success', 'failed')) = (response_code IS NOT NULL)),
    CONSTRAINT signal_deliveries_code_known
        CHECK (response_code BETWEEN 100 AND 999),
    CONSTRAINT signal_deliveries_duration_counted
        CHECK (duration_ms >= 0),
    CONSTRAINT signal_deliveries_attempt_counted
        CHECK (attempt_number >= 0)
);

ALTER TABLE signal_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE signal_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON signal_deliveries
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A stream's history in each order it can be listed in, the id last; the
-- first leads with the stream for its foreign key too.
CREATE INDEX signal_deliveries_of_stream_by_attempted
    ON signal_deliveries (tenant_id, stream_id, attempted_at, id);
CREATE INDEX signal_deliveries_of_stream_by_status
    ON signal_deliveries (tenant_id, stream_id, status, id);

-- The tokens a poll stream holds until its receiver acknowledges them,
-- numbered in the order they were queued.
CREATE TABLE signal_poll_events (
    tenant_id uuid NOT NULL,
    stream_id uuid NOT NULL,
    jti uuid NOT NULL,
    token text NOT NULL,
    queued bigint GENERATED ALWAYS AS IDENTITY,
    PRIMARY KEY (tenant_id, stream_id, jti),
    -- What a stream holds is dropped with the stream.
    CONSTRAINT signal_poll_events_stream_fkey FOREIGN KEY (tenant_id, stream_id)
        REFERENCES signal_streams (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE signal_poll_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE signal_poll_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON signal_poll_events
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A stream's tokens, oldest first, as a poll hands them back.
CREATE INDEX signal_poll_events_in_order ON signal_poll_events (tenant_id, stream_id, queued);

-- A tenant's subscriptions to its events, delivered by signed HTTP
-- callback.
CREATE TABLE webhook_subscriptions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    url text NOT NULL,
    -- The secret deliveries are signed with, sealed.
    signing_secret_sealed text NOT NULL,
    -- The secret before the last rotation, sealed, and when it stops
    -- signing, or NULL in both when none signs.
    previous_secret_sealed text,
    previous_secret_until timestamptz,
    event_types text[] NOT NULL,
    status text NOT NULL,
    description text,
    retry text NOT NULL,
    -- Who made it. Every delivery asks again what they may see.
    created_by_kind text NOT NULL,
    -- no foreign key: the maker is any kind of principal, kept in another context's table, and the webhook outlives it.
    created_by_id uuid NOT NULL,
    consecutive_failures bigint NOT NULL,
    last_delivered_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT webhook_subscriptions_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT webhook_subscriptions_previous_whole
        CHECK (num_nulls(previous_secret_sealed, previous_secret_until) IN (0, 2)),
    CONSTRAINT webhook_subscriptions_subscribes
        CHECK (cardinality(event_types) >= 1),
    CONSTRAINT webhook_subscriptions_status_known
        CHECK (status IN ('active', 'paused', 'disabled')),
    CONSTRAINT webhook_subscriptions_retry_known
        CHECK (retry IN ('standard', 'aggressive', 'patient')),
    CONSTRAINT webhook_subscriptions_maker_kind_known
        CHECK (created_by_kind IN ('user', 'org_user', 'agent', 'consumer')),
    CONSTRAINT webhook_subscriptions_failures_counted
        CHECK (consecutive_failures >= 0),
    CONSTRAINT webhook_subscriptions_changed_after_created
        CHECK (updated_at >= created_at),
    CONSTRAINT webhook_subscriptions_delivered_in_its_life
        CHECK (last_delivered_at IS NULL
            OR last_delivered_at BETWEEN created_at AND updated_at)
);

ALTER TABLE webhook_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_subscriptions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON webhook_subscriptions
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One index per order a webhook list can ask for, the id last, and the
-- webhooks of one status, the active ones every event is sent to.
CREATE INDEX webhook_subscriptions_by_created ON webhook_subscriptions (tenant_id, created_at, id);
CREATE INDEX webhook_subscriptions_by_updated ON webhook_subscriptions (tenant_id, updated_at, id);
CREATE INDEX webhook_subscriptions_by_status ON webhook_subscriptions (tenant_id, status, id);
CREATE INDEX webhook_subscriptions_by_url ON webhook_subscriptions (tenant_id, url, id);
CREATE INDEX webhook_subscriptions_of_status_by_created
    ON webhook_subscriptions (tenant_id, status, created_at, id);

-- The body each event was sent to one webhook as, kept so it can be sent
-- again under the same message id.
CREATE TABLE webhook_messages (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    event_type text NOT NULL,
    payload bytea NOT NULL,
    CONSTRAINT webhook_messages_tenant_id_key UNIQUE (tenant_id, id),
    -- A message is part of its webhook's delivery history, so it goes with
    -- the webhook.
    CONSTRAINT webhook_messages_subscription_fkey FOREIGN KEY (tenant_id, subscription_id)
        REFERENCES webhook_subscriptions (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE webhook_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_messages FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON webhook_messages
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A webhook's messages, for its foreign key.
CREATE INDEX webhook_messages_of_subscription ON webhook_messages (tenant_id, subscription_id);

-- Every try at sending a message to a webhook, kept for debugging and
-- audit.
CREATE TABLE webhook_deliveries (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    message_id uuid NOT NULL,
    event_type text NOT NULL,
    status text NOT NULL,
    -- The code the endpoint answered with, or NULL when it did not answer.
    response_code integer,
    duration_ms bigint NOT NULL,
    attempt_number smallint NOT NULL,
    attempted_at timestamptz NOT NULL,
    -- A webhook's history is part of the webhook, so it goes with it.
    CONSTRAINT webhook_deliveries_subscription_fkey FOREIGN KEY (tenant_id, subscription_id)
        REFERENCES webhook_subscriptions (tenant_id, id) ON DELETE CASCADE,
    -- A try names the message it sent, which is kept before it is tried,
    -- and goes with it.
    CONSTRAINT webhook_deliveries_message_fkey FOREIGN KEY (tenant_id, message_id)
        REFERENCES webhook_messages (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT webhook_deliveries_status_known
        CHECK (status IN ('success', 'failed', 'timeout', 'unreachable')),
    CONSTRAINT webhook_deliveries_code_fits_status
        CHECK ((status IN ('success', 'failed')) = (response_code IS NOT NULL)),
    CONSTRAINT webhook_deliveries_code_known
        CHECK (response_code BETWEEN 100 AND 999),
    CONSTRAINT webhook_deliveries_duration_counted
        CHECK (duration_ms >= 0),
    CONSTRAINT webhook_deliveries_attempt_counted
        CHECK (attempt_number >= 0)
);

ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON webhook_deliveries
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A webhook's tries in each order they can be listed in, the id last; the
-- first leads with the webhook for its foreign key too. And the tries of
-- one message, for its foreign key.
CREATE INDEX webhook_deliveries_of_subscription_by_attempted
    ON webhook_deliveries (tenant_id, subscription_id, attempted_at, id);
CREATE INDEX webhook_deliveries_of_subscription_by_status
    ON webhook_deliveries (tenant_id, subscription_id, status, id);
CREATE INDEX webhook_deliveries_of_subscription_by_attempt
    ON webhook_deliveries (tenant_id, subscription_id, attempt_number, id);
CREATE INDEX webhook_deliveries_of_message ON webhook_deliveries (tenant_id, message_id);
