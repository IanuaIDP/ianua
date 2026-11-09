-- The tenant tables of the audit trail and of the proxy's own records: a
-- tenant's audit records and how far their chain is known to hold, the
-- streams that copy them to a SIEM, and the pipelines, uploaded modules,
-- log shipping targets and request records of the tenant's gateway.

-- A tenant's audit records: who did what, when and from where, each linked
-- to the record before it in the tenant's chain. `entry_hash` is SHA-256 of
-- `prev_hash` and the record's every other column, so a record removed,
-- reordered or edited breaks the chain from that point on.
--
-- Records are only ever added. Row-level security, forced on the owner
-- too, has no policy that lets a record be changed. Only the retention
-- purge removes one, signed in as a role of its own: the app's role holds
-- no UPDATE, DELETE or TRUNCATE on this table, and the purge's role holds
-- SELECT and DELETE here and little else (postgres/foundation/roles.rs).
-- The delete policy holds the purge to the one tenant its transaction is
-- scoped to, never to work spanning tenants (postgres/audit/retention).
-- It removes a tenant's oldest records and keeps the hash of the last one
-- it removed as the chain's new anchor, sealed, so a purge never reads as a
-- break.
--
-- So whoever holds the app's role cannot remove a record by any setting.
-- Against whoever holds the purge's role the sealed head, anchor and
-- checkpoint hold: records not yet walked cannot be removed unseen.
CREATE TABLE audit_records (
    tenant_id uuid NOT NULL,
    id uuid PRIMARY KEY,
    -- The record's place in its tenant's chain, from 1.
    seq bigint NOT NULL,
    -- no foreign key: organizations live in the platform database, and a record outlives the organization it names
    organization_id uuid,
    -- Who acted, as the domain labels them, an agent's delegation chain
    -- included.
    actor text NOT NULL,
    -- The acting principal's kind and id, for the filters by actor; no id
    -- for the system or someone who never proved who they are.
    actor_kind text NOT NULL,
    -- no foreign key: a record outlives the actor it names, who may live in the platform database
    actor_id uuid,
    event_type text NOT NULL,
    -- The entity the action affected, of any kind, or NULL for none.
    target_id text,
    ip_address text,
    user_agent text,
    payload jsonb NOT NULL,
    -- Whether the actor acted in their own name, as an operator acting as
    -- a user, or as an admin acting as a person for support.
    acted_through text NOT NULL,
    -- no foreign key: operators live in the platform database, and a record outlives them
    through_operator_id uuid,
    -- no foreign key: a record outlives the admin it names
    through_admin_id uuid,
    -- no foreign key: a record outlives the person it names
    as_user_id uuid,
    -- no foreign key: a record outlives the impersonation that allowed it
    support_impersonation_id uuid,
    occurred_at timestamptz NOT NULL,
    prev_hash bytea NOT NULL,
    entry_hash bytea NOT NULL,
    -- The workflow run a company step acted through, as the person the run
    -- is for: "Pat, through run 4182", never Pat acting by hand.
    -- no foreign key: a record outlives the run it names
    through_execution_id uuid,
    CONSTRAINT audit_records_seq_key UNIQUE (tenant_id, seq),
    -- The outbox links to a record through its tenant.
    CONSTRAINT audit_records_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT audit_records_seq_from_one
        CHECK (seq >= 1),
    CONSTRAINT audit_records_actor_kind_known
        CHECK (actor_kind IN ('tenant_user', 'org_user', 'operator', 'system', 'anonymous',
                              'oauth_client', 'api_key', 'service', 'agent')),
    CONSTRAINT audit_records_actor_named_by_kind
        CHECK ((actor_kind IN ('system', 'anonymous')) = (actor_id IS NULL)),
    CONSTRAINT audit_records_acted_through_known
        CHECK (acted_through IN ('directly', 'impersonation', 'support_impersonation',
                                 'workflow_run')),
    CONSTRAINT audit_records_acted_through_names_its_parties
        CHECK (CASE acted_through
                   WHEN 'directly' THEN num_nonnulls(through_operator_id, through_admin_id,
                                                     as_user_id, support_impersonation_id,
                                                     through_execution_id) = 0
                   WHEN 'impersonation' THEN through_operator_id IS NOT NULL
                       AND as_user_id IS NOT NULL
                       AND num_nonnulls(through_admin_id, support_impersonation_id,
                                        through_execution_id) = 0
                   WHEN 'support_impersonation' THEN through_operator_id IS NULL
                       AND through_execution_id IS NULL
                       AND num_nonnulls(through_admin_id, as_user_id, support_impersonation_id) = 3
                   WHEN 'workflow_run' THEN through_execution_id IS NOT NULL
                       AND num_nonnulls(through_operator_id, through_admin_id, as_user_id,
                                        support_impersonation_id) = 0
                   ELSE false
               END),
    CONSTRAINT audit_records_hashes_are_digests
        CHECK (octet_length(prev_hash) = 32 AND octet_length(entry_hash) = 32)
);

ALTER TABLE audit_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_records_read ON audit_records FOR SELECT
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));
CREATE POLICY tenant_records_added ON audit_records FOR INSERT
    WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));
CREATE POLICY tenant_records_purged ON audit_records FOR DELETE
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- The log by time, newest first, and the retention purge, which finds the
-- first record it keeps by time.
CREATE INDEX audit_records_by_time ON audit_records (tenant_id, occurred_at, id) INCLUDE (seq);
-- The log by event type, and the filter by an event type's start, which
-- also counts sign-ins in a window for the metrics.
CREATE INDEX audit_records_by_event_type ON audit_records (tenant_id, event_type, id);
CREATE INDEX audit_records_of_event_type
    ON audit_records (tenant_id, event_type text_pattern_ops, occurred_at);
-- The records of one actor: the filter by actor, and an agent's evidence
-- in chain order.
CREATE INDEX audit_records_of_actor ON audit_records (tenant_id, actor_kind, actor_id, seq);
CREATE INDEX audit_records_about_target ON audit_records (tenant_id, target_id);
CREATE INDEX audit_records_from_address ON audit_records (tenant_id, ip_address);
-- The records made while acting as a person, for their data export.
CREATE INDEX audit_records_as_user ON audit_records (tenant_id, as_user_id, seq)
    WHERE as_user_id IS NOT NULL;

-- How far back a tenant's chain was purged: the last record removed, whose
-- hash the oldest record kept links to. Sealed with an HMAC under a key the
-- database never holds, as the head is: the walk starts from an anchor only
-- when its seal holds, so whoever can write this table cannot move the
-- chain's start past records they removed. The purge's role moves an
-- anchor; the app's role only adds one, when a tenant's trail is copied
-- into its own schema, and never moves or removes one.
CREATE TABLE audit_chain_anchors (
    tenant_id uuid PRIMARY KEY,
    seq bigint NOT NULL,
    entry_hash bytea NOT NULL,
    -- The cutoff of the purge that left this anchor.
    purged_before timestamptz NOT NULL,
    seal bytea NOT NULL,
    CONSTRAINT audit_chain_anchors_seq_from_one
        CHECK (seq >= 1),
    CONSTRAINT audit_chain_anchors_are_digests
        CHECK (octet_length(entry_hash) = 32 AND octet_length(seal) = 32)
);

ALTER TABLE audit_chain_anchors ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_anchors FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON audit_chain_anchors
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The newest link of each tenant's chain, sealed with an HMAC under a key
-- the database never holds. The trail writes it in the transaction that
-- adds records, and the walk compares where the chain ends with it, so the
-- newest records cannot be cut off the chain unseen: whoever can write
-- this table cannot seal a head of their own.
CREATE TABLE audit_chain_heads (
    tenant_id uuid PRIMARY KEY,
    seq bigint NOT NULL,
    entry_hash bytea NOT NULL,
    seal bytea NOT NULL,
    CONSTRAINT audit_chain_heads_seq_from_one
        CHECK (seq >= 1),
    CONSTRAINT audit_chain_heads_are_digests
        CHECK (octet_length(entry_hash) = 32 AND octet_length(seal) = 32)
);

ALTER TABLE audit_chain_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON audit_chain_heads
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The tenant's audit records still to be published on the message bus,
-- written in the transaction that adds the records, so a change, its
-- record and the promise to publish it are kept or dropped together. The
-- relay publishes each under the record's id and removes it here; one it
-- could not publish waits for the next pass.
CREATE TABLE event_outbox (
    tenant_id uuid NOT NULL,
    record_id uuid NOT NULL,
    queued_at timestamptz NOT NULL,
    -- How deep in a workflow chain the work that raised the event was: 0
    -- outside any workflow, else the depth of the execution whose work
    -- raised it. The relay carries it on the bus, under the event's seal,
    -- so a workflow the event starts continues the chain and the chain's
    -- limit still holds.
    chain_depth smallint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, record_id),
    -- A record the retention purge removed is not published any more.
    CONSTRAINT event_outbox_record_fkey FOREIGN KEY (tenant_id, record_id)
        REFERENCES audit_records (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT event_outbox_chain_depth_known CHECK (chain_depth >= 0)
);

ALTER TABLE event_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON event_outbox
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The relay takes the oldest first.
CREATE INDEX event_outbox_by_age ON event_outbox (queued_at, record_id);

-- The last verdict of the scheduled sweep on a tenant's chain, and the
-- last link it verified, where the next sweep starts. Sealed over every
-- column with an HMAC under a key the database never holds, so a checkpoint
-- moved past records removed since, or a broken chain marked intact, is
-- refused when read rather than trusted.
CREATE TABLE audit_chain_verdicts (
    tenant_id uuid PRIMARY KEY,
    verified_at timestamptz NOT NULL,
    standing text NOT NULL,
    -- The first record that did not verify, for a broken chain.
    broken_at_seq bigint,
    -- The last link verified, or NULL when the walk verified none.
    checkpoint_seq bigint,
    checkpoint_hash bytea,
    seal bytea NOT NULL,
    CONSTRAINT audit_chain_verdicts_standing_known
        CHECK (standing IN ('intact', 'intact_so_far', 'broken')),
    CONSTRAINT audit_chain_verdicts_break_named
        CHECK ((standing = 'broken') = (broken_at_seq IS NOT NULL)),
    CONSTRAINT audit_chain_verdicts_checkpoint_whole
        CHECK ((checkpoint_seq IS NULL) = (checkpoint_hash IS NULL)),
    CONSTRAINT audit_chain_verdicts_checkpoint_is_a_digest
        CHECK (checkpoint_hash IS NULL OR octet_length(checkpoint_hash) = 32),
    CONSTRAINT audit_chain_verdicts_seal_is_a_digest
        CHECK (octet_length(seal) = 32)
);

ALTER TABLE audit_chain_verdicts ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_verdicts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON audit_chain_verdicts
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The streams that copy a tenant's audit records to a SIEM. Every
-- credential in a destination was sealed by the platform's secret sealer
-- before the stream was made, and is kept sealed.
CREATE TABLE audit_streams (
    tenant_id uuid NOT NULL,
    id uuid PRIMARY KEY,
    name text NOT NULL,
    destination jsonb NOT NULL,
    -- The event types sent, or NULL for every record.
    events text[],
    state text NOT NULL,
    -- When the failures began, or when the stream was paused.
    state_since timestamptz,
    failures integer NOT NULL,
    pause_reason text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT audit_streams_state_known
        CHECK (state IN ('active', 'failing', 'paused')),
    CONSTRAINT audit_streams_pause_reason_known
        CHECK (pause_reason IN ('by_administrator', 'after_failures')),
    CONSTRAINT audit_streams_state_parts
        CHECK (CASE state
                   WHEN 'active' THEN state_since IS NULL AND failures = 0 AND pause_reason IS NULL
                   WHEN 'failing' THEN state_since IS NOT NULL AND failures > 0
                       AND pause_reason IS NULL
                   ELSE state_since IS NOT NULL AND failures = 0 AND pause_reason IS NOT NULL
               END),
    CONSTRAINT audit_streams_events_named
        CHECK (events IS NULL OR cardinality(events) > 0),
    CONSTRAINT audit_streams_changed_after_created
        CHECK (updated_at >= created_at)
);

ALTER TABLE audit_streams ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_streams FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON audit_streams
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A tenant's streams, oldest first.
CREATE INDEX audit_streams_by_created ON audit_streams (tenant_id, created_at, id);

-- A tenant's proxy pipelines, each the ordered stages a request on its
-- routes passes through.
CREATE TABLE pipelines (
    tenant_id uuid NOT NULL,
    id uuid PRIMARY KEY,
    name text NOT NULL,
    status text NOT NULL,
    stages jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pipelines_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT pipelines_name_key UNIQUE (tenant_id, name),
    CONSTRAINT pipelines_status_known
        CHECK (status IN ('draft', 'active', 'disabled')),
    CONSTRAINT pipelines_changed_after_created
        CHECK (updated_at >= created_at)
);

ALTER TABLE pipelines ENABLE ROW LEVEL SECURITY;
ALTER TABLE pipelines FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON pipelines
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A tenant's pipelines, oldest first.
CREATE INDEX pipelines_by_created ON pipelines (tenant_id, created_at, id);

-- The WASM modules a tenant uploaded for its stages, each found by the
-- SHA-256 of its bytes, so a module's bytes never change.
CREATE TABLE wasm_modules (
    tenant_id uuid NOT NULL,
    module_ref text NOT NULL,
    bytecode bytea NOT NULL,
    uploaded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, module_ref),
    CONSTRAINT wasm_modules_ref_is_a_digest
        CHECK (module_ref ~ '^sha256:[0-9a-f]{64}$')
);

ALTER TABLE wasm_modules ENABLE ROW LEVEL SECURITY;
ALTER TABLE wasm_modules FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON wasm_modules
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The places a tenant ships its request records to. A credential was
-- sealed by the platform's secret sealer before the target was made.
CREATE TABLE log_shipping_targets (
    tenant_id uuid NOT NULL,
    id uuid PRIMARY KEY,
    name text NOT NULL,
    destination jsonb NOT NULL,
    -- The sealed credential, or NULL when the destination takes none.
    credential text,
    records text NOT NULL,
    -- The share of allowed requests sent, for a sampled target.
    sample_percent smallint,
    format text NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT log_shipping_targets_name_key UNIQUE (tenant_id, name),
    CONSTRAINT log_shipping_targets_records_known
        CHECK (records IN ('all', 'denied_only', 'sampled')),
    CONSTRAINT log_shipping_targets_sample_fits_records
        CHECK ((records = 'sampled') = (sample_percent IS NOT NULL)),
    CONSTRAINT log_shipping_targets_sample_in_range
        CHECK (sample_percent BETWEEN 1 AND 100),
    CONSTRAINT log_shipping_targets_format_known
        CHECK (format IN ('json_lines', 'open_telemetry')),
    CONSTRAINT log_shipping_targets_status_known
        CHECK (status IN ('active', 'paused')),
    CONSTRAINT log_shipping_targets_changed_after_created
        CHECK (updated_at >= created_at)
);

ALTER TABLE log_shipping_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE log_shipping_targets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON log_shipping_targets
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One record per proxied request of a tenant: who asked for what, what the
-- gateway decided and how long it took. It holds what the proxy observed
-- and nothing more: never a token, a cookie, a header or a body.
--
-- The gateway writes them in batches. Nothing deletes them yet: the
-- retention sweep of the worker wave removes a tenant's records older
-- than its retention through the index by time below.
CREATE TABLE proxy_request_records (
    tenant_id uuid NOT NULL,
    -- no foreign key: it names one request, whose logs and traces carry it too
    correlation_id uuid PRIMARY KEY,
    -- Who the proxy decided was asking.
    principal text NOT NULL,
    -- no foreign key: a record outlives the user, agent or consumer it names
    principal_id uuid,
    -- no foreign key: a record outlives the delegation an agent acted under
    delegation_id uuid,
    -- Whom an agent acted for.
    on_behalf_kind text,
    -- no foreign key: a record outlives the principal an agent acted for
    on_behalf_id uuid,
    consumer_credential text,
    -- no foreign key: the tenant user asking, directly or through an agent, outlived by the record
    person_id uuid,
    -- no foreign key: a deleted route's traffic still counts in its window
    route_id uuid,
    -- no foreign key: a deleted service's traffic still counts in its window
    service_id uuid,
    ip_address text NOT NULL,
    method text NOT NULL,
    path text NOT NULL,
    outcome text NOT NULL,
    status smallint NOT NULL,
    reason text,
    -- The gateway check or the kind of stage that refused it.
    decided_by text,
    -- no foreign key: a stage lives inside its pipeline's stages
    decided_by_stage_id uuid,
    -- The named policy rule it was refused under, or NULL for none.
    rule text,
    duration_ms integer NOT NULL,
    -- The data classification levels found, highest first.
    classification text[] NOT NULL,
    occurred_at timestamptz NOT NULL,
    -- The version of the tenant's policy that ruled on the request, or
    -- NULL when the route's own policy alone did: refused before the
    -- tenant's policy was read, the policy unreadable, or none live.
    policy_version bigint,
    -- How the gateway closed the connection the request upgraded, when it
    -- closed it for access: one of the words the gateway records, and when.
    closed_reason text,
    closed_at timestamptz,
    CONSTRAINT proxy_request_records_principal_known
        CHECK (principal IN ('anonymous', 'user', 'agent', 'consumer')),
    CONSTRAINT proxy_request_records_principal_parts
        CHECK (CASE principal
                   WHEN 'anonymous' THEN num_nonnulls(principal_id, delegation_id, on_behalf_kind,
                                                      on_behalf_id, consumer_credential) = 0
                   WHEN 'user' THEN principal_id IS NOT NULL
                       AND num_nonnulls(delegation_id, on_behalf_kind, on_behalf_id,
                                        consumer_credential) = 0
                   WHEN 'agent' THEN num_nonnulls(principal_id, delegation_id, on_behalf_kind,
                                                  on_behalf_id) = 4
                       AND consumer_credential IS NULL
                   ELSE num_nonnulls(principal_id, consumer_credential) = 2
                       AND num_nonnulls(delegation_id, on_behalf_kind, on_behalf_id) = 0
               END),
    CONSTRAINT proxy_request_records_on_behalf_known
        CHECK (on_behalf_kind IN ('tenant_user', 'org_user', 'agent', 'consumer')),
    CONSTRAINT proxy_request_records_credential_known
        CHECK (consumer_credential IN ('api_key', 'certificate', 'token')),
    CONSTRAINT proxy_request_records_route_whole
        CHECK ((route_id IS NULL) = (service_id IS NULL)),
    CONSTRAINT proxy_request_records_outcome_known
        CHECK (outcome IN ('allowed', 'denied', 'undecided')),
    CONSTRAINT proxy_request_records_refusal_parts
        CHECK ((outcome = 'denied') = (reason IS NOT NULL AND decided_by IS NOT NULL)),
    CONSTRAINT proxy_request_records_rule_of_a_refusal
        CHECK (outcome = 'denied' OR (rule IS NULL AND decided_by_stage_id IS NULL)),
    CONSTRAINT proxy_request_records_status_in_range
        CHECK (status BETWEEN 100 AND 599),
    CONSTRAINT proxy_request_records_duration_not_negative
        CHECK (duration_ms >= 0),
    CONSTRAINT proxy_request_records_policy_version_positive
        CHECK (policy_version > 0),
    CONSTRAINT proxy_request_records_closed_known
        CHECK (closed_reason IN ('access_ended', 'check_failed', 'credential_expired')),
    CONSTRAINT proxy_request_records_closed_whole
        CHECK ((closed_reason IS NULL) = (closed_at IS NULL))
);

ALTER TABLE proxy_request_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE proxy_request_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON proxy_request_records
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One index per order a search can ask for, the correlation id last; the
-- one by time also serves the window of the metrics and the retention
-- sweep.
CREATE INDEX proxy_request_records_by_time
    ON proxy_request_records (tenant_id, occurred_at, correlation_id)
    INCLUDE (duration_ms, outcome, status);
CREATE INDEX proxy_request_records_by_status
    ON proxy_request_records (tenant_id, status, correlation_id);
CREATE INDEX proxy_request_records_by_duration
    ON proxy_request_records (tenant_id, duration_ms, correlation_id);
-- The records of one route, for the search by route and the traffic per
-- route in a window.
CREATE INDEX proxy_request_records_of_route
    ON proxy_request_records (tenant_id, route_id, occurred_at);
-- The records of one person, agent or consumer.
CREATE INDEX proxy_request_records_of_person
    ON proxy_request_records (tenant_id, person_id, occurred_at);
CREATE INDEX proxy_request_records_of_principal
    ON proxy_request_records (tenant_id, principal_id, occurred_at);

-- The records of stream connections: one per connection a stream route's
-- port took, whatever was decided. A stream has no method, path or status,
-- so its record has a table of its own beside the request records: the
-- route and its port, the client, the name its handshake asked for, who was
-- named on it, the decision and why, the backend it was spliced to and how
-- many bytes moved each way. Never a byte of what moved, a token or a
-- certificate. The gateway writes them in batches and never reads them.
-- They are kept as the request records are: the retention sweep that
-- removes a tenant's request records older than its retention removes these
-- through the index by time below.
CREATE TABLE stream_records (
    -- no foreign key: one connection's record, named by nothing else
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    -- no foreign key: a deleted stream route's connections are still kept
    stream_route_id uuid NOT NULL,
    listen_port integer NOT NULL,
    client_address text NOT NULL,
    -- The name the TLS handshake asked for, when there was one.
    server_name text,
    -- Who was named on the connection, or NULL when its credential named
    -- no one.
    caller text,
    -- no foreign key: a record outlives the consumer or person it names
    caller_id uuid,
    decision text NOT NULL,
    -- Why it was refused, or how it ended: a short, stable word.
    reason text NOT NULL,
    -- The backend it was spliced to, as host:port, once one was picked.
    backend text,
    bytes_to_backend bigint NOT NULL,
    bytes_to_client bigint NOT NULL,
    duration_ms integer NOT NULL,
    occurred_at timestamptz NOT NULL,
    CONSTRAINT stream_records_caller_known
        CHECK (caller IN ('nobody', 'unnamed_certificate', 'consumer', 'person')),
    CONSTRAINT stream_records_caller_named
        CHECK (COALESCE(caller IN ('consumer', 'person'), false) = (caller_id IS NOT NULL)),
    CONSTRAINT stream_records_decision_known
        CHECK (decision IN ('allowed', 'denied')),
    CONSTRAINT stream_records_denied_before_a_backend
        CHECK (decision = 'allowed' OR backend IS NULL),
    CONSTRAINT stream_records_port_in_range
        CHECK (listen_port BETWEEN 1024 AND 65535),
    CONSTRAINT stream_records_bytes_not_negative
        CHECK (bytes_to_backend >= 0 AND bytes_to_client >= 0),
    CONSTRAINT stream_records_duration_not_negative
        CHECK (duration_ms >= 0)
);

ALTER TABLE stream_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE stream_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON stream_records
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A tenant's records by time, for a search of a window and the retention
-- sweep; and one route's records by time.
CREATE INDEX stream_records_by_time ON stream_records (tenant_id, occurred_at, id);
CREATE INDEX stream_records_of_route
    ON stream_records (tenant_id, stream_route_id, occurred_at);

-- The events of each tenant the platform's monitors acted on, one row per
-- monitor and event, so an event the bus hands out twice is acted on
-- once. Written in the same transaction as what the monitor changed, and
-- forgotten once the bus can no longer hand the event out again.
CREATE TABLE event_reactions (
    tenant_id uuid NOT NULL,
    -- The monitor that acted, as a word.
    reaction text NOT NULL,
    -- The audit record of the event acted on.
    -- no foreign key: the record may be purged by retention, or live in the tenant's own database
    record_id uuid NOT NULL,
    noted_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, reaction, record_id),
    CONSTRAINT event_reactions_reaction_known
        CHECK (reaction IN ('drift', 'convergence', 'egress_denial'))
);

ALTER TABLE event_reactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_reactions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON event_reactions
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The tenant's notes by age, forgotten once the bus keeps their events no
-- longer.
CREATE INDEX event_reactions_by_age ON event_reactions (tenant_id, noted_at);

-- The gateway's inbox: the few events the data plane raises, each sealed
-- by the gateway, waiting for the worker to check them and append them to
-- the tenant's audit trail. The gateway never writes the trail or the
-- outbox: the trail's head and the outbox's relay are sealed by the control
-- plane, so a row it wrote there would leave vouched for by a key it never
-- holds. It writes here, and only the types its seal may vouch for; the
-- worker checks each row's seal and type again before it appends it. Kept
-- beside the tenant's trail, in the database the tenant lives in.
CREATE TABLE gateway_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    event_type text NOT NULL,
    -- The bus subject the event is sealed for.
    subject text NOT NULL,
    -- The event as the gateway sealed it, kept as the exact text sealed:
    -- jsonb would rewrite the order of its keys and the form of its
    -- numbers, and the seal would no longer hold.
    payload text NOT NULL,
    seal text NOT NULL,
    occurred_at timestamptz NOT NULL,
    written_at timestamptz NOT NULL,
    CONSTRAINT gateway_events_event_type_raised_by_the_gateway
        CHECK (event_type IN ('agents.action_authorized', 'agents.action_denied',
                              'agents.egress_denied', 'agents.token_attack_refused',
                              'proxy.honeypot_hit', 'proxy.person_turned_away',
                              'proxy.automated_threat_detected',
                              'proxy.canary_token_triggered',
                              'proxy.canary_token_leaked',
                              'authentication.session_suspended',
                              'authentication.session_revoked'))
);

ALTER TABLE gateway_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON gateway_events
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The worker drains the oldest first.
CREATE INDEX gateway_events_by_age ON gateway_events (written_at, id);
