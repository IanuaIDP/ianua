-- The platform's tables of the audit trail and of the metrics: the audit
-- records of organizations and of the platform itself, the exports of
-- every audit log, and the snapshots the metrics trends compare against.

-- The audit records that belong to no tenant: an organization's own, and
-- the platform's. The domain chains only a tenant's records, so these
-- carry no chain; they are only ever added all the same, as the policies
-- below hold for the app's role and the owner alike.
CREATE TABLE platform_audit_records (
    id uuid PRIMARY KEY,
    -- no foreign key: a record outlives the organization it names
    organization_id uuid,
    actor text NOT NULL,
    actor_kind text NOT NULL,
    -- no foreign key: a record outlives the actor it names, who may live in a tenant's own database
    actor_id uuid,
    event_type text NOT NULL,
    target_id text,
    ip_address text,
    user_agent text,
    payload jsonb NOT NULL,
    acted_through text NOT NULL,
    -- no foreign key: a record outlives the operator it names
    through_operator_id uuid,
    -- no foreign key: a record outlives the admin it names
    through_admin_id uuid,
    -- no foreign key: a record outlives the person it names
    as_user_id uuid,
    -- no foreign key: a record outlives the impersonation that allowed it
    support_impersonation_id uuid,
    occurred_at timestamptz NOT NULL,
    -- The workflow run a company step acted through, as the person the run
    -- is for: "Pat, through run 4182", never Pat acting by hand.
    -- no foreign key: a record outlives the run it names
    through_execution_id uuid,
    CONSTRAINT platform_audit_records_actor_kind_known
        CHECK (actor_kind IN ('tenant_user', 'org_user', 'operator', 'system', 'anonymous',
                              'oauth_client', 'api_key', 'service', 'agent')),
    CONSTRAINT platform_audit_records_actor_named_by_kind
        CHECK ((actor_kind IN ('system', 'anonymous')) = (actor_id IS NULL)),
    CONSTRAINT platform_audit_records_acted_through_known
        CHECK (acted_through IN ('directly', 'impersonation', 'support_impersonation',
                                 'workflow_run')),
    CONSTRAINT platform_audit_records_acted_through_names_its_parties
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
               END)
);

-- An organization's log and the platform's, by time and by event type.
CREATE INDEX platform_audit_records_of_organization
    ON platform_audit_records (organization_id, occurred_at, id);
CREATE INDEX platform_audit_records_of_organization_by_event_type
    ON platform_audit_records (organization_id, event_type, id);
CREATE INDEX platform_audit_records_by_time ON platform_audit_records (occurred_at, id);
CREATE INDEX platform_audit_records_by_event_type ON platform_audit_records (event_type, id);
CREATE INDEX platform_audit_records_of_event_type
    ON platform_audit_records (event_type text_pattern_ops, occurred_at);
CREATE INDEX platform_audit_records_of_actor
    ON platform_audit_records (actor_kind, actor_id, occurred_at);
CREATE INDEX platform_audit_records_about_target ON platform_audit_records (target_id);
CREATE INDEX platform_audit_records_from_address ON platform_audit_records (ip_address);

-- Records are read and added, and nothing else: row-level security, forced
-- on the owner too, has no policy that lets a record be changed or
-- removed, so an update or a delete touches no row. The app's role is
-- never given TRUNCATE (postgres/foundation/roles.rs).
ALTER TABLE platform_audit_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_audit_records FORCE ROW LEVEL SECURITY;
CREATE POLICY records_read ON platform_audit_records FOR SELECT USING (true);
CREATE POLICY records_added ON platform_audit_records FOR INSERT WITH CHECK (true);

-- The organization and platform records still to be published on the
-- message bus, written with them, as `event_outbox` is for a tenant's.
CREATE TABLE platform_event_outbox (
    record_id uuid PRIMARY KEY,
    queued_at timestamptz NOT NULL,
    -- The record it points at is never removed; were it, there would be
    -- nothing left to publish.
    CONSTRAINT platform_event_outbox_record_fkey FOREIGN KEY (record_id)
        REFERENCES platform_audit_records (id) ON DELETE CASCADE
);

-- The relay takes the oldest first.
CREATE INDEX platform_event_outbox_by_age ON platform_event_outbox (queued_at, record_id);

-- Exports of the audit logs: a tenant's own, an organization's, or the
-- platform's, written by the worker and downloaded once ready. A tenant
-- export names its tenant, so it is under row-level security; the store
-- reads them all as platform work.
CREATE TABLE audit_exports (
    id uuid PRIMARY KEY,
    log text NOT NULL,
    -- The organization whose log it exports. An export goes with it.
    organization_id uuid REFERENCES organizations (id) ON DELETE CASCADE,
    -- The tenant whose log it exports. An export goes with it.
    tenant_id uuid REFERENCES tenants (id) ON DELETE CASCADE,
    -- Who asked, as the domain labels one principal.
    requested_by text NOT NULL,
    -- Which records it holds.
    record_filter jsonb NOT NULL,
    format text NOT NULL,
    status text NOT NULL,
    -- When it was written or given up on.
    state_at timestamptz,
    available_until timestamptz,
    -- How many records the written file holds.
    row_count bigint,
    requested_at timestamptz NOT NULL,
    CONSTRAINT audit_exports_log_known
        CHECK (log IN ('platform', 'organization', 'tenant')),
    CONSTRAINT audit_exports_log_names_its_scope
        CHECK (CASE log
                   WHEN 'platform' THEN num_nonnulls(organization_id, tenant_id) = 0
                   WHEN 'organization' THEN organization_id IS NOT NULL AND tenant_id IS NULL
                   ELSE tenant_id IS NOT NULL AND organization_id IS NULL
               END),
    CONSTRAINT audit_exports_format_known
        CHECK (format IN ('csv', 'json')),
    CONSTRAINT audit_exports_status_known
        CHECK (status IN ('pending', 'ready', 'failed', 'expired')),
    CONSTRAINT audit_exports_state_parts
        CHECK (CASE status
                   WHEN 'ready' THEN num_nonnulls(state_at, available_until, row_count) = 3
                   WHEN 'failed' THEN state_at IS NOT NULL
                       AND num_nonnulls(available_until, row_count) = 0
                   ELSE num_nonnulls(state_at, available_until, row_count) = 0
               END),
    CONSTRAINT audit_exports_rows_not_negative
        CHECK (row_count >= 0)
);

ALTER TABLE audit_exports ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_exports FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON audit_exports
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The exports of one log, for those still being written.
CREATE INDEX audit_exports_of_tenant ON audit_exports (tenant_id, status);
CREATE INDEX audit_exports_of_organization ON audit_exports (organization_id, status);
CREATE INDEX audit_exports_of_platform ON audit_exports (log, status);
-- The exports due to end, oldest first: pending past their deadline, and
-- ready past their window.
CREATE INDEX audit_exports_pending ON audit_exports (requested_at, id) WHERE status = 'pending';
CREATE INDEX audit_exports_ready ON audit_exports (available_until, id) WHERE status = 'ready';

-- What an organization held at one moment, captured on a schedule, so a
-- trend can compare against a past count no live table can give.
CREATE TABLE org_metric_snapshots (
    -- The organization measured. Its snapshots go with it.
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    captured_at timestamptz NOT NULL,
    users_count bigint NOT NULL,
    tenants_count bigint NOT NULL,
    active_sessions_count bigint NOT NULL,
    PRIMARY KEY (organization_id, captured_at),
    CONSTRAINT org_metric_snapshots_counts_not_negative
        CHECK (users_count >= 0 AND tenants_count >= 0 AND active_sessions_count >= 0)
);

-- What a tenant held at one moment. The tenant's people may live in a
-- database of their own; their counts are kept here all the same.
CREATE TABLE tenant_metric_snapshots (
    -- The tenant measured. Its snapshots go with it.
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    captured_at timestamptz NOT NULL,
    users_count bigint NOT NULL,
    active_sessions_count bigint NOT NULL,
    PRIMARY KEY (tenant_id, captured_at),
    CONSTRAINT tenant_metric_snapshots_counts_not_negative
        CHECK (users_count >= 0 AND active_sessions_count >= 0)
);

ALTER TABLE tenant_metric_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_metric_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON tenant_metric_snapshots
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));
