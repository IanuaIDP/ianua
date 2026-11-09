-- The identity context: a tenant's users and what belongs to them, their
-- custom attributes, the links mailed to them, their imports, support
-- impersonations, data exports, erasure requests, consents and invitations.
--
-- Every table is a tenant table: it lives in the platform database and in
-- a tenant's own, so it names no platform table. Row-level security keeps
-- each row to its tenant, and every foreign key between these tables
-- carries the tenant too, so a row can never point at another tenant's.
--
-- The checks repeat the rules the domain keeps between columns, so a row
-- written past the domain is refused here too.

-- Substring searches over addresses and names read a trigram index, led
-- by the tenant through btree_gin, rather than every user of the tenant.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS btree_gin;

CREATE TABLE users (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    email text NOT NULL,
    display_name text NOT NULL,
    status text NOT NULL,
    -- Whether the holder was shown to hold the address.
    email_verified boolean NOT NULL,
    -- The holder's own choice, or NULL to follow the tenant's.
    locale text,
    timezone text,
    given_name text,
    family_name text,
    preferred_username text,
    picture text,
    phone_number text,
    -- What the provisioning directory calls the account.
    external_id text,
    department text,
    manager_id uuid,
    employee_number text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    last_login_at timestamptz,
    joined_at timestamptz,
    credentials_changed_at timestamptz,
    -- The names a name search reads, kept apart by a character no name
    -- holds, so a search never matches across two of them.
    name_search text GENERATED ALWAYS AS (
        display_name || chr(31) || coalesce(given_name, '') || chr(31) || coalesce(family_name, '')
    ) STORED,
    -- Whether an accepted invitation still vouches for the next sign-in:
    -- set when the invitation is accepted, cleared by the first sign-in
    -- after it.
    route_vouches boolean NOT NULL DEFAULT false,
    CONSTRAINT users_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT users_email_key UNIQUE (tenant_id, email),
    -- A manager is one of the tenant's users. Deleting the manager leaves
    -- the person without one, never without their account.
    CONSTRAINT users_manager_fkey FOREIGN KEY (tenant_id, manager_id)
        REFERENCES users (tenant_id, id) ON DELETE SET NULL (manager_id),
    CONSTRAINT users_status_known
        CHECK (status IN ('invited', 'pending_verification', 'active', 'locked', 'deactivated', 'closing')),
    CONSTRAINT users_joined_fits_status
        CHECK (
            (status IN ('invited', 'pending_verification') AND joined_at IS NULL)
            OR (status IN ('active', 'locked', 'closing') AND joined_at IS NOT NULL)
            OR status = 'deactivated'
        ),
    CONSTRAINT users_unverified_while_pending
        CHECK (NOT (status = 'pending_verification' AND email_verified)),
    CONSTRAINT users_not_own_manager
        CHECK (manager_id IS NULL OR manager_id <> id),
    CONSTRAINT users_changed_after_created
        CHECK (updated_at >= created_at),
    -- Only an account that joined holds a vouch.
    CONSTRAINT users_route_vouches_once_joined
        CHECK (NOT route_vouches OR joined_at IS NOT NULL)
);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON users
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One index per order a user list can ask for, the id last.
CREATE INDEX users_by_created ON users (tenant_id, created_at, id);
CREATE INDEX users_by_updated ON users (tenant_id, updated_at, id);
CREATE INDEX users_by_email ON users (tenant_id, email, id);
CREATE INDEX users_by_name ON users (tenant_id, display_name, id);
CREATE INDEX users_by_status ON users (tenant_id, status, id);
CREATE INDEX users_by_last_login ON users (tenant_id, last_login_at, id);
CREATE INDEX users_by_manager ON users (tenant_id, manager_id);
CREATE INDEX users_email_search ON users USING gin (tenant_id, email gin_trgm_ops);
CREATE INDEX users_name_search ON users USING gin (tenant_id, name_search gin_trgm_ops);

-- The custom attributes a tenant declares for its users.
CREATE TABLE user_attribute_definitions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    namespace text NOT NULL,
    key text NOT NULL,
    kind text NOT NULL,
    control text NOT NULL,
    display_name text NOT NULL,
    description text,
    options text[] NOT NULL,
    -- Each limit is NULL when none applies.
    max_length integer,
    minimum double precision,
    maximum double precision,
    required boolean NOT NULL,
    sensitive boolean NOT NULL,
    filterable boolean NOT NULL,
    sortable boolean NOT NULL,
    listed boolean NOT NULL,
    archived boolean NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT user_attribute_definitions_key_key UNIQUE (tenant_id, namespace, key),
    CONSTRAINT user_attribute_definitions_namespace_known
        CHECK (namespace IN ('user', 'app')),
    CONSTRAINT user_attribute_definitions_max_length_positive
        CHECK (max_length IS NULL OR max_length > 0),
    CONSTRAINT user_attribute_definitions_range
        CHECK (minimum IS NULL OR maximum IS NULL OR minimum <= maximum),
    CONSTRAINT user_attribute_definitions_changed_after_created
        CHECK (updated_at >= created_at)
);

ALTER TABLE user_attribute_definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_attribute_definitions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON user_attribute_definitions
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The schema in the order it was declared.
CREATE INDEX user_attribute_definitions_by_created
    ON user_attribute_definitions (tenant_id, created_at, id);

-- A user's metadata: one row per value, in the column its type keeps.
-- The keys are the tenant's declared attributes or any other label an app
-- writes, so they name no declaration.
CREATE TABLE user_metadata (
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    namespace text NOT NULL,
    key text NOT NULL,
    value_type text NOT NULL,
    value_text text,
    value_int bigint,
    value_float double precision,
    value_bool boolean,
    value_array text[],
    PRIMARY KEY (tenant_id, user_id, namespace, key),
    -- A value describes one user and means nothing without them.
    CONSTRAINT user_metadata_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT user_metadata_namespace_known
        CHECK (namespace IN ('user', 'app')),
    CONSTRAINT user_metadata_value_fits_type
        CHECK (
            num_nonnulls(value_text, value_int, value_float, value_bool, value_array)
                = (CASE WHEN value_type = 'null' THEN 0 ELSE 1 END)
            AND CASE value_type
                WHEN 'string' THEN value_text IS NOT NULL
                WHEN 'integer' THEN value_int IS NOT NULL
                WHEN 'number' THEN value_float IS NOT NULL
                WHEN 'boolean' THEN value_bool IS NOT NULL
                WHEN 'string_array' THEN value_array IS NOT NULL
                WHEN 'null' THEN TRUE
                ELSE FALSE
            END
        )
);

ALTER TABLE user_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_metadata FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON user_metadata
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A filter or count by one attribute probes its key, then its value: one
-- index per value column, as a filter reads exactly one of them.
CREATE INDEX user_metadata_text ON user_metadata (tenant_id, namespace, key, value_text);
CREATE INDEX user_metadata_int ON user_metadata (tenant_id, namespace, key, value_int);
CREATE INDEX user_metadata_float ON user_metadata (tenant_id, namespace, key, value_float);
CREATE INDEX user_metadata_bool ON user_metadata (tenant_id, namespace, key, value_bool);
CREATE INDEX user_metadata_array ON user_metadata USING gin (tenant_id, namespace, key, value_array);

-- The single-use links mailed to a user: email verification, magic links
-- and sign-in confirmations, each found only by a lookup for its purpose.
CREATE TABLE mailed_links (
    tenant_id uuid NOT NULL,
    purpose text NOT NULL,
    token_hash text NOT NULL,
    user_id uuid NOT NULL,
    sent_to text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    PRIMARY KEY (tenant_id, purpose, token_hash),
    -- A link is for one account and opens nothing once it is gone.
    CONSTRAINT mailed_links_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT mailed_links_purpose_known
        CHECK (purpose IN ('email_verification', 'magic_link', 'sign_in_confirmation')),
    CONSTRAINT mailed_links_used_while_in_date
        CHECK (used_at IS NULL OR (used_at >= created_at AND used_at < expires_at))
);

ALTER TABLE mailed_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE mailed_links FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON mailed_links
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A user's links of one purpose, newest last.
CREATE INDEX mailed_links_of_user ON mailed_links (tenant_id, user_id, purpose, created_at);

-- Imports of accounts from another system, and how far the worker got.
CREATE TABLE user_imports (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    started_by jsonb NOT NULL,
    status text NOT NULL,
    ended_at timestamptz,
    total integer NOT NULL,
    done integer NOT NULL,
    imported integer NOT NULL,
    -- The records set aside, by line and reason, in line order.
    refused_lines integer[] NOT NULL,
    refused_reasons text[] NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT user_imports_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT user_imports_status_known
        CHECK (status IN ('pending', 'running', 'finished', 'failed')),
    CONSTRAINT user_imports_end_fits_status
        CHECK ((status IN ('finished', 'failed')) = (ended_at IS NOT NULL)),
    CONSTRAINT user_imports_refusals_paired
        CHECK (cardinality(refused_lines) = cardinality(refused_reasons)),
    CONSTRAINT user_imports_counts_add_up
        CHECK (imported + cardinality(refused_lines) = done AND done <= total)
);

ALTER TABLE user_imports ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_imports FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON user_imports
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The records one import sent, by the line they stood on. They are
-- written once, with the import, and never change.
CREATE TABLE user_import_records (
    tenant_id uuid NOT NULL,
    import_id uuid NOT NULL,
    line integer NOT NULL,
    email text NOT NULL,
    display_name text NOT NULL,
    given_name text,
    family_name text,
    preferred_username text,
    picture text,
    phone_number text,
    external_id text,
    department text,
    -- The record keeps the manager it was sent with, whatever becomes of
    -- that account.
    -- no foreign key: a sent record is kept as sent, the manager checked when its account opens
    manager_id uuid,
    employee_number text,
    -- The other system's hash, or NULL when the record carries none.
    password_hash text,
    PRIMARY KEY (tenant_id, import_id, line),
    -- The records belong to their import and go with it.
    CONSTRAINT user_import_records_import_fkey FOREIGN KEY (tenant_id, import_id)
        REFERENCES user_imports (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT user_import_records_line_positive
        CHECK (line > 0)
);

ALTER TABLE user_import_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_import_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON user_import_records
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- Tenant admins acting as one of the tenant's people for support.
CREATE TABLE support_impersonations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    admin_id uuid NOT NULL,
    user_id uuid NOT NULL,
    reason text NOT NULL,
    window_minutes integer NOT NULL,
    consent text NOT NULL,
    status text NOT NULL,
    -- When the status began, NULL while it awaits consent.
    since timestamptz,
    requested_at timestamptz NOT NULL,
    -- The audit trail keeps the record of every impersonation; the request
    -- itself goes with the admin who made it.
    CONSTRAINT support_impersonations_admin_fkey FOREIGN KEY (tenant_id, admin_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    -- And with the person acted as, so erasing them leaves nothing behind.
    CONSTRAINT support_impersonations_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT support_impersonations_consent_known
        CHECK (consent IN ('admin_decides', 'holder_approves')),
    CONSTRAINT support_impersonations_status_known
        CHECK (status IN ('awaiting_consent', 'active', 'declined', 'ended')),
    CONSTRAINT support_impersonations_since_fits_status
        CHECK ((status = 'awaiting_consent') = (since IS NULL)),
    CONSTRAINT support_impersonations_window_bounds
        CHECK (window_minutes BETWEEN 5 AND 60),
    CONSTRAINT support_impersonations_not_oneself
        CHECK (admin_id <> user_id)
);

ALTER TABLE support_impersonations ENABLE ROW LEVEL SECURITY;
ALTER TABLE support_impersonations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON support_impersonations
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- Every impersonation newest first, and those naming one person on either
-- side.
CREATE INDEX support_impersonations_by_requested
    ON support_impersonations (tenant_id, requested_at, id);
CREATE INDEX support_impersonations_by_admin
    ON support_impersonations (tenant_id, admin_id, requested_at, id);
CREATE INDEX support_impersonations_by_user
    ON support_impersonations (tenant_id, user_id, requested_at, id);

-- Requests for a copy of a person's data.
CREATE TABLE data_exports (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    scope text NOT NULL,
    asked_by text NOT NULL,
    status text NOT NULL,
    ready_at timestamptz,
    available_until timestamptz,
    requested_at timestamptz NOT NULL,
    -- The copy is the person's own and goes with their account.
    CONSTRAINT data_exports_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT data_exports_scope_known
        CHECK (scope IN ('access', 'portability')),
    CONSTRAINT data_exports_asked_by_known
        CHECK (asked_by IN ('holder', 'staff')),
    CONSTRAINT data_exports_status_known
        CHECK (status IN ('requested', 'ready', 'expired')),
    CONSTRAINT data_exports_window_fits_status
        CHECK ((status = 'ready') = (ready_at IS NOT NULL AND available_until IS NOT NULL)
            AND num_nulls(ready_at, available_until) IN (0, 2)),
    CONSTRAINT data_exports_ready_after_requested
        CHECK (ready_at IS NULL OR (ready_at >= requested_at AND available_until > ready_at))
);

ALTER TABLE data_exports ENABLE ROW LEVEL SECURITY;
ALTER TABLE data_exports FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON data_exports
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A person has at most one request asked for or ready at a time.
CREATE UNIQUE INDEX data_exports_one_open ON data_exports (tenant_id, user_id)
    WHERE status IN ('requested', 'ready');
CREATE INDEX data_exports_of_user ON data_exports (tenant_id, user_id, requested_at, id);
CREATE INDEX data_exports_waiting ON data_exports (tenant_id, requested_at, id)
    WHERE status = 'requested';
CREATE INDEX data_exports_ready ON data_exports (tenant_id, available_until, id)
    WHERE status = 'ready';

-- Requests to erase a person's data.
CREATE TABLE erasure_requests (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    -- The request is the record that the erasure was asked for and carried
    -- out, so it stays once the account is gone.
    -- no foreign key: the request outlives the account it erases
    user_id uuid NOT NULL,
    reason text,
    status text NOT NULL,
    completed_at timestamptz,
    requested_at timestamptz NOT NULL,
    scheduled_at timestamptz NOT NULL,
    cancel_token_hash text NOT NULL,
    sent_to text NOT NULL,
    CONSTRAINT erasure_requests_cancel_token_key UNIQUE (tenant_id, cancel_token_hash),
    CONSTRAINT erasure_requests_status_known
        CHECK (status IN ('pending', 'processing', 'completed', 'cancelled', 'held', 'failed')),
    CONSTRAINT erasure_requests_completion_fits_status
        CHECK ((status = 'completed') = (completed_at IS NOT NULL)),
    CONSTRAINT erasure_requests_scheduled_after_requested
        CHECK (scheduled_at > requested_at)
);

ALTER TABLE erasure_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE erasure_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON erasure_requests
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX erasure_requests_of_user ON erasure_requests (tenant_id, user_id, requested_at);
-- The requests still to carry out, by when they may start.
CREATE INDEX erasure_requests_due ON erasure_requests (tenant_id, scheduled_at, id)
    WHERE status IN ('pending', 'failed');

-- Consent decisions, kept as made: a withdrawal is a new record.
CREATE TABLE consent_records (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    consent_type text NOT NULL,
    granted boolean NOT NULL,
    version text NOT NULL,
    ip_address text,
    recorded_at timestamptz NOT NULL,
    -- A consent is the person's own word and goes with their account.
    CONSTRAINT consent_records_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT consent_records_type_known
        CHECK (consent_type IN ('data_processing', 'marketing', 'terms_of_service',
                                'privacy_policy', 'health_data_sharing', 'cookies'))
);

ALTER TABLE consent_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE consent_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON consent_records
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX consent_records_of_user ON consent_records (tenant_id, user_id, recorded_at, id);
CREATE INDEX consent_records_of_type
    ON consent_records (tenant_id, user_id, consent_type, recorded_at, id);

-- Invitations to join a tenant, each for one invited account.
CREATE TABLE invitations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    email text NOT NULL,
    invited_by jsonb NOT NULL,
    -- The role accepting gives, linked to roles in 0010.
    role_id uuid NOT NULL,
    token_hash text NOT NULL,
    status text NOT NULL,
    accepted_at timestamptz,
    message text,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT invitations_token_key UNIQUE (tenant_id, token_hash),
    -- An invitation belongs to the account waiting to join, and goes with it.
    CONSTRAINT invitations_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT invitations_status_known
        CHECK (status IN ('pending', 'accepted', 'declined', 'expired', 'revoked')),
    CONSTRAINT invitations_acceptance_fits_status
        CHECK ((status = 'accepted') = (accepted_at IS NOT NULL)),
    CONSTRAINT invitations_accepted_after_sent
        CHECK (accepted_at IS NULL OR accepted_at >= created_at)
);

ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON invitations
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX invitations_of_user ON invitations (tenant_id, user_id);
-- The open invitations, by address and by when they were sent.
CREATE INDEX invitations_pending_by_email ON invitations (tenant_id, email)
    WHERE status = 'pending';
CREATE INDEX invitations_pending_by_created ON invitations (tenant_id, created_at, id)
    WHERE status = 'pending';
-- Each listed user's newest pending invitation, found by an ordered seek.
CREATE INDEX invitations_pending_of_user
    ON invitations (tenant_id, user_id, created_at DESC, id DESC)
    WHERE status = 'pending';
