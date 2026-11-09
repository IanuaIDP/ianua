-- The operators who run the platform, the API keys they act with, and the
-- grants that let one act as a tenant's user for a while.
--
-- Platform tables, in the platform database alone: an operator belongs to
-- no tenant. An impersonation grant names its tenant, so it sits under
-- row-level security too.
--
-- The checks repeat the rules the domain keeps between columns, so a row
-- written past the domain is refused here too.

CREATE TABLE operators (
    id uuid PRIMARY KEY,
    email text NOT NULL,
    password_hash text NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    -- An operator signs in by address, so it names one operator.
    CONSTRAINT operators_email_key UNIQUE (email),
    CONSTRAINT operators_status_known
        CHECK (status IN ('active', 'disabled'))
);

-- One index per order an operator list can ask for, the id last, and the
-- same led by status for a list narrowed to one status.
CREATE INDEX operators_by_created ON operators (created_at, id);
CREATE INDEX operators_by_email ON operators (email, id);
CREATE INDEX operators_by_status ON operators (status, id);
CREATE INDEX operators_in_status_by_created ON operators (status, created_at, id);
CREATE INDEX operators_in_status_by_email ON operators (status, email, id);

-- An operator's API keys, each found by the prefix it is shown with. Only
-- the hash of a key is kept.
CREATE TABLE operator_api_keys (
    key_prefix text PRIMARY KEY,
    -- Operators are disabled, never removed; were one removed, their keys
    -- would act for nobody, so they go too.
    operator_id uuid NOT NULL REFERENCES operators (id) ON DELETE CASCADE,
    key_hash text NOT NULL,
    -- When the key stops working, or NULL for never.
    expires_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL,
    CONSTRAINT operator_api_keys_prefix_known
        CHECK (starts_with(key_prefix, 'opk_')),
    CONSTRAINT operator_api_keys_expire_after_created
        CHECK (expires_at IS NULL OR expires_at > created_at),
    CONSTRAINT operator_api_keys_revoked_after_created
        CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

-- An operator's keys, and the foreign key to the operator.
CREATE INDEX operator_api_keys_of_operator ON operator_api_keys (operator_id, created_at, key_prefix);
-- An operator's key is found by its digest alone when it is presented, so
-- the lookup needs a key of its own.
CREATE INDEX operator_api_keys_by_hash ON operator_api_keys (key_hash);

-- The grants that let an operator act as one user of one tenant, for at
-- most a day.
CREATE TABLE impersonation_grants (
    id uuid PRIMARY KEY,
    -- A grant acts for its operator alone, so it goes with them.
    operator_id uuid NOT NULL REFERENCES operators (id) ON DELETE CASCADE,
    -- A grant into a tenant means nothing once the tenant is gone.
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    -- no foreign key: the user lives in the tenant's database, which may
    -- be one of its own.
    user_id uuid NOT NULL,
    reason text NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL,
    CONSTRAINT impersonation_grants_window
        CHECK (expires_at > created_at AND expires_at <= created_at + interval '24 hours'),
    CONSTRAINT impersonation_grants_revoked_after_created
        CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

ALTER TABLE impersonation_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE impersonation_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON impersonation_grants
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- An operator's grants, by the user they act as, and the foreign key to
-- the operator.
CREATE INDEX impersonation_grants_of_operator
    ON impersonation_grants (operator_id, tenant_id, user_id, expires_at);

-- A tenant's grants, for the foreign key to the tenant.
CREATE INDEX impersonation_grants_in_tenant ON impersonation_grants (tenant_id);
