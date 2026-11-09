-- Copies of one tenant's setup into another of the same organization: the
-- parts asked for, those copied so far, and how the copy stands. Kept in
-- the platform database, since a clone spans two tenants that may each
-- live in a database of their own. A clone is filed under the tenant it
-- fills, its `tenant_id`.
CREATE TABLE tenant_clones (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    source_tenant_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    parts text[] NOT NULL,
    copied text[] NOT NULL,
    state text NOT NULL,
    failure text,
    ended_at timestamptz,
    started_at timestamptz NOT NULL,
    -- A clone fills its tenant, and goes with the platform's record of it.
    CONSTRAINT tenant_clones_tenant_fkey FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    -- A clone copies from its source, and goes with the platform's record of it.
    CONSTRAINT tenant_clones_source_fkey FOREIGN KEY (source_tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    -- A clone is its organization's, and goes with it.
    CONSTRAINT tenant_clones_organization_fkey FOREIGN KEY (organization_id)
        REFERENCES organizations (id) ON DELETE CASCADE,
    CONSTRAINT tenant_clones_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT tenant_clones_not_into_itself
        CHECK (source_tenant_id <> tenant_id),
    CONSTRAINT tenant_clones_parts_known
        CHECK (parts <@ ARRAY['settings', 'branding', 'roles_and_policies', 'routes',
                              'oauth_applications']
           AND cardinality(parts) >= 1
           AND copied <@ parts),
    CONSTRAINT tenant_clones_state_known
        CHECK (state IN ('copying', 'completed', 'failed')),
    CONSTRAINT tenant_clones_failure_named_when_failed
        CHECK ((state = 'failed') = (failure IS NOT NULL)),
    CONSTRAINT tenant_clones_failure_known
        CHECK (failure IN ('source_gone', 'target_gone', 'copy_failed')),
    CONSTRAINT tenant_clones_ended_unless_copying
        CHECK ((state = 'copying') = (ended_at IS NULL)),
    CONSTRAINT tenant_clones_ended_after_started
        CHECK (ended_at >= started_at)
);

ALTER TABLE tenant_clones ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_clones FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON tenant_clones
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'))
    WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- Whether a tenant is being filled by a clone now.
CREATE INDEX tenant_clones_copying_into ON tenant_clones (tenant_id) WHERE state = 'copying';
-- The clones still copying, the oldest first, for the reconcile sweep.
CREATE INDEX tenant_clones_copying_since ON tenant_clones (started_at, id) WHERE state = 'copying';
-- The clones of a source, and the foreign key to it.
CREATE INDEX tenant_clones_of_source ON tenant_clones (source_tenant_id);
-- The clones of an organization, and the foreign key to it.
CREATE INDEX tenant_clones_of_organization ON tenant_clones (organization_id);
