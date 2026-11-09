-- Each tenant's setup: the steps it holds, the ones done in the order they
-- were done, and the step that failed with why. Kept in the platform
-- database beside the tenant, since a setup runs before a tenant with a
-- database of its own has that database.
CREATE TABLE tenant_setups (
    tenant_id uuid PRIMARY KEY,
    planned text[] NOT NULL,
    done text[] NOT NULL,
    failed_step text,
    failed_reason text,
    started_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- A setup is its tenant's, and goes with it.
    CONSTRAINT tenant_setups_tenant_fkey FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT tenant_setups_steps_known
        CHECK (planned <@ ARRAY['database', 'signing_key', 'assertion_key', 'starting_roles',
                                'activate']
           AND done <@ planned),
    CONSTRAINT tenant_setups_failure_whole
        CHECK (num_nulls(failed_step, failed_reason) IN (0, 2)),
    CONSTRAINT tenant_setups_failed_step_planned
        CHECK (failed_step IS NULL OR failed_step = ANY (planned)),
    CONSTRAINT tenant_setups_changed_after_started
        CHECK (updated_at >= started_at)
);

ALTER TABLE tenant_setups ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_setups FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON tenant_setups
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));
