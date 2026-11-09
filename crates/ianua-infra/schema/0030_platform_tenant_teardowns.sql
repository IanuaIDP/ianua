-- Each deleted tenant's teardown: the steps it holds, the ones done in the
-- order they were done, and the step that failed with why. Kept in the
-- platform database beside the tenant, since it outlives a database of the
-- tenant's own.
CREATE TABLE tenant_teardowns (
    tenant_id uuid PRIMARY KEY,
    planned text[] NOT NULL,
    done text[] NOT NULL,
    failed_step text,
    failed_reason text,
    started_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- A teardown is its tenant's, and goes with the platform's record of it.
    CONSTRAINT tenant_teardowns_tenant_fkey FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT tenant_teardowns_steps_known
        CHECK (planned <@ ARRAY['data', 'audit_trail', 'database']
           AND done <@ planned),
    CONSTRAINT tenant_teardowns_failure_whole
        CHECK (num_nulls(failed_step, failed_reason) IN (0, 2)),
    CONSTRAINT tenant_teardowns_failed_step_planned
        CHECK (failed_step IS NULL OR failed_step = ANY (planned)),
    CONSTRAINT tenant_teardowns_changed_after_started
        CHECK (updated_at >= started_at)
);

ALTER TABLE tenant_teardowns ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_teardowns FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON tenant_teardowns
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));
