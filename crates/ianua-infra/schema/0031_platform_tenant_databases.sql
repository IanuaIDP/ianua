-- The tenants that live in a database of their own: for now a schema of
-- the platform's database, named after the tenant. Every node routes a
-- tenant by these rows, loads them at start and follows their changes,
-- and the trail reads them before it adds a record in the platform's
-- database, so a node that has not heard of a move yet is refused instead
-- of splitting the tenant's chain.
CREATE TABLE tenant_databases (
    tenant_id uuid PRIMARY KEY,
    schema_name text NOT NULL,
    registered_at timestamptz NOT NULL,
    -- A tenant's database is its own, and goes with the platform's record of it.
    CONSTRAINT tenant_databases_tenant_fkey FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT tenant_databases_schema_key UNIQUE (schema_name),
    -- The schema made for this tenant, never another's.
    CONSTRAINT tenant_databases_schema_made_here
        CHECK (schema_name = 'tenant_' || replace(tenant_id::text, '-', ''))
);

ALTER TABLE tenant_databases ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_databases FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON tenant_databases
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'))
    WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));
