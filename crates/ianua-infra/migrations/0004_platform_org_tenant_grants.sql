-- The roles organization members hold in the organization's tenants.
--
-- It lives with the organization in the platform database, but each row
-- belongs to one tenant, so row-level security keeps it to that tenant
-- like every tenant table. The member it names gets its foreign key when
-- the members' table is made; the role never can, see below.

CREATE TABLE org_tenant_grants (
    org_user_id uuid NOT NULL,
    -- A grant means nothing without its tenant, so it goes when the tenant
    -- is removed.
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    -- no foreign key: the role lives in the tenant's own database, which
    -- may not be this one.
    role_id uuid NOT NULL,
    -- The member who granted it, or NULL for the platform.
    granted_by uuid,
    granted_at timestamptz NOT NULL,
    PRIMARY KEY (org_user_id, tenant_id, role_id)
);

ALTER TABLE org_tenant_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_tenant_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON org_tenant_grants
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX org_tenant_grants_in_tenant ON org_tenant_grants (tenant_id, org_user_id);
