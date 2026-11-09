-- The listening ports stream routes claim.
--
-- A port belongs to the whole deployment, not to a tenant: every gateway
-- listens on it. So the claim lives in the platform database alone,
-- whichever database the tenant's routes live in, and the primary key keeps
-- each port to one route across every tenant.

CREATE TABLE stream_route_ports (
    listen_port integer PRIMARY KEY,
    -- A tenant's claims go with the tenant.
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    -- no foreign key: the route lives in the tenant's own database, which
    -- may not be this one.
    stream_route_id uuid NOT NULL,
    CONSTRAINT stream_route_ports_route_key UNIQUE (tenant_id, stream_route_id),
    CONSTRAINT stream_route_ports_in_range
        CHECK (listen_port BETWEEN 1024 AND 65535)
);

ALTER TABLE stream_route_ports ENABLE ROW LEVEL SECURITY;
ALTER TABLE stream_route_ports FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON stream_route_ports
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));
