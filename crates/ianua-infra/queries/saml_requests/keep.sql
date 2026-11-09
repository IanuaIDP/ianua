-- Keeps a SAML sign-in request of a tenant under its ID until it is
-- answered. A request kept again under the same ID replaces the one
-- before.
INSERT INTO saml_requests
    (tenant_id, request_id, connection_id, binding_hash, dashboard_hash, lapses_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tenant_id, request_id) DO UPDATE SET
    connection_id = EXCLUDED.connection_id,
    binding_hash = EXCLUDED.binding_hash,
    dashboard_hash = EXCLUDED.dashboard_hash,
    lapses_at = EXCLUDED.lapses_at
