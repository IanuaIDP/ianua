-- Keeps a tenant's limit on access requests, replacing the one stored.
INSERT INTO access_request_policies (tenant_id, longest_seconds, updated_at)
VALUES ($1, $2, $3)
ON CONFLICT (tenant_id) DO UPDATE SET
    longest_seconds = EXCLUDED.longest_seconds,
    updated_at = EXCLUDED.updated_at
