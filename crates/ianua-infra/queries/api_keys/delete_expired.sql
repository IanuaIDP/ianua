-- Deletes every tenant's API keys that expired by the given time, answering
-- the tenant, id and name of each for the audit of the expiry.
DELETE FROM api_keys
WHERE expires_at <= $1
RETURNING tenant_id, id, name
