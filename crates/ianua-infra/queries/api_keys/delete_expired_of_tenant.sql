-- Deletes one tenant's API keys that expired by the given time, in the
-- database of its own it lives in, answering the tenant, id and name of
-- each for the audit of the expiry.
DELETE FROM api_keys
WHERE tenant_id = $1 AND expires_at <= $2
RETURNING tenant_id, id, name
