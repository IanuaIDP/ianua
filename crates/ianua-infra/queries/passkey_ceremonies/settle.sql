-- Settles a passkey ceremony of a tenant at the given time, only if
-- nothing settled it before: a row changed means this call settled it.
UPDATE passkey_ceremonies
SET consumed_at = $3
WHERE tenant_id = $1 AND id = $2 AND consumed_at IS NULL
