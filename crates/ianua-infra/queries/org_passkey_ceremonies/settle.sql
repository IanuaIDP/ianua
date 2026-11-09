-- Settles a passkey ceremony at the given time, only if nothing settled it
-- before: a row changed means this call settled it.
UPDATE org_passkey_ceremonies
SET consumed_at = $2
WHERE id = $1 AND consumed_at IS NULL
