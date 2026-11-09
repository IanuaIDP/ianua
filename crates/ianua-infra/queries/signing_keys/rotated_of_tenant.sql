-- Whether one tenant, read from the database of its own it lives in, holds
-- a key rotated out and not yet revoked.
SELECT EXISTS (
    SELECT 1 FROM signing_keys WHERE tenant_id = $1 AND status = 'rotated'
) AS "held!"
