-- Every tenant in this database holding a key rotated out and not yet
-- revoked, for the sweep that revokes it once its grace is over.
SELECT DISTINCT tenant_id AS "tenant_id!"
FROM signing_keys
WHERE status = 'rotated'
