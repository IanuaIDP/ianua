-- Every enrolled connector of one tenant, revoked ones included, with the
-- parts the gateway judges a link by. No enrollment code's digest is read.
SELECT id, scope, public_key AS "public_key!", status
FROM connectors
WHERE tenant_id = $1 AND public_key IS NOT NULL
ORDER BY id
