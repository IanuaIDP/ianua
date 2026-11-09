-- Every tenant in this database holding an active key made before the
-- cutoff, for the sweep that rotates keys by age.
SELECT DISTINCT tenant_id AS "tenant_id!"
FROM signing_keys
WHERE status = 'active' AND created_at < $1
