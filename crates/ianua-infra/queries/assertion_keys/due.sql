-- Every tenant in this database holding assertion keys but none active
-- made at or after the cutoff: its signing key is old, or nothing signs.
-- For the sweep that rotates assertion keys by age.
SELECT DISTINCT held.tenant_id AS "tenant_id!"
FROM assertion_keys held
WHERE NOT EXISTS (
    SELECT 1 FROM assertion_keys fresh
    WHERE fresh.tenant_id = held.tenant_id
      AND fresh.status = 'active'
      AND fresh.created_at >= $1
)
