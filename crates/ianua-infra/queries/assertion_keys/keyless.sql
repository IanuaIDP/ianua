-- Every active tenant holding no assertion key in this database: one made
-- before assertion keys were, whose setup never made one. For the sweep
-- that gives it a first key. A tenant living in a database of its own is
-- listed too, and its own database is asked before it is given one.
SELECT tenants.id AS "tenant_id!"
FROM tenants
WHERE tenants.status = 'active'
  AND NOT EXISTS (
      SELECT 1 FROM assertion_keys WHERE assertion_keys.tenant_id = tenants.id
  )
