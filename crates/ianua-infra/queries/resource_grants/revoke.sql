-- Takes a relation on a named resource away from a principal of a tenant.
-- Taking one it does not hold changes nothing.
DELETE FROM resource_grants
WHERE tenant_id = $1 AND subject_kind = $2 AND subject_id = $3 AND relation = $4
  AND object_ref = $5
