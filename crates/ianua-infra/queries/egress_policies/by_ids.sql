-- The egress policies of one tenant with the given ids.
SELECT id, name, service, destinations, max_data_class, created_by_kind,
       created_by, created_at, updated_at
FROM egress_policies
WHERE tenant_id = $1 AND id = ANY($2)
