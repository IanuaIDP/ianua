-- Every egress policy of one tenant, by name.
SELECT id, name, service, destinations, max_data_class, created_by_kind,
       created_by, created_at, updated_at
FROM egress_policies
WHERE tenant_id = $1
ORDER BY name, id
