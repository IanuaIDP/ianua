-- The egress policy of one tenant for the given service, if it has one.
SELECT id, name, service, destinations, max_data_class, created_by_kind,
       created_by, created_at, updated_at
FROM egress_policies
WHERE tenant_id = $1 AND service = $2
