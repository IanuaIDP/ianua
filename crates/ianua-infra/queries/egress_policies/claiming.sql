-- Every tenant's egress policy for the given service, with its tenant, for the egress gateway.
SELECT tenant_id, id, name, service, destinations, max_data_class,
       created_by_kind, created_by, created_at, updated_at
FROM egress_policies
WHERE service = $1
ORDER BY tenant_id, id
