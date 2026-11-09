-- Keeps an egress policy: a new one is added, a known one of the same
-- tenant takes the new values. Its tenant, its maker and its creation time
-- never change.
INSERT INTO egress_policies
    (id, tenant_id, name, service, destinations, max_data_class,
     created_by_kind, created_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    service = EXCLUDED.service,
    destinations = EXCLUDED.destinations,
    max_data_class = EXCLUDED.max_data_class,
    updated_at = EXCLUDED.updated_at
WHERE egress_policies.tenant_id = EXCLUDED.tenant_id
