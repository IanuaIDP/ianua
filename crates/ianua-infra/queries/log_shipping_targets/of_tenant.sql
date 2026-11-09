-- Every log shipping target of the tenant, by name.
SELECT id, name, destination, credential, records, sample_percent, format, status, created_at,
       updated_at
FROM log_shipping_targets
WHERE tenant_id = $1
ORDER BY name
