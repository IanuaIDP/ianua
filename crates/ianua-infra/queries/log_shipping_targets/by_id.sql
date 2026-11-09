-- The tenant's log shipping target with the given id.
SELECT id, name, destination, credential, records, sample_percent, format, status, created_at,
       updated_at
FROM log_shipping_targets
WHERE tenant_id = $1 AND id = $2
