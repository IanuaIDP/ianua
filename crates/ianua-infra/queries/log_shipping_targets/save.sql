-- Keeps a log shipping target: a new one is added, a known one takes the
-- new values. Its tenant and creation time never change.
INSERT INTO log_shipping_targets
    (id, tenant_id, name, destination, credential, records, sample_percent, format, status,
     created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    destination = EXCLUDED.destination,
    credential = EXCLUDED.credential,
    records = EXCLUDED.records,
    sample_percent = EXCLUDED.sample_percent,
    format = EXCLUDED.format,
    status = EXCLUDED.status,
    updated_at = EXCLUDED.updated_at
WHERE log_shipping_targets.tenant_id = EXCLUDED.tenant_id
