-- Adds a consent decision. A decision is never changed once made, so a
-- record already kept is left as it is.
INSERT INTO consent_records
    (id, tenant_id, user_id, consent_type, granted, version, ip_address, recorded_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO NOTHING
