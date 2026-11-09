-- Adds a member's consent decision. A record is never changed once made,
-- so adding one already kept leaves it as it is.
INSERT INTO org_consents
    (id, organization_id, org_user_id, consent_type, granted, version,
     ip_address, recorded_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO NOTHING
