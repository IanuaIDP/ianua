-- Keeps a device authorization: a new one is added, a known one of the
-- same tenant takes where it stands, who approved it and its polling, only
-- while it still waits for an answer. Its codes, client, scopes and times
-- never change, and an answered, redeemed or lapsed request is never moved
-- again by a copy read before that happened.
INSERT INTO oauth_device_authorizations
    (tenant_id, device_code_hash, user_code_hash, user_code_sealed, client_id, scopes, status,
     approved_by, interval_secs, last_polled_at, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (tenant_id, device_code_hash) DO UPDATE SET
    status = EXCLUDED.status,
    approved_by = EXCLUDED.approved_by,
    interval_secs = EXCLUDED.interval_secs,
    last_polled_at = EXCLUDED.last_polled_at
WHERE oauth_device_authorizations.status = 'pending'
