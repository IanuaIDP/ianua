-- Retires a session of a tenant a refresh used, only while it is not
-- revoked, and in the same statement keeps the session carrying it on: a
-- row added means this refresh won, and no child is ever kept for a parent
-- another refresh retired.
WITH retired AS (
    UPDATE sessions
    SET status = $3, factor = $4, owed = $5, last_active_at = $6, kept_through = $7
    WHERE tenant_id = $1 AND id = $2 AND status <> 'revoked'
    RETURNING tenant_id
)
INSERT INTO sessions
    (id, tenant_id, user_id, refresh_token_hash, parent_id, ip_address, user_agent,
     auth_method, factor, owed, status, app_service_id,
     signed_in_at, created_at, last_active_at, expires_at, kept_through, signed_in_from,
     last_used_network, last_used_latitude, last_used_longitude, last_used_country, last_used_at)
SELECT $8::uuid, retired.tenant_id, $9::uuid, $10::text, $11::uuid, $12::text, $13::text,
       $14::text, $15::text, $16::text, $17::text, $18::uuid,
       $19::timestamptz, $20::timestamptz, $21::timestamptz, $22::timestamptz, $23::timestamptz,
       $24::uuid, $25::text, $26::float8, $27::float8, $28::text, $29::timestamptz
FROM retired
