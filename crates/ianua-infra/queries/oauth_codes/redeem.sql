-- Marks one tenant's authorization code used, only while it is still
-- unused: of two exchanges of one code arriving together, only one changes
-- the row.
UPDATE oauth_codes
SET consumed_at = $3
WHERE tenant_id = $1 AND code_hash = $2 AND consumed_at IS NULL
