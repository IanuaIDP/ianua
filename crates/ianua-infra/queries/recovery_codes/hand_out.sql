-- Writes the codes of a user's set, all in one statement: each code's hash
-- with when it was used, NULL for one still unused.
INSERT INTO recovery_codes (tenant_id, user_id, code_hash, used_at)
SELECT $1, $2, code.code_hash, code.used_at
FROM UNNEST($3::text[], $4::timestamptz[]) AS code (code_hash, used_at)
