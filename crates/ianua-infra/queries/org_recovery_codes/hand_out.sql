-- Writes the codes of a member's set, all in one statement: each code's
-- digest with when it was used, NULL for one still unused.
INSERT INTO org_recovery_codes (org_user_id, code_hash, used_at)
SELECT $1, code.code_hash, code.used_at
FROM UNNEST($2::text[], $3::timestamptz[]) AS code (code_hash, used_at)
