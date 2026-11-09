-- The latest code sent for the second factor of a user of a tenant, locked
-- until the running transaction ends, so a second answer to it waits for
-- this one's count.
SELECT user_id, enrolled_at, method, code_hash, issued_at, expires_at, wrong_tries, spent_at
FROM mfa_sent_codes
WHERE tenant_id = $1 AND user_id = $2
FOR UPDATE
