-- The claims still to be proved of one tenant, read from the database of
-- its own it lives in, with the same delay and back-off as
-- `awaiting_proof.sql`. The oldest hundred first.
SELECT tenant_id, id, domain, connection, verification_status, verified_at, failed_at,
       dns_challenge_token, tls_status, created_at
FROM registered_domains
WHERE tenant_id = $2
  AND verification_status <> 'verified'
  AND created_at < $1::timestamptz - interval '2 minutes'
  AND (last_checked_at IS NULL OR last_checked_at < $1::timestamptz - CASE
        WHEN created_at > $1::timestamptz - interval '1 hour' THEN interval '5 minutes'
        WHEN created_at > $1::timestamptz - interval '6 hours' THEN interval '30 minutes'
        ELSE interval '6 hours'
      END)
ORDER BY created_at
LIMIT 100
