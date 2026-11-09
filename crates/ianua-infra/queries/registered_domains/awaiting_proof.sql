-- The claims still to be proved of every tenant in this database,
-- registered more than two minutes before now ($1) and due for another
-- check: every five minutes in their first hour, every half hour until
-- they are six hours old, every six hours after. The oldest hundred first.
SELECT tenant_id, id, domain, connection, verification_status, verified_at, failed_at,
       dns_challenge_token, tls_status, created_at
FROM registered_domains
WHERE verification_status <> 'verified'
  AND created_at < $1::timestamptz - interval '2 minutes'
  AND (last_checked_at IS NULL OR last_checked_at < $1::timestamptz - CASE
        WHEN created_at > $1::timestamptz - interval '1 hour' THEN interval '5 minutes'
        WHEN created_at > $1::timestamptz - interval '6 hours' THEN interval '30 minutes'
        ELSE interval '6 hours'
      END)
ORDER BY created_at
LIMIT 100
